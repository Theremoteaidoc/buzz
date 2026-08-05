import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";

import { relayMembersQueryKey } from "@/features/community-members/hooks";
import { useMyRelayMembershipLookupQuery } from "@/features/community-members/hooks";
import { useCommunities } from "@/features/communities/useCommunities";
import {
  joinAlertBody,
  joinAlertTitle,
  normalizeJoinPubkey,
  readJoinAlertLedger,
  reconcileJoinAlertLedger,
  writeJoinAlertLedger,
  type JoinAlertLedger,
  EMPTY_JOIN_ALERT_LEDGER,
} from "@/features/community-members/lib/joinAlerts";
import { sendDesktopNotification } from "@/features/notifications/lib/desktop";
import { resolveUserLabel } from "@/features/profile/lib/identity";
import type { UserProfileLookup } from "@/features/profile/lib/identity";
import { relayClient } from "@/shared/api/relayClient";
import { useIdentityQuery } from "@/shared/api/hooks";
import {
  canManageCommunityMembers,
  relayMembersFromEvent,
} from "@/shared/api/relayMembers";
import { getUsersBatch } from "@/shared/api/tauriProfiles";
import type { RelayEvent } from "@/shared/api/types";

const KIND_NIP43_MEMBERSHIP_LIST = 13534;
const KIND_NIP43_MEMBER_ADDED = 8000;

/**
 * Notify community owners/admins the first time a key appears in their roster.
 *
 * Delivery rests on a live kind:13534 subscription because that snapshot is the
 * only membership signal covering every join path with cross-pod propagation;
 * see `lib/joinAlerts.ts` for the full rationale. Desktop's other 13534 read
 * (`relayMembers.ts`) is a one-shot fetch, so without this subscription no
 * snapshot ever arrives passively and nothing could fire.
 *
 * The kind:8000 delta is subscribed purely to shorten latency on the paths that
 * emit one. It refreshes the authoritative snapshot rather than alerting from
 * the delta's own payload, so one ledger governs both signals and the pair
 * cannot double-alert.
 *
 * Viewer, community, and role are read from context rather than passed in:
 * `AppShell` is at the file-size ratchet ceiling, so the mount has to stay a
 * single call.
 */
export function useCommunityJoinAlerts({ enabled }: { enabled: boolean }) {
  const queryClient = useQueryClient();
  const { activeCommunity } = useCommunities();
  const identityQuery = useIdentityQuery();
  const membershipQuery = useMyRelayMembershipLookupQuery();

  const communityId = activeCommunity?.id ?? null;
  const communityName = activeCommunity?.name ?? null;
  const normalizedViewer = normalizeJoinPubkey(
    identityQuery.data?.pubkey ?? "",
  );
  const active =
    enabled &&
    canManageCommunityMembers(membershipQuery.data) &&
    communityId !== null &&
    normalizedViewer.length > 0;

  // Ledger mirror. A ref keeps the subscription callbacks stable: re-subscribing
  // on every roster change would drop deltas in the gap between REQ and CLOSE.
  const ledgerRef = React.useRef<JoinAlertLedger>(EMPTY_JOIN_ALERT_LEDGER);
  const communityNameRef = React.useRef(communityName);
  communityNameRef.current = communityName;

  const handleSnapshot = React.useEffectEvent(async (event: RelayEvent) => {
    if (communityId === null) return;

    const rosterPubkeys = relayMembersFromEvent(event).map(
      (member) => member.pubkey,
    );
    if (rosterPubkeys.length === 0) return;

    // The roster can change shape without anything being new to us (a removal
    // or a role change), so refresh the panel regardless of alert eligibility.
    void queryClient.invalidateQueries({ queryKey: relayMembersQueryKey });

    const { alerts, changed, ledger } = reconcileJoinAlertLedger({
      ledger: ledgerRef.current,
      rosterPubkeys,
      viewerPubkey: normalizedViewer,
    });
    if (!changed) return;

    // Persisted before notifying, never after: a crash between the two must
    // lose the notification rather than repeat it on every later snapshot.
    ledgerRef.current = ledger;
    writeJoinAlertLedger(communityId, normalizedViewer, ledger);
    if (alerts.length === 0) return;

    // Resolve display names so the alert reads "Alice joined" rather than a
    // truncated key; a lookup failure degrades to the key, it does not skip.
    let profiles: UserProfileLookup | undefined;
    try {
      profiles = (await getUsersBatch(alerts)).profiles;
    } catch {
      profiles = undefined;
    }

    for (const pubkey of alerts) {
      await sendDesktopNotification({
        body: joinAlertBody(
          resolveUserLabel({ preferResolvedSelfLabel: true, profiles, pubkey }),
        ),
        target: {
          channelId: null,
          eventId: event.id,
          kind: event.kind,
          pubkey,
        },
        title: joinAlertTitle(communityNameRef.current),
      });
    }
  });

  React.useEffect(() => {
    if (!active || communityId === null) return;

    ledgerRef.current = readJoinAlertLedger(communityId, normalizedViewer);

    let disposed = false;
    const disposers: Array<() => Promise<void>> = [];

    const track = (unsubscribe: () => Promise<void>) => {
      if (disposed) {
        void unsubscribe();
        return;
      }
      disposers.push(unsubscribe);
    };

    const refreshSnapshot = () => {
      void relayClient
        .fetchFirstEvent({ kinds: [KIND_NIP43_MEMBERSHIP_LIST], limit: 1 })
        .then((snapshot) => {
          if (!disposed && snapshot) void handleSnapshot(snapshot);
        })
        .catch(() => {
          // Best effort: the live 13534 subscription still delivers.
        });
    };

    void relayClient
      .subscribeLive({ kinds: [KIND_NIP43_MEMBERSHIP_LIST], limit: 1 }, (e) => {
        if (!disposed) void handleSnapshot(e);
      })
      .then(track)
      .catch((error) => {
        console.error("Couldn’t subscribe to community membership", error);
      });

    // Accelerator only: refetch the authoritative snapshot instead of trusting
    // the delta, so the ledger only ever sees one consistent roster view.
    void relayClient
      .subscribeLive({ kinds: [KIND_NIP43_MEMBER_ADDED], limit: 0 }, () => {
        if (!disposed) refreshSnapshot();
      })
      .then(track)
      .catch((error) => {
        console.error("Couldn’t subscribe to community joins", error);
      });

    // A reconnect can span joins that landed while the socket was down, and
    // `limit: 1` backfill is not guaranteed to redeliver them.
    const unsubscribeReconnect =
      relayClient.subscribeToReconnects(refreshSnapshot);

    return () => {
      disposed = true;
      unsubscribeReconnect();
      for (const dispose of disposers) void dispose();
    };
  }, [active, communityId, normalizedViewer]);
}
