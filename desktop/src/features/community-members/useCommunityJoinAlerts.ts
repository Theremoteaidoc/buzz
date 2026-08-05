import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";

import {
  myRelayMembershipLookupQueryKey,
  relayMembersQueryKey,
} from "@/features/community-members/hooks";
import { useMyRelayMembershipLookupQuery } from "@/features/community-members/hooks";
import { useCommunities } from "@/features/communities/useCommunities";
import {
  joinAlertBody,
  joinAlertSummaryBody,
  joinAlertTitle,
  normalizeJoinPubkey,
  readJoinAlertLedger,
  reconcileJoinAlertLedger,
  writeJoinAlertLedger,
  type JoinAlertLedger,
  EMPTY_JOIN_ALERT_LEDGER,
  JOIN_ALERT_MAX_INDIVIDUAL,
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
 * Trailing window for coalescing kind:8000-triggered snapshot refetches.
 *
 * Long enough that a bulk add collapses to a single REQ, short enough that a
 * lone join still feels immediate — the accelerator exists only to beat the
 * live snapshot's own arrival, so sub-second is the whole budget.
 */
const MEMBER_REFRESH_DEBOUNCE_MS = 500;

/**
 * Trailing quiet window for coalescing join alerts ACROSS snapshots.
 *
 * The per-snapshot cap bounds "one snapshot, many keys". It does nothing for
 * "one burst, many snapshots": the relay republishes the whole 13534 as each
 * concurrent add commits, so a 50-join storm arrives as a handful of growing
 * rosters and each one independently emitted its own capped batch. Max measured
 * 10 banners from 50 real joins at `fdeda44f0` for exactly this reason.
 *
 * Sized above the observed intermediate-snapshot cadence so a burst lands in
 * one batch, and above MEMBER_REFRESH_DEBOUNCE_MS so an 8000-triggered refetch
 * folds into the same window rather than flushing behind it.
 */
const JOIN_ALERT_NOTIFY_WINDOW_MS = 1_500;

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

  // Pending cross-snapshot batch. A burst arrives as several growing rosters,
  // so alerts accumulate here and flush once the roster stops moving.
  //
  // `pendingEventRef` holds the LATEST snapshot only, as the notification's
  // click target. Every key in the batch is present in that roster (the ledger
  // is monotonic within a burst), so the newest snapshot is the accurate
  // referent for the whole batch.
  const pendingRef = React.useRef<string[]>([]);
  const pendingEventRef = React.useRef<RelayEvent | null>(null);
  const notifyTimerRef = React.useRef<number | null>(null);

  /** Drop anything queued but not yet delivered. */
  const clearPending = React.useCallback(() => {
    pendingRef.current = [];
    pendingEventRef.current = null;
    if (notifyTimerRef.current !== null) {
      window.clearTimeout(notifyTimerRef.current);
      notifyTimerRef.current = null;
    }
  }, []);

  const flushPending = React.useEffectEvent(async () => {
    const alerts = pendingRef.current;
    const event = pendingEventRef.current;
    pendingRef.current = [];
    pendingEventRef.current = null;
    if (alerts.length === 0 || !event) return;

    // Resolve display names so the alert reads "Alice joined" rather than a
    // truncated key; a lookup failure degrades to the key, it does not skip.
    //
    // Above the cap the batch collapses into one summary, so skip the profile
    // fetch entirely — it would be a 250-key request whose result is unused.
    if (alerts.length > JOIN_ALERT_MAX_INDIVIDUAL) {
      await sendDesktopNotification({
        body: joinAlertSummaryBody(alerts.length),
        target: {
          channelId: null,
          eventId: event.id,
          kind: event.kind,
          pubkey: undefined,
        },
        title: joinAlertTitle(communityNameRef.current),
      });
      return;
    }

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

  const handleSnapshot = React.useEffectEvent(async (event: RelayEvent) => {
    if (communityId === null) return;

    const roster = relayMembersFromEvent(event);
    const rosterPubkeys = roster.map((member) => member.pubkey);
    if (rosterPubkeys.length === 0) return;

    // The roster can change shape without anything being new to us (a removal
    // or a role change), so refresh the panel regardless of alert eligibility.
    void queryClient.invalidateQueries({ queryKey: relayMembersQueryKey });

    // Authorize against the snapshot in hand, not the cached role that mounted
    // this effect. `useMyRelayMembershipLookupQuery` is only invalidated by this
    // client's own membership mutations, and `staleTime` marks data stale
    // without scheduling a refetch, so a viewer demoted by another admin keeps
    // a cached owner/admin role for as long as the app stays open — and would
    // otherwise keep learning every later joiner's identity from a role they no
    // longer hold. The snapshot carries the viewer's own role
    // (`["member", pubkey, role]`, relay-signed in `publish_nip43_membership_locked`),
    // so the event that revokes authorization is the same event that would
    // disclose the join. Checking it here closes that race in one read rather
    // than racing an async invalidation.
    //
    // Fail closed: a snapshot that does not list the viewer at all means they
    // were removed outright.
    const viewerEntry = roster.find(
      (member) => member.pubkey === normalizedViewer,
    );
    if (viewerEntry?.role !== "owner" && viewerEntry?.role !== "admin") {
      // Revocation must also drop anything queued but not yet delivered.
      // Batching across snapshots would otherwise reopen the disclosure Wren
      // found as a *delayed* one: joins accumulated while authorized would
      // still fire from a timer after the snapshot that revoked the role.
      clearPending();
      // Refresh the mount gate so the subscriptions themselves tear down.
      void queryClient.invalidateQueries({
        queryKey: myRelayMembershipLookupQueryKey,
      });
      return;
    }

    const { alerts, changed, ledger } = reconcileJoinAlertLedger({
      ledger: ledgerRef.current,
      rosterPubkeys,
      viewerPubkey: normalizedViewer,
    });
    if (!changed) return;

    // Persisted before notifying, never after: a crash between the two must
    // lose the notification rather than repeat it on every later snapshot.
    //
    // A write that cannot land (quota still exceeded after cache eviction)
    // leaves the ledger ref alone deliberately. Advancing it would mark these
    // keys seen in memory while nothing reached storage, so the alert would be
    // lost until a reload; leaving it means the next snapshot retries the
    // write and the alert survives to whichever attempt lands. The notify is
    // skipped either way — a false return means nothing was persisted, so
    // notifying here is exactly the "repeat on every later snapshot" this
    // ordering exists to prevent.
    if (!writeJoinAlertLedger(communityId, normalizedViewer, ledger)) return;
    ledgerRef.current = ledger;
    if (alerts.length === 0) return;

    // Queue rather than notify. Persistence and the ledger ref advance stay
    // synchronous per snapshot (above), so cross-snapshot dedupe still holds
    // and a crash before the flush loses the alert rather than repeating it —
    // the ordering invariant this feature already committed to. Only the
    // delivery is deferred, onto a trailing quiet window, so one burst
    // produces one alert instead of one per intermediate snapshot.
    pendingRef.current.push(...alerts);
    pendingEventRef.current = event;
    if (notifyTimerRef.current !== null) {
      window.clearTimeout(notifyTimerRef.current);
    }
    notifyTimerRef.current = window.setTimeout(() => {
      notifyTimerRef.current = null;
      void flushPending();
    }, JOIN_ALERT_NOTIFY_WINDOW_MS);
  });

  React.useEffect(() => {
    if (!active || communityId === null) return;

    ledgerRef.current = readJoinAlertLedger(communityId, normalizedViewer);

    let disposed = false;
    const disposers: Array<() => Promise<void>> = [];
    let refreshTimeout: number | null = null;

    const track = (unsubscribe: () => Promise<void>) => {
      if (disposed) {
        void unsubscribe();
        return;
      }
      disposers.push(unsubscribe);
    };

    const fetchSnapshot = () => {
      void relayClient
        .fetchFirstEvent({ kinds: [KIND_NIP43_MEMBERSHIP_LIST], limit: 1 })
        .then((snapshot) => {
          if (!disposed && snapshot) void handleSnapshot(snapshot);
        })
        .catch(() => {
          // Best effort: the live 13534 subscription still delivers.
        });
    };

    /**
     * Coalesce refetches on a trailing window.
     *
     * Each refetch is a REQ frame, and REQ is billed against the same per-
     * principal `WsEvents` budget as the user's own sends (default 10/s over a
     * 5s window). A bulk add emits one kind:8000 per member, so an uncoalesced
     * 1:1 refetch would spend the budget the owner needs for messages and
     * channel opens — rate-limiting them out of their own app. One snapshot is
     * authoritative for the whole burst, so the trailing edge loses nothing.
     */
    const refreshSnapshot = () => {
      if (disposed || refreshTimeout !== null) return;
      refreshTimeout = window.setTimeout(() => {
        refreshTimeout = null;
        if (!disposed) fetchSnapshot();
      }, MEMBER_REFRESH_DEBOUNCE_MS);
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
      if (refreshTimeout !== null) window.clearTimeout(refreshTimeout);
      // Drop the queued batch too, not just its timer: on a community switch
      // this effect re-keys, and keys accumulated for the old community must
      // not flush against the new one.
      clearPending();
      unsubscribeReconnect();
      for (const dispose of disposers) void dispose();
    };
  }, [active, communityId, normalizedViewer, clearPending]);
}
