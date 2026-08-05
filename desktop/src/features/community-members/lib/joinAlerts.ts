/**
 * First-join alert bookkeeping for community owners/admins.
 *
 * # Why the roster snapshot is the source of truth, not the kind:8000 delta
 *
 * The relay emits a kind:8000 "member-added" delta on the invite-claim and
 * relay-admin paths, but `buzz-admin add-member` deliberately emits none
 * (`crates/buzz-admin/src/main.rs:6-13`), and kind:8000 fan-out is pod-local
 * (`fan_out_event_to_local_subscribers` never calls `publish_event`, unlike
 * `dispatch_persistent_event_inner`). The kind:13534 membership snapshot is the
 * only signal that covers every join path *and* propagates across pods, so it
 * is the correctness signal here; kind:8000 is a latency accelerator only.
 *
 * # Why a persisted ledger rather than snapshot-to-snapshot diffing
 *
 * Snapshot publication is eventual, not transactional: a failed post-commit
 * publish is repaired by the relay's periodic reconciler, so the same member
 * can first appear in a snapshot arriving up to a reconcile interval late, and
 * a reconciler-published snapshot is indistinguishable from a fresh one. Only a
 * ledger of pubkeys we have already alerted on can answer "is this new to the
 * user", which is the question the notification actually asks. The ledger also
 * absorbs kind:8000 redelivery on reconnect, where the replay filter re-sends
 * events at or after `lastSeenCreatedAt - skew` and can repeat a seen delta.
 */

const JOIN_ALERT_STORAGE_PREFIX = "buzz-community-join-seen.v1";

/**
 * Cap on retained pubkeys per community. Ledger entries are only consulted for
 * membership, so the oldest are the safest to shed once a roster grows past
 * this bound.
 */
export const JOIN_ALERT_SEEN_MAX_ITEMS = 5_000;

export type JoinAlertLedger = {
  /**
   * Whether a roster snapshot has already been folded in for this community.
   *
   * Tracked explicitly rather than inferred from `pubkeys.length > 0`, because
   * the two are not the same proposition: a community whose only member is the
   * viewer seeds to an *empty* pubkey list (the viewer is never recorded), and
   * inferring from emptiness would then classify the first genuine join as the
   * seeding run and silently swallow the very alert this feature exists for.
   */
  seeded: boolean;
  /** Pubkeys already alerted on, oldest first. */
  pubkeys: string[];
};

export const EMPTY_JOIN_ALERT_LEDGER: JoinAlertLedger = {
  seeded: false,
  pubkeys: [],
};

export function joinAlertStorageKey(communityId: string, viewerPubkey: string) {
  return `${JOIN_ALERT_STORAGE_PREFIX}:${communityId}:${viewerPubkey}`;
}

export function normalizeJoinPubkey(pubkey: string): string {
  return pubkey.trim().toLowerCase();
}

export function readJoinAlertLedger(
  communityId: string,
  viewerPubkey: string,
): JoinAlertLedger {
  if (
    typeof window === "undefined" ||
    communityId.length === 0 ||
    viewerPubkey.length === 0
  ) {
    return EMPTY_JOIN_ALERT_LEDGER;
  }

  const rawValue = window.localStorage.getItem(
    joinAlertStorageKey(communityId, viewerPubkey),
  );
  if (!rawValue) {
    return EMPTY_JOIN_ALERT_LEDGER;
  }

  try {
    const parsed: unknown = JSON.parse(rawValue);
    if (parsed === null || typeof parsed !== "object") {
      return EMPTY_JOIN_ALERT_LEDGER;
    }

    const { pubkeys, seeded } = parsed as Partial<JoinAlertLedger>;
    if (!Array.isArray(pubkeys)) {
      return EMPTY_JOIN_ALERT_LEDGER;
    }

    return {
      // A stored ledger is by definition the residue of a snapshot we already
      // folded in, so unreadable/absent `seeded` reads as true. Defaulting the
      // other way would re-seed and drop a real join.
      seeded: seeded !== false,
      pubkeys: pubkeys
        .filter((value): value is string => typeof value === "string")
        .slice(-JOIN_ALERT_SEEN_MAX_ITEMS),
    };
  } catch {
    return EMPTY_JOIN_ALERT_LEDGER;
  }
}

export function writeJoinAlertLedger(
  communityId: string,
  viewerPubkey: string,
  ledger: JoinAlertLedger,
) {
  if (
    typeof window === "undefined" ||
    communityId.length === 0 ||
    viewerPubkey.length === 0
  ) {
    return;
  }

  window.localStorage.setItem(
    joinAlertStorageKey(communityId, viewerPubkey),
    JSON.stringify({
      seeded: ledger.seeded,
      pubkeys: ledger.pubkeys.slice(-JOIN_ALERT_SEEN_MAX_ITEMS),
    } satisfies JoinAlertLedger),
  );
}

/**
 * Fold a roster snapshot into the ledger, returning the pubkeys to alert on.
 *
 * The viewer's own pubkey is never alerted on or recorded: an owner does not
 * need to be told they joined their own community.
 *
 * `alerts` is empty on the seeding run — the first snapshot for a community
 * records every existing member silently, so installing the app against an
 * established roster does not produce a notification per member.
 */
export function reconcileJoinAlertLedger({
  ledger,
  rosterPubkeys,
  viewerPubkey,
}: {
  ledger: JoinAlertLedger;
  rosterPubkeys: readonly string[];
  viewerPubkey: string;
}): { alerts: string[]; changed: boolean; ledger: JoinAlertLedger } {
  const normalizedViewer = normalizeJoinPubkey(viewerPubkey);
  const seen = new Set(ledger.pubkeys);
  const fresh: string[] = [];

  for (const rawPubkey of rosterPubkeys) {
    const pubkey = normalizeJoinPubkey(rawPubkey);
    if (pubkey.length === 0) continue;
    if (pubkey === normalizedViewer) continue;
    if (seen.has(pubkey)) continue;
    seen.add(pubkey);
    fresh.push(pubkey);
  }

  if (fresh.length === 0 && ledger.seeded) {
    return { alerts: [], changed: false, ledger };
  }

  return {
    alerts: ledger.seeded ? fresh : [],
    changed: true,
    ledger: {
      seeded: true,
      pubkeys: [...ledger.pubkeys, ...fresh].slice(-JOIN_ALERT_SEEN_MAX_ITEMS),
    },
  };
}

/** Notification copy for a single first join. */
export function joinAlertTitle(communityName: string | null | undefined) {
  const trimmed = communityName?.trim();
  return trimmed && trimmed.length > 0
    ? `New member in ${trimmed}`
    : "New community member";
}

export function joinAlertBody(displayName: string) {
  return `${displayName} joined`;
}
