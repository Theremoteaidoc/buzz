/**
 * Mounted-hook tests for useCommunityJoinAlerts.
 *
 * The ledger reducer is covered by lib/joinAlerts.test.mjs. Nothing there
 * exercises the parts of this feature that only exist once the hook is
 * mounted, and those are exactly the parts a unit test cannot reach:
 *
 *   - the owner/admin gate sitting BEFORE any storage access, so a plain
 *     member creates no ledger key at all;
 *   - the reconnect arm, which refetches the snapshot across a socket gap and
 *     must not re-alert keys the ledger already carries;
 *   - the effect re-key on community switch, so each community gets its own
 *     subscription and its own seed state;
 *   - the kind:8000 arm refetching the authoritative snapshot rather than
 *     alerting from the delta's own payload.
 *
 * Max's live-local matrix could not land the reconnect arm (simultaneous
 * browser reloads tripped relay rate limiting) and did not exercise community
 * switch, so these are the only evidence for those two paths.
 *
 * ── Harness shape ────────────────────────────────────────────────────────────
 * Same pattern as useLoadArchivedObserverEvents.test.mjs: minimal DOM shim →
 * __TAURI_INTERNALS__.invoke interception → production imports → createRoot/act
 * inside a QueryClientProvider. relayClient's three entry points are replaced
 * with mock.method so no socket is opened; window.Notification is stubbed so
 * sendDesktopNotification takes its real permission-granted path and we can
 * count what it emitted.
 */

import assert from "node:assert/strict";
import { describe, it, beforeEach, afterEach, mock } from "node:test";

// ── Minimal DOM shim ─────────────────────────────────────────────────────────

function installDOMShim() {
  class MinimalEventTarget {
    constructor() {
      this._listeners = {};
    }
    addEventListener(type, fn) {
      if (!this._listeners[type]) this._listeners[type] = [];
      this._listeners[type].push(fn);
    }
    removeEventListener(type, fn) {
      if (this._listeners[type]) {
        this._listeners[type] = this._listeners[type].filter((f) => f !== fn);
      }
    }
    dispatchEvent(e) {
      for (const fn of this._listeners[e.type] ?? []) fn(e);
      return true;
    }
  }

  class MinimalNode extends MinimalEventTarget {
    constructor(tagName) {
      super();
      this.tagName = tagName;
      this.children = [];
      this.childNodes = [];
      this.style = {};
      this.nodeType = 1;
      this.parentNode = null;
    }
    get ownerDocument() {
      return globalThis.document;
    }
    get firstChild() {
      return this.children[0] ?? null;
    }
    get lastChild() {
      return this.children[this.children.length - 1] ?? null;
    }
    get nextSibling() {
      return null;
    }
    get nodeValue() {
      return null;
    }
    appendChild(child) {
      this.children.push(child);
      this.childNodes.push(child);
      child.parentNode = this;
      return child;
    }
    removeChild(child) {
      this.children = this.children.filter((c) => c !== child);
      this.childNodes = this.childNodes.filter((c) => c !== child);
      return child;
    }
    insertBefore(newNode, refNode) {
      if (!refNode) return this.appendChild(newNode);
      const i = this.children.indexOf(refNode);
      if (i < 0) return this.appendChild(newNode);
      this.children.splice(i, 0, newNode);
      this.childNodes.splice(i, 0, newNode);
      newNode.parentNode = this;
      return newNode;
    }
    contains(node) {
      if (!node) return false;
      return this === node || this.children.some((c) => c?.contains?.(node));
    }
  }

  class MinimalDocument extends MinimalEventTarget {
    constructor() {
      super();
      this.nodeType = 9;
    }
    createElement(tagName) {
      return new MinimalNode(tagName);
    }
    createTextNode(value) {
      const n = new MinimalNode("#text");
      n.nodeValue = value;
      n.nodeType = 3;
      return n;
    }
    createComment(value) {
      const n = new MinimalNode("#comment");
      n.nodeValue = value;
      n.nodeType = 8;
      return n;
    }
    get body() {
      if (!this._body) this._body = this.createElement("body");
      return this._body;
    }
    get activeElement() {
      return null;
    }
    contains(node) {
      return node != null;
    }
  }

  globalThis.document = new MinimalDocument();
  globalThis.HTMLElement = MinimalNode;
  // react-dom's commit phase does `element instanceof window.HTMLIFrameElement`
  // (getActiveElementDeep, react-dom-client.development.js:3667). Leaving it
  // undefined throws "Right-hand side of 'instanceof' is not an object" out of
  // commitRoot, before any assertion runs.
  globalThis.HTMLIFrameElement = MinimalNode;
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  process.env.IS_REACT_ACT_ENVIRONMENT = "true";

  if (typeof globalThis.window === "undefined") {
    Object.defineProperty(globalThis, "window", {
      value: globalThis,
      configurable: true,
    });
  }
  if (!Object.getOwnPropertyDescriptor(globalThis, "navigator")?.value) {
    Object.defineProperty(globalThis, "navigator", {
      value: { userAgent: "node" },
      configurable: true,
    });
  }
  globalThis.MutationObserver = class {
    observe() {}
    disconnect() {}
    takeRecords() {
      return [];
    }
  };
  globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);
}

installDOMShim();

// ── localStorage shim ────────────────────────────────────────────────────────
//
// Backs the real production ledger read/write. Kept as a plain Map so a test
// can inspect exactly which keys the feature created — the plain-member arm
// asserts on key ABSENCE, so a shim that silently swallows writes would make
// that assertion vacuous.

const storage = new Map();
/** When true the shim rejects writes the way a full origin quota does. */
let storageFull = false;

globalThis.localStorage = {
  get length() {
    return storage.size;
  },
  key: (index) => [...storage.keys()][index] ?? null,
  getItem: (key) => storage.get(key) ?? null,
  setItem: (key, value) => {
    if (storageFull) {
      const error = new Error("QuotaExceededError");
      error.name = "QuotaExceededError";
      throw error;
    }
    storage.set(key, value);
  },
  removeItem: (key) => storage.delete(key),
  clear: () => storage.clear(),
};
globalThis.window.localStorage = globalThis.localStorage;

// ── Notification shim ────────────────────────────────────────────────────────
//
// sendDesktopNotification returns false unless permission is "granted", so
// without this every alert assertion would pass for the wrong reason (silent
// success). Recording the constructor calls is how we count alerts.

const notifications = [];

class StubNotification {
  static permission = "granted";
  constructor(title, options) {
    notifications.push({ title, body: options?.body, options });
  }
  close() {}
}

globalThis.Notification = StubNotification;
globalThis.window.Notification = StubNotification;

// ── Tauri IPC interceptor ────────────────────────────────────────────────────

/** @type {Map<string, (args: unknown) => Promise<unknown>>} */
const ipcHandlers = new Map();

globalThis.__TAURI_INTERNALS__ = {
  invoke: (cmd, args) => {
    const handler = ipcHandlers.get(cmd);
    if (handler) return handler(args);
    return Promise.reject(new Error(`unmocked Tauri command: ${cmd}`));
  },
  transformCallback: () => Math.random(),
};

// ── Production imports (after shims) ─────────────────────────────────────────

import React from "react";
import { createRoot } from "react-dom/client";
import { act } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { useCommunityJoinAlerts } from "@/features/community-members/useCommunityJoinAlerts.ts";
import { joinAlertStorageKey } from "@/features/community-members/lib/joinAlerts.ts";
import { relayClient } from "@/shared/api/relayClient.ts";
import { CommunitiesProvider } from "@/features/communities/useCommunities.tsx";
import { useCommunities } from "@/features/communities/useCommunities.tsx";
import {
  myRelayMembershipLookupQueryKey,
  relayMembersQueryKey,
} from "@/features/community-members/hooks.ts";

// ── Constants ────────────────────────────────────────────────────────────────

const VIEWER = "a".repeat(64);
const ALICE = "b".repeat(64);
const BOB = "c".repeat(64);
const CAROL = "d".repeat(64);
const COMMUNITY_A = "community-a";
const COMMUNITY_B = "community-b";

const KIND_SNAPSHOT = 13534;
const KIND_MEMBER_ADDED = 8000;

/**
 * A kind:13534 membership snapshot carrying the given roster.
 *
 * The viewer is stamped `owner` unless `viewerRole` says otherwise, mirroring
 * the relay: `publish_nip43_membership_locked` emits `["member", pubkey, role]`
 * for every row, so the viewer's own authorization always rides in the
 * snapshot. A fixture that stamped everyone `member` could not express the
 * demotion this hook now gates on.
 */
function snapshot(
  rosterPubkeys,
  { id = "snap-1", createdAt = 1000, viewerRole = "owner" } = {},
) {
  return {
    id,
    pubkey: "f".repeat(64),
    created_at: createdAt,
    kind: KIND_SNAPSHOT,
    tags: rosterPubkeys.map((pubkey) => [
      "member",
      pubkey,
      pubkey === VIEWER ? viewerRole : "member",
    ]),
    content: "",
    sig: "s".repeat(128),
  };
}

/** Seed the communities the provider will load from localStorage. */
function seedCommunities(activeId) {
  storage.set(
    "buzz-communities",
    JSON.stringify([
      {
        id: COMMUNITY_A,
        name: "Community A",
        relayUrl: "wss://a.test",
        addedAt: "2026-01-01T00:00:00Z",
      },
      {
        id: COMMUNITY_B,
        name: "Community B",
        relayUrl: "wss://b.test",
        addedAt: "2026-01-01T00:00:00Z",
      },
    ]),
  );
  storage.set("buzz-active-community-id", activeId);
}

/**
 * Replace relayClient's three entry points and hand the test direct control of
 * every callback the hook registers.
 */
function installRelayStub() {
  /** @type {Map<number, Array<(event: unknown) => void>>} */
  const liveByKind = new Map();
  const reconnectListeners = [];
  let fetchFirstEventCalls = 0;
  let nextSnapshot = null;
  let subscribeCount = 0;
  let unsubscribeCount = 0;

  mock.method(relayClient, "subscribeLive", async (filter, onEvent) => {
    subscribeCount++;
    const kind = filter.kinds[0];
    if (!liveByKind.has(kind)) liveByKind.set(kind, []);
    liveByKind.get(kind).push(onEvent);
    return async () => {
      unsubscribeCount++;
      const list = liveByKind.get(kind) ?? [];
      liveByKind.set(
        kind,
        list.filter((fn) => fn !== onEvent),
      );
    };
  });

  mock.method(relayClient, "fetchFirstEvent", async () => {
    fetchFirstEventCalls++;
    return nextSnapshot;
  });

  mock.method(relayClient, "subscribeToReconnects", (listener) => {
    reconnectListeners.push(listener);
    return () => {
      const i = reconnectListeners.indexOf(listener);
      if (i >= 0) reconnectListeners.splice(i, 1);
    };
  });

  return {
    /** Deliver a snapshot down every live kind:13534 callback. */
    emitSnapshot: (event) => {
      for (const fn of liveByKind.get(KIND_SNAPSHOT) ?? []) fn(event);
    },
    /** Deliver a kind:8000 delta down every live accelerator callback. */
    emitDelta: (event) => {
      for (const fn of liveByKind.get(KIND_MEMBER_ADDED) ?? []) fn(event);
    },
    /** Fire the relay client's reconnect notification. */
    emitReconnect: () => {
      for (const fn of [...reconnectListeners]) fn();
    },
    /** What a subsequent fetchFirstEvent (refetch) resolves to. */
    setRefetchSnapshot: (event) => {
      nextSnapshot = event;
    },
    counts: () => ({
      fetchFirstEventCalls,
      subscribeCount,
      unsubscribeCount,
      liveSnapshotSubs: (liveByKind.get(KIND_SNAPSHOT) ?? []).length,
      liveDeltaSubs: (liveByKind.get(KIND_MEMBER_ADDED) ?? []).length,
      reconnectListeners: reconnectListeners.length,
    }),
  };
}

/** Mount the real hook under a real CommunitiesProvider + QueryClientProvider. */
function mountHook({ role = "owner", enabled = true } = {}) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  queryClient.setQueryData(["identity"], { pubkey: VIEWER });
  queryClient.setQueryData(myRelayMembershipLookupQueryKey, {
    snapshotFound: true,
    membershipRequired: true,
    membership:
      role === null
        ? null
        : { pubkey: VIEWER, role, addedBy: null, createdAt: null },
  });

  const invalidations = [];
  const realInvalidate = queryClient.invalidateQueries.bind(queryClient);
  queryClient.invalidateQueries = (args) => {
    invalidations.push(args?.queryKey);
    return realInvalidate(args);
  };

  // Captured from inside the tree so a test can switch community the way the
  // rail does — in the SAME mounted tree. Unmount/remount would tear the
  // subscriptions down no matter what the effect keys on, which makes the
  // re-key assertion pass on a hook with an empty dependency array.
  const control = { switchCommunity: null };

  function Harness() {
    control.switchCommunity = useCommunities().switchCommunity;
    useCommunityJoinAlerts({ enabled });
    return null;
  }

  const container = document.createElement("div");
  const root = createRoot(container);

  const render = async () => {
    await act(async () => {
      root.render(
        React.createElement(
          QueryClientProvider,
          { client: queryClient },
          React.createElement(
            CommunitiesProvider,
            null,
            React.createElement(Harness, null),
          ),
        ),
      );
    });
  };

  return {
    render,
    invalidations,
    switchCommunity: async (id) => {
      await act(async () => {
        control.switchCommunity(id);
      });
    },
    unmount: async () => {
      await act(async () => {
        root.unmount();
      });
    },
  };
}

async function settle(iterations = 4) {
  for (let i = 0; i < iterations; i++) {
    await act(async () => {
      await new Promise((r) => setTimeout(r, 5));
    });
  }
}

/**
 * Advance past the kind:8000 refetch debounce, then settle.
 *
 * The accelerator coalesces refetches on a 500ms trailing window so a bulk add
 * costs one REQ instead of one per member; anything asserting on a refetch has
 * to outwait that window or it is asserting on a timer that has not fired.
 */
async function settleAfterRefreshDebounce() {
  await act(async () => {
    await new Promise((r) => setTimeout(r, 600));
  });
  await settle();
}

/**
 * Advance past the cross-snapshot notify window, then settle.
 *
 * Alerts are queued per snapshot and delivered on a trailing quiet window, so
 * a burst spanning several intermediate 13534s produces one notification
 * instead of one per snapshot. Anything asserting that a notification WAS
 * delivered has to outwait that window; anything asserting an absence should
 * outwait it too, or it proves only that delivery is deferred.
 */
async function settleAfterNotifyWindow() {
  await act(async () => {
    await new Promise((r) => setTimeout(r, 1_700));
  });
  await settle();
}

function ledgerKeys() {
  return [...storage.keys()].filter((key) =>
    key.startsWith("buzz-community-join-seen.v1"),
  );
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe("useCommunityJoinAlerts — mounted subscription behaviour", () => {
  beforeEach(() => {
    storage.clear();
    storageFull = false;
    notifications.length = 0;
    seedCommunities(COMMUNITY_A);
  });

  afterEach(() => {
    mock.restoreAll();
  });

  /**
   * Positive control for the whole harness. Every other arm asserts an absence
   * (no alert, no key, no extra subscription); if the harness could never
   * produce an alert in the first place, all of them would pass vacuously.
   */
  it("seeds silently on the first snapshot, then alerts on a genuine join", async () => {
    const relay = installRelayStub();
    const { render, unmount } = mountHook();

    await render();
    await settle();

    relay.emitSnapshot(snapshot([VIEWER, ALICE]));
    await settle();

    assert.equal(
      notifications.length,
      0,
      "the first snapshot per community must seed silently",
    );
    assert.equal(ledgerKeys().length, 1, "the seed must be persisted");

    relay.emitSnapshot(snapshot([VIEWER, ALICE, BOB], { id: "snap-2" }));
    await settleAfterNotifyWindow();

    assert.equal(notifications.length, 1, "a genuine join must alert once");
    assert.match(notifications[0].title, /Community A/);
    assert.match(notifications[0].body, /joined/);

    await unmount();
  });

  /**
   * A plain member mounts the hook (it is mounted unconditionally alongside the
   * other desktop notification wiring) and must be inert. Eva asked for the
   * stronger assertion: not merely "no notification" but "no ledger key", which
   * proves the role gate sits before storage access rather than after it.
   *
   * A key materializing here would not be a gate-ordering nit — it would mean
   * canManageCommunityMembers returned true for a non-manager, i.e. a
   * role-resolution bug upstream in relayMembers.ts.
   */
  it("is completely inert for a plain member: no subscription, no ledger key", async () => {
    const relay = installRelayStub();
    const { render, unmount } = mountHook({ role: "member" });

    await render();
    await settle();

    const counts = relay.counts();
    assert.equal(
      counts.subscribeCount,
      0,
      "a plain member must open no subscription",
    );
    assert.equal(
      counts.reconnectListeners,
      0,
      "a plain member must register no reconnect listener",
    );

    // Even if a snapshot somehow arrived, nothing is wired to receive it.
    relay.emitSnapshot(snapshot([VIEWER, ALICE, BOB]));
    await settle();

    assert.equal(notifications.length, 0);
    assert.deepEqual(
      ledgerKeys(),
      [],
      "no buzz-community-join-seen.v1 key may be created for a plain member",
    );

    await unmount();
  });

  /**
   * `enabled: false` is the desktopEnabled precondition from
   * useAppShellDesktopNotifications. An owner with notifications switched off
   * must be as inert as a plain member — including writing no ledger, so
   * turning notifications back on later seeds rather than back-alerting.
   */
  it("is inert for an owner when notifications are disabled", async () => {
    const relay = installRelayStub();
    const { render, unmount } = mountHook({ enabled: false });

    await render();
    await settle();

    assert.equal(relay.counts().subscribeCount, 0);
    assert.deepEqual(ledgerKeys(), []);

    await unmount();
  });

  /**
   * Reconnect arm. Max could not land this live (simultaneous browser reloads
   * tripped relay rate limiting), so this is the only evidence for it.
   *
   * Two halves, and the second is the one that matters: the reconnect must
   * refetch (a socket gap can span joins that `limit: 1` backfill will not
   * redeliver), AND the refetched snapshot must not re-alert keys the ledger
   * already carries. Asserting only the refetch would pass on a hook that
   * alerts twice for every reconnect.
   */
  it("refetches on reconnect without re-alerting already-seen keys", async () => {
    const relay = installRelayStub();
    const { render, unmount } = mountHook();

    await render();
    await settle();

    relay.emitSnapshot(snapshot([VIEWER, ALICE]));
    await settle();
    relay.emitSnapshot(snapshot([VIEWER, ALICE, BOB], { id: "snap-2" }));
    await settleAfterNotifyWindow();
    assert.equal(notifications.length, 1, "precondition: one join alerted");

    const before = relay.counts().fetchFirstEventCalls;

    // The socket drops and recovers; the relay client replays the same roster.
    relay.setRefetchSnapshot(
      snapshot([VIEWER, ALICE, BOB], { id: "snap-replay", createdAt: 2000 }),
    );
    relay.emitReconnect();
    await settleAfterRefreshDebounce();
    await settleAfterNotifyWindow();

    assert.ok(
      relay.counts().fetchFirstEventCalls > before,
      "reconnect must refetch the authoritative snapshot",
    );
    assert.equal(
      notifications.length,
      1,
      "a reconnect replay of a known roster must not re-alert",
    );

    // A key that joined during the gap still alerts on the refetched snapshot.
    relay.setRefetchSnapshot(
      snapshot([VIEWER, ALICE, BOB, "d".repeat(64)], {
        id: "snap-gap",
        createdAt: 3000,
      }),
    );
    relay.emitReconnect();
    await settleAfterRefreshDebounce();
    await settleAfterNotifyWindow();

    assert.equal(
      notifications.length,
      2,
      "a join that landed during the socket gap must alert on refetch",
    );

    await unmount();
  });

  /**
   * The kind:8000 accelerator must refetch the authoritative snapshot rather
   * than alert from the delta's own payload — that is what lets one ledger
   * govern both signals so the pair cannot double-alert.
   *
   * The delta here names a pubkey that is NOT in the refetched roster. A hook
   * alerting off the delta payload would fire; the correct hook fires nothing,
   * because the snapshot is the authority.
   */
  it("treats kind:8000 as a refetch trigger, not an alert payload", async () => {
    const relay = installRelayStub();
    const { render, unmount } = mountHook();

    await render();
    await settle();

    relay.emitSnapshot(snapshot([VIEWER, ALICE]));
    await settle();
    assert.equal(notifications.length, 0);

    const before = relay.counts().fetchFirstEventCalls;

    // Delta names a pubkey the authoritative roster does not (yet) carry.
    relay.setRefetchSnapshot(
      snapshot([VIEWER, ALICE], { id: "snap-unchanged", createdAt: 2000 }),
    );
    relay.emitDelta({
      id: "delta-1",
      pubkey: "f".repeat(64),
      created_at: 1500,
      kind: KIND_MEMBER_ADDED,
      tags: [["p", BOB]],
      content: "",
      sig: "s".repeat(128),
    });
    await settleAfterRefreshDebounce();

    assert.ok(
      relay.counts().fetchFirstEventCalls > before,
      "a kind:8000 delta must trigger a snapshot refetch",
    );
    assert.equal(
      notifications.length,
      0,
      "the delta's own payload must never produce an alert — only the snapshot decides",
    );

    // Now the snapshot agrees, and exactly one alert follows.
    relay.setRefetchSnapshot(
      snapshot([VIEWER, ALICE, BOB], { id: "snap-agrees", createdAt: 3000 }),
    );
    relay.emitDelta({
      id: "delta-2",
      pubkey: "f".repeat(64),
      created_at: 2500,
      kind: KIND_MEMBER_ADDED,
      tags: [["p", BOB]],
      content: "",
      sig: "s".repeat(128),
    });
    await settleAfterRefreshDebounce();
    await settleAfterNotifyWindow();

    assert.equal(notifications.length, 1);

    // And the live snapshot carrying the same join must not alert a second time.
    relay.emitSnapshot(
      snapshot([VIEWER, ALICE, BOB], { id: "snap-live", createdAt: 3500 }),
    );
    await settle();
    assert.equal(
      notifications.length,
      1,
      "the accelerator and the live snapshot share one ledger and must not double-alert",
    );

    await unmount();
  });

  /**
   * Community switch. Max's live-local run did not exercise this.
   *
   * The switch happens in the SAME mounted tree (via the provider's real
   * switchCommunity), not by remounting: a remount tears every subscription
   * down regardless of what the effect keys on, so a remount-based version of
   * this test would pass on a hook with an empty dependency array. Switching
   * in-tree makes the assertion actually about [active, communityId, viewer].
   */
  it("re-keys on community switch: fresh subscription and independent seed", async () => {
    const relay = installRelayStub();
    const harness = mountHook();

    await harness.render();
    await settle();

    relay.emitSnapshot(snapshot([VIEWER, ALICE]));
    await settle();
    relay.emitSnapshot(snapshot([VIEWER, ALICE, BOB], { id: "snap-2" }));
    await settleAfterNotifyWindow();
    assert.equal(notifications.length, 1, "precondition: A alerted once");
    assert.deepEqual(ledgerKeys(), [joinAlertStorageKey(COMMUNITY_A, VIEWER)]);

    const beforeSwitch = relay.counts();
    assert.equal(
      beforeSwitch.liveSnapshotSubs,
      1,
      "precondition: A holds one live snapshot subscription",
    );

    await harness.switchCommunity(COMMUNITY_B);
    await settle();

    const afterSwitch = relay.counts();
    assert.equal(
      afterSwitch.unsubscribeCount,
      beforeSwitch.subscribeCount,
      `switching must close every subscription community A opened — opened ${beforeSwitch.subscribeCount}, closed ${afterSwitch.unsubscribeCount}`,
    );
    assert.equal(
      afterSwitch.subscribeCount,
      beforeSwitch.subscribeCount * 2,
      "switching must open a fresh pair of subscriptions for community B",
    );
    assert.equal(
      afterSwitch.liveSnapshotSubs,
      1,
      "exactly one live snapshot subscription may be open after the switch",
    );
    assert.equal(
      afterSwitch.liveDeltaSubs,
      1,
      "exactly one live delta subscription may be open after the switch",
    );

    // B's existing roster must seed silently even though A is already seeded.
    relay.emitSnapshot(
      snapshot([VIEWER, ALICE, BOB], { id: "snap-b", createdAt: 4000 }),
    );
    await settle();

    assert.equal(
      notifications.length,
      1,
      "community B must seed silently — its roster is not a set of joins",
    );

    const keys = ledgerKeys().sort();
    assert.deepEqual(
      keys,
      [
        joinAlertStorageKey(COMMUNITY_A, VIEWER),
        joinAlertStorageKey(COMMUNITY_B, VIEWER),
      ].sort(),
      "each community must keep its own ledger",
    );

    // And B alerts on its own first genuine join.
    relay.emitSnapshot(
      snapshot([VIEWER, ALICE, BOB, "d".repeat(64)], {
        id: "snap-b2",
        createdAt: 5000,
      }),
    );
    await settleAfterNotifyWindow();
    assert.equal(notifications.length, 2);

    // Switching back must not re-alert A's roster: its ledger persisted.
    await harness.switchCommunity(COMMUNITY_A);
    await settle();
    relay.emitSnapshot(
      snapshot([VIEWER, ALICE, BOB], { id: "snap-a-return", createdAt: 6000 }),
    );
    await settleAfterNotifyWindow();
    assert.equal(
      notifications.length,
      2,
      "returning to A must not re-alert keys A's ledger already carries",
    );

    await harness.unmount();
  });

  /**
   * Eva's red-team finding (thread 866f149d): writeJoinAlertLedger returns
   * whether the write landed, and the caller dropped it. On a quota failure
   * that survives cache eviction the alert fired against an unpersisted
   * ledger — so the next reload re-alerted the same keys, which is exactly the
   * "repeat" the ordering comment one line above promises never to do.
   *
   * Two halves, and both are needed. Asserting only "no notification" would
   * pass on a hook that also poisons the in-memory ref, silently swallowing
   * the alert forever. The second half proves the alert is deferred, not lost:
   * once storage recovers, the next snapshot delivers it.
   */
  it("does not notify when the ledger write cannot land, and delivers once it can", async () => {
    const relay = installRelayStub();
    const { render, unmount } = mountHook();

    await render();
    await settle();

    relay.emitSnapshot(snapshot([VIEWER, ALICE]));
    await settle();
    assert.equal(ledgerKeys().length, 1, "precondition: the seed persisted");

    // Origin quota is exhausted and cache eviction cannot free enough.
    storageFull = true;
    relay.emitSnapshot(snapshot([VIEWER, ALICE, BOB], { id: "snap-full" }));
    await settleAfterNotifyWindow();

    assert.equal(
      notifications.length,
      0,
      "an alert must not fire against a ledger that was never persisted",
    );

    // Storage recovers. The same join must still be pending, not consumed by
    // the failed attempt: the ref was deliberately left un-advanced.
    storageFull = false;
    relay.emitSnapshot(
      snapshot([VIEWER, ALICE, BOB], { id: "snap-recovered", createdAt: 2000 }),
    );
    await settleAfterNotifyWindow();

    assert.equal(
      notifications.length,
      1,
      "the deferred alert must be delivered by the first snapshot whose write lands",
    );

    // And it is not delivered twice now that the ledger is on disk.
    relay.emitSnapshot(
      snapshot([VIEWER, ALICE, BOB], { id: "snap-after", createdAt: 3000 }),
    );
    await settleAfterNotifyWindow();
    assert.equal(notifications.length, 1);

    await unmount();
  });

  /**
   * A snapshot refreshes the members panel regardless of alert eligibility: a
   * removal or a role change alters the roster without producing anything new
   * to alert on, and the open panel must still repaint.
   */
  it("invalidates the members query on every snapshot, including a seeding one", async () => {
    const relay = installRelayStub();
    const { render, invalidations, unmount } = mountHook();

    await render();
    await settle();

    relay.emitSnapshot(snapshot([VIEWER, ALICE]));
    await settle();

    assert.ok(
      invalidations.some(
        (key) => JSON.stringify(key) === JSON.stringify(relayMembersQueryKey),
      ),
      "the seeding snapshot must still refresh the roster panel",
    );

    await unmount();
  });
  /**
   * Authorization must come from the snapshot in hand, not the cached role that
   * mounted the effect.
   *
   * `useMyRelayMembershipLookupQuery` is invalidated only by this client's own
   * membership mutations, and `staleTime` marks data stale without scheduling a
   * refetch — so a viewer demoted by ANOTHER admin keeps a cached owner/admin
   * role for as long as the app stays open. Found by Wren, reproduced live by
   * Max against a real relay: the demoted viewer kept learning every later
   * joiner's identity.
   *
   * The demotion and the join ride in the SAME snapshot, which is the racy
   * shape: an async invalidation cannot beat the handler it is racing.
   */
  it("stops alerting when the snapshot itself demotes the viewer", async () => {
    const relay = installRelayStub();
    const { render, unmount } = mountHook({ role: "admin" });

    await render();
    await settle();

    relay.emitSnapshot(snapshot([VIEWER, ALICE], { viewerRole: "admin" }));
    await settle();

    // Positive control: still admin, so a genuine join must alert. Without
    // this, a gate that refused everything would pass the assertions below.
    relay.emitSnapshot(
      snapshot([VIEWER, ALICE, BOB], { id: "snap-join", viewerRole: "admin" }),
    );
    await settleAfterNotifyWindow();
    assert.equal(notifications.length, 1, "precondition: admin still alerts");

    const ledgerBefore = storage.get(joinAlertStorageKey(COMMUNITY_A, VIEWER));

    // Remote demotion + a new member, in one authoritative snapshot.
    relay.emitSnapshot(
      snapshot([VIEWER, ALICE, BOB, CAROL], {
        id: "snap-demote",
        createdAt: 4000,
        viewerRole: "member",
      }),
    );
    await settleAfterNotifyWindow();

    assert.equal(
      notifications.length,
      1,
      "a demoted viewer must not be told who joined",
    );
    assert.equal(
      storage.get(joinAlertStorageKey(COMMUNITY_A, VIEWER)),
      ledgerBefore,
      "the ledger must not advance on a snapshot the viewer is not authorized for",
    );

    await unmount();
  });

  /**
   * Removal is the same disclosure as demotion, and `find` returning undefined
   * is a different code path from a role that is present but wrong.
   */
  it("stops alerting when the viewer is dropped from the roster entirely", async () => {
    const relay = installRelayStub();
    const { render, unmount } = mountHook({ role: "owner" });

    await render();
    await settle();

    relay.emitSnapshot(snapshot([VIEWER, ALICE]));
    await settle();

    // Viewer absent from the snapshot; a new key arrives alongside.
    relay.emitSnapshot({
      id: "snap-removed",
      pubkey: "f".repeat(64),
      created_at: 5000,
      kind: KIND_SNAPSHOT,
      tags: [
        ["member", ALICE, "member"],
        ["member", BOB, "member"],
      ],
      content: "",
      sig: "s".repeat(128),
    });
    await settleAfterNotifyWindow();

    assert.equal(
      notifications.length,
      0,
      "a removed viewer must learn nothing about later joins",
    );

    await unmount();
  });

  /**
   * A snapshot is a whole roster, so a bulk add lands every new key at once.
   * Uncapped that is one OS notification per member — measured at 248 banners
   * for a 250-key snapshot, delivered through a serial await loop.
   */
  it("collapses a bulk join into one summary instead of a banner per member", async () => {
    const relay = installRelayStub();
    const { render, unmount } = mountHook();

    await render();
    await settle();

    relay.emitSnapshot(snapshot([VIEWER, ALICE]));
    await settle();

    const bulk = [];
    for (let i = 0; i < 40; i++) {
      bulk.push(`${i.toString(16).padStart(2, "0").repeat(31)}ff`);
    }
    relay.emitSnapshot(
      snapshot([VIEWER, ALICE, ...bulk], { id: "snap-bulk", createdAt: 6000 }),
    );
    await settleAfterNotifyWindow();

    assert.equal(notifications.length, 1, "one summary, not one per member");
    assert.equal(notifications[0].body, "40 new members joined");

    await unmount();
  });

  /**
   * Below the cap the alert still names people — the summary must not swallow
   * the ordinary one-or-two-join case the feature exists for.
   */
  it("still names individuals for a small batch", async () => {
    const relay = installRelayStub();
    const { render, unmount } = mountHook();

    await render();
    await settle();

    relay.emitSnapshot(snapshot([VIEWER, ALICE]));
    await settle();

    relay.emitSnapshot(
      snapshot([VIEWER, ALICE, BOB, CAROL], {
        id: "snap-two",
        createdAt: 7000,
      }),
    );
    await settleAfterNotifyWindow();

    assert.equal(notifications.length, 2, "two joins, two named alerts");
    assert.ok(
      notifications.every((entry) => entry.body.endsWith(" joined")),
      "each alert names the joiner rather than summarizing",
    );

    await unmount();
  });

  /**
   * Each refetch is a REQ frame billed against the same per-principal WsEvents
   * budget as the user's own sends (default 10/s over a 5s window), and a bulk
   * add emits one kind:8000 per member. Uncoalesced that was 250 REQs for 250
   * deltas — spending the budget the owner needs to send messages and open
   * channels.
   */
  it("coalesces a burst of kind:8000 deltas into a single refetch", async () => {
    const relay = installRelayStub();
    const { render, unmount } = mountHook();

    await render();
    await settle();

    relay.emitSnapshot(snapshot([VIEWER, ALICE]));
    await settle();

    const before = relay.counts().fetchFirstEventCalls;
    relay.setRefetchSnapshot(
      snapshot([VIEWER, ALICE], { id: "snap-burst", createdAt: 8000 }),
    );

    for (let i = 0; i < 50; i++) {
      relay.emitDelta({
        id: `burst-${i}`,
        pubkey: "f".repeat(64),
        created_at: 8000 + i,
        kind: KIND_MEMBER_ADDED,
        tags: [["p", BOB]],
        content: "",
        sig: "s".repeat(128),
      });
    }
    await settleAfterRefreshDebounce();

    assert.equal(
      relay.counts().fetchFirstEventCalls - before,
      1,
      "50 deltas must cost exactly one REQ, not 50",
    );

    await unmount();
  });

  /**
   * Max's live 50-join storm at `fdeda44f0`: 10 banners, not 1.
   *
   * The per-snapshot cap answers "one snapshot, many keys". The relay answers
   * back "one burst, many snapshots" — it republishes the whole 13534 as each
   * concurrent add commits, so a storm arrives as several growing rosters and
   * each one independently emitted its own capped batch. The batch sizes below
   * are Max's observed live values (6, 17, 4, 4, 4, 4, 11 = 50).
   */
  it("collapses a burst spanning several snapshots into one alert", async () => {
    const relay = installRelayStub();
    const { render, unmount } = mountHook();

    await render();
    await settle();

    relay.emitSnapshot(snapshot([VIEWER]));
    await settleAfterNotifyWindow();
    assert.equal(notifications.length, 0, "precondition: seeded silently");

    const roster = [VIEWER];
    let minted = 0;
    let snapIndex = 0;
    for (const size of [6, 17, 4, 4, 4, 4, 11]) {
      for (let i = 0; i < size; i++) {
        minted += 1;
        roster.push(minted.toString(16).padStart(2, "0").repeat(32));
      }
      snapIndex += 1;
      relay.emitSnapshot(
        snapshot([...roster], {
          id: `storm-${snapIndex}`,
          createdAt: 9000 + snapIndex,
        }),
      );
      await settle();
    }
    await settleAfterNotifyWindow();

    assert.equal(minted, 50, "fixture must mint Max's 50 joins");
    assert.equal(
      notifications.length,
      1,
      "a burst spanning 7 snapshots must produce one alert, not one per snapshot",
    );
    assert.equal(notifications[0].body, "50 new members joined");

    await unmount();
  });

  /**
   * Wren's arm 3, and the reason batching is not free: deferring delivery
   * reopens his disclosure as a DELAYED one unless revocation also drops what
   * is already queued. Measured failing before the clearPending() call existed
   * — the queued batch flushed "5 new members joined" after the demotion.
   */
  it("drops queued alerts when a later snapshot demotes the viewer", async () => {
    const relay = installRelayStub();
    const { render, unmount } = mountHook({ role: "admin" });

    await render();
    await settle();

    relay.emitSnapshot(snapshot([VIEWER], { viewerRole: "admin" }));
    await settle();

    // Joins land and are queued, but the flush window has not elapsed.
    const roster = [VIEWER, ALICE, BOB, CAROL];
    relay.emitSnapshot(
      snapshot([...roster], {
        id: "queued-joins",
        createdAt: 10_000,
        viewerRole: "admin",
      }),
    );
    await settle();
    assert.equal(
      notifications.length,
      0,
      "precondition: delivery is still pending on the window",
    );

    // Demotion arrives before the timer fires.
    relay.emitSnapshot(
      snapshot([...roster], {
        id: "queued-demote",
        createdAt: 10_001,
        viewerRole: "member",
      }),
    );
    await settleAfterNotifyWindow();

    assert.equal(
      notifications.length,
      0,
      "a demotion before the flush must cancel the queued batch, not delay it",
    );

    await unmount();
  });

  /**
   * Wren's arm 5. The window must batch a burst without swallowing legitimate
   * later joins — otherwise the fix trades 10 spurious alerts for a silently
   * dropped one.
   */
  it("still alerts separately for joins beyond the batching window", async () => {
    const relay = installRelayStub();
    const { render, unmount } = mountHook();

    await render();
    await settle();

    relay.emitSnapshot(snapshot([VIEWER]));
    await settleAfterNotifyWindow();

    relay.emitSnapshot(
      snapshot([VIEWER, ALICE], { id: "join-1", createdAt: 11_000 }),
    );
    await settleAfterNotifyWindow();
    assert.equal(notifications.length, 1, "first join alerts on its own");

    relay.emitSnapshot(
      snapshot([VIEWER, ALICE, BOB], { id: "join-2", createdAt: 12_000 }),
    );
    await settleAfterNotifyWindow();

    assert.equal(
      notifications.length,
      2,
      "a join after the window closed must get its own alert, not be suppressed",
    );

    await unmount();
  });

  /**
   * Teardown must drop the queued batch, not just its timer. On a community
   * switch the effect re-keys, and keys accumulated for the old community must
   * never flush against the new one.
   */
  it("does not deliver a queued batch after unmount", async () => {
    const relay = installRelayStub();
    const { render, unmount } = mountHook();

    await render();
    await settle();

    relay.emitSnapshot(snapshot([VIEWER]));
    await settle();
    relay.emitSnapshot(
      snapshot([VIEWER, ALICE, BOB, CAROL], {
        id: "queued-at-teardown",
        createdAt: 13_000,
      }),
    );
    await settle();
    assert.equal(notifications.length, 0, "precondition: still queued");

    await unmount();
    await settleAfterNotifyWindow();

    assert.equal(
      notifications.length,
      0,
      "a torn-down mount must not fire its pending batch",
    );
  });
});
