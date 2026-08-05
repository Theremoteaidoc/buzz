//! Local SQLite retention store for persona events.
//!
//! Provides durable client-side storage for persona events, enabling offline
//! boot when the relay is unreachable. Upserts via `ON CONFLICT DO UPDATE`
//! keyed on `(kind, pubkey, d_tag)`, replacing only on a newer-or-equal
//! `created_at` for NIP-33 latest-wins semantics.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use tauri::AppHandle;

use crate::app_state::AppState;

mod legacy_migration;
pub use legacy_migration::migrate_legacy_retention_db;

/// Durable event-retention scope for one community relay and owner identity.
///
/// Persona, team, and managed-agent definitions are workspace-global, but
/// their relay heads and pending publications are not. Keeping a separate
/// database per `(relay_url, owner_pubkey)` prevents a pending write created in
/// community A from being drained into community B after a workspace switch.
pub struct RetentionScope {
    pub db_path: PathBuf,
    pub relay_url: String,
    pub owner_keys: nostr::Keys,
}

/// Decide whether `scope` — the workspace's active retention scope — is the one
/// that owns an event delivered by `arrival_relay_url`.
///
/// Inbound reconcile resolves its retention database when it PROCESSES an event,
/// while the event belongs to the community that DELIVERED it. `None` means a
/// workspace switch happened in between and the caller must drop the event
/// rather than file community A's event into community B's store.
///
/// The comparison goes through the same normalization
/// [`scoped_retention_db_path`] hashes, so "same relay" can never disagree with
/// "same database".
pub fn scope_for_arrival(scope: RetentionScope, arrival_relay_url: &str) -> Option<RetentionScope> {
    let same_scope =
        normalized_relay_scope(&scope.relay_url) == normalized_relay_scope(arrival_relay_url);
    same_scope.then_some(scope)
}

/// Relay-URL form that identifies a retention scope: equivalent workspace URLs
/// (surrounding space, trailing slash) must resolve to one scope.
fn normalized_relay_scope(relay_url: &str) -> &str {
    relay_url.trim().trim_end_matches('/')
}

/// Resolve the retention database path for a relay + owner pair.
///
/// The normalized scope is hashed so relay URLs never become path components.
/// Trimming a trailing slash keeps equivalent workspace URLs on one scope.
pub fn scoped_retention_db_path(base_dir: &Path, relay_url: &str, owner_pubkey: &str) -> PathBuf {
    let normalized_relay = normalized_relay_scope(relay_url);
    let mut hasher = Sha256::new();
    hasher.update(owner_pubkey.trim().to_ascii_lowercase().as_bytes());
    hasher.update(b"\0");
    hasher.update(normalized_relay.as_bytes());
    let scope_id = hex::encode(hasher.finalize());
    base_dir.join("retention").join(format!("{scope_id}.db"))
}

/// Snapshot the active relay + owner and resolve their durable event store.
///
/// Callers keep the returned relay and keys alongside the path whenever work
/// crosses an `.await`; a later workspace switch cannot retarget that work.
pub fn active_retention_scope(app: &AppHandle, state: &AppState) -> Result<RetentionScope, String> {
    let relay_url = crate::relay::relay_ws_url_with_override(state);
    let owner_keys = state.signing_keys()?;
    let base_dir = super::managed_agents_base_dir(app)?;
    let db_path =
        scoped_retention_db_path(&base_dir, &relay_url, &owner_keys.public_key().to_hex());
    let parent = db_path
        .parent()
        .ok_or_else(|| "retention scope path has no parent".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create retention scope directory: {error}"))?;
    Ok(RetentionScope {
        db_path,
        relay_url,
        owner_keys,
    })
}

/// Snapshot the active relay + owner, but only when it is the scope that owns
/// events delivered by `arrival_relay_url`.
///
/// Resolving the scope and matching it in one step is what closes the gap: the
/// returned scope is both the one that will be written to and the one the event
/// arrived on. `Ok(None)` means the arrival community is no longer active and
/// the caller must drop the event — see [`scope_for_arrival`].
pub fn arrival_retention_scope(
    app: &AppHandle,
    state: &AppState,
    arrival_relay_url: &str,
) -> Result<Option<RetentionScope>, String> {
    Ok(scope_for_arrival(
        active_retention_scope(app, state)?,
        arrival_relay_url,
    ))
}

/// One durable kind:30179 aggregate request retained for offline retry.
///
/// The exact serialized request is immutable for a generation: retrying must
/// submit the same signed events and CAS predecessor, never rebuild them with a
/// fresh timestamp after local state has moved.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Consumed by the PMA aggregate submit/retry driver in the next slice.
pub struct RetainedManagedAgentAggregate {
    pub owner_pubkey: String,
    pub agent_pubkey: String,
    pub generation: u64,
    pub private_event_id: String,
    pub state: String,
    pub request_json: String,
    pub pending_sync: bool,
    pub last_error: Option<String>,
    /// Durable proof that a verified deletion has already applied the local
    /// record/key erase for this exact generation. Only ever set on a
    /// `state = "deleted"` row, immediately before `pending_sync` is cleared,
    /// so crash-replay can distinguish "our verified deletion erased the
    /// record" from an unrelated/manual local deletion. Always `false` on a
    /// freshly retained row.
    pub local_authority_applied: bool,
}

pub fn seed_confirmed_managed_agent_aggregate(
    conn: &Connection,
    aggregate: &RetainedManagedAgentAggregate,
) -> Result<(), String> {
    if aggregate.pending_sync || aggregate.state != "active" {
        return Err("confirmed managed-agent seed must be a synced active head".to_string());
    }
    conn.execute(
        "INSERT OR IGNORE INTO managed_agent_aggregates
            (owner_pubkey, agent_pubkey, generation, private_event_id, state,
             request_json, pending_sync, last_error, local_authority_applied)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, NULL, 0)",
        params![
            aggregate.owner_pubkey,
            aggregate.agent_pubkey,
            aggregate.generation as i64,
            aggregate.private_event_id,
            aggregate.state,
            aggregate.request_json,
        ],
    )
    .map_err(|error| format!("failed to seed confirmed managed-agent aggregate: {error}"))?;
    Ok(())
}

/// Insert or idempotently refresh a retained aggregate generation.
///
/// Generation may advance by exactly one. A byte-identical rewrite of the
/// current generation is accepted for crash recovery; divergent same-generation
/// content and skipped/stale generations are rejected before touching disk.
#[allow(dead_code)] // Consumed by the PMA aggregate submit/retry driver in the next slice.
pub fn retain_managed_agent_aggregate(
    conn: &mut Connection,
    aggregate: &RetainedManagedAgentAggregate,
) -> Result<(), String> {
    if aggregate.generation == 0 || aggregate.generation > i64::MAX as u64 {
        return Err("managed-agent aggregate generation is out of range".to_string());
    }
    if !matches!(aggregate.state.as_str(), "active" | "deleted") {
        return Err("managed-agent aggregate state must be active or deleted".to_string());
    }

    if !aggregate.pending_sync || aggregate.last_error.is_some() {
        return Err("new managed-agent aggregate must start pending without an error".to_string());
    }
    if aggregate.local_authority_applied {
        return Err(
            "new managed-agent aggregate must not start with local authority applied".to_string(),
        );
    }

    let tx = conn
        .transaction()
        .map_err(|e| format!("failed to retain managed-agent aggregate: {e}"))?;
    let current = tx
        .query_row(
            "SELECT generation, private_event_id, state, request_json
               FROM managed_agent_aggregates
              WHERE owner_pubkey = ?1 AND agent_pubkey = ?2
              ORDER BY generation DESC
              LIMIT 1",
            params![aggregate.owner_pubkey, aggregate.agent_pubkey],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|e| format!("failed to read retained managed-agent aggregate: {e}"))?;

    if let Some((generation, event_id, state, request_json)) = current {
        let generation = u64::try_from(generation)
            .map_err(|_| "retained managed-agent aggregate generation is invalid".to_string())?;
        if aggregate.generation == generation {
            if aggregate.private_event_id != event_id
                || aggregate.state != state
                || aggregate.request_json != request_json
            {
                return Err(
                    "managed-agent aggregate conflicts with retained generation".to_string()
                );
            }
            // An exact retry is a true no-op. Do not re-arm an already
            // confirmed row or erase its persisted diagnostic on startup.
            return Ok(());
        }

        let next_generation = generation.checked_add(1).ok_or_else(|| {
            "retained managed-agent aggregate generation cannot advance".to_string()
        })?;
        if aggregate.generation != next_generation {
            return Err(format!(
                "managed-agent aggregate generation must advance from {generation} to {next_generation}"
            ));
        }
    } else if aggregate.generation != 1 {
        return Err("first retained managed-agent aggregate must be generation 1".to_string());
    }

    tx.execute(
        "INSERT INTO managed_agent_aggregates
            (owner_pubkey, agent_pubkey, generation, private_event_id, state,
             request_json, pending_sync, last_error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, NULL)",
        params![
            aggregate.owner_pubkey,
            aggregate.agent_pubkey,
            aggregate.generation as i64,
            aggregate.private_event_id,
            aggregate.state,
            aggregate.request_json,
        ],
    )
    .map_err(|e| format!("failed to write retained managed-agent aggregate: {e}"))?;
    tx.commit()
        .map_err(|e| format!("failed to commit retained managed-agent aggregate: {e}"))
}

#[allow(dead_code)] // Consumed by the PMA aggregate submit/retry driver in the next slice.
pub fn get_retained_managed_agent_aggregate(
    conn: &Connection,
    owner_pubkey: &str,
    agent_pubkey: &str,
) -> Result<Option<RetainedManagedAgentAggregate>, String> {
    conn.query_row(
        "SELECT owner_pubkey, agent_pubkey, generation, private_event_id, state,
                request_json, pending_sync, last_error, local_authority_applied
           FROM managed_agent_aggregates
          WHERE owner_pubkey = ?1 AND agent_pubkey = ?2
          ORDER BY generation DESC
          LIMIT 1",
        params![owner_pubkey, agent_pubkey],
        aggregate_from_row,
    )
    .optional()
    .map_err(|e| format!("failed to get retained managed-agent aggregate: {e}"))
}

/// Snapshot every pending aggregate attempt for one captured owner scope.
///
/// At most one generation per agent may be pending during normal operation,
/// but selecting the latest pending generation defensively avoids replaying a
/// superseded row after a crash between generation advance and acknowledgement.
pub fn get_pending_managed_agent_aggregates(
    conn: &Connection,
    owner_pubkey: &str,
) -> Result<Vec<RetainedManagedAgentAggregate>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT a.owner_pubkey, a.agent_pubkey, a.generation,
                    a.private_event_id, a.state, a.request_json,
                    a.pending_sync, a.last_error, a.local_authority_applied
               FROM managed_agent_aggregates a
              WHERE a.owner_pubkey = ?1 AND a.pending_sync = 1
                AND a.generation = (
                    SELECT MAX(latest.generation)
                      FROM managed_agent_aggregates latest
                     WHERE latest.owner_pubkey = a.owner_pubkey
                       AND latest.agent_pubkey = a.agent_pubkey
                )
              ORDER BY a.agent_pubkey",
        )
        .map_err(|e| format!("failed to prepare pending managed-agent aggregates: {e}"))?;
    let rows = stmt
        .query_map(params![owner_pubkey], aggregate_from_row)
        .map_err(|e| format!("failed to query pending managed-agent aggregates: {e}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to read pending managed-agent aggregate: {e}"))
}

fn aggregate_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RetainedManagedAgentAggregate> {
    let generation = row.get::<_, i64>(2)?;
    let generation = u64::try_from(generation).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    Ok(RetainedManagedAgentAggregate {
        owner_pubkey: row.get(0)?,
        agent_pubkey: row.get(1)?,
        generation,
        private_event_id: row.get(3)?,
        state: row.get(4)?,
        request_json: row.get(5)?,
        pending_sync: row.get::<_, i32>(6)? != 0,
        last_error: row.get(7)?,
        local_authority_applied: row.get::<_, i32>(8)? != 0,
    })
}

/// Mark one exact retained aggregate request as confirmed by relay read-back.
#[allow(dead_code)] // Consumed by the PMA aggregate submit/retry driver in the next slice.
pub fn mark_managed_agent_aggregate_synced(
    conn: &Connection,
    owner_pubkey: &str,
    agent_pubkey: &str,
    generation: u64,
    private_event_id: &str,
) -> Result<bool, String> {
    let changed = conn
        .execute(
            "UPDATE managed_agent_aggregates
                SET pending_sync = 0, last_error = NULL
              WHERE owner_pubkey = ?1 AND agent_pubkey = ?2
                AND generation = ?3 AND private_event_id = ?4",
            params![
                owner_pubkey,
                agent_pubkey,
                generation as i64,
                private_event_id
            ],
        )
        .map_err(|e| format!("failed to mark managed-agent aggregate synced: {e}"))?;
    Ok(changed == 1)
}

/// Persist a diagnostic for one exact retained attempt without clearing retry.
#[allow(dead_code)] // Consumed by the PMA aggregate submit/retry driver in the next slice.
pub fn record_managed_agent_aggregate_error(
    conn: &Connection,
    owner_pubkey: &str,
    agent_pubkey: &str,
    generation: u64,
    private_event_id: &str,
    error: &str,
) -> Result<bool, String> {
    let changed = conn
        .execute(
            "UPDATE managed_agent_aggregates
                SET last_error = ?5, pending_sync = 1
              WHERE owner_pubkey = ?1 AND agent_pubkey = ?2
                AND generation = ?3 AND private_event_id = ?4",
            params![
                owner_pubkey,
                agent_pubkey,
                generation as i64,
                private_event_id,
                error
            ],
        )
        .map_err(|e| format!("failed to record managed-agent aggregate error: {e}"))?;
    Ok(changed == 1)
}

/// Durably record that a verified deletion has applied the local record/key
/// erase for one exact retained tombstone generation.
///
/// Written on the `state = "deleted"` row immediately AFTER the local erase and
/// BEFORE [`mark_managed_agent_aggregate_synced`] clears the retry. Together
/// they order the crash-safe deletion seam: erase → mark-applied → clear. On
/// replay, a set marker (never mere record absence) proves the exact deletion
/// reached local authority, so the retry may be cleared without re-erasing an
/// unrelated agent. Returns `true` iff the exact `(owner, agent, generation,
/// event)` deleted row was updated.
#[allow(dead_code)] // Consumed by the deletion flush lane.
pub fn mark_managed_agent_deletion_local_authority_applied(
    conn: &Connection,
    owner_pubkey: &str,
    agent_pubkey: &str,
    generation: u64,
    private_event_id: &str,
) -> Result<bool, String> {
    let changed = conn
        .execute(
            "UPDATE managed_agent_aggregates
                SET local_authority_applied = 1
              WHERE owner_pubkey = ?1 AND agent_pubkey = ?2
                AND generation = ?3 AND private_event_id = ?4
                AND state = 'deleted'",
            params![
                owner_pubkey,
                agent_pubkey,
                generation as i64,
                private_event_id
            ],
        )
        .map_err(|e| format!("failed to mark managed-agent deletion authority applied: {e}"))?;
    Ok(changed == 1)
}

/// A retained persona event row.
#[derive(Debug, Clone)]
pub struct RetainedEvent {
    pub kind: u32,
    pub pubkey: String,
    pub d_tag: String,
    pub content: String,
    pub created_at: i64,
    pub raw_event: String,
    pub pending_sync: bool,
}

/// Open (or create) the retention database at the given path.
///
/// Sets WAL journaling and a `busy_timeout` on every connection so the
/// flush-loop connection and command-path connections can write concurrently
/// without spurious `SQLITE_BUSY` errors.
pub fn open_retention_db(path: &Path) -> Result<Connection, String> {
    let conn = Connection::open(path).map_err(|e| format!("failed to open retention db: {e}"))?;

    conn.pragma_update(None, "busy_timeout", 5000)
        .map_err(|e| format!("failed to set busy_timeout: {e}"))?;
    set_wal_mode(&conn)?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS persona_events (
            kind INTEGER NOT NULL,
            pubkey TEXT NOT NULL,
            d_tag TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            raw_event TEXT NOT NULL,
            pending_sync INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (kind, pubkey, d_tag)
        );
        CREATE TABLE IF NOT EXISTS managed_agent_aggregates (
            owner_pubkey TEXT NOT NULL,
            agent_pubkey TEXT NOT NULL,
            generation INTEGER NOT NULL CHECK (generation > 0),
            private_event_id TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('active', 'deleted')),
            request_json TEXT NOT NULL,
            pending_sync INTEGER NOT NULL DEFAULT 1,
            last_error TEXT,
            PRIMARY KEY (owner_pubkey, agent_pubkey, generation)
        );",
    )
    .map_err(|e| format!("failed to create retention table: {e}"))?;

    // Durable terminal-deletion marker: set to 1 the instant a verified deletion
    // has applied the local record/key erase, BEFORE `pending_sync` is cleared.
    // Crash-replay uses this — never mere record absence — to prove the exact
    // deletion reached local authority before it clears the retry. Added via a
    // guarded ALTER so stores written before this column deserialize as 0.
    add_column_if_missing(
        &conn,
        "managed_agent_aggregates",
        "local_authority_applied",
        "INTEGER NOT NULL DEFAULT 0",
    )?;

    Ok(conn)
}

/// Add `column` to `table` if it is not already present. Idempotent: SQLite has
/// no `ADD COLUMN IF NOT EXISTS`, so existence is probed via `PRAGMA
/// table_info` and the `ALTER` is skipped when the column already exists.
fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), String> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| format!("failed to inspect {table} columns: {e}"))?;
    let existing: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| format!("failed to read {table} columns: {e}"))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("failed to collect {table} columns: {e}"))?;
    if existing.iter().any(|name| name == column) {
        return Ok(());
    }
    conn.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    )
    .map_err(|e| format!("failed to add {table}.{column}: {e}"))?;
    Ok(())
}

fn set_wal_mode(conn: &Connection) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match conn.pragma_update(None, "journal_mode", "WAL") {
            Ok(()) => return Ok(()),
            Err(error) if sqlite_is_busy(&error) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(format!("failed to set WAL mode: {error}")),
        }
    }
}

fn sqlite_is_busy(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
    )
}

/// Build the retention `d_tag` column value for a kind:5 tombstone row.
///
/// Tombstones for all target kinds share `kind = 5` in the retention table, so
/// keying a tombstone by the bare target d-tag would collide across kinds when
/// a persona slug, team id, and agent pubkey happen to coincide — one
/// tombstone row would clobber another's pending publish. Folding the target
/// kind into the key (`"<target_kind>:<d_tag>"`) gives each its own PK row.
/// This is the retention-store key only; the published NIP-09 event still
/// carries the plain `a`-tag coordinate.
pub fn tombstone_retention_d_tag(target_kind: u32, d_tag: &str) -> String {
    format!("{target_kind}:{d_tag}")
}

/// Whether a pending row must be deferred to the next sweep because a kind:5
/// tombstone covering its coordinate failed to publish earlier in the same
/// sweep.
///
/// `get_pending_sync` orders tombstones first so a deletion always reaches the
/// relay before the replacement that supersedes it — but the flush is
/// best-effort per row, so a tombstone that fails mid-sweep would otherwise be
/// leapfrogged by its own replacement and then wipe it on the next sweep.
/// Deferring the replacement restores the ordering guarantee: next sweep the
/// `ORDER BY` puts the tombstone first again. Kind:5 rows are never deferred.
pub fn deferred_behind_failed_tombstone(
    kind: u32,
    pubkey: &str,
    d_tag: &str,
    failed_tombstones: &std::collections::HashSet<(String, String)>,
) -> bool {
    kind != 5
        && failed_tombstones.contains(&(pubkey.to_string(), tombstone_retention_d_tag(kind, d_tag)))
}

/// Upsert a persona event into the retention store.
///
/// Only replaces if the new event has a newer or equal `created_at` (NIP-33 semantics).
pub fn retain_event(conn: &Connection, event: &RetainedEvent) -> Result<(), String> {
    conn.execute(
        "INSERT INTO persona_events (kind, pubkey, d_tag, content, created_at, raw_event, pending_sync)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT (kind, pubkey, d_tag) DO UPDATE SET
            content = excluded.content,
            created_at = excluded.created_at,
            raw_event = excluded.raw_event,
            pending_sync = excluded.pending_sync
         WHERE excluded.created_at >= persona_events.created_at",
        params![
            event.kind,
            event.pubkey,
            event.d_tag,
            event.content,
            event.created_at,
            event.raw_event,
            event.pending_sync as i32,
        ],
    )
    .map_err(|e| format!("failed to retain event: {e}"))?;

    Ok(())
}

/// Outcome of an inbound retain — whether the local store now reflects the
/// inbound event, so the caller knows whether to patch `personas.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundOutcome {
    /// The inbound event was applied (no row, or it was strictly newer than a
    /// non-conflicting local row). The caller patches the local record store.
    Applied,
    /// The inbound event was NOT applied: either it is older than the retained
    /// row, or it collides at the same `created_at` with a pending local edit.
    /// The local record store is left untouched and the pending edit republishes.
    Skipped,
}

/// Retain an event arriving FROM the relay, resolving it against any local row.
///
/// Inbound events are already on the relay, so they are retained with
/// `pending_sync = 0`. The resolution is deliberately narrower than
/// [`retain_event`]'s blind newer-or-equal upsert, which would clobber a
/// pending local edit's `pending_sync` flag and silently drop its publish:
///
/// - No local row, or inbound strictly newer (`created_at >`): apply the
///   inbound event, clearing `pending_sync`. Inbound wins; a stale local edit
///   the relay already superseded stops republishing instead of looping.
/// - Equal `created_at`: skip. Nostr time is seconds-granularity, so a pending
///   local edit and an inbound event can share a timestamp; applying here would
///   clear `pending_sync` and drop the local publish. Skipping leaves the
///   pending row intact so the flush republishes and the relay resolves
///   last-writer-wins. (A re-received echo at equal time is also a no-op.)
/// - Inbound older: skip — nothing to change.
pub fn retain_inbound_event(
    conn: &Connection,
    event: &RetainedEvent,
) -> Result<InboundOutcome, String> {
    let existing = get_retained_event(conn, event.kind, &event.pubkey, &event.d_tag)?;

    let apply = match &existing {
        None => true,
        Some(row) if event.created_at > row.created_at => true,
        // Equal or older: skip. Equal time may collide with a pending local
        // edit, so we never clear its `pending_sync`; older is stale.
        Some(_) => false,
    };

    if !apply {
        return Ok(InboundOutcome::Skipped);
    }

    // Inbound is strictly newer (or there was no row): overwrite and clear
    // `pending_sync`. No upsert guard is needed — the Rust check above already
    // established that this event wins.
    conn.execute(
        "INSERT INTO persona_events (kind, pubkey, d_tag, content, created_at, raw_event, pending_sync)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)
         ON CONFLICT (kind, pubkey, d_tag) DO UPDATE SET
            content = excluded.content,
            created_at = excluded.created_at,
            raw_event = excluded.raw_event,
            pending_sync = 0",
        params![
            event.kind,
            event.pubkey,
            event.d_tag,
            event.content,
            event.created_at,
            event.raw_event,
        ],
    )
    .map_err(|e| format!("failed to retain inbound event: {e}"))?;

    Ok(InboundOutcome::Applied)
}

/// Load all retained persona events for a given pubkey.
#[cfg(test)]
pub fn get_retained_personas(
    conn: &Connection,
    pubkey: &str,
) -> Result<Vec<RetainedEvent>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT kind, pubkey, d_tag, content, created_at, raw_event, pending_sync
             FROM persona_events
             WHERE pubkey = ?1
             ORDER BY d_tag",
        )
        .map_err(|e| format!("failed to prepare query: {e}"))?;

    let rows = stmt
        .query_map(params![pubkey], |row| {
            Ok(RetainedEvent {
                kind: row.get(0)?,
                pubkey: row.get(1)?,
                d_tag: row.get(2)?,
                content: row.get(3)?,
                created_at: row.get(4)?,
                raw_event: row.get(5)?,
                pending_sync: row.get::<_, i32>(6)? != 0,
            })
        })
        .map_err(|e| format!("failed to query retained events: {e}"))?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to read retained event row: {e}"))
}

/// Get all events marked as pending sync (not yet confirmed on relay).
///
/// Tombstones (kind:5) sort FIRST: a delete retained in one session and its
/// coordinate's replacement retained in a later one (B5 backfill resurrecting
/// a deleted definition) must publish in that order — the relay's a-tag
/// deletion soft-deletes every live row at the coordinate with no timestamp
/// comparison, so a tombstone published AFTER the replacement would wipe it.
/// Within each group, oldest first for the same reason.
pub fn get_pending_sync(conn: &Connection) -> Result<Vec<RetainedEvent>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT kind, pubkey, d_tag, content, created_at, raw_event, pending_sync
             FROM persona_events
             WHERE pending_sync = 1
             ORDER BY (kind != 5), created_at ASC",
        )
        .map_err(|e| format!("failed to prepare pending sync query: {e}"))?;

    let rows = stmt
        .query_map([], |row| {
            Ok(RetainedEvent {
                kind: row.get(0)?,
                pubkey: row.get(1)?,
                d_tag: row.get(2)?,
                content: row.get(3)?,
                created_at: row.get(4)?,
                raw_event: row.get(5)?,
                pending_sync: row.get::<_, i32>(6)? != 0,
            })
        })
        .map_err(|e| format!("failed to query pending sync events: {e}"))?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to read pending sync row: {e}"))
}

/// Clear the `pending_sync` flag for an event the relay just confirmed.
///
/// Compare-and-clear: only clears the row if its `created_at` and `content`
/// still match what was published. A concurrent edit that upserted a newer
/// version at the same coordinate between the flush loop's read and this call
/// leaves `pending_sync` set, so the newer edit publishes on the next pass
/// instead of being silently dropped.
pub fn mark_synced(
    conn: &Connection,
    kind: u32,
    pubkey: &str,
    d_tag: &str,
    created_at: i64,
    content: &str,
) -> Result<(), String> {
    conn.execute(
        "UPDATE persona_events SET pending_sync = 0
         WHERE kind = ?1 AND pubkey = ?2 AND d_tag = ?3
           AND created_at = ?4 AND content = ?5",
        params![kind, pubkey, d_tag, created_at, content],
    )
    .map_err(|e| format!("failed to mark event synced: {e}"))?;

    Ok(())
}

/// Delete a retained event by its coordinate.
///
/// Called from the synchronous, lock-held delete-persona command body so the
/// purge serializes against `retain_event` upserts at the same coordinate —
/// closing the same-second resurrect race where a pending edit would otherwise
/// publish after the deletion tombstone.
pub fn delete_retained_event(
    conn: &Connection,
    kind: u32,
    pubkey: &str,
    d_tag: &str,
) -> Result<(), String> {
    conn.execute(
        "DELETE FROM persona_events
         WHERE kind = ?1 AND pubkey = ?2 AND d_tag = ?3",
        params![kind, pubkey, d_tag],
    )
    .map_err(|e| format!("failed to delete retained event: {e}"))?;

    Ok(())
}

/// Check if the retention store has any persona events for the given pubkey.
#[cfg(test)]
pub fn has_retained_personas(conn: &Connection, pubkey: &str) -> Result<bool, String> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM persona_events WHERE pubkey = ?1)",
        params![pubkey],
        |row| row.get(0),
    )
    .map_err(|e| format!("failed to check retained personas: {e}"))
}

/// Look up a single retained event by its coordinate.
pub fn get_retained_event(
    conn: &Connection,
    kind: u32,
    pubkey: &str,
    d_tag: &str,
) -> Result<Option<RetainedEvent>, String> {
    conn.query_row(
        "SELECT kind, pubkey, d_tag, content, created_at, raw_event, pending_sync
         FROM persona_events
         WHERE kind = ?1 AND pubkey = ?2 AND d_tag = ?3",
        params![kind, pubkey, d_tag],
        |row| {
            Ok(RetainedEvent {
                kind: row.get(0)?,
                pubkey: row.get(1)?,
                d_tag: row.get(2)?,
                content: row.get(3)?,
                created_at: row.get(4)?,
                raw_event: row.get(5)?,
                pending_sync: row.get::<_, i32>(6)? != 0,
            })
        },
    )
    .optional()
    .map_err(|e| format!("failed to get retained event: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_scope_is_stable_and_separates_relay_and_owner() {
        let base = Path::new("/tmp/buzz-retention-test");
        let owner_a = "a".repeat(64);
        let owner_b = "b".repeat(64);
        let community_a = scoped_retention_db_path(base, "wss://a.example/", &owner_a);
        assert_eq!(
            community_a,
            scoped_retention_db_path(base, "wss://a.example", &owner_a)
        );
        assert_ne!(
            community_a,
            scoped_retention_db_path(base, "wss://b.example", &owner_a)
        );
        assert_ne!(
            community_a,
            scoped_retention_db_path(base, "wss://a.example", &owner_b)
        );
    }

    #[test]
    fn test_arrival_relay_matching_agrees_with_database_identity() {
        let base = Path::new("/tmp/buzz-retention-test");
        let keys = nostr::Keys::generate();
        let owner = keys.public_key().to_hex();
        let scope = |relay: &str| RetentionScope {
            db_path: scoped_retention_db_path(base, relay, &owner),
            relay_url: relay.to_string(),
            owner_keys: keys.clone(),
        };
        let community_a = scoped_retention_db_path(base, "wss://a.example", &owner);

        // "Same relay" and "same database" must never disagree: every URL the
        // match accepts has to hash to the scope's own db path, and every URL it
        // rejects has to hash somewhere else.
        for equivalent in ["wss://a.example", "wss://a.example/", " wss://a.example "] {
            assert_eq!(
                scope_for_arrival(scope("wss://a.example"), equivalent).map(|scope| scope.db_path),
                Some(community_a.clone()),
                "{equivalent}"
            );
            assert_eq!(
                scoped_retention_db_path(base, equivalent, &owner),
                community_a,
                "{equivalent}"
            );
        }

        assert!(
            scope_for_arrival(scope("wss://b.example"), "wss://a.example").is_none(),
            "an event from community A must not be filed while community B is active"
        );
        assert_ne!(
            scoped_retention_db_path(base, "wss://b.example", &owner),
            community_a
        );
    }

    #[test]
    fn concurrent_open_waits_for_initialization_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("retention.db");
        let first = open_retention_db(&path).unwrap();
        first.execute_batch("BEGIN EXCLUSIVE").unwrap();

        let second_path = path.clone();
        let second = std::thread::spawn(move || open_retention_db(&second_path));
        std::thread::sleep(std::time::Duration::from_millis(100));
        first.execute_batch("COMMIT").unwrap();

        assert!(second.join().unwrap().is_ok());
    }

    fn test_db() -> Connection {
        open_retention_db(Path::new(":memory:")).unwrap()
    }

    fn sample_event() -> RetainedEvent {
        RetainedEvent {
            kind: 30175,
            pubkey: "abc123".to_string(),
            d_tag: "test-persona".to_string(),
            content: r#"{"display_name":"Test"}"#.to_string(),
            created_at: 1000,
            raw_event: r#"{"id":"..."}"#.to_string(),
            pending_sync: true,
        }
    }

    fn aggregate(
        generation: u64,
        event_id: &str,
        state: &str,
        request_json: &str,
    ) -> RetainedManagedAgentAggregate {
        RetainedManagedAgentAggregate {
            owner_pubkey: "owner".to_string(),
            agent_pubkey: "agent".to_string(),
            generation,
            private_event_id: event_id.to_string(),
            state: state.to_string(),
            request_json: request_json.to_string(),
            pending_sync: true,
            last_error: None,
            local_authority_applied: false,
        }
    }

    #[test]
    fn aggregate_retention_enforces_contiguous_immutable_generations() {
        let mut conn = test_db();
        let first = aggregate(1, "event-1", "active", r#"{"generation":1}"#);
        retain_managed_agent_aggregate(&mut conn, &first).unwrap();
        retain_managed_agent_aggregate(&mut conn, &first).unwrap();

        let conflicting = aggregate(1, "other", "active", r#"{"generation":1}"#);
        assert!(retain_managed_agent_aggregate(&mut conn, &conflicting)
            .unwrap_err()
            .contains("conflicts"));
        let skipped = aggregate(3, "event-3", "deleted", r#"{"generation":3}"#);
        assert!(retain_managed_agent_aggregate(&mut conn, &skipped)
            .unwrap_err()
            .contains("advance from 1 to 2"));

        let tombstone = aggregate(2, "event-2", "deleted", r#"{"generation":2}"#);
        retain_managed_agent_aggregate(&mut conn, &tombstone).unwrap();
        assert_eq!(
            get_retained_managed_agent_aggregate(&conn, "owner", "agent").unwrap(),
            Some(tombstone)
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM managed_agent_aggregates
                  WHERE owner_pubkey = 'owner' AND agent_pubkey = 'agent'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            2
        );
    }

    #[test]
    fn pending_aggregate_snapshot_is_owner_scoped_and_latest_only() {
        let mut conn = test_db();
        retain_managed_agent_aggregate(
            &mut conn,
            &aggregate(1, "event-a1", "active", r#"{"generation":1}"#),
        )
        .unwrap();
        retain_managed_agent_aggregate(
            &mut conn,
            &aggregate(2, "event-a2", "deleted", r#"{"generation":2}"#),
        )
        .unwrap();
        let mut other = aggregate(1, "event-b1", "active", r#"{"generation":1}"#);
        other.owner_pubkey = "other-owner".into();
        other.agent_pubkey = "other-agent".into();
        retain_managed_agent_aggregate(&mut conn, &other).unwrap();

        let pending = get_pending_managed_agent_aggregates(&conn, "owner").unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].generation, 2);
        assert_eq!(pending[0].private_event_id, "event-a2");
    }

    #[test]
    fn aggregate_compare_and_clear_cannot_ack_a_newer_attempt() {
        let mut conn = test_db();
        retain_managed_agent_aggregate(
            &mut conn,
            &aggregate(1, "event-1", "active", r#"{"generation":1}"#),
        )
        .unwrap();
        retain_managed_agent_aggregate(
            &mut conn,
            &aggregate(2, "event-2", "deleted", r#"{"generation":2}"#),
        )
        .unwrap();

        assert!(
            mark_managed_agent_aggregate_synced(&conn, "owner", "agent", 1, "event-1").unwrap()
        );
        // A stale success can clear its own retained attempt, but cannot clear
        // or otherwise acknowledge the newer tombstone.
        assert!(
            get_retained_managed_agent_aggregate(&conn, "owner", "agent")
                .unwrap()
                .unwrap()
                .pending_sync
        );
        assert!(
            mark_managed_agent_aggregate_synced(&conn, "owner", "agent", 2, "event-2").unwrap()
        );
        assert!(
            !get_retained_managed_agent_aggregate(&conn, "owner", "agent")
                .unwrap()
                .unwrap()
                .pending_sync
        );

        // Rebuilding the exact same generation during startup must not turn a
        // confirmed row back into pending work.
        retain_managed_agent_aggregate(
            &mut conn,
            &aggregate(2, "event-2", "deleted", r#"{"generation":2}"#),
        )
        .unwrap();
        assert!(
            !get_retained_managed_agent_aggregate(&conn, "owner", "agent")
                .unwrap()
                .unwrap()
                .pending_sync
        );
    }

    #[test]
    fn aggregate_error_is_scoped_to_the_exact_attempt() {
        let mut conn = test_db();
        retain_managed_agent_aggregate(
            &mut conn,
            &aggregate(1, "event-1", "active", r#"{"generation":1}"#),
        )
        .unwrap();
        assert!(
            !record_managed_agent_aggregate_error(&conn, "owner", "agent", 1, "wrong", "nope")
                .unwrap()
        );
        assert!(record_managed_agent_aggregate_error(
            &conn,
            "owner",
            "agent",
            1,
            "event-1",
            "relay unavailable"
        )
        .unwrap());
        let row = get_retained_managed_agent_aggregate(&conn, "owner", "agent")
            .unwrap()
            .unwrap();
        assert!(row.pending_sync);
        assert_eq!(row.last_error.as_deref(), Some("relay unavailable"));
    }

    #[test]
    fn retain_and_retrieve() {
        let conn = test_db();
        let event = sample_event();
        retain_event(&conn, &event).unwrap();

        let results = get_retained_personas(&conn, "abc123").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].d_tag, "test-persona");
        assert_eq!(results[0].created_at, 1000);
        assert!(results[0].pending_sync);
    }

    #[test]
    fn tombstone_retention_keys_are_distinct_across_kinds() {
        // A persona slug, team id, and agent pubkey that all happen to equal
        // "shared" must occupy DISTINCT kind:5 rows so one tombstone's pending
        // publish never clobbers another's (F2c).
        let conn = test_db();
        for target_kind in [30175u32, 30176, 30177] {
            retain_event(
                &conn,
                &RetainedEvent {
                    kind: 5,
                    pubkey: "owner".to_string(),
                    d_tag: tombstone_retention_d_tag(target_kind, "shared"),
                    content: String::new(),
                    created_at: 1000,
                    raw_event: format!("{{\"k\":{target_kind}}}"),
                    pending_sync: true,
                },
            )
            .unwrap();
        }
        // Three distinct rows survive — no PK collision clobbered any of them.
        for target_kind in [30175u32, 30176, 30177] {
            let row = get_retained_event(
                &conn,
                5,
                "owner",
                &tombstone_retention_d_tag(target_kind, "shared"),
            )
            .unwrap();
            assert!(
                row.is_some(),
                "tombstone for kind {target_kind} was clobbered"
            );
        }
    }

    #[test]
    fn upsert_replaces_newer() {
        let conn = test_db();
        let mut event = sample_event();
        retain_event(&conn, &event).unwrap();

        event.content = r#"{"display_name":"Updated"}"#.to_string();
        event.created_at = 2000;
        retain_event(&conn, &event).unwrap();

        let results = get_retained_personas(&conn, "abc123").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].created_at, 2000);
        assert!(results[0].content.contains("Updated"));
    }

    #[test]
    fn upsert_ignores_older() {
        let conn = test_db();
        let mut event = sample_event();
        event.created_at = 2000;
        retain_event(&conn, &event).unwrap();

        event.content = r#"{"display_name":"Old"}"#.to_string();
        event.created_at = 1000;
        retain_event(&conn, &event).unwrap();

        let results = get_retained_personas(&conn, "abc123").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].created_at, 2000);
        assert!(!results[0].content.contains("Old"));
    }

    #[test]
    fn pending_sync_query() {
        let conn = test_db();
        let mut event = sample_event();
        event.pending_sync = true;
        retain_event(&conn, &event).unwrap();

        let mut event2 = sample_event();
        event2.d_tag = "other".to_string();
        event2.pending_sync = false;
        retain_event(&conn, &event2).unwrap();

        let pending = get_pending_sync(&conn).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].d_tag, "test-persona");
    }

    #[test]
    fn test_mark_synced_matching_row_clears_flag() {
        let conn = test_db();
        let event = sample_event();
        retain_event(&conn, &event).unwrap();

        mark_synced(&conn, 30175, "abc123", "test-persona", 1000, &event.content).unwrap();

        let pending = get_pending_sync(&conn).unwrap();
        assert!(pending.is_empty());

        let results = get_retained_personas(&conn, "abc123").unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].pending_sync);
    }

    #[test]
    fn test_mark_synced_stale_version_leaves_flag_set() {
        let conn = test_db();
        let published = sample_event();
        retain_event(&conn, &published).unwrap();

        // A newer edit lands at the same coordinate before the flush loop
        // clears the version it published.
        let mut newer = sample_event();
        newer.content = r#"{"display_name":"Edited"}"#.to_string();
        newer.created_at = 2000;
        retain_event(&conn, &newer).unwrap();

        // Clearing against the OLD version must not touch the newer pending row.
        mark_synced(
            &conn,
            30175,
            "abc123",
            "test-persona",
            1000,
            &published.content,
        )
        .unwrap();

        let pending = get_pending_sync(&conn).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].created_at, 2000);
    }

    #[test]
    fn test_delete_retained_event_removes_row() {
        let conn = test_db();
        retain_event(&conn, &sample_event()).unwrap();

        delete_retained_event(&conn, 30175, "abc123", "test-persona").unwrap();

        assert!(get_retained_event(&conn, 30175, "abc123", "test-persona")
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_delete_retained_event_missing_row_is_noop() {
        let conn = test_db();
        delete_retained_event(&conn, 30175, "abc123", "nonexistent").unwrap();
    }

    #[test]
    fn has_retained_personas_works() {
        let conn = test_db();
        assert!(!has_retained_personas(&conn, "abc123").unwrap());

        let event = sample_event();
        retain_event(&conn, &event).unwrap();

        assert!(has_retained_personas(&conn, "abc123").unwrap());
        assert!(!has_retained_personas(&conn, "other").unwrap());
    }

    #[test]
    fn get_retained_event_by_coordinate() {
        let conn = test_db();
        let event = sample_event();
        retain_event(&conn, &event).unwrap();

        let found = get_retained_event(&conn, 30175, "abc123", "test-persona").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().d_tag, "test-persona");

        let not_found = get_retained_event(&conn, 30175, "abc123", "nonexistent").unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn idempotent_retain_same_timestamp() {
        let conn = test_db();
        let event = sample_event();
        retain_event(&conn, &event).unwrap();
        retain_event(&conn, &event).unwrap();

        let results = get_retained_personas(&conn, "abc123").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn inbound_no_local_row_applies() {
        let conn = test_db();
        let mut event = sample_event();
        event.pending_sync = false;

        assert_eq!(
            retain_inbound_event(&conn, &event).unwrap(),
            InboundOutcome::Applied
        );

        let row = get_retained_event(&conn, 30175, "abc123", "test-persona")
            .unwrap()
            .unwrap();
        assert_eq!(row.created_at, 1000);
        assert!(!row.pending_sync);
    }

    #[test]
    fn inbound_equal_second_skips_and_preserves_pending() {
        let conn = test_db();
        // Pending local edit at t=1000.
        let local = sample_event();
        retain_event(&conn, &local).unwrap();

        // Inbound at the SAME second with different content.
        let inbound = RetainedEvent {
            content: r#"{"display_name":"Remote"}"#.to_string(),
            pending_sync: false,
            ..sample_event()
        };
        assert_eq!(
            retain_inbound_event(&conn, &inbound).unwrap(),
            InboundOutcome::Skipped
        );

        // Local pending row is untouched: flag preserved, content unchanged so
        // the flush republishes and the relay resolves last-writer-wins.
        let row = get_retained_event(&conn, 30175, "abc123", "test-persona")
            .unwrap()
            .unwrap();
        assert!(row.pending_sync);
        assert!(row.content.contains("Test"));
    }

    #[test]
    fn inbound_strictly_newer_applies_and_clears_pending() {
        let conn = test_db();
        // Pending local edit at t=1000.
        let local = sample_event();
        retain_event(&conn, &local).unwrap();

        // Inbound strictly newer with different content.
        let inbound = RetainedEvent {
            content: r#"{"display_name":"Remote"}"#.to_string(),
            created_at: 2000,
            pending_sync: false,
            ..sample_event()
        };
        assert_eq!(
            retain_inbound_event(&conn, &inbound).unwrap(),
            InboundOutcome::Applied
        );

        // Inbound wins: content replaced and pending cleared, so the stale
        // local edit stops republishing instead of looping.
        let row = get_retained_event(&conn, 30175, "abc123", "test-persona")
            .unwrap()
            .unwrap();
        assert_eq!(row.created_at, 2000);
        assert!(!row.pending_sync);
        assert!(row.content.contains("Remote"));
    }

    #[test]
    fn inbound_older_skips() {
        let conn = test_db();
        let mut local = sample_event();
        local.created_at = 2000;
        retain_event(&conn, &local).unwrap();

        let inbound = RetainedEvent {
            content: r#"{"display_name":"Stale"}"#.to_string(),
            created_at: 1000,
            pending_sync: false,
            ..sample_event()
        };
        assert_eq!(
            retain_inbound_event(&conn, &inbound).unwrap(),
            InboundOutcome::Skipped
        );

        let row = get_retained_event(&conn, 30175, "abc123", "test-persona")
            .unwrap()
            .unwrap();
        assert_eq!(row.created_at, 2000);
        assert!(!row.content.contains("Stale"));
    }

    #[test]
    fn pending_sync_publishes_tombstones_before_replacements() {
        // B5 resurrection race: a kind:5 retained in session N and the same
        // coordinate's replacement 30175 retained on the next boot can sit
        // pending together. The relay's a-tag deletion ignores timestamps,
        // so the tombstone MUST publish first or it wipes the replacement.
        let conn = test_db();
        let replacement = RetainedEvent {
            kind: 30175,
            created_at: 2000,
            pending_sync: true,
            ..sample_event()
        };
        retain_event(&conn, &replacement).unwrap();
        let tombstone = RetainedEvent {
            kind: 5,
            d_tag: tombstone_retention_d_tag(30175, "test-persona"),
            content: String::new(),
            created_at: 1000,
            pending_sync: true,
            ..sample_event()
        };
        retain_event(&conn, &tombstone).unwrap();

        let pending = get_pending_sync(&conn).unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].kind, 5, "tombstone first");
        assert_eq!(pending[1].kind, 30175, "replacement second");
    }

    #[test]
    fn deferral_predicate_is_kind_and_pubkey_qualified() {
        // Mid-sweep barrier semantics: a failed tombstone defers ONLY the
        // replacement at its exact coordinate — same target kind, same pubkey.
        use std::collections::HashSet;

        let failed: HashSet<(String, String)> = HashSet::from([(
            "abc123".to_string(),
            tombstone_retention_d_tag(30175, "test-persona"),
        )]);

        // The covered replacement defers.
        assert!(deferred_behind_failed_tombstone(
            30175,
            "abc123",
            "test-persona",
            &failed
        ));
        // Kind-qualified: a coinciding slug under a DIFFERENT kind is a
        // distinct coordinate (the cross-kind collision the retention d-tag
        // encoding exists to prevent) — never deferred.
        assert!(!deferred_behind_failed_tombstone(
            30177,
            "abc123",
            "test-persona",
            &failed
        ));
        // Never crosses pubkeys.
        assert!(!deferred_behind_failed_tombstone(
            30175,
            "other-key",
            "test-persona",
            &failed
        ));
        // Never defers kind:5 rows, even at a "matching" retention key.
        assert!(!deferred_behind_failed_tombstone(
            5,
            "abc123",
            "test-persona",
            &failed
        ));
        // Unrelated d-tags publish normally.
        assert!(!deferred_behind_failed_tombstone(
            30175,
            "abc123",
            "other-persona",
            &failed
        ));
    }

    #[test]
    fn deletion_marker_is_the_terminal_crash_replay_proof() {
        // Carl's correction: bare record absence must NOT license clearing the
        // retry. The durable `local_authority_applied` marker is the proof that
        // THIS exact verified deletion reached local authority.
        let mut conn = test_db();
        retain_managed_agent_aggregate(
            &mut conn,
            &aggregate(1, "event-1", "active", r#"{"generation":1}"#),
        )
        .unwrap();
        retain_managed_agent_aggregate(
            &mut conn,
            &aggregate(2, "event-2", "deleted", r#"{"generation":2}"#),
        )
        .unwrap();

        // Freshly retained: marker is unset — absence of the marker means the
        // flush has not proven erase yet.
        let row = get_retained_managed_agent_aggregate(&conn, "owner", "agent")
            .unwrap()
            .unwrap();
        assert!(!row.local_authority_applied);

        // A new aggregate can never be born with the marker set.
        let mut premature = aggregate(3, "event-3", "deleted", r#"{"generation":3}"#);
        premature.local_authority_applied = true;
        assert!(retain_managed_agent_aggregate(&mut conn, &premature)
            .unwrap_err()
            .contains("must not start with local authority applied"));

        // The marker sets only the EXACT deleted row and only once effectively.
        assert!(mark_managed_agent_deletion_local_authority_applied(
            &conn, "owner", "agent", 2, "event-2"
        )
        .unwrap());
        let marked = get_retained_managed_agent_aggregate(&conn, "owner", "agent")
            .unwrap()
            .unwrap();
        assert!(
            marked.local_authority_applied,
            "the marker is durable and read back"
        );

        // A wrong coordinate (generation/event/owner/agent) never sets it.
        assert!(!mark_managed_agent_deletion_local_authority_applied(
            &conn,
            "owner",
            "agent",
            2,
            "wrong-event"
        )
        .unwrap());
        assert!(!mark_managed_agent_deletion_local_authority_applied(
            &conn,
            "owner",
            "other-agent",
            2,
            "event-2"
        )
        .unwrap());
    }

    #[test]
    fn deletion_marker_refuses_a_non_deleted_row() {
        // The marker is a deletion-terminal proof; it must never flip an active
        // (promotion) row. `mark_managed_agent_deletion_local_authority_applied`
        // is scoped to state = 'deleted'.
        let mut conn = test_db();
        retain_managed_agent_aggregate(
            &mut conn,
            &aggregate(1, "event-1", "active", r#"{"generation":1}"#),
        )
        .unwrap();
        assert!(!mark_managed_agent_deletion_local_authority_applied(
            &conn, "owner", "agent", 1, "event-1"
        )
        .unwrap());
        let row = get_retained_managed_agent_aggregate(&conn, "owner", "agent")
            .unwrap()
            .unwrap();
        assert!(!row.local_authority_applied);
    }
}
