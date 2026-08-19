//! Agent heartbeat + progress signal (WO #133 / R2.1).
//!
//! Liveness is not progress. A process can be alive while writing nothing;
//! this module distinguishes `running` / `stalled` / `dead` / `returned_empty`
//! and keeps a founder-readable snapshot separate from agent-only logs.
//!
//! Identity is three-way: agent seats (full model), cron/notify keys (excluded),
//! and human-backed sessions (visible, never stalled/dead as agents).
//!
//! ## Startup emit (WO #148)
//!
//! [`HeartbeatRegistry::emit_initial`] writes the status file at process boot
//! (state `agent_initialized`) so a running seat never appears file-less to
//! the external liveness watcher before its first turn.
//!
//! ## Death detection honesty (B2)
//!
//! In-process `tick()` can declare `dead` only when `last_seen_at` goes silent
//! past [`HeartbeatRegistry::dead_after`]. The wired harness calls
//! [`HeartbeatRegistry::touch_alive`] on the same event loop immediately before
//! `tick`, so that branch cannot observe a wedged process. Production `dead`
//! today comes from explicit [`HeartbeatRegistry::mark_dead`] (respawn/exit).
//! Cap-independent wedge detection requires an out-of-process consumer of the
//! status-file mtime (follow-up WO) — do not document in-process
//! dead-within-one-cadence as a live signal for the self-heartbeat path.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Cadence window pinned by WO #133: emit every 60–90s while a turn is active.
pub const HEARTBEAT_CADENCE_MIN: Duration = Duration::from_secs(60);
pub const HEARTBEAT_CADENCE_MAX: Duration = Duration::from_secs(90);
/// Default emit interval inside the pinned window.
pub const HEARTBEAT_CADENCE_DEFAULT: Duration = Duration::from_secs(75);
/// Silence without a write past this → `stalled` (not healthy).
pub const STALL_AFTER_DEFAULT: Duration = Duration::from_secs(180);

/// Smallest multiple of `cadence` that is strictly greater than `stall_after`.
///
/// Keeps dead-by-missed-seen ordered after stall so a silent-but-still-seen
/// seat can stall before any latent missed-seen death path fires (B3).
pub fn dead_after_for(stall_after: Duration, cadence: Duration) -> Duration {
    assert!(
        cadence > Duration::ZERO,
        "heartbeat cadence must be positive"
    );
    let mut n = 1u32;
    let mut dead = cadence;
    while dead <= stall_after {
        n = n
            .checked_add(1)
            .expect("dead_after cadence multiple overflow");
        dead = cadence.saturating_mul(n);
    }
    dead
}

/// Three identity categories (WO #133 tightened spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityClass {
    /// `buzz-agent@*` seats — full heartbeat / stall model.
    AgentSeat,
    /// Cron/notify keys with no agent service — excluded entirely.
    CronNotify,
    /// Human-backed session speaking through a key (e.g. Factory).
    HumanBackedSession,
}

/// Turn / seat lifecycle states for the heartbeat payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeartbeatState {
    /// Freshly-started seat, before any turn (WO #148 startup emit).
    AgentInitialized,
    Idle,
    Claimed,
    Running,
    Blocked,
    Returned,
    /// Progress signal failed: alive but no write within stall window.
    Stalled,
    /// Process gone / kill observed (explicit `mark_dead`), or — only when
    /// `touch_alive` is *not* wired on the same loop — missed-seen past
    /// `dead_after`. The self-heartbeat harness cannot observe its own wedge.
    Dead,
    /// Turn ended ok with neither message nor file.
    ReturnedEmpty,
}

impl HeartbeatState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentInitialized => "agent_initialized",
            Self::Idle => "idle",
            Self::Claimed => "claimed",
            Self::Running => "running",
            Self::Blocked => "blocked",
            Self::Returned => "returned",
            Self::Stalled => "stalled",
            Self::Dead => "dead",
            Self::ReturnedEmpty => "returned_empty",
        }
    }
}

/// Outcome label recorded when a turn completes successfully at the ACP layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnOutcomeLabel {
    Ok,
    ReturnedEmpty,
}

impl TurnOutcomeLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::ReturnedEmpty => "returned_empty",
        }
    }
}

/// Classify an ACP-ok turn. No message and no file → `returned_empty`.
///
/// Covers the E13 class: token-budget exhaustion mid-tool-calls that leaves
/// zero output budget still ends as ACP-ok with nothing published — that must
/// never read as `ok` / healthy, regardless of the cap value.
pub fn classify_ok_turn_outcome(produced_message: bool, produced_file: bool) -> TurnOutcomeLabel {
    if produced_message || produced_file {
        TurnOutcomeLabel::Ok
    } else {
        TurnOutcomeLabel::ReturnedEmpty
    }
}

/// Kind of durable write that advances `last_mutation_at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationKind {
    Message,
    File,
}

/// Flatten ACP `rawInput` (`unknown` JSON) into text for mutation heuristics.
///
/// Shell tools (Cursor/Codex) typically send `{"command":"…"}` objects, not
/// bare strings. Treating `rawInput` as string-only missed reply-only turns
/// whose sole durable write was `buzz messages send` → false `returned_empty`.
pub fn raw_input_hint(raw: Option<&serde_json::Value>) -> String {
    let Some(raw) = raw else {
        return String::new();
    };
    match raw {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(map) => {
            for key in ["command", "cmd", "script", "input", "code", "query"] {
                if let Some(s) = map.get(key).and_then(|v| v.as_str()) {
                    if !s.is_empty() {
                        return s.to_string();
                    }
                }
            }
            // Last resort: stringify so substring match still sees the command.
            raw.to_string()
        }
        other => other.to_string(),
    }
}

/// Build the title+input blob passed to [`classify_tool_mutation`].
pub fn tool_mutation_classify_blob(
    title: &str,
    raw: Option<&serde_json::Value>,
    content_text: &str,
) -> String {
    let hint = raw_input_hint(raw);
    let hint = if hint.is_empty() {
        content_text
    } else {
        hint.as_str()
    };
    if hint.is_empty() {
        title.to_string()
    } else if title.is_empty() {
        hint.to_string()
    } else {
        format!("{title} {hint}")
    }
}

/// Default founder-readable status path (outside systemd PrivateTmp).
///
/// Units set `PrivateTmp=true`, so `/tmp/buzz-acp-heartbeat-*.json` is invisible
/// to the founder and other seats. Default is under the shared home tree
/// (`ReadWritePaths` already covers `/opt/buzz/agents/home`). Override with
/// `BUZZ_ACP_HEARTBEAT_STATUS_PATH`. Deploy must ensure
/// `/opt/buzz/agents/home/shared/heartbeat/` exists and is writable by seats.
pub fn default_status_path(agent_label: &str) -> PathBuf {
    let safe: String = agent_label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let safe = if safe.is_empty() {
        "agent".to_string()
    } else {
        safe
    };
    PathBuf::from(format!(
        "/opt/buzz/agents/home/shared/heartbeat/{safe}.json"
    ))
}

/// Heuristic: does this ACP tool_call title/kind count as a durable write?
///
/// `agent_message_chunk` is intentionally NOT a mutation — that is the ACP
/// stream to the observer, not a Buzz publish or filesystem write. A real
/// Buzz publish is detected when the tool input contains `buzz messages send`
/// (see [`raw_input_hint`] for object-shaped `rawInput`).
///
/// Over-counts progress (fail-safe): shell redirects / `tee` / scratch writes
/// may count as File. Prefer false "healthy" over false `stalled`.
pub fn classify_tool_mutation(title: &str, kind: &str) -> Option<MutationKind> {
    let title_l = title.to_ascii_lowercase();
    let kind_l = kind.to_ascii_lowercase();
    let blob = format!("{title_l} {kind_l}");

    if blob.contains("messages send")
        || blob.contains("send_message")
        || blob.contains("buzz messages")
        || blob.contains("publish_event")
        || (blob.contains("buzz") && blob.contains("messages") && blob.contains("send"))
    {
        return Some(MutationKind::Message);
    }

    if matches!(
        title_l.as_str(),
        "write"
            | "edit"
            | "streplace"
            | "apply_patch"
            | "editnotebook"
            | "delete"
            | "create_file"
            | "write_file"
    ) || title_l.contains("strreplace")
        || title_l.contains("applypatch")
        || title_l.contains("edit_notebook")
        || title_l.contains("notebook edit")
        || (blob.contains("drop-box") || blob.contains("dropbox") || blob.contains("outbox"))
    {
        return Some(MutationKind::File);
    }

    // Shell / Bash that clearly publishes or writes.
    if (kind_l == "shell" || title_l.contains("shell") || title_l.contains("bash"))
        && (blob.contains("buzz messages send")
            || blob.contains("messages send")
            || blob.contains(" > ")
            || blob.contains(">>")
            || blob.contains("tee "))
    {
        if blob.contains("messages send") || blob.contains("buzz messages") {
            return Some(MutationKind::Message);
        }
        return Some(MutationKind::File);
    }

    None
}

/// Per-turn progress flags collected while the prompt is in flight.
#[derive(Debug, Clone, Default)]
pub struct TurnProgress {
    pub produced_message: bool,
    pub produced_file: bool,
    pub last_action: Option<String>,
    pub last_mutation_at: Option<SystemTime>,
}

impl TurnProgress {
    pub fn record_mutation(&mut self, kind: MutationKind, action: impl Into<String>, at: SystemTime) {
        match kind {
            MutationKind::Message => self.produced_message = true,
            MutationKind::File => self.produced_file = true,
        }
        self.last_action = Some(action.into());
        self.last_mutation_at = Some(at);
    }

    pub fn note_action(&mut self, action: impl Into<String>) {
        self.last_action = Some(action.into());
    }

    pub fn has_durable_output(&self) -> bool {
        self.produced_message || self.produced_file
    }
}

/// Cross-task bridge: ACP records mid-turn durable writes here; the main-loop
/// ticker drains into [`HeartbeatRegistry`] so `last_mutation_at` advances
/// during the turn (B1), not only at turn end.
#[derive(Clone, Default)]
pub struct MidTurnMutationSink {
    inner: Arc<Mutex<Option<(MutationKind, String, SystemTime)>>>,
}

impl MidTurnMutationSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Note the latest classified durable write (Message/File).
    pub fn note(&self, kind: MutationKind, action: impl Into<String>, at: SystemTime) {
        if let Ok(mut guard) = self.inner.lock() {
            *guard = Some((kind, action.into(), at));
        }
    }

    /// Take the pending write (if any) without applying it — tests / probes.
    pub fn take(&self) -> Option<(MutationKind, String, SystemTime)> {
        self.inner.lock().ok().and_then(|mut g| g.take())
    }

    /// Drain the latest mid-turn write into the registry (idempotent if empty).
    pub fn drain_into(&self, reg: &mut HeartbeatRegistry, agent: &str) {
        if let Some((kind, action, at)) = self.take() {
            reg.record_mutation(agent, kind, action, at);
        }
    }
}

/// Founder-readable heartbeat payload (WO #133 shape).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HeartbeatPayload {
    pub agent: String,
    pub state: HeartbeatState,
    pub phase: String,
    pub last_action: Option<String>,
    pub last_mutation_at: Option<u64>,
    pub elapsed_in_phase_secs: u64,
    pub turn_id: Option<String>,
    pub identity: IdentityClass,
    pub dropped_events: u64,
    pub dropped_event_reasons: HashMap<String, u64>,
}

/// Dropped-event counter with labeled reasons.
#[derive(Debug, Default, Clone)]
pub struct DroppedEventCounter {
    by_reason: HashMap<String, u64>,
    total: u64,
}

impl DroppedEventCounter {
    pub fn record(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        *self.by_reason.entry(reason).or_insert(0) += 1;
        self.total = self.total.saturating_add(1);
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn count_for(&self, reason: &str) -> u64 {
        self.by_reason.get(reason).copied().unwrap_or(0)
    }

    pub fn reasons(&self) -> &HashMap<String, u64> {
        &self.by_reason
    }
}

#[derive(Debug, Clone)]
struct SeatRecord {
    identity: IdentityClass,
    state: HeartbeatState,
    phase: String,
    phase_entered_at: SystemTime,
    last_action: Option<String>,
    last_mutation_at: Option<SystemTime>,
    turn_id: Option<String>,
    last_emit_at: Option<SystemTime>,
    /// Wall clock of last observed liveness tick from the process.
    last_seen_at: SystemTime,
    alive: bool,
}

/// In-process registry: one seat per persona / agent name.
#[derive(Debug)]
pub struct HeartbeatRegistry {
    seats: HashMap<String, SeatRecord>,
    drops: DroppedEventCounter,
    stall_after: Duration,
    cadence: Duration,
    /// Missed-seen death threshold: multiple of cadence, strictly > stall_after.
    dead_after: Duration,
    status_path: Option<PathBuf>,
    /// Emitted payloads (tests / in-process consumers).
    pub emissions: Vec<HeartbeatPayload>,
    /// Last status-file write outcome (WO #150).
    ///
    /// Lets in-process consumers and the liveness watcher tell "seat up,
    /// heartbeat broken" (an emit happened but the file write failed) from
    /// "no heartbeat yet" (no emit attempted). `emit_now` previously dropped
    /// the write result with `let _ =`, so a persistently failing write was
    /// invisible while the seat looked live in memory.
    write_health: WriteHealth,
}

/// Status-file write health, tracked across `emit_now` calls (WO #150).
///
/// A write is only attempted when a `status_path` is configured; seats with
/// no path never leave [`WriteHealth::default`] (no attempt, no error).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteHealth {
    /// Human-readable last write error, cleared on the next successful write.
    /// `Some` here with a non-zero `attempts` is the "heartbeat broken" signal.
    pub last_error: Option<String>,
    /// Consecutive failed writes since the last success (reset to 0 on success).
    pub consecutive_failures: u64,
    /// Total status-file write attempts (success or failure).
    pub attempts: u64,
    /// Wall clock of the last successful write, if any.
    pub last_success_at: Option<SystemTime>,
}

impl WriteHealth {
    /// True once at least one write was attempted and the most recent one failed.
    ///
    /// This is the "seat up, heartbeat broken" predicate: distinct from a seat
    /// that has never attempted a write (`attempts == 0` → "no heartbeat yet").
    pub fn is_broken(&self) -> bool {
        self.attempts > 0 && self.last_error.is_some()
    }
}

impl HeartbeatRegistry {
    pub fn new(stall_after: Duration, cadence: Duration) -> Self {
        let dead_after = dead_after_for(stall_after, cadence);
        debug_assert!(
            dead_after > stall_after,
            "dead_after ({dead_after:?}) must be strictly greater than stall_after ({stall_after:?})"
        );
        debug_assert!(
            dead_after.as_nanos() % cadence.as_nanos() == 0,
            "dead_after must be a multiple of cadence"
        );
        Self {
            seats: HashMap::new(),
            drops: DroppedEventCounter::default(),
            stall_after,
            cadence,
            dead_after,
            status_path: None,
            emissions: Vec::new(),
            write_health: WriteHealth::default(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(STALL_AFTER_DEFAULT, HEARTBEAT_CADENCE_DEFAULT)
    }

    pub fn set_status_path(&mut self, path: impl Into<PathBuf>) {
        self.status_path = Some(path.into());
    }

    pub fn cadence(&self) -> Duration {
        self.cadence
    }

    pub fn stall_after(&self) -> Duration {
        self.stall_after
    }

    pub fn dead_after(&self) -> Duration {
        self.dead_after
    }

    pub fn dropped_events(&self) -> &DroppedEventCounter {
        &self.drops
    }

    pub fn register_identity(&mut self, agent: impl Into<String>, identity: IdentityClass, now: SystemTime) {
        let agent = agent.into();
        self.seats
            .entry(agent)
            .and_modify(|s| {
                s.identity = identity;
                s.last_seen_at = now;
            })
            .or_insert_with(|| SeatRecord {
                identity,
                state: HeartbeatState::Idle,
                phase: "idle".into(),
                phase_entered_at: now,
                last_action: None,
                last_mutation_at: None,
                turn_id: None,
                last_emit_at: None,
                last_seen_at: now,
                alive: true,
            });
    }

    /// Write the initial status snapshot before any turn (WO #148).
    ///
    /// `register_identity` alone does not touch the status path — without this
    /// call a freshly-booted seat has no file, and the external liveness
    /// watcher alarms `unknown` until the first turn. Emits state
    /// [`HeartbeatState::AgentInitialized`] on the configured status path.
    pub fn emit_initial(&mut self, agent: &str, now: SystemTime) -> Option<HeartbeatPayload> {
        self.set_state(
            agent,
            HeartbeatState::AgentInitialized,
            "agent_initialized",
            None,
            now,
        )
    }

    pub fn record_dropped_event(&mut self, reason: impl Into<String>) {
        self.drops.record(reason);
    }

    /// Transition seat state. Emits immediately on change (WO cadence rule).
    pub fn set_state(
        &mut self,
        agent: &str,
        state: HeartbeatState,
        phase: impl Into<String>,
        turn_id: Option<String>,
        now: SystemTime,
    ) -> Option<HeartbeatPayload> {
        let Some(seat) = self.seats.get_mut(agent) else {
            return None;
        };
        if seat.identity == IdentityClass::CronNotify {
            return None;
        }
        // Human-backed sessions are visible but never enter stalled/dead agent states.
        let requested = state;
        let state = match (seat.identity, state) {
            (IdentityClass::HumanBackedSession, HeartbeatState::Stalled | HeartbeatState::Dead) => {
                HeartbeatState::Idle
            }
            _ => state,
        };
        let remapped = requested != state;

        let changed = remapped || seat.state != state || seat.turn_id != turn_id;
        if seat.state != state {
            seat.phase_entered_at = now;
        }
        seat.state = state;
        seat.phase = phase.into();
        seat.turn_id = turn_id;
        seat.last_seen_at = now;
        seat.alive = state != HeartbeatState::Dead;

        if changed {
            return self.emit_now(agent, now);
        }
        None
    }

    pub fn record_mutation(
        &mut self,
        agent: &str,
        kind: MutationKind,
        action: impl Into<String>,
        now: SystemTime,
    ) {
        let unstall = {
            let Some(seat) = self.seats.get_mut(agent) else {
                return;
            };
            if seat.identity == IdentityClass::CronNotify {
                return;
            }
            let _ = kind;
            seat.last_action.replace(action.into());
            seat.last_mutation_at = Some(now);
            seat.last_seen_at = now;
            if seat.state == HeartbeatState::Stalled {
                seat.state = HeartbeatState::Running;
                seat.phase = "running".into();
                seat.phase_entered_at = now;
                true
            } else {
                false
            }
        };
        if unstall {
            let _ = self.emit_now(agent, now);
        }
    }

    pub fn note_action(&mut self, agent: &str, action: impl Into<String>, now: SystemTime) {
        if let Some(seat) = self.seats.get_mut(agent) {
            if seat.identity != IdentityClass::CronNotify {
                seat.last_action = Some(action.into());
                seat.last_seen_at = now;
            }
        }
    }

    /// Mark the seat dead (kill / process exit). Emits immediately.
    pub fn mark_dead(&mut self, agent: &str, now: SystemTime) -> Option<HeartbeatPayload> {
        self.set_state(agent, HeartbeatState::Dead, "dead", None, now)
    }

    /// Evaluate stall / missed-seen death and emit on cadence while active.
    ///
    /// Missed-seen → `dead` uses [`Self::dead_after`] (cadence multiple >
    /// `stall_after`), not a single cadence. When the harness calls
    /// [`Self::touch_alive`] immediately before this method, that death branch
    /// cannot fire (B2 honesty) — rely on [`Self::mark_dead`] for exit/respawn.
    pub fn tick(&mut self, agent: &str, now: SystemTime) -> Option<HeartbeatPayload> {
        let identity = self.seats.get(agent).map(|s| s.identity)?;
        if identity == IdentityClass::CronNotify {
            return None;
        }

        // Reborrow after the early checks by collecting decisions first.
        let decision = {
            let seat = self.seats.get(agent)?;
            if identity == IdentityClass::HumanBackedSession {
                // Visible, never stalled/dead via the agent model.
                let due = seat
                    .last_emit_at
                    .map(|t| now.duration_since(t).unwrap_or_default() >= self.cadence)
                    .unwrap_or(true);
                return if due {
                    self.emit_now(agent, now)
                } else {
                    None
                };
            }

            if !seat.alive || seat.state == HeartbeatState::Dead {
                return None;
            }

            let due = seat
                .last_emit_at
                .map(|t| now.duration_since(t).unwrap_or_default() >= self.cadence)
                .unwrap_or(true);

            let active = matches!(
                seat.state,
                HeartbeatState::Claimed
                    | HeartbeatState::Running
                    | HeartbeatState::Blocked
                    | HeartbeatState::Stalled
            );

            // Missed-seen past dead_after (multiple of cadence > stall_after).
            // Latent unless touch_alive is withheld (out-of-process / rewire).
            let since_seen = now
                .duration_since(seat.last_seen_at)
                .unwrap_or_default();
            if active && since_seen > self.dead_after {
                Some(("dead", HeartbeatState::Dead))
            } else if active && self.should_stall(seat, now) {
                Some(("stalled", HeartbeatState::Stalled))
            } else if active {
                if due {
                    Some(("emit", seat.state))
                } else {
                    None
                }
            } else if due && seat.state != HeartbeatState::Idle {
                Some(("idle", HeartbeatState::Idle))
            } else if due {
                Some(("emit_idle", HeartbeatState::Idle))
            } else {
                None
            }
        };

        match decision {
            Some(("dead", _)) => self.mark_dead(agent, now),
            Some(("stalled", _)) => {
                self.set_state(agent, HeartbeatState::Stalled, "stalled", None, now)
            }
            Some(("idle", _)) => self.set_state(agent, HeartbeatState::Idle, "idle", None, now),
            Some(("emit", _)) => self.emit_now(agent, now),
            Some(("emit_idle", _)) => self.emit_now(agent, now),
            _ => None,
        }
    }

    /// Touch liveness without implying a durable write (process still answering).
    ///
    /// The wired harness calls this immediately before [`Self::tick`], which
    /// masks in-process missed-seen death (B2). Do not treat that path as a
    /// wedge detector.
    pub fn touch_alive(&mut self, agent: &str, now: SystemTime) {
        if let Some(seat) = self.seats.get_mut(agent) {
            seat.last_seen_at = now;
            seat.alive = true;
        }
    }

    fn should_stall(&self, seat: &SeatRecord, now: SystemTime) -> bool {
        if !matches!(
            seat.state,
            HeartbeatState::Claimed | HeartbeatState::Running | HeartbeatState::Blocked
        ) {
            return false;
        }
        let anchor = seat
            .last_mutation_at
            .unwrap_or(seat.phase_entered_at);
        now.duration_since(anchor).unwrap_or_default() >= self.stall_after
            && seat.state != HeartbeatState::Stalled
    }

    fn emit_now(&mut self, agent: &str, now: SystemTime) -> Option<HeartbeatPayload> {
        let payload = self.payload_for(agent, now)?;
        if let Some(seat) = self.seats.get_mut(agent) {
            seat.last_emit_at = Some(now);
        }
        self.emissions.push(payload.clone());
        if let Some(path) = self.status_path.clone() {
            self.write_health.attempts += 1;
            match write_status_snapshot(path.as_path(), &self.snapshot(now)) {
                Ok(()) => {
                    self.write_health.consecutive_failures = 0;
                    self.write_health.last_error = None;
                    self.write_health.last_success_at = Some(now);
                }
                Err(err) => {
                    self.write_health.consecutive_failures += 1;
                    let msg = format!("{err}");
                    // Surface the failure the liveness watcher would otherwise
                    // never learn about: the seat is up (emit happened) but the
                    // status file the watcher reads is not being written.
                    tracing::error!(
                        agent = %agent,
                        path = %path.display(),
                        consecutive_failures = self.write_health.consecutive_failures,
                        error = %msg,
                        "heartbeat status write failed (seat up, heartbeat broken)"
                    );
                    self.write_health.last_error = Some(msg);
                }
            }
        }
        Some(payload)
    }

    /// Status-file write health for this registry (WO #150).
    ///
    /// Use [`WriteHealth::is_broken`] to distinguish "seat up, heartbeat broken"
    /// (a write was attempted and the most recent one failed) from "no heartbeat
    /// yet" (`attempts == 0`).
    pub fn write_health(&self) -> &WriteHealth {
        &self.write_health
    }

    pub fn payload_for(&self, agent: &str, now: SystemTime) -> Option<HeartbeatPayload> {
        let seat = self.seats.get(agent)?;
        if seat.identity == IdentityClass::CronNotify {
            return None;
        }
        let elapsed = now
            .duration_since(seat.phase_entered_at)
            .unwrap_or_default()
            .as_secs();
        Some(HeartbeatPayload {
            agent: agent.to_string(),
            state: seat.state,
            phase: seat.phase.clone(),
            last_action: seat.last_action.clone(),
            last_mutation_at: seat.last_mutation_at.map(system_time_secs),
            elapsed_in_phase_secs: elapsed,
            turn_id: seat.turn_id.clone(),
            identity: seat.identity,
            dropped_events: self.drops.total(),
            dropped_event_reasons: self.drops.reasons().clone(),
        })
    }

    pub fn snapshot(&self, now: SystemTime) -> Vec<HeartbeatPayload> {
        let mut out: Vec<_> = self
            .seats
            .keys()
            .filter_map(|name| self.payload_for(name, now))
            .collect();
        out.sort_by(|a, b| a.agent.cmp(&b.agent));
        out
    }

    pub fn liveness_label(&self, agent: &str, now: SystemTime) -> Option<&'static str> {
        let seat = self.seats.get(agent)?;
        match seat.identity {
            IdentityClass::CronNotify => None,
            IdentityClass::HumanBackedSession => Some("human_backed"),
            IdentityClass::AgentSeat => match seat.state {
                HeartbeatState::Dead => Some("dead"),
                HeartbeatState::Stalled => Some("stalled"),
                HeartbeatState::ReturnedEmpty => Some("returned_empty"),
                HeartbeatState::Running | HeartbeatState::Claimed | HeartbeatState::Blocked
                    if self.should_stall(seat, now) =>
                {
                    Some("stalled")
                }
                HeartbeatState::Running
                | HeartbeatState::Claimed
                | HeartbeatState::Blocked
                | HeartbeatState::Returned
                | HeartbeatState::Idle
                | HeartbeatState::AgentInitialized => {
                    if seat.last_mutation_at.is_some()
                        || matches!(
                            seat.state,
                            HeartbeatState::Idle
                                | HeartbeatState::Returned
                                | HeartbeatState::AgentInitialized
                        )
                    {
                        Some("healthy")
                    } else if matches!(
                        seat.state,
                        HeartbeatState::Running | HeartbeatState::Claimed | HeartbeatState::Blocked
                    ) {
                        // Active but no writes yet — not healthy progress.
                        Some("running_no_progress")
                    } else {
                        Some("healthy")
                    }
                }
            },
        }
    }
}

fn system_time_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Founder-readable status snapshot (JSON array of payloads).
pub fn write_status_snapshot(path: &Path, payloads: &[HeartbeatPayload]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_vec_pretty(payloads)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, body)
}

/// Resolve identity from a key/service name hint.
pub fn classify_identity(name: &str, has_buzz_agent_service: bool) -> IdentityClass {
    let n = name.to_ascii_lowercase();
    if has_buzz_agent_service || n.starts_with("buzz-agent@") {
        return IdentityClass::AgentSeat;
    }
    // Cron/notify first so names like `factory-notify.key` are not mistaken
    // for the human-backed Factory session.
    if n.contains("notify")
        || n.contains("cron")
        || n.contains("cost-report")
        || n.contains("pr-shots")
        || n.contains("factory-driver")
        || n.contains("factory-notify")
    {
        return IdentityClass::CronNotify;
    }
    // Human-backed orchestrator session (Factory), not cron and not an agent seat.
    if n == "factory"
        || n == "factory.key"
        || n.ends_with("/factory.key")
        || n == "@factory"
    {
        return IdentityClass::HumanBackedSession;
    }
    if n.ends_with(".key") {
        // Bare key without agent service: excluded unless recognized above.
        return IdentityClass::CronNotify;
    }
    IdentityClass::AgentSeat
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    /// Kill mid-turn → `dead` via explicit mark_dead (respawn/exit path).
    #[test]
    fn heartbeat_dead_on_kill() {
        let mut reg = HeartbeatRegistry::new(Duration::from_secs(180), Duration::from_secs(75));
        reg.register_identity("codex", IdentityClass::AgentSeat, t0());
        reg.set_state(
            "codex",
            HeartbeatState::Running,
            "running",
            Some("turn-1".into()),
            t0(),
        );
        // Kill observed before the next cadence elapses.
        let killed_at = t0() + Duration::from_secs(30);
        let payload = reg.mark_dead("codex", killed_at).expect("emit on kill");
        assert_eq!(payload.state, HeartbeatState::Dead);
        assert_eq!(payload.state.as_str(), "dead");
        assert!(
            killed_at.duration_since(t0()).unwrap() < reg.cadence(),
            "explicit mark_dead must surface promptly (not gated on dead_after)"
        );
        assert_eq!(reg.liveness_label("codex", killed_at), Some("dead"));
    }

    /// Long turn, no writes → `stalled`, not healthy.
    #[test]
    fn heartbeat_stalled_on_silent_write() {
        let stall_after = Duration::from_secs(120);
        let mut reg = HeartbeatRegistry::new(stall_after, Duration::from_secs(75));
        reg.register_identity("firstmate", IdentityClass::AgentSeat, t0());
        reg.set_state(
            "firstmate",
            HeartbeatState::Running,
            "running",
            Some("turn-silent".into()),
            t0(),
        );
        // Keep the process "alive" (liveness ticks) but never mutate.
        let mid = t0() + Duration::from_secs(60);
        reg.touch_alive("firstmate", mid);
        let after_stall = t0() + stall_after + Duration::from_secs(1);
        reg.touch_alive("firstmate", after_stall);
        let payload = reg
            .tick("firstmate", after_stall)
            .expect("stall emit");
        assert_eq!(payload.state, HeartbeatState::Stalled);
        assert_ne!(reg.liveness_label("firstmate", after_stall), Some("healthy"));
        assert_eq!(reg.liveness_label("firstmate", after_stall), Some("stalled"));
    }

    /// L1 tripwire (B1): long turn with periodic durable writes stays running.
    ///
    /// Uses the production MidTurnMutationSink → drain_into path. Without
    /// mid-turn registry updates, `should_stall` would freeze on
    /// `phase_entered_at` and flip to stalled after stall_after.
    #[test]
    fn heartbeat_long_turn_with_periodic_writes_stays_running() {
        let stall_after = Duration::from_secs(180);
        let cadence = Duration::from_secs(75);
        let mut reg = HeartbeatRegistry::new(stall_after, cadence);
        let sink = MidTurnMutationSink::new();
        reg.register_identity("codex", IdentityClass::AgentSeat, t0());
        reg.set_state(
            "codex",
            HeartbeatState::Running,
            "running",
            Some("turn-long".into()),
            t0(),
        );

        // 10-minute turn, durable write every 60s — well past stall_after.
        for minute in 1u64..=10 {
            let t = t0() + Duration::from_secs(60 * minute);
            sink.note(MutationKind::File, format!("tool_call:Write@{minute}"), t);
            // Production ticker: drain mid-turn writes, then touch_alive, then tick.
            sink.drain_into(&mut reg, "codex");
            reg.touch_alive("codex", t);
            let _ = reg.tick("codex", t);
            let payload = reg.payload_for("codex", t).expect("payload");
            assert_ne!(
                payload.state,
                HeartbeatState::Stalled,
                "minute {minute}: healthy long turn must not stall"
            );
            assert_eq!(payload.state, HeartbeatState::Running);
            assert_eq!(reg.liveness_label("codex", t), Some("healthy"));
        }

        // Contrast: turn-local progress alone (pre-B1 wiring) leaves the
        // registry anchor frozen at phase_entered_at → stalls past stall_after.
        let mut frozen = HeartbeatRegistry::new(stall_after, cadence);
        frozen.register_identity("codex", IdentityClass::AgentSeat, t0());
        frozen.set_state(
            "codex",
            HeartbeatState::Running,
            "running",
            Some("turn-frozen".into()),
            t0(),
        );
        let mut local_only = TurnProgress::default();
        for minute in 1u64..=4 {
            let t = t0() + Duration::from_secs(60 * minute);
            local_only.record_mutation(MutationKind::File, "Write", t);
            // Deliberately do NOT call record_mutation / drain_into on registry.
        }
        let after = t0() + stall_after + Duration::from_secs(1);
        frozen.touch_alive("codex", after);
        let stalled = frozen
            .tick("codex", after)
            .expect("stall without mid-turn registry");
        assert_eq!(stalled.state, HeartbeatState::Stalled);
        assert!(local_only.has_durable_output());
    }

    /// B3: dead_after is a cadence multiple strictly greater than stall_after.
    #[test]
    fn dead_after_exceeds_stall_and_is_cadence_multiple() {
        let stall = STALL_AFTER_DEFAULT;
        let cadence = HEARTBEAT_CADENCE_DEFAULT;
        let dead = dead_after_for(stall, cadence);
        assert!(dead > stall);
        assert_eq!(dead.as_secs() % cadence.as_secs(), 0);
        // Defaults: 75s cadence, 180s stall → 225s dead (3× cadence).
        assert_eq!(dead, Duration::from_secs(225));

        let reg = HeartbeatRegistry::with_defaults();
        assert_eq!(reg.dead_after(), dead);
        assert!(reg.dead_after() > reg.stall_after());

        // Without touch_alive, stall must win before missed-seen dead.
        let mut reg = HeartbeatRegistry::new(stall, cadence);
        reg.register_identity("codex", IdentityClass::AgentSeat, t0());
        reg.set_state("codex", HeartbeatState::Running, "running", None, t0());
        // Do not touch_alive — last_seen stays at t0.
        let at_stall = t0() + stall + Duration::from_secs(1);
        let payload = reg.tick("codex", at_stall).expect("stall before dead");
        assert_eq!(payload.state, HeartbeatState::Stalled);
        assert!(at_stall.duration_since(t0()).unwrap() < reg.dead_after());
    }

    /// Turn returns ok with no message/file → recorded `returned_empty`.
    #[test]
    fn turn_outcome_returned_empty() {
        assert_eq!(
            classify_ok_turn_outcome(false, false),
            TurnOutcomeLabel::ReturnedEmpty
        );
        assert_eq!(classify_ok_turn_outcome(true, false), TurnOutcomeLabel::Ok);
        assert_eq!(classify_ok_turn_outcome(false, true), TurnOutcomeLabel::Ok);

        // E13: token exhaustion mid-tool-calls with zero publish/file still empty.
        let mut progress = TurnProgress::default();
        progress.note_action("tool_call:read");
        progress.note_action("tool_call:grep");
        // No durable mutation recorded despite tool activity.
        assert!(!progress.has_durable_output());
        assert_eq!(
            classify_ok_turn_outcome(progress.produced_message, progress.produced_file).as_str(),
            "returned_empty"
        );

        let mut reg = HeartbeatRegistry::with_defaults();
        reg.register_identity("firstmate", IdentityClass::AgentSeat, t0());
        let payload = reg
            .set_state(
                "firstmate",
                HeartbeatState::ReturnedEmpty,
                "returned_empty",
                Some("turn-e13".into()),
                t0(),
            )
            .expect("emit");
        assert_eq!(payload.state.as_str(), "returned_empty");
    }

    /// Unmatched event dropped → counter increments with reason.
    #[test]
    fn dropped_event_counter_labels_reason() {
        let mut reg = HeartbeatRegistry::with_defaults();
        reg.record_dropped_event("matched_no_rule");
        reg.record_dropped_event("matched_no_rule");
        reg.record_dropped_event("self_authored");
        assert_eq!(reg.dropped_events().total(), 3);
        assert_eq!(reg.dropped_events().count_for("matched_no_rule"), 2);
        assert_eq!(reg.dropped_events().count_for("self_authored"), 1);
        assert!(reg.dropped_events().reasons().contains_key("matched_no_rule"));
    }

    /// Non-agent identity never counted stalled/dead; human-backed is its own class.
    #[test]
    fn non_agent_identity_excluded_from_liveness() {
        assert_eq!(
            classify_identity("factory-notify.key", false),
            IdentityClass::CronNotify
        );
        assert_eq!(
            classify_identity("cost-report", false),
            IdentityClass::CronNotify
        );
        assert_eq!(
            classify_identity("factory.key", false),
            IdentityClass::HumanBackedSession
        );
        assert_eq!(
            classify_identity("buzz-agent@codex", true),
            IdentityClass::AgentSeat
        );

        let mut reg = HeartbeatRegistry::new(Duration::from_secs(1), Duration::from_secs(1));
        reg.register_identity("cron.key", IdentityClass::CronNotify, t0());
        reg.register_identity("factory.key", IdentityClass::HumanBackedSession, t0());
        reg.register_identity("codex", IdentityClass::AgentSeat, t0());

        // Cron: excluded — no payload, no stall, no dead.
        assert!(reg
            .set_state("cron.key", HeartbeatState::Running, "running", None, t0())
            .is_none());
        assert!(reg.tick("cron.key", t0() + Duration::from_secs(10)).is_none());
        assert!(reg.mark_dead("cron.key", t0()).is_none());
        assert!(reg.payload_for("cron.key", t0()).is_none());
        assert_eq!(reg.liveness_label("cron.key", t0()), None);

        // Human-backed: visible, never stalled/dead.
        let human = reg
            .set_state(
                "factory.key",
                HeartbeatState::Stalled,
                "stalled",
                None,
                t0(),
            )
            .expect("human visible");
        assert_ne!(human.state, HeartbeatState::Stalled);
        assert_ne!(human.state, HeartbeatState::Dead);
        assert_eq!(human.identity, IdentityClass::HumanBackedSession);
        let dead_attempt = reg.mark_dead("factory.key", t0() + Duration::from_secs(1));
        assert!(dead_attempt.is_some());
        assert_ne!(dead_attempt.unwrap().state, HeartbeatState::Dead);
        assert_eq!(
            reg.liveness_label("factory.key", t0()),
            Some("human_backed")
        );

        // Agent seat still participates (keep last_seen fresh so miss-cadence
        // death does not win over stall).
        reg.set_state("codex", HeartbeatState::Running, "running", None, t0());
        let later = t0() + Duration::from_secs(5);
        reg.touch_alive("codex", later);
        let stalled = reg.tick("codex", later).expect("agent can stall");
        assert_eq!(stalled.state, HeartbeatState::Stalled);
    }

    #[test]
    fn tool_mutation_classifies_message_and_file() {
        assert_eq!(
            classify_tool_mutation("buzz messages send", "shell"),
            Some(MutationKind::Message)
        );
        assert_eq!(
            classify_tool_mutation("Write", "edit"),
            Some(MutationKind::File)
        );
        assert_eq!(classify_tool_mutation("Read", "read"), None);
        assert_eq!(classify_tool_mutation("agent_message_chunk", "stream"), None);
    }

    /// Object-shaped ACP rawInput (the common Cursor/Codex Shell shape) must
    /// surface the command so `buzz messages send` counts as a Message.
    #[test]
    fn raw_input_object_command_classifies_as_message() {
        let raw = serde_json::json!({
            "command": "buzz messages send --channel abc --content 'hi'"
        });
        let blob = tool_mutation_classify_blob("Shell", Some(&raw), "");
        assert!(
            blob.contains("buzz messages send"),
            "blob must include command text, got {blob}"
        );
        assert_eq!(
            classify_tool_mutation(&blob, "shell"),
            Some(MutationKind::Message)
        );
        // String rawInput still works.
        let raw_str = serde_json::json!("buzz messages send --reply-to x --content y");
        let blob_str = tool_mutation_classify_blob("Shell", Some(&raw_str), "");
        assert_eq!(
            classify_tool_mutation(&blob_str, "execute"),
            Some(MutationKind::Message)
        );
    }

    /// Mirror of `turn_outcome_returned_empty`: a reply-only turn (message,
    /// no file) must classify `ok`, never `returned_empty`.
    #[test]
    fn turn_outcome_reply_only_is_ok_not_returned_empty() {
        let raw = serde_json::json!({
            "command": "printf 'ack' | buzz messages send --channel c --content -"
        });
        let blob = tool_mutation_classify_blob("Shell", Some(&raw), "");
        let mut progress = TurnProgress::default();
        let kind = classify_tool_mutation(&blob, "shell").expect("publish is Message");
        progress.record_mutation(kind, "tool_call:Shell", t0());
        assert!(progress.produced_message);
        assert!(!progress.produced_file);
        assert_eq!(
            classify_ok_turn_outcome(progress.produced_message, progress.produced_file),
            TurnOutcomeLabel::Ok
        );
        assert_ne!(
            classify_ok_turn_outcome(progress.produced_message, progress.produced_file),
            TurnOutcomeLabel::ReturnedEmpty
        );
    }

    #[test]
    fn default_status_path_is_shared_home_not_tmp() {
        let path = default_status_path("FirstMate");
        let s = path.to_string_lossy();
        assert!(
            s.starts_with("/opt/buzz/agents/home/shared/heartbeat/"),
            "must be under shared/heartbeat (outside PrivateTmp), got {s}"
        );
        assert!(!s.contains("/tmp/"), "must not use PrivateTmp /tmp");
        assert!(s.ends_with("FirstMate.json"));
        let ugly = default_status_path("buzz-agent@codex/../x");
        assert!(!ugly.to_string_lossy().contains(".."));
    }

    #[test]
    fn cadence_constants_match_spec() {
        assert_eq!(HEARTBEAT_CADENCE_MIN, Duration::from_secs(60));
        assert_eq!(HEARTBEAT_CADENCE_MAX, Duration::from_secs(90));
        assert!(HEARTBEAT_CADENCE_DEFAULT >= HEARTBEAT_CADENCE_MIN);
        assert!(HEARTBEAT_CADENCE_DEFAULT <= HEARTBEAT_CADENCE_MAX);
    }

    /// WO #148 tripwire: a freshly-started seat writes a status file *before*
    /// any inbound turn is dispatched. `register_identity` alone must not
    /// write; `emit_initial` must produce the watcher-shaped snapshot.
    #[test]
    fn startup_emit_writes_status_file_before_any_turn() {
        let dir = std::env::temp_dir().join(format!(
            "buzz-acp-wo148-hb-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp heartbeat dir");
        let status_path = dir.join("codex.json");

        let mut reg = HeartbeatRegistry::with_defaults();
        reg.set_status_path(&status_path);
        reg.register_identity("codex", IdentityClass::AgentSeat, t0());

        // Precondition: register alone leaves no file (the #148 bug class).
        assert!(
            !status_path.exists(),
            "register_identity must not write the status file"
        );

        let payload = reg
            .emit_initial("codex", t0())
            .expect("startup emit must produce a payload");
        assert_eq!(payload.state, HeartbeatState::AgentInitialized);
        assert_eq!(payload.state.as_str(), "agent_initialized");
        assert_eq!(payload.phase, "agent_initialized");
        assert!(payload.turn_id.is_none(), "startup emit has no turn");
        assert_eq!(payload.agent, "codex");
        assert_eq!(payload.dropped_events, 0);
        assert_eq!(reg.liveness_label("codex", t0()), Some("healthy"));

        // File must exist before any Claimed/Running transition.
        assert!(
            status_path.is_file(),
            "status file must exist before any turn"
        );
        let body = std::fs::read_to_string(&status_path).expect("read status");
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("status JSON");
        let seat = parsed
            .as_array()
            .and_then(|a| a.first())
            .expect("snapshot array with one seat");
        assert_eq!(seat["agent"], "codex");
        assert_eq!(seat["state"], "agent_initialized");
        assert!(seat["turn_id"].is_null());
        assert_eq!(seat["elapsed_in_phase_secs"], 0);
        assert_eq!(seat["dropped_events"], 0);

        // Still no turn dispatched — advancing to Claimed is a later step.
        assert!(
            !matches!(
                reg.payload_for("codex", t0()).map(|p| p.state),
                Some(HeartbeatState::Claimed | HeartbeatState::Running)
            ),
            "must not have entered a turn state"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// WO #150 tripwire: `emit_now` must surface status-file write failures via
    /// `write_health()` instead of swallowing them, so the liveness watcher can
    /// tell "seat up, heartbeat broken" from "no heartbeat yet".
    #[test]
    fn emit_surfaces_status_write_failure() {
        let base = std::env::temp_dir().join(format!(
            "buzz-acp-wo150-hb-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("temp base dir");
        // Make the status path's parent a *file* so create_dir_all/write fail
        // deterministically (NotADirectory) on every emit.
        let blocker = base.join("blocker");
        std::fs::write(&blocker, b"not a dir").expect("write blocker file");
        let status_path = blocker.join("codex.json");

        let mut reg = HeartbeatRegistry::with_defaults();
        reg.register_identity("codex", IdentityClass::AgentSeat, t0());

        // Precondition: no write attempted yet → "no heartbeat yet", not broken.
        assert_eq!(reg.write_health().attempts, 0);
        assert!(
            !reg.write_health().is_broken(),
            "a seat with no write attempt must read as 'no heartbeat yet', not broken"
        );

        reg.set_status_path(&status_path);
        let payload = reg
            .emit_initial("codex", t0())
            .expect("emit still produces a payload even when the write fails");
        assert_eq!(payload.state, HeartbeatState::AgentInitialized);

        // The write must have been attempted and failed — and be observable.
        assert_eq!(reg.write_health().attempts, 1, "write must be attempted");
        assert_eq!(reg.write_health().consecutive_failures, 1);
        assert!(
            reg.write_health().is_broken(),
            "a failed status write must surface as 'seat up, heartbeat broken'"
        );
        assert!(
            reg.write_health().last_error.is_some(),
            "the write error text must be captured, not swallowed"
        );
        assert!(
            reg.write_health().last_success_at.is_none(),
            "no successful write has happened"
        );
        assert!(
            !status_path.exists(),
            "the file genuinely was not written (failure is real, not simulated)"
        );

        // A second failing emit compounds the failure counter.
        reg.set_state(
            "codex",
            HeartbeatState::Running,
            "running",
            Some("turn-1".into()),
            t0() + Duration::from_secs(1),
        );
        assert_eq!(reg.write_health().consecutive_failures, 2);
        assert!(reg.write_health().is_broken());

        // Repoint at a writable path: the next successful emit clears the error,
        // proving recovery is observable too.
        let good_path = base.join("codex.json");
        reg.set_status_path(&good_path);
        reg.set_state(
            "codex",
            HeartbeatState::Blocked,
            "blocked",
            Some("turn-1".into()),
            t0() + Duration::from_secs(2),
        );
        assert!(good_path.is_file(), "recovery write must land");
        assert_eq!(
            reg.write_health().consecutive_failures,
            0,
            "a successful write resets the failure streak"
        );
        assert!(
            !reg.write_health().is_broken(),
            "a healthy write clears the 'broken' signal"
        );
        assert!(reg.write_health().last_error.is_none());
        assert!(reg.write_health().last_success_at.is_some());

        let _ = std::fs::remove_dir_all(&base);
    }

    /// WO #146: `elapsed_in_phase_secs` is live on `payload_for(now)` and
    /// cadence-sampled on the status file. Two file reads 15s apart showing
    /// the same elapsed is the 75s emit window, not a frozen SystemTime.
    #[test]
    fn elapsed_in_phase_is_live_and_cadence_sampled_on_file() {
        let dir = std::env::temp_dir().join(format!(
            "buzz-acp-wo146-elapsed-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let status_path = dir.join("status.json");

        let cadence = HEARTBEAT_CADENCE_DEFAULT;
        let mut reg = HeartbeatRegistry::new(STALL_AFTER_DEFAULT, cadence);
        reg.set_status_path(&status_path);
        reg.register_identity("firstmate", IdentityClass::AgentSeat, t0());
        reg.set_state(
            "firstmate",
            HeartbeatState::Running,
            "running",
            Some("turn-elapsed".into()),
            t0(),
        );
        let _ = reg.tick("firstmate", t0());
        assert!(status_path.is_file(), "running seat writes a snapshot");

        let file_elapsed = |path: &std::path::Path| -> u64 {
            let body = std::fs::read_to_string(path).expect("read status");
            let parsed: serde_json::Value = serde_json::from_str(&body).expect("status JSON");
            parsed
                .as_array()
                .and_then(|a| a.first())
                .and_then(|seat| seat["elapsed_in_phase_secs"].as_u64())
                .expect("elapsed_in_phase_secs")
        };

        assert_eq!(file_elapsed(&status_path), 0);
        assert_eq!(
            reg.payload_for("firstmate", t0())
                .expect("payload")
                .elapsed_in_phase_secs,
            0
        );

        let t15 = t0() + Duration::from_secs(15);
        reg.touch_alive("firstmate", t15);
        assert!(
            reg.tick("firstmate", t15).is_none(),
            "cadence is 75s; a 15s tick must not re-emit"
        );
        assert_eq!(
            file_elapsed(&status_path),
            0,
            "status file stays at last emit until cadence"
        );
        assert_eq!(
            reg.payload_for("firstmate", t15)
                .expect("payload")
                .elapsed_in_phase_secs,
            15,
            "live payload_for must advance with now"
        );

        let t_cadence = t0() + cadence;
        reg.touch_alive("firstmate", t_cadence);
        let emitted = reg
            .tick("firstmate", t_cadence)
            .expect("cadence emit");
        assert_eq!(emitted.elapsed_in_phase_secs, cadence.as_secs());
        assert_eq!(file_elapsed(&status_path), cadence.as_secs());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn idle_tick_advances_status_mtime_and_emits_idle() {
        let dir = std::env::temp_dir().join(format!(
            "buzz-acp-wo349-idle-heartbeat-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let status_path = dir.join("status.json");

        let cadence = Duration::from_millis(1);
        let mut reg = HeartbeatRegistry::new(STALL_AFTER_DEFAULT, cadence);
        reg.set_status_path(&status_path);
        reg.register_identity("sprig", IdentityClass::AgentSeat, t0());
        let initial = reg.emit_initial("sprig", t0()).expect("startup emit");
        assert_eq!(initial.state, HeartbeatState::AgentInitialized);
        let first_mtime = std::fs::metadata(&status_path)
            .expect("startup status file")
            .modified()
            .expect("startup mtime");

        std::thread::sleep(Duration::from_millis(20));

        let later = t0() + cadence;
        let emitted = reg.tick("sprig", later).expect("idle cadence emit");
        let second_mtime = std::fs::metadata(&status_path)
            .expect("idle status file")
            .modified()
            .expect("idle mtime");

        assert_eq!(emitted.state, HeartbeatState::Idle);
        assert_eq!(emitted.phase, "idle");
        assert!(emitted.turn_id.is_none(), "idle heartbeat clears turn identity");
        assert!(
            second_mtime > first_mtime,
            "idle cadence tick must rewrite the status file so mtime advances"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn in_flight_tick_advances_status_mtime_without_new_mutation() {
        let dir = std::env::temp_dir().join(format!(
            "buzz-acp-wo349-running-heartbeat-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let status_path = dir.join("status.json");

        let cadence = Duration::from_millis(1);
        let t_start = t0();
        let t_tool = t_start + Duration::from_secs(5);
        let t_tick = t_start + Duration::from_secs(95);
        let mut reg = HeartbeatRegistry::new(STALL_AFTER_DEFAULT, cadence);
        reg.set_status_path(&status_path);
        reg.register_identity("sprig", IdentityClass::AgentSeat, t_start);
        let _ = reg.set_state(
            "sprig",
            HeartbeatState::Running,
            "running",
            Some("turn-349".into()),
            t_start,
        );
        reg.record_mutation(
            "sprig",
            MutationKind::Message,
            "tool_call:Shell",
            t_tool,
        );
        let first_mtime = std::fs::metadata(&status_path)
            .expect("running status file")
            .modified()
            .expect("running mtime");

        std::thread::sleep(Duration::from_millis(20));

        reg.touch_alive("sprig", t_tick);
        let emitted = reg.tick("sprig", t_tick).expect("running cadence emit");
        let second_mtime = std::fs::metadata(&status_path)
            .expect("refreshed status file")
            .modified()
            .expect("refreshed mtime");

        assert_eq!(emitted.state, HeartbeatState::Running);
        assert_eq!(emitted.phase, "running");
        assert_eq!(emitted.turn_id.as_deref(), Some("turn-349"));
        assert_eq!(emitted.elapsed_in_phase_secs, 95);
        assert_eq!(emitted.last_mutation_at, Some(system_time_secs(t_tool)));
        assert!(
            second_mtime > first_mtime,
            "in-flight cadence tick must rewrite the status file even without a new mutation"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Cron/notify keys stay excluded: emit_initial must not write for them.
    #[test]
    fn startup_emit_skips_cron_notify_identity() {
        let dir = std::env::temp_dir().join(format!(
            "buzz-acp-wo148-cron-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let status_path = dir.join("cron.json");

        let mut reg = HeartbeatRegistry::with_defaults();
        reg.set_status_path(&status_path);
        reg.register_identity("cron.key", IdentityClass::CronNotify, t0());
        assert!(reg.emit_initial("cron.key", t0()).is_none());
        assert!(!status_path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
