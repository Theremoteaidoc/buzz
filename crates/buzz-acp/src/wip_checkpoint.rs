//! Turn WIP checkpointing (WO #691 / SPEC-08 / WO #1093).
//!
//! Drops a work-in-progress bundle under `OUTBOX/wip/` every five minutes
//! (and on termination), splits formerly-collapsed empty turn outcomes into
//! four distinct labels, and selects the newest WIP bundle for resume.
//!
//! WO #1093: placeholder checkpoints (bare `# buzz-acp wip checkpoint` markers)
//! are archived instead of resumed, and two consecutive `killed_idle` outcomes
//! for the same seat/channel force-skip WIP resume with a one-line channel notice.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use crate::pool::{PromptOutcome, TimeoutKind};

/// Wall-clock interval between periodic WIP bundle drops.
pub const WIP_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(300);

/// Relative path under an agent work dir where WIP bundles are written.
/// Branch-watcher only processes `<persona>/OUTBOX/branch/request.go` (WO #364);
/// this path must stay outside that glob (WO #691 acceptance).
pub const WIP_OUTBOX_REL: &str = "OUTBOX/wip";

/// Branch-watcher request trigger suffix (SSOT: scripts/ops/factory-ci1/branch-watcher).
pub const BRANCH_WATCHER_REQUEST_SUFFIX: &str = "OUTBOX/branch/request.go";

/// Marker header written by [`write_wip_bundle`] when a real `git bundle` is unavailable.
pub const WIP_CHECKPOINT_HEADER: &str = "# buzz-acp wip checkpoint";

/// Size floor for a resumable checkpoint (WO #1093 AC1). Bundles strictly under
/// this many bytes are treated as placeholders and archived, never resumed.
pub const PLACEHOLDER_MAX_BYTES: u64 = 1024;

/// Consecutive `killed_idle` outcomes before the next turn force-skips WIP resume
/// (WO #1093 AC2).
pub const IDLE_KILL_SKIP_THRESHOLD: u32 = 2;

/// Refined empty-turn cause. Replaces the collapsed `returned_empty` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyOutcomeKind {
    /// Hard wall-clock turn cap fired ([`TimeoutKind::Hard`]).
    KilledTurnCap,
    /// Idle (no ACP activity) timeout fired ([`TimeoutKind::Idle`]).
    KilledIdle,
    /// Agent process exited or returned a transport/protocol error.
    Crashed,
    /// ACP-ok turn with neither durable message nor file.
    Empty,
}

impl EmptyOutcomeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KilledTurnCap => "killed_turn_cap",
            Self::KilledIdle => "killed_idle",
            Self::Crashed => "crashed",
            Self::Empty => "empty",
        }
    }
}

/// Classify a terminal [`PromptOutcome`] into an empty-outcome kind.
///
/// Returns `None` for non-empty outcomes (`Ok` with a produced message/file,
/// `Cancelled`, `CancelDrainTimeout`). Pure — no I/O.
pub fn split_empty_outcome(
    outcome: &PromptOutcome,
    produced_message: bool,
    produced_file: bool,
) -> Option<EmptyOutcomeKind> {
    match outcome {
        PromptOutcome::Timeout(TimeoutKind::Hard { .. }) => Some(EmptyOutcomeKind::KilledTurnCap),
        PromptOutcome::Timeout(TimeoutKind::Idle) => Some(EmptyOutcomeKind::KilledIdle),
        PromptOutcome::AgentExited | PromptOutcome::Error(_) => Some(EmptyOutcomeKind::Crashed),
        PromptOutcome::Ok(_) => {
            if produced_message || produced_file {
                None
            } else {
                Some(EmptyOutcomeKind::Empty)
            }
        }
        PromptOutcome::Cancelled | PromptOutcome::CancelDrainTimeout(_) => None,
    }
}

/// Drop a WIP bundle under `work_dir/OUTBOX/wip/<unix_ts>.bundle` when due.
///
/// Cadence:
/// - first drop: `elapsed` since turn start ≥ [`WIP_CHECKPOINT_INTERVAL`]
/// - later drops: wall time since `*last_drop` ≥ [`WIP_CHECKPOINT_INTERVAL`]
/// - `force` (termination signal): always drop, regardless of elapsed
///
/// Updates `*last_drop` on a successful drop. Returns the bundle path.
pub fn maybe_drop_wip(
    work_dir: &Path,
    elapsed: Duration,
    last_drop: &mut Option<Instant>,
    force: bool,
) -> Option<PathBuf> {
    let should_drop = if force {
        true
    } else {
        match *last_drop {
            None => elapsed >= WIP_CHECKPOINT_INTERVAL,
            Some(prev) => Instant::now().saturating_duration_since(prev) >= WIP_CHECKPOINT_INTERVAL,
        }
    };
    if !should_drop {
        return None;
    }

    let path = write_wip_bundle(work_dir)?;
    *last_drop = Some(Instant::now());
    Some(path)
}

/// Select the newest `*.bundle` under `wip_dir` by mtime (not alphabetical).
pub fn latest_wip_bundle(wip_dir: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(wip_dir).ok()?;
    let mut best: Option<(PathBuf, SystemTime)> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("bundle") {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(UNIX_EPOCH);
        match &best {
            None => best = Some((path, modified)),
            Some((_, best_mtime)) if modified > *best_mtime => best = Some((path, modified)),
            _ => {}
        }
    }
    best.map(|(p, _)| p)
}

/// Decision for the next turn's WIP-resume path (WO #1093).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WipResumeDecision {
    /// Insert this hint at the front of prompt sections.
    Resume(String),
    /// Skip resume; caller must post `notice` exactly once to the channel.
    SkipAfterIdleKills { notice: String },
    /// No WIP to resume and no skip notice.
    None,
}

/// Per-seat/channel consecutive `killed_idle` streak (WO #1093 AC2).
///
/// Survives agent respawn when held outside the agent process (e.g. shared via
/// [`crate::pool::PromptContext`]).
#[derive(Debug, Default, Clone)]
pub struct IdleKillTracker {
    /// `(agent_index, channel_id)` → consecutive killed_idle count.
    streaks: HashMap<(usize, Uuid), u32>,
}

impl IdleKillTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a turn outcome for `(agent, channel)`. Returns the new streak.
    ///
    /// Non-`killed_idle` outcomes clear the streak for that pairing.
    pub fn record(&mut self, agent_index: usize, channel: Uuid, killed_idle: bool) -> u32 {
        let key = (agent_index, channel);
        if killed_idle {
            let entry = self.streaks.entry(key).or_insert(0);
            *entry = entry.saturating_add(1);
            *entry
        } else {
            self.streaks.remove(&key);
            0
        }
    }

    /// If the pairing has reached [`IDLE_KILL_SKIP_THRESHOLD`], clear it and
    /// return the streak so the caller can post exactly one skip notice.
    pub fn take_skip(&mut self, agent_index: usize, channel: Uuid) -> Option<u32> {
        let key = (agent_index, channel);
        match self.streaks.get(&key).copied() {
            Some(n) if n >= IDLE_KILL_SKIP_THRESHOLD => {
                self.streaks.remove(&key);
                Some(n)
            }
            _ => None,
        }
    }

    /// Current streak for tests / diagnostics.
    pub fn streak(&self, agent_index: usize, channel: Uuid) -> u32 {
        self.streaks
            .get(&(agent_index, channel))
            .copied()
            .unwrap_or(0)
    }
}

/// One-line channel notice when WIP resume is force-skipped (WO #1093 AC2).
pub fn wip_idle_skip_notice(consecutive: u32) -> String {
    format!(
        "resuming from queue, WIP resume skipped after {consecutive} consecutive idle-kills"
    )
}

/// True when `path` is a bare placeholder checkpoint (WO #1093 AC1).
///
/// A checkpoint is a placeholder when either:
/// - its size is strictly under [`PLACEHOLDER_MAX_BYTES`], or
/// - its body is only the [`WIP_CHECKPOINT_HEADER`] line plus `ts=<digits>` lines.
pub fn is_placeholder_checkpoint(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        // Unreadable → treat as unusable (do not resume).
        return true;
    };
    if meta.len() < PLACEHOLDER_MAX_BYTES {
        return true;
    }
    match fs::read_to_string(path) {
        Ok(body) => is_header_only_checkpoint_body(&body),
        Err(_) => false,
    }
}

/// True when `body` is only the checkpoint header plus `ts=` lines (no WIP payload).
pub fn is_header_only_checkpoint_body(body: &str) -> bool {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return true;
    }
    let mut lines = trimmed.lines().filter(|l| !l.trim().is_empty());
    match lines.next() {
        Some(first) if first.trim() == WIP_CHECKPOINT_HEADER => {}
        _ => return false,
    }
    for line in lines {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("ts=") else {
            return false;
        };
        if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    true
}

/// Move `bundle` into `work_dir/OUTBOX/wip-archive-<UTC>/` (Ox incident shape).
///
/// Returns the destination path on success.
pub fn archive_wip_bundle(work_dir: &Path, bundle: &Path) -> Option<PathBuf> {
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let dest_dir = work_dir
        .join("OUTBOX")
        .join(format!("wip-archive-{stamp}"));
    fs::create_dir_all(&dest_dir).ok()?;
    let name = bundle.file_name()?;
    let dest = dest_dir.join(name);
    match fs::rename(bundle, &dest) {
        Ok(()) => Some(dest),
        Err(_) => {
            // Cross-device fallback.
            fs::copy(bundle, &dest).ok()?;
            fs::remove_file(bundle).ok()?;
            Some(dest)
        }
    }
}

/// Build the prompt hint that points a resumed turn at the newest WIP bundle.
///
/// Returns `None` when `work_dir/OUTBOX/wip/` has no resumable bundles. Placeholder
/// checkpoints are archived (WO #1093 AC1) and never surface as a resume hint.
/// Used by the prompt-task resume path in `pool.rs` (WO #691 slice 4).
pub fn resume_wip_hint(work_dir: &Path) -> Option<String> {
    let dir = wip_dir(work_dir);
    loop {
        let bundle = latest_wip_bundle(&dir)?;
        if is_placeholder_checkpoint(&bundle) {
            if archive_wip_bundle(work_dir, &bundle).is_none() {
                // Archive failed — delete so we cannot loop forever on a stuck file.
                let _ = fs::remove_file(&bundle);
            }
            continue;
        }
        return Some(format!(
            "[WIP Resume]\nA prior turn left a checkpoint at `{}`. Resume from that \
             work-in-progress bundle — at most five minutes of progress may be missing. \
             Do not announce the resume.",
            bundle.display()
        ));
    }
}

/// Plan WIP resume for the next turn (WO #1093).
///
/// When `channel` is set and the idle-kill streak has reached the skip threshold,
/// returns [`WipResumeDecision::SkipAfterIdleKills`] and clears the streak.
/// Otherwise archives placeholders and optionally returns a resume hint.
pub fn decide_wip_resume(
    work_dir: &Path,
    tracker: &mut IdleKillTracker,
    agent_index: usize,
    channel: Option<Uuid>,
) -> WipResumeDecision {
    if let Some(ch) = channel {
        if let Some(n) = tracker.take_skip(agent_index, ch) {
            return WipResumeDecision::SkipAfterIdleKills {
                notice: wip_idle_skip_notice(n),
            };
        }
    }
    match resume_wip_hint(work_dir) {
        Some(hint) => WipResumeDecision::Resume(hint),
        None => WipResumeDecision::None,
    }
}

/// True when `rel` is the branch-watcher trigger path (not a WIP bundle path).
///
/// Negative-acceptance helper for WO #691: WIP drops must never match this.
pub fn is_branch_watcher_request(rel: &str) -> bool {
    rel.ends_with(BRANCH_WATCHER_REQUEST_SUFFIX)
}

/// Resolve `work_dir/OUTBOX/wip` using [`WIP_OUTBOX_REL`] (keeps the const live
/// outside `cfg(test)` so Windows `-D warnings` stays green).
fn wip_dir(work_dir: &Path) -> PathBuf {
    // Split on `/` so Windows does not embed a literal slash component.
    WIP_OUTBOX_REL
        .split('/')
        .fold(work_dir.to_path_buf(), |acc, part| acc.join(part))
}

/// Write `OUTBOX/wip/<unix_ts>.bundle` under `work_dir`.
///
/// Prefer a real `git bundle` when `work_dir` is a git checkout; otherwise
/// write a minimal checkpoint marker so resume still has a selectable file.
fn write_wip_bundle(work_dir: &Path) -> Option<PathBuf> {
    let wip_dir = wip_dir(work_dir);
    fs::create_dir_all(&wip_dir).ok()?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Uniquify within the same second so rapid force+cadence tests don't collide.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let path = wip_dir.join(format!("{ts}-{nanos}.bundle"));

    if work_dir.join(".git").exists() {
        let status = std::process::Command::new("git")
            .args(["bundle", "create"])
            .arg(&path)
            .arg("HEAD")
            .current_dir(work_dir)
            .status();
        if matches!(status, Ok(s) if s.success()) {
            return Some(path);
        }
        // Fall through to marker if git bundle fails (no commits, etc.).
        let _ = fs::remove_file(&path);
    }

    let body = format!("{WIP_CHECKPOINT_HEADER}\nts={ts}\n");
    fs::write(&path, body).ok()?;
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acp::{AcpError, StopReason};
    use std::io::Write;
    use std::thread;
    use std::time::Duration as StdDuration;

    #[test]
    fn test_split_empty_outcome_hard_timeout_is_killed_turn_cap() {
        let outcome = PromptOutcome::Timeout(TimeoutKind::Hard {
            recently_active: false,
        });
        assert_eq!(
            split_empty_outcome(&outcome, false, false),
            Some(EmptyOutcomeKind::KilledTurnCap)
        );
        assert_eq!(
            split_empty_outcome(&outcome, false, false)
                .unwrap()
                .as_str(),
            "killed_turn_cap"
        );
    }

    #[test]
    fn test_split_empty_outcome_idle_timeout_is_killed_idle() {
        let outcome = PromptOutcome::Timeout(TimeoutKind::Idle);
        assert_eq!(
            split_empty_outcome(&outcome, false, false),
            Some(EmptyOutcomeKind::KilledIdle)
        );
        assert_eq!(
            split_empty_outcome(&outcome, false, false)
                .unwrap()
                .as_str(),
            "killed_idle"
        );
    }

    #[test]
    fn test_split_empty_outcome_agent_exited_is_crashed() {
        assert_eq!(
            split_empty_outcome(&PromptOutcome::AgentExited, false, false),
            Some(EmptyOutcomeKind::Crashed)
        );
        assert_eq!(
            split_empty_outcome(
                &PromptOutcome::Error(AcpError::Protocol("boom".into())),
                false,
                false
            ),
            Some(EmptyOutcomeKind::Crashed)
        );
        assert_eq!(EmptyOutcomeKind::Crashed.as_str(), "crashed");
    }

    #[test]
    fn test_split_empty_outcome_ok_no_output_is_empty() {
        assert_eq!(
            split_empty_outcome(&PromptOutcome::Ok(StopReason::EndTurn), false, false),
            Some(EmptyOutcomeKind::Empty)
        );
        assert_eq!(EmptyOutcomeKind::Empty.as_str(), "empty");
    }

    #[test]
    fn test_split_empty_outcome_ok_with_message_is_none() {
        assert_eq!(
            split_empty_outcome(&PromptOutcome::Ok(StopReason::EndTurn), true, false),
            None
        );
        assert_eq!(
            split_empty_outcome(&PromptOutcome::Ok(StopReason::EndTurn), false, true),
            None
        );
        assert_eq!(
            split_empty_outcome(&PromptOutcome::Cancelled, false, false),
            None
        );
        assert_eq!(
            split_empty_outcome(
                &PromptOutcome::CancelDrainTimeout(StdDuration::from_secs(5)),
                false,
                false
            ),
            None
        );
    }

    #[test]
    fn test_maybe_drop_wip_fires_at_five_minutes() {
        let dir = tempfile_dir("drop-at-five");
        let mut last = None;
        let path = maybe_drop_wip(&dir, WIP_CHECKPOINT_INTERVAL, &mut last, false);
        assert!(path.is_some(), "expected drop at five minutes");
        assert!(path.unwrap().exists());
        assert!(last.is_some());
    }

    #[test]
    fn test_maybe_drop_wip_does_not_fire_before_five_minutes() {
        let dir = tempfile_dir("drop-before-five");
        let mut last = None;
        let path = maybe_drop_wip(
            &dir,
            WIP_CHECKPOINT_INTERVAL - StdDuration::from_secs(1),
            &mut last,
            false,
        );
        assert!(path.is_none());
        assert!(last.is_none());
        assert!(latest_wip_bundle(&dir.join("OUTBOX").join("wip")).is_none());
    }

    #[test]
    fn test_maybe_drop_wip_fires_on_termination_signal_regardless_of_elapsed() {
        let dir = tempfile_dir("drop-on-term");
        let mut last = None;
        let path = maybe_drop_wip(&dir, StdDuration::from_secs(1), &mut last, true);
        assert!(path.is_some(), "termination must force a drop");
        assert!(path.unwrap().exists());
    }

    #[test]
    fn test_latest_wip_bundle_picks_newest_not_alphabetical_first() {
        let dir = tempfile_dir("newest-bundle");
        let wip = dir.join("OUTBOX").join("wip");
        fs::create_dir_all(&wip).unwrap();
        // Alphabetical first would be "aaa.bundle"; newest by mtime is "zzz.bundle"
        // written second with a sleep so mtimes differ.
        let older = wip.join("zzz.bundle");
        let newer = wip.join("aaa.bundle");
        fs::write(&older, b"older").unwrap();
        thread::sleep(StdDuration::from_millis(20));
        fs::write(&newer, b"newer").unwrap();
        let picked = latest_wip_bundle(&wip).expect("bundle");
        assert_eq!(
            picked, newer,
            "must pick newest mtime, not alphabetical first"
        );
    }

    #[test]
    fn test_latest_wip_bundle_none_when_directory_empty() {
        let dir = tempfile_dir("empty-wip");
        let wip = dir.join("OUTBOX").join("wip");
        fs::create_dir_all(&wip).unwrap();
        assert!(latest_wip_bundle(&wip).is_none());
        assert!(latest_wip_bundle(&dir.join("missing")).is_none());
    }

    /// Negative test: wip/ bundles must not match the branch-watcher glob.
    #[test]
    fn test_wip_outbox_path_outside_branch_watcher_glob() {
        let wip_bundle = format!("{}/checkpoint.bundle", WIP_OUTBOX_REL);
        assert!(
            !is_branch_watcher_request(&wip_bundle),
            "wip bundles must not match branch-watcher trigger path"
        );
        assert!(
            is_branch_watcher_request(BRANCH_WATCHER_REQUEST_SUFFIX),
            "canonical request.go path must match"
        );
        assert!(
            !BRANCH_WATCHER_REQUEST_SUFFIX.contains("/wip"),
            "branch-watcher glob must not include OUTBOX/wip"
        );
        assert_ne!(WIP_OUTBOX_REL, "OUTBOX/branch");
    }

    /// Acceptance: a turn killed at minute 25 has a bundle no older than 5
    /// minutes, and the resume hint references that bundle.
    ///
    /// Uses a >1 KB payload so WO #1093 placeholder detection does not archive it.
    #[test]
    fn test_kill_at_25_minutes_resumes_from_bundle_within_5_minutes() {
        let dir = tempfile_dir("kill-at-25");
        let wip = dir.join("OUTBOX").join("wip");
        fs::create_dir_all(&wip).unwrap();
        let drop_at_20 = wip.join("drop-at-20.bundle");
        let kill_at_25 = wip.join("kill-at-25.bundle");
        // Real-sized payloads (not placeholder markers).
        let payload = vec![b'x'; PLACEHOLDER_MAX_BYTES as usize + 64];
        fs::write(&drop_at_20, &payload).unwrap();
        thread::sleep(StdDuration::from_millis(20));
        fs::write(&kill_at_25, &payload).unwrap();
        let latest = latest_wip_bundle(&wip).unwrap();
        assert_eq!(latest, kill_at_25);
        let hint = resume_wip_hint(&dir).expect("resume hint");
        assert!(
            hint.contains(kill_at_25.to_string_lossy().as_ref()),
            "resume hint must reference the kill-time bundle: {hint}"
        );
        // Bundle mtime is "now"; within 5 minutes of the kill by construction.
        let age = SystemTime::now()
            .duration_since(
                fs::metadata(&latest)
                    .and_then(|m| m.modified())
                    .unwrap_or(UNIX_EPOCH),
            )
            .unwrap_or_default();
        assert!(
            age < WIP_CHECKPOINT_INTERVAL,
            "bundle age {:?} must be < 5 minutes",
            age
        );
    }

    /// WO #1093 AC1/AC3: Ox-shaped 40-byte placeholder is archived, never resumed.
    #[test]
    fn test_placeholder_fixture_is_archived_not_resumed() {
        let dir = tempfile_dir("placeholder-ox");
        let wip = dir.join("OUTBOX").join("wip");
        fs::create_dir_all(&wip).unwrap();
        let bundle = wip.join("1788281363-666978601.bundle");
        // Byte-for-byte Ox incident shape (40 bytes).
        let body = format!("{WIP_CHECKPOINT_HEADER}\nts=1788281363\n");
        assert_eq!(body.len(), 40, "fixture must match Ox 40-byte shape");
        fs::write(&bundle, &body).unwrap();
        assert!(is_placeholder_checkpoint(&bundle));
        assert!(
            resume_wip_hint(&dir).is_none(),
            "placeholder must not surface as [WIP Resume]"
        );
        assert!(!bundle.exists(), "placeholder must leave OUTBOX/wip/");
        let archives: Vec<_> = fs::read_dir(dir.join("OUTBOX"))
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("wip-archive-"))
            })
            .collect();
        assert_eq!(archives.len(), 1, "exactly one archive dir");
        let archived = archives[0].join("1788281363-666978601.bundle");
        assert!(archived.exists());
        assert_eq!(fs::read_to_string(&archived).unwrap(), body);
    }

    #[test]
    fn test_header_only_body_is_placeholder_even_when_padded_past_1kb() {
        let mut body = format!("{WIP_CHECKPOINT_HEADER}\nts=42\n");
        while body.len() < PLACEHOLDER_MAX_BYTES as usize + 8 {
            body.push('\n');
        }
        assert!(is_header_only_checkpoint_body(&body));
        let dir = tempfile_dir("padded-header");
        let wip = dir.join("OUTBOX").join("wip");
        fs::create_dir_all(&wip).unwrap();
        let bundle = wip.join("padded.bundle");
        fs::write(&bundle, &body).unwrap();
        assert!(is_placeholder_checkpoint(&bundle));
        assert!(resume_wip_hint(&dir).is_none());
    }

    #[test]
    fn test_real_sized_bundle_still_resumes() {
        let dir = tempfile_dir("real-bundle");
        let wip = dir.join("OUTBOX").join("wip");
        fs::create_dir_all(&wip).unwrap();
        let bundle = wip.join("real.bundle");
        let mut payload = b"PACK\nreal git-ish payload\n".to_vec();
        payload.resize(PLACEHOLDER_MAX_BYTES as usize + 32, b'y');
        fs::write(&bundle, &payload).unwrap();
        assert!(!is_placeholder_checkpoint(&bundle));
        let hint = resume_wip_hint(&dir).expect("real bundle resumes");
        assert!(hint.contains("real.bundle"));
        assert!(bundle.exists(), "real bundle must stay in place");
    }

    /// WO #1093 AC2: after 2 consecutive killed_idle, next decide skips + one notice.
    #[test]
    fn test_two_consecutive_killed_idle_force_skips_wip_resume_once() {
        let dir = tempfile_dir("idle-skip");
        let wip = dir.join("OUTBOX").join("wip");
        fs::create_dir_all(&wip).unwrap();
        // Leave a real-sized bundle so skip is not confusable with AC1 archive.
        let bundle = wip.join("real.bundle");
        let payload = vec![b'z'; PLACEHOLDER_MAX_BYTES as usize + 16];
        fs::write(&bundle, &payload).unwrap();

        let channel = Uuid::from_u128(0x_c678_ae42_6b3f_4e3f_9649_5fd3_288f_33bb);
        let agent = 0usize;
        let mut tracker = IdleKillTracker::new();

        assert_eq!(tracker.record(agent, channel, true), 1);
        // Streak 1: still resume.
        match decide_wip_resume(&dir, &mut tracker, agent, Some(channel)) {
            WipResumeDecision::Resume(hint) => assert!(hint.contains("real.bundle")),
            other => panic!("expected Resume at streak=1, got {other:?}"),
        }
        assert_eq!(tracker.streak(agent, channel), 1);

        assert_eq!(tracker.record(agent, channel, true), 2);
        let mut notices = 0u32;
        match decide_wip_resume(&dir, &mut tracker, agent, Some(channel)) {
            WipResumeDecision::SkipAfterIdleKills { notice } => {
                notices += 1;
                assert_eq!(notice, wip_idle_skip_notice(2));
            }
            other => panic!("expected SkipAfterIdleKills at streak=2, got {other:?}"),
        }
        assert_eq!(notices, 1);
        assert_eq!(tracker.streak(agent, channel), 0);

        // Counter reset → resume again; no second notice.
        match decide_wip_resume(&dir, &mut tracker, agent, Some(channel)) {
            WipResumeDecision::Resume(_) => {}
            other => panic!("expected Resume after reset, got {other:?}"),
        }
        assert!(tracker.take_skip(agent, channel).is_none());
        assert!(bundle.exists(), "AC2 skip must not delete a real bundle");
    }

    #[test]
    fn test_non_idle_outcome_clears_streak() {
        let channel = Uuid::from_u128(1);
        let mut tracker = IdleKillTracker::new();
        assert_eq!(tracker.record(0, channel, true), 1);
        assert_eq!(tracker.record(0, channel, false), 0);
        assert_eq!(tracker.streak(0, channel), 0);
        assert!(tracker.take_skip(0, channel).is_none());
    }

    fn tempfile_dir(label: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "buzz-acp-wip-{}-{}-{}",
            label,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        // Touch a sentinel so the dir is non-empty for debugging.
        let mut f = fs::File::create(dir.join(".keep")).unwrap();
        let _ = writeln!(f, "{label}");
        dir
    }
}
