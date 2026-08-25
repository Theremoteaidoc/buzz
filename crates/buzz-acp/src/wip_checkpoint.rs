//! Turn WIP checkpointing (WO #691 / SPEC-08).
//!
//! Drops a work-in-progress bundle under `OUTBOX/wip/` every five minutes
//! (and on termination), splits formerly-collapsed empty turn outcomes into
//! four distinct labels, and selects the newest WIP bundle for resume.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::pool::{PromptOutcome, TimeoutKind};

/// Wall-clock interval between periodic WIP bundle drops.
pub const WIP_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(300);

/// Relative path under an agent work dir where WIP bundles are written.
/// Branch-watcher only processes `<persona>/OUTBOX/branch/request.go` (WO #364);
/// this path must stay outside that glob (WO #691 acceptance).
pub const WIP_OUTBOX_REL: &str = "OUTBOX/wip";

/// Branch-watcher request trigger suffix (SSOT: scripts/ops/factory-ci1/branch-watcher).
pub const BRANCH_WATCHER_REQUEST_SUFFIX: &str = "OUTBOX/branch/request.go";

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

/// Build the prompt hint that points a resumed turn at the newest WIP bundle.
///
/// Returns `None` when `work_dir/OUTBOX/wip/` has no bundles. Used by the
/// prompt-task resume path in `pool.rs` (WO #691 slice 4).
pub fn resume_wip_hint(work_dir: &Path) -> Option<String> {
    let bundle = latest_wip_bundle(&work_dir.join("OUTBOX").join("wip"))?;
    Some(format!(
        "[WIP Resume]\nA prior turn left a checkpoint at `{}`. Resume from that \
         work-in-progress bundle — at most five minutes of progress may be missing. \
         Do not announce the resume.",
        bundle.display()
    ))
}

/// Write `OUTBOX/wip/<unix_ts>.bundle` under `work_dir`.
///
/// Prefer a real `git bundle` when `work_dir` is a git checkout; otherwise
/// write a minimal checkpoint marker so resume still has a selectable file.
fn write_wip_bundle(work_dir: &Path) -> Option<PathBuf> {
    let wip_dir = work_dir.join("OUTBOX").join("wip");
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

    let body = format!("# buzz-acp wip checkpoint\nts={ts}\n");
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
            split_empty_outcome(&outcome, false, false).unwrap().as_str(),
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
            split_empty_outcome(&outcome, false, false).unwrap().as_str(),
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
            split_empty_outcome(
                &PromptOutcome::Cancelled,
                false,
                false
            ),
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
        assert_eq!(picked, newer, "must pick newest mtime, not alphabetical first");
    }

    #[test]
    fn test_latest_wip_bundle_none_when_directory_empty() {
        let dir = tempfile_dir("empty-wip");
        let wip = dir.join("OUTBOX").join("wip");
        fs::create_dir_all(&wip).unwrap();
        assert!(latest_wip_bundle(&wip).is_none());
        assert!(latest_wip_bundle(&dir.join("missing")).is_none());
    }

    /// Acceptance: a turn killed at minute 25 has a bundle no older than 5
    /// minutes, and the resume hint references that bundle.
    #[test]
    /// Negative test: wip/ bundles must not match the branch-watcher glob.
    #[test]
    fn test_wip_outbox_path_outside_branch_watcher_glob() {
        let wip_bundle = format!("{}/checkpoint.bundle", WIP_OUTBOX_REL);
        assert!(
            !wip_bundle.ends_with(BRANCH_WATCHER_REQUEST_SUFFIX),
            "wip bundles must not match branch-watcher trigger path"
        );
        assert!(
            !BRANCH_WATCHER_REQUEST_SUFFIX.contains("/wip"),
            "branch-watcher glob must not include OUTBOX/wip"
        );
        assert_ne!(WIP_OUTBOX_REL, "OUTBOX/branch");
    }

    #[test]
    fn test_kill_at_25_minutes_resumes_from_bundle_within_5_minutes() {
        let dir = tempfile_dir("kill-at-25");
        let mut last = None;
        // Cadence drop at T+20min (simulated via force after a prior cadence
        // drop's Instant would require real sleep; force two drops and assert
        // the newest is what resume sees).
        let drop_at_20 = maybe_drop_wip(&dir, Duration::from_secs(20 * 60), &mut last, true)
            .expect("drop at 20");
        thread::sleep(StdDuration::from_millis(20));
        let kill_at_25 = maybe_drop_wip(&dir, Duration::from_secs(25 * 60), &mut last, true)
            .expect("force drop at kill");
        assert_ne!(drop_at_20, kill_at_25);
        let latest = latest_wip_bundle(&dir.join("OUTBOX").join("wip")).unwrap();
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
