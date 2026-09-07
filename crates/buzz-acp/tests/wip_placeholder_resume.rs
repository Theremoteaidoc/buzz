//! WO #1093 — placeholder WIP checkpoints must not wedge seats in a resume loop.
//!
//! Tripwires:
//! 1. Ox-shaped 40-byte fixture is archived, never surfaced as `[WIP Resume]` (AC1/AC3).
//! 2. Two consecutive `killed_idle` outcomes force-skip WIP resume and yield exactly
//!    one channel notice string (AC2).

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use buzz_acp::{
    decide_wip_resume, is_placeholder_checkpoint, resume_wip_hint, wip_idle_skip_notice,
    IdleKillTracker, WipResumeDecision, PLACEHOLDER_MAX_BYTES, WIP_CHECKPOINT_HEADER,
};
use uuid::Uuid;

fn tempfile_dir(label: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "buzz-acp-wo1093-{}-{}-{}",
        label,
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// AC1/AC3: fixture matching Ox's 109 archived placeholders is never resumed.
#[test]
fn placeholder_fixture_archived_not_resumed() {
    let dir = tempfile_dir("fixture");
    let wip = dir.join("OUTBOX").join("wip");
    fs::create_dir_all(&wip).unwrap();
    let bundle = wip.join("1788281363-666978601.bundle");
    let body = format!("{WIP_CHECKPOINT_HEADER}\nts=1788281363\n");
    assert_eq!(body.len(), 40, "must match Ox 40-byte placeholder shape");
    fs::write(&bundle, &body).unwrap();

    assert!(is_placeholder_checkpoint(&bundle));
    assert!(
        resume_wip_hint(&dir).is_none(),
        "placeholder must not produce a [WIP Resume] hint"
    );
    assert!(!bundle.exists());

    let archive_dirs: Vec<_> = fs::read_dir(dir.join("OUTBOX"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("wip-archive-"))
        })
        .collect();
    assert_eq!(archive_dirs.len(), 1);
    let archived = archive_dirs[0].join("1788281363-666978601.bundle");
    assert_eq!(fs::read_to_string(archived).unwrap(), body);
}

/// AC2: after 2 consecutive killed_idle, decide yields exactly one skip notice.
#[test]
fn two_consecutive_killed_idle_skips_once_with_one_notice() {
    let dir = tempfile_dir("idle-skip");
    let wip = dir.join("OUTBOX").join("wip");
    fs::create_dir_all(&wip).unwrap();
    let bundle = wip.join("real.bundle");
    fs::write(&bundle, vec![b'R'; PLACEHOLDER_MAX_BYTES as usize + 8]).unwrap();

    let channel = Uuid::from_u128(0xdead_beef_cafe_u128);
    let mut tracker = IdleKillTracker::new();
    let agent = 0usize;

    tracker.record(agent, channel, true);
    assert!(matches!(
        decide_wip_resume(&dir, &mut tracker, agent, Some(channel)),
        WipResumeDecision::Resume(_)
    ));

    tracker.record(agent, channel, true);
    let mut notices: Vec<String> = Vec::new();
    match decide_wip_resume(&dir, &mut tracker, agent, Some(channel)) {
        WipResumeDecision::SkipAfterIdleKills { notice } => {
            notices.push(notice);
        }
        other => panic!("expected SkipAfterIdleKills, got {other:?}"),
    }
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0], wip_idle_skip_notice(2));

    // Counter cleared — no second notice on the following decide.
    match decide_wip_resume(&dir, &mut tracker, agent, Some(channel)) {
        WipResumeDecision::Resume(_) => {}
        other => panic!("expected Resume after skip reset, got {other:?}"),
    }
    assert!(tracker.take_skip(agent, channel).is_none());
}
