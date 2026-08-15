//! Integration tests for the out-of-process liveness watcher (WO #135).
//!
//! Tripwires:
//! 1. Starve a fake status-file of mtime updates past dead_after → `dead`.
//! 2. Active roster seat with no status file → loud `unknown` alarm.
//! 3. Negative check: watcher implementation never mentions the in-process
//!    alive-refresh symbol that masked B2 on #133.
//! 4. dead_after strictly greater than stall_after.
//! 5. Roster includes buzz-orchestrator.service; directory listing does not
//!    expand the authoritative seat list.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use buzz_acp::{
    build_report, evaluate_mtime, parse_systemctl_roster, watcher_dead_after, ExternalLiveness,
    RosterSeat, STALL_AFTER_DEFAULT,
};

fn t0() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn watcher_impl_sources() -> Vec<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    vec![
        manifest.join("src/liveness_watcher.rs"),
        manifest.join("src/bin/liveness_watcher.rs"),
    ]
}

#[test]
fn wedge_detection_starved_mtime_declares_dead_without_alive_refresh() {
    let dead_after = watcher_dead_after();
    assert!(dead_after > STALL_AFTER_DEFAULT);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Codex.json");
    fs::write(&path, br#"[{"agent":"Codex","state":"running"}]"#).unwrap();
    let status = Command::new("touch")
        .args(["-d", "1970-01-01 00:00:01 UTC", path.to_str().unwrap()])
        .status()
        .expect("touch");
    assert!(status.success());

    let roster = vec![RosterSeat {
        unit: "buzz-agent@codex.service".into(),
        seat: "codex".into(),
    }];
    let report = build_report(
        "seascope-ci-1",
        dir.path(),
        &roster,
        SystemTime::now(),
        dead_after,
    );

    assert_eq!(report.seats.len(), 1);
    assert!(
        matches!(report.seats[0].verdict, ExternalLiveness::Dead { .. }),
        "expected dead after starved mtime, got {:?}",
        report.seats[0].verdict
    );
    assert!(report.seats[0].alarm);
    assert_eq!(report.alarm_count, 1);

    // Same class via injectable clock (no filesystem race).
    let v = evaluate_mtime(
        Some(t0()),
        t0() + dead_after + Duration::from_secs(1),
        dead_after,
    );
    assert!(matches!(v, ExternalLiveness::Dead { .. }));
}

#[test]
fn active_unit_with_no_heartbeat_file_alarms_unknown() {
    let dir = tempfile::tempdir().unwrap();
    // hermes is systemd-active in production with NO heartbeat file — the
    // exact class this tripwire locks. Roster comes from units, not the dir.
    let roster = vec![
        RosterSeat {
            unit: "buzz-agent@hermes.service".into(),
            seat: "hermes".into(),
        },
        RosterSeat {
            unit: "buzz-orchestrator.service".into(),
            seat: "orchestrator".into(),
        },
    ];
    let report = build_report(
        "srv1389530",
        dir.path(),
        &roster,
        SystemTime::now(),
        watcher_dead_after(),
    );

    assert_eq!(report.coverage.scope, "host-local");
    assert_eq!(report.coverage.host, "srv1389530");
    assert!(report
        .coverage
        .authoritative_units
        .iter()
        .any(|u| u == "buzz-orchestrator.service"));
    assert_eq!(report.alarm_count, 2);
    for seat in &report.seats {
        assert_eq!(
            seat.verdict,
            ExternalLiveness::Unknown,
            "seat {} must be unknown, got {:?}",
            seat.seat,
            seat.verdict
        );
        assert!(seat.alarm);
        assert_ne!(seat.verdict.as_str(), "healthy");
    }
}

#[test]
fn roster_includes_orchestrator_and_ignores_stray_heartbeat_files() {
    let stdout = "\
buzz-agent@codex.service   loaded active running
buzz-orchestrator.service  loaded active running
";
    let roster = parse_systemctl_roster(stdout);
    let seats: Vec<_> = roster.iter().map(|r| r.seat.as_str()).collect();
    assert!(seats.contains(&"codex"));
    assert!(
        seats.contains(&"orchestrator"),
        "naive buzz-agent@* glob misses orchestrator — parser must keep it: {seats:?}"
    );

    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("Codex.json"), b"[]").unwrap();
    // Stray file for a seat not on this host's roster must not appear.
    fs::write(dir.path().join("Claude.json"), b"[]").unwrap();

    let report = build_report(
        "seascope-ci-1",
        dir.path(),
        &roster,
        SystemTime::now(),
        watcher_dead_after(),
    );
    assert_eq!(report.seats.len(), 2);
    assert!(!report
        .coverage
        .authoritative_seats
        .iter()
        .any(|s| s == "claude"));
    assert_eq!(report.coverage.scope, "host-local");
}

/// Grepable negative check: watcher impl must not reference the in-process
/// alive-refresh API (the B2 mask). The forbidden token is assembled so this
/// test file itself is not a false positive for a naive repo-wide grep of the
/// same string.
#[test]
fn watcher_impl_never_mentions_alive_refresh_api() {
    let forbidden = format!("{}{}", "touch_", "alive");
    let mut hits = Vec::new();
    for path in watcher_impl_sources() {
        let body = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        for (i, line) in body.lines().enumerate() {
            if line.contains(&forbidden) {
                hits.push(format!("{}:{}: {line}", path.display(), i + 1));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "liveness watcher must not reference {forbidden} (B2).\n{}",
        hits.join("\n")
    );
}

#[test]
fn dead_threshold_strictly_greater_than_stall_after() {
    let dead = watcher_dead_after();
    assert!(
        dead > STALL_AFTER_DEFAULT,
        "dead_after ({dead:?}) must be > stall_after ({STALL_AFTER_DEFAULT:?})"
    );
    // Defaults: 75s cadence × 3 = 225s > 180s stall.
    assert_eq!(dead, Duration::from_secs(225));
}
