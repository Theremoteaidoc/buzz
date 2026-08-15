//! Integration tests for the out-of-process liveness watcher (WO #135 / #145).
//!
//! Tripwires:
//! 1. Starve mtime + inactive/failed unit → `dead` (corroborated death).
//! 2. Starve mtime + active unit → `stale`, never `dead` (WO #145 regression).
//! 3. Starve mtime + undetermined unit → `unknown`, never `dead`.
//! 4. Inactive/failed units remain on the roster and can be reported `dead`.
//! 5. Active roster seat with no status file → loud `unknown` alarm.
//! 6. Negative check: watcher never mentions the in-process alive-refresh symbol.
//! 7. dead_after strictly greater than stall_after.
//! 8. Future status-file mtime → Unknown (not Healthy); is_alarm().

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use buzz_acp::{
    build_report, evaluate_mtime, parse_systemctl_roster, watcher_dead_after, ExternalLiveness,
    RosterSeat, UnitState, STALL_AFTER_DEFAULT,
};

fn t0() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn seat(unit: &str, name: &str, state: UnitState) -> RosterSeat {
    RosterSeat {
        unit: unit.into(),
        seat: name.into(),
        unit_state: state,
    }
}

fn watcher_impl_sources() -> Vec<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    vec![
        manifest.join("src/liveness_watcher.rs"),
        manifest.join("src/bin/liveness_watcher.rs"),
    ]
}

#[test]
fn wedge_detection_starved_mtime_inactive_unit_declares_dead() {
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

    let roster = vec![seat(
        "buzz-agent@codex.service",
        "codex",
        UnitState::InactiveOrFailed,
    )];
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
        "expected dead after starved mtime + inactive unit, got {:?}",
        report.seats[0].verdict
    );
    assert!(report.seats[0].alarm);
    assert_eq!(report.alarm_count, 1);

    let v = evaluate_mtime(
        Some(t0()),
        UnitState::InactiveOrFailed,
        t0() + dead_after + Duration::from_secs(1),
        dead_after,
    );
    assert!(matches!(v, ExternalLiveness::Dead { .. }));
}

/// WO #145 primary regression: idle-but-healthy seats must never page as Dead.
#[test]
fn stale_mtime_active_unit_is_stale_never_dead() {
    let dead_after = watcher_dead_after();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Codex.json");
    fs::write(&path, br#"[{"agent":"Codex","state":"running"}]"#).unwrap();
    let status = Command::new("touch")
        .args(["-d", "1970-01-01 00:00:01 UTC", path.to_str().unwrap()])
        .status()
        .expect("touch");
    assert!(status.success());

    let roster = vec![seat(
        "buzz-agent@codex.service",
        "codex",
        UnitState::Active,
    )];
    let report = build_report(
        "seascope-ci-1",
        dir.path(),
        &roster,
        SystemTime::now(),
        dead_after,
    );

    assert_eq!(report.seats.len(), 1);
    assert!(
        matches!(report.seats[0].verdict, ExternalLiveness::Stale { .. }),
        "active+starved must be Stale, got {:?}",
        report.seats[0].verdict
    );
    assert_ne!(report.seats[0].verdict.as_str(), "dead");
    assert!(!report.seats[0].alarm);
    assert_eq!(report.alarm_count, 0);

    let v = evaluate_mtime(
        Some(t0()),
        UnitState::Active,
        t0() + dead_after + Duration::from_secs(1),
        dead_after,
    );
    assert_eq!(v, ExternalLiveness::Stale { age_secs: 226 });
    assert!(!v.is_alarm());
}

#[test]
fn unit_state_unavailable_is_unknown_not_dead() {
    let dead_after = watcher_dead_after();
    let v = evaluate_mtime(
        Some(t0()),
        UnitState::Undetermined,
        t0() + dead_after + Duration::from_secs(1),
        dead_after,
    );
    assert_eq!(v, ExternalLiveness::Unknown);
    assert_ne!(v.as_str(), "dead");
    assert!(v.is_alarm());
}

#[test]
fn inactive_failed_units_stay_on_roster_and_can_report_dead() {
    // Second half of #145: active-only roster made true-dead seats invisible.
    let stdout = "\
buzz-agent@codex.service     loaded active running
buzz-agent@hermes.service    loaded failed failed
buzz-agent@firstmate.service loaded inactive dead
buzz-orchestrator.service    loaded active running
";
    let roster = parse_systemctl_roster(stdout);
    assert!(
        roster.iter().any(|r| r.seat == "hermes"
            && r.unit_state == UnitState::InactiveOrFailed),
        "failed hermes must remain on roster: {roster:?}"
    );
    assert!(
        roster.iter().any(|r| r.seat == "firstmate"
            && r.unit_state == UnitState::InactiveOrFailed),
        "inactive firstmate must remain on roster: {roster:?}"
    );

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hermes.json");
    fs::write(&path, b"[]").unwrap();
    let status = Command::new("touch")
        .args(["-d", "1970-01-01 00:00:01 UTC", path.to_str().unwrap()])
        .status()
        .expect("touch");
    assert!(status.success());

    let report = build_report(
        "seascope-ci-1",
        dir.path(),
        &roster,
        SystemTime::now(),
        watcher_dead_after(),
    );
    let hermes = report
        .seats
        .iter()
        .find(|s| s.seat == "hermes")
        .expect("hermes must be enumerated");
    assert!(
        matches!(hermes.verdict, ExternalLiveness::Dead { .. }),
        "inactive/failed + starved must report Dead, got {:?}",
        hermes.verdict
    );
    assert!(hermes.alarm);
}

#[test]
fn future_mtime_is_unknown_alarms_not_healthy() {
    let dead_after = watcher_dead_after();
    let now = t0();
    let future_mtime = t0() + Duration::from_secs(3_600);
    let v = evaluate_mtime(Some(future_mtime), UnitState::Active, now, dead_after);
    assert_eq!(v, ExternalLiveness::Unknown);
    assert_ne!(v.as_str(), "healthy");
    assert!(v.is_alarm());

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Codex.json");
    fs::write(&path, br#"[{"agent":"Codex","state":"running"}]"#).unwrap();
    let status = Command::new("touch")
        .args(["-d", "2099-01-01 00:00:00 UTC", path.to_str().unwrap()])
        .status()
        .expect("touch");
    assert!(status.success());

    let roster = vec![seat(
        "buzz-agent@codex.service",
        "codex",
        UnitState::Active,
    )];
    let report = build_report(
        "seascope-ci-1",
        dir.path(),
        &roster,
        SystemTime::now(),
        dead_after,
    );
    assert_eq!(report.seats.len(), 1);
    assert_eq!(report.seats[0].verdict, ExternalLiveness::Unknown);
    assert_ne!(report.seats[0].verdict.as_str(), "healthy");
    assert!(report.seats[0].alarm);
    assert!(report.seats[0].verdict.is_alarm());
    assert_eq!(report.alarm_count, 1);
}

#[test]
fn active_unit_with_no_heartbeat_file_alarms_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let roster = vec![
        seat("buzz-agent@hermes.service", "hermes", UnitState::Active),
        seat(
            "buzz-orchestrator.service",
            "orchestrator",
            UnitState::Active,
        ),
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
    for seat_obs in &report.seats {
        assert_eq!(
            seat_obs.verdict,
            ExternalLiveness::Unknown,
            "seat {} must be unknown, got {:?}",
            seat_obs.seat,
            seat_obs.verdict
        );
        assert!(seat_obs.alarm);
        assert_ne!(seat_obs.verdict.as_str(), "healthy");
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
    assert_eq!(dead, Duration::from_secs(225));
}
