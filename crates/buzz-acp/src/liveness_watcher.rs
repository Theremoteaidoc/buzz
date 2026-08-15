//! Out-of-process agent liveness watcher (WO #135).
//!
//! Consumes heartbeat status-file **mtime** from outside any agent's event
//! loop. Declares `dead` when a file goes silent past [`dead_after`], which is
//! strictly greater than [`crate::agent_heartbeat::STALL_AFTER_DEFAULT`].
//!
//! ## Fail-closed roster (merge-gate)
//!
//! Expected seats come from **systemd ground truth** (`buzz-agent@*` plus
//! `buzz-orchestrator.service`), never from listing the heartbeat directory.
//! An active unit with no status file is loud [`ExternalLiveness::Unknown`] —
//! never silently healthy. Absence of a file is not evidence the seat is fine.
//!
//! ## Coverage honesty
//!
//! Each report declares which host and which seats this instance is
//! authoritative for. Heartbeat dirs are host-local; one instance must not
//! imply factory-wide coverage.
//!
//! ## B2 — no in-process alive-refresh
//!
//! This module must never call or import the registry's alive-refresh helper
//! (the in-process tick that masked wedge detection on #133). Wedge detection
//! here is mtime-only, from outside the agent loop.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use serde::Serialize;

use crate::agent_heartbeat::{
    dead_after_for, default_status_path, HEARTBEAT_CADENCE_DEFAULT, STALL_AFTER_DEFAULT,
};

/// Default heartbeat status directory (per-host; not shared across boxes).
pub const DEFAULT_HEARTBEAT_DIR: &str = "/opt/buzz/agents/home/shared/heartbeat";

/// External watcher dead threshold: same formula as the registry, strictly
/// greater than `stall_after` (defaults → 225s > 180s).
pub fn watcher_dead_after() -> Duration {
    dead_after_for(STALL_AFTER_DEFAULT, HEARTBEAT_CADENCE_DEFAULT)
}

/// Verdict for one active seat on this host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalLiveness {
    /// Status file mtime is within `dead_after`.
    Healthy { age_secs: u64 },
    /// Status file exists but mtime silence exceeded `dead_after`.
    Dead { age_secs: u64 },
    /// Active systemd unit with no status file at all — loud alarm.
    Unknown,
}

impl ExternalLiveness {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy { .. } => "healthy",
            Self::Dead { .. } => "dead",
            Self::Unknown => "unknown",
        }
    }

    pub fn is_alarm(&self) -> bool {
        matches!(self, Self::Dead { .. } | Self::Unknown)
    }
}

/// One seat observed by this watcher instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SeatObservation {
    /// Systemd unit name (e. for `buzz-agent@codex.service`).
    pub unit: String,
    /// Seat id derived from the unit (e.g. `codex`, `orchestrator`).
    pub seat: String,
    /// Resolved status path, if a file was found.
    pub status_path: Option<String>,
    pub verdict: ExternalLiveness,
    /// True when humans/agents must treat this as an alarm.
    pub alarm: bool,
}

/// Declares which host/seats this instance covers — never factory-wide by implication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageDeclaration {
    pub host: String,
    /// Scope label. Heartbeat dirs are per-host; always `host-local`.
    pub scope: &'static str,
    pub authoritative_units: Vec<String>,
    pub authoritative_seats: Vec<String>,
}

/// Full one-shot report from the watcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WatcherReport {
    pub host: String,
    pub coverage: CoverageDeclaration,
    pub stall_after_secs: u64,
    pub dead_after_secs: u64,
    pub heartbeat_dir: String,
    pub seats: Vec<SeatObservation>,
    pub alarm_count: usize,
}

impl WatcherReport {
    pub fn has_alarms(&self) -> bool {
        self.alarm_count > 0
    }
}

/// A roster entry from systemd (ground truth), not from the heartbeat dir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterSeat {
    pub unit: String,
    pub seat: String,
}

/// Map a systemd unit name to a roster seat, or `None` if not a watched unit.
///
/// Catches `buzz-agent@*` **and** `buzz-orchestrator.service` explicitly
/// (orchestrator is not under the template glob).
pub fn parse_unit_to_seat(unit: &str) -> Option<RosterSeat> {
    let unit = unit.trim();
    if unit.is_empty() {
        return None;
    }
    let bare = unit.strip_suffix(".service").unwrap_or(unit);

    if bare.eq_ignore_ascii_case("buzz-orchestrator") {
        return Some(RosterSeat {
            unit: format_unit_name(bare),
            seat: "orchestrator".to_string(),
        });
    }

    if let Some(instance) = bare.strip_prefix("buzz-agent@") {
        let seat = instance.trim();
        if seat.is_empty() {
            return None;
        }
        return Some(RosterSeat {
            unit: format_unit_name(bare),
            seat: seat.to_ascii_lowercase(),
        });
    }

    None
}

fn format_unit_name(bare: &str) -> String {
    if bare.ends_with(".service") {
        bare.to_string()
    } else {
        format!("{bare}.service")
    }
}

/// Parse `systemctl list-units --no-legend --plain` style lines into roster seats.
///
/// Only lines that name an active buzz agent / orchestrator unit are kept.
/// Directory listings are never consulted here.
pub fn parse_systemctl_roster(stdout: &str) -> Vec<RosterSeat> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("UNIT") {
            continue;
        }
        let unit_token = line.split_whitespace().next().unwrap_or("");
        if let Some(seat) = parse_unit_to_seat(unit_token) {
            if seen.insert(seat.unit.clone()) {
                out.push(seat);
            }
        }
    }
    out.sort_by(|a, b| a.seat.cmp(&b.seat));
    out
}

/// Evaluate one seat given optional status-file mtime (injectable for tests).
///
/// `status_mtime == None` means the file is absent → [`ExternalLiveness::Unknown`].
pub fn evaluate_mtime(
    status_mtime: Option<SystemTime>,
    now: SystemTime,
    dead_after: Duration,
) -> ExternalLiveness {
    let Some(mtime) = status_mtime else {
        return ExternalLiveness::Unknown;
    };
    let age = now.duration_since(mtime).unwrap_or(Duration::ZERO);
    let age_secs = age.as_secs();
    if age > dead_after {
        ExternalLiveness::Dead { age_secs }
    } else {
        ExternalLiveness::Healthy { age_secs }
    }
}

/// Resolve the status file for a seat under `heartbeat_dir`.
///
/// Looks for a case-insensitive `{seat}.json` match among directory entries.
/// Does **not** invent roster membership from extra files present in the dir.
pub fn resolve_status_path(heartbeat_dir: &Path, seat: &str) -> Option<PathBuf> {
    let want = format!("{seat}.json");
    let entries = fs::read_dir(heartbeat_dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.eq_ignore_ascii_case(&want) {
            return Some(entry.path());
        }
    }
    // Fallback: conventional display-name path (may not exist yet).
    let conventional = default_status_path(&title_case_seat(seat));
    if conventional.parent() == Some(heartbeat_dir) && conventional.is_file() {
        return Some(conventional);
    }
    // Last resort: exact seat spelling under this dir.
    let direct = heartbeat_dir.join(format!("{seat}.json"));
    if direct.is_file() {
        return Some(direct);
    }
    None
}

fn title_case_seat(seat: &str) -> String {
    // firstmate → Firstmate is wrong for FirstMate; prefer known map, else capitalize.
    match seat.to_ascii_lowercase().as_str() {
        "firstmate" => "FirstMate".into(),
        "opencode" => "OpenCode".into(),
        "orchestrator" => "Orchestrator".into(),
        other => {
            let mut c = other.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_ascii_uppercase().to_string() + c.as_str(),
            }
        }
    }
}

fn read_mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).ok()?.modified().ok()
}

/// Build a full report from an injected roster + heartbeat dir + clock.
pub fn build_report(
    host: &str,
    heartbeat_dir: &Path,
    roster: &[RosterSeat],
    now: SystemTime,
    dead_after: Duration,
) -> WatcherReport {
    let authoritative_units: Vec<String> = roster.iter().map(|r| r.unit.clone()).collect();
    let authoritative_seats: Vec<String> = roster.iter().map(|r| r.seat.clone()).collect();

    let mut seats = Vec::with_capacity(roster.len());
    for r in roster {
        let path = resolve_status_path(heartbeat_dir, &r.seat);
        let mtime = path.as_ref().and_then(|p| read_mtime(p));
        let verdict = evaluate_mtime(mtime, now, dead_after);
        let alarm = verdict.is_alarm();
        seats.push(SeatObservation {
            unit: r.unit.clone(),
            seat: r.seat.clone(),
            status_path: path.map(|p| p.display().to_string()),
            verdict,
            alarm,
        });
    }
    seats.sort_by(|a, b| a.seat.cmp(&b.seat));
    let alarm_count = seats.iter().filter(|s| s.alarm).count();

    WatcherReport {
        host: host.to_string(),
        coverage: CoverageDeclaration {
            host: host.to_string(),
            scope: "host-local",
            authoritative_units,
            authoritative_seats,
        },
        stall_after_secs: STALL_AFTER_DEFAULT.as_secs(),
        dead_after_secs: dead_after.as_secs(),
        heartbeat_dir: heartbeat_dir.display().to_string(),
        seats,
        alarm_count,
    }
}

/// Discover active buzz seats via systemd. Fail-closed: command failure → error.
pub fn discover_systemd_roster() -> std::io::Result<Vec<RosterSeat>> {
    // Explicitly name orchestrator so a naive buzz-agent@* glob cannot miss it.
    let output = Command::new("systemctl")
        .args([
            "list-units",
            "buzz-agent@*",
            "buzz-orchestrator.service",
            "--state=active",
            "--no-legend",
            "--plain",
            "--no-pager",
        ])
        .output()?;

    if !output.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "systemctl roster discovery failed (exit {:?}): {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_systemctl_roster(&stdout))
}

/// Local hostname for coverage declaration.
pub fn local_hostname() -> String {
    if let Ok(h) = fs::read_to_string("/etc/hostname") {
        let h = h.trim();
        if !h.is_empty() {
            return h.to_string();
        }
    }
    Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown-host".into())
}

/// Run one probe cycle against the live host (systemd + heartbeat dir).
pub fn run_probe(heartbeat_dir: &Path) -> std::io::Result<WatcherReport> {
    let roster = discover_systemd_roster()?;
    let host = local_hostname();
    let dead_after = watcher_dead_after();
    Ok(build_report(
        &host,
        heartbeat_dir,
        &roster,
        SystemTime::now(),
        dead_after,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn t0() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn dead_after_strictly_exceeds_stall() {
        let dead = watcher_dead_after();
        assert!(dead > STALL_AFTER_DEFAULT);
        assert_eq!(dead, Duration::from_secs(225));
    }

    #[test]
    fn parse_unit_catches_agent_and_orchestrator() {
        let a = parse_unit_to_seat("buzz-agent@codex.service").unwrap();
        assert_eq!(a.seat, "codex");
        assert_eq!(a.unit, "buzz-agent@codex.service");

        let o = parse_unit_to_seat("buzz-orchestrator.service").unwrap();
        assert_eq!(o.seat, "orchestrator");
        assert_eq!(o.unit, "buzz-orchestrator.service");

        assert!(parse_unit_to_seat("sshd.service").is_none());
        assert!(parse_unit_to_seat("buzz-agent@.service").is_none());
    }

    #[test]
    fn roster_from_systemctl_not_from_directory_listing() {
        // Naive glob of buzz-agent@* alone would miss orchestrator — parser must keep it.
        let stdout = "\
buzz-agent@codex.service          loaded active running Buzz headless agent persona codex
buzz-agent@hermes.service         loaded active running Buzz headless agent persona hermes
buzz-orchestrator.service         loaded active running Buzz orchestrator
";
        let roster = parse_systemctl_roster(stdout);
        let seats: Vec<_> = roster.iter().map(|r| r.seat.as_str()).collect();
        assert!(seats.contains(&"codex"));
        assert!(seats.contains(&"hermes"));
        assert!(
            seats.contains(&"orchestrator"),
            "orchestrator must be in roster even though it is not buzz-agent@*: {seats:?}"
        );
    }

    #[test]
    fn missing_status_file_is_loud_unknown_never_healthy() {
        let v = evaluate_mtime(None, t0(), Duration::from_secs(225));
        assert_eq!(v, ExternalLiveness::Unknown);
        assert_eq!(v.as_str(), "unknown");
        assert!(v.is_alarm());
    }

    #[test]
    fn starved_mtime_past_dead_after_is_dead() {
        let dead_after = Duration::from_secs(225);
        let mtime = t0();
        let now = t0() + dead_after + Duration::from_secs(1);
        let v = evaluate_mtime(Some(mtime), now, dead_after);
        assert_eq!(v, ExternalLiveness::Dead { age_secs: 226 });
        assert!(v.is_alarm());
    }

    #[test]
    fn fresh_mtime_within_dead_after_is_healthy() {
        let dead_after = Duration::from_secs(225);
        let mtime = t0();
        let now = t0() + Duration::from_secs(100);
        let v = evaluate_mtime(Some(mtime), now, dead_after);
        assert_eq!(v, ExternalLiveness::Healthy { age_secs: 100 });
        assert!(!v.is_alarm());
    }

    #[test]
    fn active_unit_without_heartbeat_file_alarms() {
        let dir = tempfile::tempdir().unwrap();
        // Roster has hermes; directory is empty — must alarm unknown.
        let roster = vec![RosterSeat {
            unit: "buzz-agent@hermes.service".into(),
            seat: "hermes".into(),
        }];
        let report = build_report(
            "seascope-ci-1",
            dir.path(),
            &roster,
            t0(),
            Duration::from_secs(225),
        );
        assert_eq!(report.coverage.scope, "host-local");
        assert_eq!(report.coverage.host, "seascope-ci-1");
        assert_eq!(
            report.coverage.authoritative_seats,
            vec!["hermes".to_string()]
        );
        assert_eq!(report.seats.len(), 1);
        assert_eq!(report.seats[0].verdict, ExternalLiveness::Unknown);
        assert!(report.seats[0].alarm);
        assert_eq!(report.alarm_count, 1);
        assert!(report.has_alarms());
    }

    #[test]
    fn coverage_declares_host_and_seats_not_factory_wide() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Codex.json");
        fs::write(&path, b"[]").unwrap();
        // Pin mtime via filetime would need extra dep; evaluate via build after touch is enough
        // for coverage shape. Fresh write → healthy under large dead_after.
        let roster = vec![
            RosterSeat {
                unit: "buzz-agent@codex.service".into(),
                seat: "codex".into(),
            },
            RosterSeat {
                unit: "buzz-agent@cursor.service".into(),
                seat: "cursor".into(),
            },
        ];
        let report = build_report(
            "seascope-ci-1",
            dir.path(),
            &roster,
            SystemTime::now(),
            Duration::from_secs(225),
        );
        assert_eq!(report.coverage.scope, "host-local");
        assert_eq!(report.host, "seascope-ci-1");
        assert_eq!(
            report.coverage.authoritative_seats,
            vec!["codex".to_string(), "cursor".to_string()]
        );
        // Extra files in dir must not expand roster.
        fs::write(dir.path().join("Claude.json"), b"[]").unwrap();
        let report2 = build_report(
            "seascope-ci-1",
            dir.path(),
            &roster,
            SystemTime::now(),
            Duration::from_secs(225),
        );
        assert_eq!(report2.seats.len(), 2, "roster must not grow from dir listing");
        assert!(!report2
            .coverage
            .authoritative_seats
            .iter()
            .any(|s| s == "claude"));
    }

    #[test]
    fn starved_file_on_disk_declares_dead_in_report() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("codex.json");
        fs::write(&path, b"[]").unwrap();
        // Pin mtime to an old wall time so the probe does not wait real seconds.
        let status = Command::new("touch")
            .args(["-d", "1970-01-01 00:00:01 UTC", path.to_str().unwrap()])
            .status()
            .expect("touch");
        assert!(status.success(), "touch -d must succeed to starve mtime");

        let roster = vec![RosterSeat {
            unit: "buzz-agent@codex.service".into(),
            seat: "codex".into(),
        }];
        let report = build_report(
            "seascope-ci-1",
            dir.path(),
            &roster,
            SystemTime::now(),
            Duration::from_secs(225),
        );
        assert_eq!(report.seats.len(), 1);
        assert!(
            matches!(report.seats[0].verdict, ExternalLiveness::Dead { .. }),
            "starved mtime must be dead, got {:?}",
            report.seats[0].verdict
        );
        assert!(report.seats[0].alarm);
        assert_eq!(report.alarm_count, 1);
    }
}
