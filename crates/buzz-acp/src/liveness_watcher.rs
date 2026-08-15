//! Out-of-process agent liveness watcher (WO #135 / #145).
//!
//! Consumes heartbeat status-file **mtime** from outside any agent's event
//! loop, **corroborated with systemd unit ActiveState** before any `Dead`
//! verdict (WO #145). A silent file alone is not death — idle seats write no
//! heartbeat until they have a turn.
//!
//! ## Verdict taxonomy (WO #145)
//!
//! - fresh mtime → [`ExternalLiveness::Healthy`]
//! - stale mtime + unit inactive/failed → [`ExternalLiveness::Dead`]
//! - stale mtime + unit active → [`ExternalLiveness::Stale`] (never `Dead`)
//! - undeterminable input (missing/future mtime, or unknown unit state) →
//!   [`ExternalLiveness::Unknown`]
//!
//! ## Fail-closed roster (merge-gate)
//!
//! Expected seats come from **systemd ground truth** (`buzz-agent@*` plus
//! `buzz-orchestrator.service` via `list-units --all`), never from listing the
//! heartbeat directory. Inactive/failed units stay on the roster so true-dead
//! seats remain visible. An active unit with no status file is loud
//! [`ExternalLiveness::Unknown`] — never silently healthy.
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
//! here is mtime + unit state, from outside the agent loop.

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

/// Systemd `ActiveState` class used to corroborate heartbeat mtime (WO #145).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitState {
    /// `ActiveState=active` (or `reloading`) — process side is up.
    Active,
    /// `ActiveState=inactive` or `failed` — positive evidence the unit is down.
    InactiveOrFailed,
    /// Could not determine (missing column, activating/deactivating, unknown).
    Undetermined,
}

/// Verdict for one rostered seat on this host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalLiveness {
    /// Status file mtime is within `dead_after`.
    Healthy { age_secs: u64 },
    /// Stale mtime **and** unit inactive/failed — corroborated death.
    Dead { age_secs: u64 },
    /// Stale mtime **but** unit still active — idle/wedged, never `dead`.
    Stale { age_secs: u64 },
    /// Undeterminable input (missing/future mtime, or unknown unit state).
    Unknown,
}

impl ExternalLiveness {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy { .. } => "healthy",
            Self::Dead { .. } => "dead",
            Self::Stale { .. } => "stale",
            Self::Unknown => "unknown",
        }
    }

    /// Pageable alarms only. `Stale` is reported but does not exit-1 — idle
    /// seats are the normal state of most agents most of the time.
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
    /// ActiveState class from `systemctl list-units` (WO #145 corroboration).
    pub unit_state: UnitState,
}

/// Map a systemd unit name to a roster seat, or `None` if not a watched unit.
///
/// Catches `buzz-agent@*` **and** `buzz-orchestrator.service` explicitly
/// (orchestrator is not under the template glob).
///
/// `unit_state` is the ActiveState class from the same list-units line.
pub fn parse_unit_to_seat(unit: &str, unit_state: UnitState) -> Option<RosterSeat> {
    let unit = unit.trim();
    if unit.is_empty() {
        return None;
    }
    let bare = unit.strip_suffix(".service").unwrap_or(unit);

    if bare.eq_ignore_ascii_case("buzz-orchestrator") {
        return Some(RosterSeat {
            unit: format_unit_name(bare),
            seat: "orchestrator".to_string(),
            unit_state,
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
            unit_state,
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

/// Classify systemd `ActiveState` token for corroboration.
///
/// - `active` / `reloading` → [`UnitState::Active`]
/// - `inactive` / `failed` → [`UnitState::InactiveOrFailed`]
/// - anything else (including empty) → [`UnitState::Undetermined`]
pub fn parse_unit_active_state(active_token: &str) -> UnitState {
    match active_token.trim().to_ascii_lowercase().as_str() {
        "active" | "reloading" => UnitState::Active,
        "inactive" | "failed" => UnitState::InactiveOrFailed,
        _ => UnitState::Undetermined,
    }
}

/// Parse `systemctl list-units --no-legend --plain` style lines into roster seats.
///
/// Includes inactive/failed units (`list-units --all`). Directory listings are
/// never consulted here.
pub fn parse_systemctl_roster(stdout: &str) -> Vec<RosterSeat> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("UNIT") {
            continue;
        }
        let mut cols = line.split_whitespace();
        let unit_token = cols.next().unwrap_or("");
        let _load = cols.next();
        let active_token = cols.next().unwrap_or("");
        let unit_state = if active_token.is_empty() {
            UnitState::Undetermined
        } else {
            parse_unit_active_state(active_token)
        };
        if let Some(seat) = parse_unit_to_seat(unit_token, unit_state) {
            if seen.insert(seat.unit.clone()) {
                out.push(seat);
            }
        }
    }
    out.sort_by(|a, b| a.seat.cmp(&b.seat));
    out
}

/// Evaluate one seat given optional status-file mtime **and** unit ActiveState.
///
/// `status_mtime == None` means the file is absent → [`ExternalLiveness::Unknown`].
/// A future mtime (clock skew / `touch -d`) is also [`ExternalLiveness::Unknown`] —
/// age is undeterminable, never fail-open to Healthy.
///
/// **WO #145:** `Dead` requires stale mtime **and** [`UnitState::InactiveOrFailed`].
/// Stale mtime with an active unit is [`ExternalLiveness::Stale`], never `Dead`.
/// Undetermined unit state fails closed to `Unknown`, never `Dead`.
pub fn evaluate_mtime(
    status_mtime: Option<SystemTime>,
    unit_state: UnitState,
    now: SystemTime,
    dead_after: Duration,
) -> ExternalLiveness {
    let Some(mtime) = status_mtime else {
        return ExternalLiveness::Unknown;
    };
    let Ok(age) = now.duration_since(mtime) else {
        // mtime > now: undeterminable input must refuse, not collapse to age 0.
        return ExternalLiveness::Unknown;
    };
    let age_secs = age.as_secs();
    if age <= dead_after {
        return ExternalLiveness::Healthy { age_secs };
    }
    // Stale mtime — corroborate with unit before asserting death.
    match unit_state {
        UnitState::InactiveOrFailed => ExternalLiveness::Dead { age_secs },
        UnitState::Active => ExternalLiveness::Stale { age_secs },
        UnitState::Undetermined => ExternalLiveness::Unknown,
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
        let verdict = evaluate_mtime(mtime, r.unit_state, now, dead_after);
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

/// Discover buzz seats via systemd, including inactive/failed (WO #145).
///
/// Uses `list-units --all` so a unit that has died stays on the roster and can
/// still be reported `Dead`. Fail-closed: command failure → error.
pub fn discover_systemd_roster() -> std::io::Result<Vec<RosterSeat>> {
    // Explicitly name orchestrator so a naive buzz-agent@* glob cannot miss it.
    // `--all` keeps inactive/failed units visible (active-only inverted coverage).
    let output = Command::new("systemctl")
        .args([
            "list-units",
            "buzz-agent@*",
            "buzz-orchestrator.service",
            "--all",
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

    fn seat(unit: &str, name: &str, state: UnitState) -> RosterSeat {
        RosterSeat {
            unit: unit.into(),
            seat: name.into(),
            unit_state: state,
        }
    }

    #[test]
    fn dead_after_strictly_exceeds_stall() {
        let dead = watcher_dead_after();
        assert!(dead > STALL_AFTER_DEFAULT);
        assert_eq!(dead, Duration::from_secs(225));
    }

    #[test]
    fn parse_unit_catches_agent_and_orchestrator() {
        let a = parse_unit_to_seat("buzz-agent@codex.service", UnitState::Active).unwrap();
        assert_eq!(a.seat, "codex");
        assert_eq!(a.unit, "buzz-agent@codex.service");
        assert_eq!(a.unit_state, UnitState::Active);

        let o = parse_unit_to_seat("buzz-orchestrator.service", UnitState::InactiveOrFailed)
            .unwrap();
        assert_eq!(o.seat, "orchestrator");
        assert_eq!(o.unit, "buzz-orchestrator.service");
        assert_eq!(o.unit_state, UnitState::InactiveOrFailed);

        assert!(parse_unit_to_seat("sshd.service", UnitState::Active).is_none());
        assert!(parse_unit_to_seat("buzz-agent@.service", UnitState::Active).is_none());
    }

    #[test]
    fn roster_includes_inactive_and_failed_units() {
        // --all output: inactive/failed must stay on the roster (WO #145).
        let stdout = "\
buzz-agent@codex.service          loaded active running Buzz headless agent persona codex
buzz-agent@hermes.service         loaded failed failed Buzz headless agent persona hermes
buzz-agent@firstmate.service      loaded inactive dead Buzz headless agent persona firstmate
buzz-orchestrator.service         loaded active running Buzz orchestrator
";
        let roster = parse_systemctl_roster(stdout);
        let by_seat: std::collections::HashMap<_, _> = roster
            .iter()
            .map(|r| (r.seat.as_str(), r.unit_state))
            .collect();
        assert_eq!(by_seat.get("codex"), Some(&UnitState::Active));
        assert_eq!(by_seat.get("hermes"), Some(&UnitState::InactiveOrFailed));
        assert_eq!(
            by_seat.get("firstmate"),
            Some(&UnitState::InactiveOrFailed)
        );
        assert_eq!(by_seat.get("orchestrator"), Some(&UnitState::Active));
        assert_eq!(roster.len(), 4, "inactive/failed must not vanish: {roster:?}");
    }

    #[test]
    fn missing_status_file_is_loud_unknown_never_healthy() {
        let v = evaluate_mtime(None, UnitState::Active, t0(), Duration::from_secs(225));
        assert_eq!(v, ExternalLiveness::Unknown);
        assert_eq!(v.as_str(), "unknown");
        assert!(v.is_alarm());
    }

    #[test]
    fn starved_mtime_inactive_unit_is_dead() {
        let dead_after = Duration::from_secs(225);
        let mtime = t0();
        let now = t0() + dead_after + Duration::from_secs(1);
        let v = evaluate_mtime(
            Some(mtime),
            UnitState::InactiveOrFailed,
            now,
            dead_after,
        );
        assert_eq!(v, ExternalLiveness::Dead { age_secs: 226 });
        assert!(v.is_alarm());
    }

    #[test]
    fn starved_mtime_active_unit_is_stale_never_dead() {
        // THE #145 regression: idle-but-healthy seats write no heartbeat.
        let dead_after = Duration::from_secs(225);
        let mtime = t0();
        let now = t0() + dead_after + Duration::from_secs(1);
        let v = evaluate_mtime(Some(mtime), UnitState::Active, now, dead_after);
        assert_eq!(v, ExternalLiveness::Stale { age_secs: 226 });
        assert_ne!(v.as_str(), "dead");
        assert!(!v.is_alarm(), "Stale must not page like Dead");
    }

    #[test]
    fn starved_mtime_undetermined_unit_is_unknown_not_dead() {
        let dead_after = Duration::from_secs(225);
        let mtime = t0();
        let now = t0() + dead_after + Duration::from_secs(1);
        let v = evaluate_mtime(Some(mtime), UnitState::Undetermined, now, dead_after);
        assert_eq!(v, ExternalLiveness::Unknown);
        assert_ne!(v.as_str(), "dead");
        assert!(v.is_alarm());
    }

    #[test]
    fn fresh_mtime_within_dead_after_is_healthy() {
        let dead_after = Duration::from_secs(225);
        let mtime = t0();
        let now = t0() + Duration::from_secs(100);
        let v = evaluate_mtime(Some(mtime), UnitState::Active, now, dead_after);
        assert_eq!(v, ExternalLiveness::Healthy { age_secs: 100 });
        assert!(!v.is_alarm());
    }

    #[test]
    fn future_mtime_is_unknown_never_healthy() {
        // Clock jump / touch -d future: duration_since errors → Unknown (alarms).
        let dead_after = Duration::from_secs(225);
        let now = t0();
        let mtime = t0() + Duration::from_secs(60);
        let v = evaluate_mtime(Some(mtime), UnitState::Active, now, dead_after);
        assert_eq!(v, ExternalLiveness::Unknown);
        assert_ne!(v.as_str(), "healthy");
        assert!(v.is_alarm());
    }

    #[test]
    fn active_unit_without_heartbeat_file_alarms() {
        let dir = tempfile::tempdir().unwrap();
        // Roster has hermes; directory is empty — must alarm unknown.
        let roster = vec![seat(
            "buzz-agent@hermes.service",
            "hermes",
            UnitState::Active,
        )];
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
        let roster = vec![
            seat("buzz-agent@codex.service", "codex", UnitState::Active),
            seat("buzz-agent@cursor.service", "cursor", UnitState::Active),
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
    fn starved_file_inactive_unit_declares_dead_in_report() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("codex.json");
        fs::write(&path, b"[]").unwrap();
        let status = Command::new("touch")
            .args(["-d", "1970-01-01 00:00:01 UTC", path.to_str().unwrap()])
            .status()
            .expect("touch");
        assert!(status.success(), "touch -d must succeed to starve mtime");

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
            Duration::from_secs(225),
        );
        assert_eq!(report.seats.len(), 1);
        assert!(
            matches!(report.seats[0].verdict, ExternalLiveness::Dead { .. }),
            "starved+inactive must be dead, got {:?}",
            report.seats[0].verdict
        );
        assert!(report.seats[0].alarm);
        assert_eq!(report.alarm_count, 1);
    }

    #[test]
    fn starved_file_active_unit_is_stale_not_dead_in_report() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("codex.json");
        fs::write(&path, b"[]").unwrap();
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
            Duration::from_secs(225),
        );
        assert_eq!(report.seats.len(), 1);
        assert!(
            matches!(report.seats[0].verdict, ExternalLiveness::Stale { .. }),
            "active+starved must be Stale, got {:?}",
            report.seats[0].verdict
        );
        assert!(!report.seats[0].alarm);
        assert_eq!(report.alarm_count, 0);
    }
}
