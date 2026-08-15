//! Out-of-process liveness watcher binary (WO #135).
//!
//! One-shot probe: reads systemd roster + status-file mtimes, prints JSON,
//! Exits non-zero when any seat alarms (`dead` or `unknown`).
//! `stale` (active unit + starved mtime) is reported but does not exit-1.
//!
//! Never performs in-process alive-refresh — wedge detection stays outside the agent loop.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use buzz_acp::{run_probe, DEFAULT_HEARTBEAT_DIR};

#[derive(Debug, Parser)]
#[command(
    name = "buzz-liveness-watcher",
    about = "Out-of-process agent liveness probe (WO #135). Host-local coverage only."
)]
struct Args {
    /// Heartbeat status directory for this host (not shared across boxes).
    #[arg(
        long,
        env = "BUZZ_LIVENESS_HEARTBEAT_DIR",
        default_value = DEFAULT_HEARTBEAT_DIR
    )]
    heartbeat_dir: PathBuf,

    /// Pretty-print JSON (default: compact one line).
    #[arg(long)]
    pretty: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let report = match run_probe(&args.heartbeat_dir) {
        Ok(r) => r,
        Err(e) => {
            // Fail closed: cannot read roster/input → refuse, do not claim healthy.
            eprintln!("ERROR: liveness probe refused (fail-closed): {e}");
            return ExitCode::from(2);
        }
    };

    let json = if args.pretty {
        serde_json::to_string_pretty(&report)
    } else {
        serde_json::to_string(&report)
    };
    match json {
        Ok(s) => println!("{s}"),
        Err(e) => {
            eprintln!("ERROR: failed to serialize report: {e}");
            return ExitCode::from(2);
        }
    }

    if report.has_alarms() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
