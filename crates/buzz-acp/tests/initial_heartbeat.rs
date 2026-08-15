//! WO #148 — initial heartbeat on startup, before any turn dispatch.
//!
//! Proves the public registry API writes a watcher-shaped status file when a
//! seat boots, with no Claimed/Running transition and no inbound message.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use buzz_acp::{HeartbeatRegistry, HeartbeatState, IdentityClass};

fn t0() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

#[test]
fn seat_startup_writes_status_before_any_inbound_dispatch() {
    let dir = std::env::temp_dir().join(format!(
        "buzz-acp-wo148-it-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp heartbeat dir");
    let status_path = dir.join("hermes.json");

    let mut reg = HeartbeatRegistry::with_defaults();
    reg.set_status_path(&status_path);
    reg.register_identity("hermes", IdentityClass::AgentSeat, t0());

    // No inbound message / turn has been dispatched yet.
    assert!(!status_path.exists());

    let payload = reg
        .emit_initial("hermes", t0())
        .expect("startup must emit");
    assert_eq!(payload.state, HeartbeatState::AgentInitialized);
    assert!(payload.turn_id.is_none());
    assert!(status_path.is_file());

    let body: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&status_path).unwrap()).unwrap();
    let seat = &body.as_array().unwrap()[0];
    assert_eq!(seat["agent"], "hermes");
    assert_eq!(seat["state"], "agent_initialized");
    assert!(seat["turn_id"].is_null());
    assert!(seat.get("elapsed_in_phase_secs").is_some());
    assert!(seat.get("dropped_events").is_some());

    let _ = std::fs::remove_dir_all(&dir);
}
