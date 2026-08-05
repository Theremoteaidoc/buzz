//! Transport tests for the PMA aggregate submit/retry driver.
//!
//! Each test builds a real signed candidate, serializes it into the exact
//! `request_json` the retention layer would persist, stands up a loopback axum
//! stub in the shape of the relay's aggregate route, and drives one submission.
//! The happy path proves a faithful read-back marks the row synced; every
//! negative path proves the row stays pending with a persisted diagnostic.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::{extract::State as AxumState, http::StatusCode, routing::post, Router};
use buzz_core_pkg::kind::{KIND_MANAGED_AGENT, KIND_PERSONA};
use nostr::{EventBuilder, Keys, Kind};
use serde_json::json;

use super::super::{build_migration_candidate, CasMetadata, MigrationCandidate};
use super::*;
use crate::managed_agents::retention::{
    get_retained_managed_agent_aggregate, open_retention_db, retain_managed_agent_aggregate,
    RetainedManagedAgentAggregate,
};
use crate::managed_agents::types::{BackendKind, ManagedAgentRecord, RespondTo};

const CAPABLE: [&str; 1] = [crate::managed_agents::authority::NIP_PMA_AGGREGATE_TOKEN];
const CREATED_AT: u64 = 1_700_000_000;

// ── Fixtures ────────────────────────────────────────────────────────────────

fn signed_projection(owner_keys: &Keys, kind: u32, d: &str, content: &str) -> nostr::Event {
    EventBuilder::new(Kind::Custom(kind as u16), content)
        .tags([nostr::Tag::parse(["d", d]).unwrap()])
        .custom_created_at(nostr::Timestamp::from(CREATED_AT))
        .sign_with_keys(owner_keys)
        .expect("sign projection")
}

fn record_for(agent_keys: &Keys) -> ManagedAgentRecord {
    ManagedAgentRecord {
        pubkey: agent_keys.public_key().to_hex(),
        name: "Test Agent".to_string(),
        persona_id: Some("persona-1".to_string()),
        team_id: Some("team-1".to_string()),
        private_key_nsec: String::new(),
        auth_tag: Some("[\"auth\",\"STALE\",\"\",\"deadbeef\"]".to_string()),
        relay_url: "wss://relay.example".to_string(),
        avatar_url: None,
        acp_command: "buzz-acp".to_string(),
        agent_command: "goose".to_string(),
        agent_command_override: None,
        agent_args: vec![],
        mcp_command: "buzz-dev-mcp".to_string(),
        turn_timeout_seconds: 0,
        idle_timeout_seconds: None,
        max_turn_duration_seconds: None,
        parallelism: 1,
        system_prompt: Some("You are a test agent.".to_string()),
        model: Some("claude-opus-4".to_string()),
        provider: Some("anthropic".to_string()),
        persona_source_version: None,
        env_vars: BTreeMap::new(),
        start_on_app_launch: false,
        auto_restart_on_config_change: true,
        runtime_pid: None,
        backend: BackendKind::Local,
        backend_agent_id: None,
        provider_binary_path: None,
        persona_team_dir: None,
        persona_name_in_team: None,
        created_at: "2025-01-01T00:00:00Z".to_string(),
        updated_at: "2025-01-01T00:00:00Z".to_string(),
        last_started_at: None,
        last_stopped_at: None,
        last_exit_code: None,
        last_error: None,
        last_error_code: None,
        respond_to: RespondTo::default(),
        respond_to_allowlist: vec![],
        display_name: None,
        slug: Some("sample-slug".to_string()),
        runtime: Some("goose".to_string()),
        name_pool: vec![],
        is_builtin: false,
        is_active: true,
        shared: false,
        source_team: None,
        source_team_persona_slug: None,
        catalog_source: None,
        definition_respond_to: None,
        definition_respond_to_allowlist: vec![],
        definition_parallelism: None,
        relay_mesh: None,
        relay_authority: crate::managed_agents::authority::RelayAuthority::legacy(),
    }
}

struct Fixture {
    owner_keys: Keys,
    agent_keys: Keys,
    candidate: MigrationCandidate,
    cas: CasMetadata,
}

impl Fixture {
    fn new() -> Self {
        let owner_keys = Keys::generate();
        let agent_keys = Keys::generate();
        let agent_hex = agent_keys.public_key().to_hex();
        let definition_event = signed_projection(
            &owner_keys,
            KIND_PERSONA,
            "def-slug",
            "{\"definition\":true}",
        );
        let instance_event = signed_projection(
            &owner_keys,
            KIND_MANAGED_AGENT,
            &agent_hex,
            "{\"instance\":true}",
        );
        let cas = CasMetadata {
            generation: 1,
            previous_event_id: None,
            definition_revision: 7,
        };
        let candidate = build_migration_candidate(
            &record_for(&agent_keys),
            &owner_keys,
            &agent_keys,
            definition_event,
            instance_event,
            &cas,
            CAPABLE,
            CREATED_AT,
        )
        .expect("candidate builds");
        Self {
            owner_keys,
            agent_keys,
            candidate,
            cas,
        }
    }

    fn owner_hex(&self) -> String {
        self.owner_keys.public_key().to_hex()
    }

    fn agent_hex(&self) -> String {
        self.agent_keys.public_key().to_hex()
    }

    /// The exact `request_json` the retention layer would persist and the
    /// driver POSTs verbatim: the relay's `AggregateBody` shape.
    fn request_json(&self) -> String {
        json!({
            "private_event": self.candidate.signed_event,
            "definition_event": self.candidate.definition_event,
            "instance_event": self.candidate.instance_event,
            "expected_definition_revision": self.cas.definition_revision,
        })
        .to_string()
    }

    /// A faithful relay read-back — the relay stored and serves back exactly
    /// what we submitted.
    fn faithful_response_json(&self) -> serde_json::Value {
        json!({
            "event_id": self.candidate.signed_event.id.to_hex(),
            "generation": self.cas.generation,
            "state": "active",
            "accepted": true,
            "inserted": true,
            "private_event": self.candidate.signed_event,
            "definition_event": self.candidate.definition_event,
            "instance_event": self.candidate.instance_event,
            "definition_revision": self.cas.definition_revision,
        })
    }

    fn retained_row(&self) -> RetainedManagedAgentAggregate {
        RetainedManagedAgentAggregate {
            owner_pubkey: self.owner_hex(),
            agent_pubkey: self.agent_hex(),
            generation: self.cas.generation,
            private_event_id: self.candidate.signed_event.id.to_hex(),
            state: "active".to_string(),
            request_json: self.request_json(),
            pending_sync: true,
            last_error: None,
        }
    }
}

// ── Stub relay ──────────────────────────────────────────────────────────────

/// A scripted reply: the HTTP status and body the stub returns.
#[derive(Clone)]
struct StubReply {
    status: StatusCode,
    body: String,
}

type StubState = (Arc<StubReply>, Arc<Mutex<Option<Vec<u8>>>>);

/// Spawn a loopback stub relay serving the aggregate route with a scripted
/// reply, capturing the raw request body it received. Returns the base URL and
/// a handle to the captured body.
async fn spawn_stub(reply: StubReply) -> (String, Arc<Mutex<Option<Vec<u8>>>>) {
    let captured: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let state: StubState = (Arc::new(reply), captured.clone());
    let app =
        Router::new()
            .route(
                "/api/managed-agents/aggregate",
                post(
                    |AxumState((reply, captured)): AxumState<StubState>,
                     body: axum::body::Bytes| async move {
                        *captured.lock().unwrap() = Some(body.to_vec());
                        (reply.status, reply.body.clone())
                    },
                ),
            )
            .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub relay");
    let addr = listener.local_addr().expect("stub relay addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), captured)
}

/// Open the retention db, seed one pending row, and hand back a fresh
/// connection for the driver to read/write committed state through.
fn seeded_conn(
    dir: &tempfile::TempDir,
    row: &RetainedManagedAgentAggregate,
) -> rusqlite::Connection {
    let path = dir.path().join("retention.db");
    let mut writer = open_retention_db(&path).expect("open db");
    retain_managed_agent_aggregate(&mut writer, row).expect("retain aggregate row");
    open_retention_db(&path).expect("reopen db")
}

fn app_state_at(url: String) -> crate::app_state::AppState {
    let state = crate::app_state::build_app_state();
    *state.relay_url_override.lock().unwrap() = Some(url);
    state
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn faithful_read_back_marks_exact_generation_synced_and_posts_verbatim() {
    let fx = Fixture::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = seeded_conn(&dir, &fx.retained_row());

    let (url, captured) = spawn_stub(StubReply {
        status: StatusCode::OK,
        body: fx.faithful_response_json().to_string(),
    })
    .await;
    let state = app_state_at(url);

    let outcome = submit_retained_aggregate(
        &state,
        &conn,
        &fx.owner_keys,
        &fx.owner_hex(),
        &fx.agent_hex(),
    )
    .await
    .expect("drive succeeds");

    assert_eq!(
        outcome,
        SubmitOutcome::Synced {
            generation: fx.cas.generation,
            private_event_id: fx.candidate.signed_event.id.to_hex(),
        }
    );

    // Posted bytes are the retained request verbatim.
    let posted = captured.lock().unwrap().clone().expect("body captured");
    assert_eq!(posted, fx.request_json().into_bytes());

    // The row is no longer pending and carries no error.
    let confirmed = get_retained_managed_agent_aggregate(&conn, &fx.owner_hex(), &fx.agent_hex())
        .unwrap()
        .unwrap();
    assert!(!confirmed.pending_sync, "verified row is marked synced");
    assert_eq!(confirmed.last_error, None);
}

#[tokio::test]
async fn conflict_status_preserves_retry_with_diagnostic() {
    let fx = Fixture::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = seeded_conn(&dir, &fx.retained_row());

    let (url, _captured) = spawn_stub(StubReply {
        status: StatusCode::CONFLICT,
        body: json!({ "error": "stale generation" }).to_string(),
    })
    .await;
    let state = app_state_at(url);

    let outcome = submit_retained_aggregate(
        &state,
        &conn,
        &fx.owner_keys,
        &fx.owner_hex(),
        &fx.agent_hex(),
    )
    .await
    .expect("drive resolves");

    assert!(matches!(outcome, SubmitOutcome::Retained { .. }));
    let row = get_retained_managed_agent_aggregate(&conn, &fx.owner_hex(), &fx.agent_hex())
        .unwrap()
        .unwrap();
    assert!(row.pending_sync, "rejected attempt stays pending");
    assert!(row.last_error.is_some(), "diagnostic persisted");
}

#[tokio::test]
async fn malformed_success_body_preserves_retry() {
    let fx = Fixture::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = seeded_conn(&dir, &fx.retained_row());

    let (url, _captured) = spawn_stub(StubReply {
        status: StatusCode::OK,
        body: "{ not json".to_string(),
    })
    .await;
    let state = app_state_at(url);

    let outcome = submit_retained_aggregate(
        &state,
        &conn,
        &fx.owner_keys,
        &fx.owner_hex(),
        &fx.agent_hex(),
    )
    .await
    .expect("drive resolves");

    assert!(matches!(outcome, SubmitOutcome::Retained { .. }));
    let row = get_retained_managed_agent_aggregate(&conn, &fx.owner_hex(), &fx.agent_hex())
        .unwrap()
        .unwrap();
    assert!(row.pending_sync);
    assert!(row.last_error.is_some());
}

#[tokio::test]
async fn tampered_read_back_fails_verification_and_preserves_retry() {
    let fx = Fixture::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = seeded_conn(&dir, &fx.retained_row());

    // A well-formed response whose head id was swapped for a different value —
    // deserializes cleanly but must fail verify_promotion.
    let mut tampered = fx.faithful_response_json();
    tampered["event_id"] = json!("0".repeat(64));
    let (url, _captured) = spawn_stub(StubReply {
        status: StatusCode::OK,
        body: tampered.to_string(),
    })
    .await;
    let state = app_state_at(url);

    let outcome = submit_retained_aggregate(
        &state,
        &conn,
        &fx.owner_keys,
        &fx.owner_hex(),
        &fx.agent_hex(),
    )
    .await
    .expect("drive resolves");

    assert!(matches!(outcome, SubmitOutcome::Retained { .. }));
    let row = get_retained_managed_agent_aggregate(&conn, &fx.owner_hex(), &fx.agent_hex())
        .unwrap()
        .unwrap();
    assert!(row.pending_sync, "unverified read-back never clears retry");
    assert!(row.last_error.is_some());
}

#[tokio::test]
async fn row_coordinate_disagreeing_with_verified_head_is_not_synced() {
    // The durable row's (generation, private_event_id) columns are the pair the
    // driver confirms. If they disagree with the request_json the row carries —
    // and thus with the verified read-back — the guard must refuse to mark it
    // synced even though the relay served a faithful copy of the request bytes.
    let fx = Fixture::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut row = fx.retained_row();
    row.private_event_id = "f".repeat(64); // column diverges from request_json head id
    let conn = seeded_conn(&dir, &row);

    let (url, _captured) = spawn_stub(StubReply {
        status: StatusCode::OK,
        body: fx.faithful_response_json().to_string(),
    })
    .await;
    let state = app_state_at(url);

    let outcome = submit_retained_aggregate(
        &state,
        &conn,
        &fx.owner_keys,
        &fx.owner_hex(),
        &fx.agent_hex(),
    )
    .await
    .expect("drive resolves");

    assert!(
        matches!(outcome, SubmitOutcome::Retained { .. }),
        "row whose coordinate disagrees with the verified head is not synced"
    );
    let stored = get_retained_managed_agent_aggregate(&conn, &fx.owner_hex(), &fx.agent_hex())
        .unwrap()
        .unwrap();
    assert!(stored.pending_sync, "mismatched row stays pending");
    assert!(stored.last_error.is_some(), "diagnostic persisted");
}

#[tokio::test]
async fn no_pending_row_is_a_noop() {
    let fx = Fixture::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = open_retention_db(&dir.path().join("retention.db")).expect("open db");

    let (url, captured) = spawn_stub(StubReply {
        status: StatusCode::OK,
        body: fx.faithful_response_json().to_string(),
    })
    .await;
    let state = app_state_at(url);

    let outcome = submit_retained_aggregate(
        &state,
        &conn,
        &fx.owner_keys,
        &fx.owner_hex(),
        &fx.agent_hex(),
    )
    .await
    .expect("drive resolves");

    assert_eq!(outcome, SubmitOutcome::Nothing);
    assert!(
        captured.lock().unwrap().is_none(),
        "no row means no network submission"
    );
}
