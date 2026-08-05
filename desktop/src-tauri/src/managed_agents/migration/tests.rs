//! Adversarial fixture matrix for the pure migration builder/verifier.
//!
//! Each test builds a fully valid candidate + faithful relay read-back, then
//! tampers exactly one axis and asserts the specific rejection. The happy-path
//! test proves an untampered round-trip yields promotion evidence, so a green
//! matrix means every check is load-bearing (a tamper that still passed would
//! fail its negative test).

use std::collections::BTreeMap;

use buzz_core_pkg::kind::{KIND_MANAGED_AGENT, KIND_PERSONA};
use nostr::{Event, EventBuilder, Keys, Kind};
use serde_json::json;

use super::*;
use crate::managed_agents::types::{BackendKind, ManagedAgentRecord, RespondTo};

const CAPABLE: [&str; 1] = [super::super::authority::NIP_PMA_AGGREGATE_TOKEN];
const CREATED_AT: u64 = 1_700_000_000;

/// Sign a public projection event at `kind` with `owner_keys`, carrying the
/// given `d` coordinate and content — the exact shape a binding validates.
fn signed_projection(owner_keys: &Keys, kind: u32, d: &str, content: &str) -> Event {
    EventBuilder::new(Kind::Custom(kind as u16), content)
        .tags([nostr::Tag::parse(["d", d]).unwrap()])
        .custom_created_at(nostr::Timestamp::from(CREATED_AT))
        .sign_with_keys(owner_keys)
        .expect("sign projection")
}

/// A record whose `pubkey` matches `agent_keys`, valid for building.
fn record_for(agent_keys: &Keys) -> ManagedAgentRecord {
    let mut record = fully_valid_record();
    record.pubkey = agent_keys.public_key().to_hex();
    record
}

/// A minimal-but-realistic record. Only the carried fields matter for the
/// codec; the rest exercise "transient/derived not carried".
fn fully_valid_record() -> ManagedAgentRecord {
    ManagedAgentRecord {
        pubkey: "unset".to_string(),
        name: "Test Agent".to_string(),
        persona_id: Some("persona-1".to_string()),
        team_id: Some("team-1".to_string()),
        private_key_nsec: String::new(),
        auth_tag: Some("[\"auth\",\"STALE-DO-NOT-TRUST\",\"\",\"deadbeef\"]".to_string()),
        relay_url: "wss://relay.example".to_string(),
        avatar_url: None,
        acp_command: "buzz-acp".to_string(),
        agent_command: "goose".to_string(),
        agent_command_override: Some("codex".to_string()),
        agent_args: vec!["--flag".to_string()],
        mcp_command: "buzz-dev-mcp".to_string(),
        turn_timeout_seconds: 0,
        idle_timeout_seconds: Some(60),
        max_turn_duration_seconds: Some(600),
        parallelism: 1,
        system_prompt: Some("You are a test agent.".to_string()),
        model: Some("claude-opus-4".to_string()),
        provider: Some("anthropic".to_string()),
        persona_source_version: None,
        env_vars: BTreeMap::from([("K".to_string(), "V".to_string())]),
        start_on_app_launch: true,
        auto_restart_on_config_change: true,
        runtime_pid: None,
        backend: BackendKind::Provider {
            id: "buzz-backend-x".to_string(),
            config: json!({ "api_key": "secret" }),
        },
        backend_agent_id: Some("remote-id".to_string()),
        provider_binary_path: None,
        persona_team_dir: None,
        persona_name_in_team: Some("member".to_string()),
        created_at: "2025-01-01T00:00:00Z".to_string(),
        updated_at: "2025-01-01T00:00:00Z".to_string(),
        last_started_at: None,
        last_stopped_at: None,
        last_exit_code: None,
        last_error: None,
        last_error_code: None,
        respond_to: RespondTo::default(),
        respond_to_allowlist: vec![],
        display_name: Some("Display".to_string()),
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
        relay_authority: super::super::authority::RelayAuthority::legacy(),
    }
}

/// Everything a test needs: keys, the signed projections, the record, and the
/// CAS coordinate. `definition_d` is the agent pubkey so the instance binding's
/// coordinate check passes, and a distinct persona `d` for the definition.
struct Fixture {
    owner_keys: Keys,
    agent_keys: Keys,
    record: ManagedAgentRecord,
    definition_event: Event,
    instance_event: Event,
    cas: CasMetadata,
}

impl Fixture {
    fn new() -> Self {
        let owner_keys = Keys::generate();
        let agent_keys = Keys::generate();
        let agent_hex = agent_keys.public_key().to_hex();
        // Definition d is a slug; instance d MUST be the agent pubkey (the codec
        // binds the instance projection to 30177:<owner>:<agent>).
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
        Self {
            owner_keys,
            record: record_for(&agent_keys),
            agent_keys,
            definition_event,
            instance_event,
            cas: CasMetadata {
                generation: 1,
                previous_event_id: None,
                definition_revision: 7,
            },
        }
    }

    fn build(&self) -> Result<MigrationCandidate, MigrationError> {
        build_migration_candidate(
            &self.record,
            &self.owner_keys,
            &self.agent_keys,
            self.definition_event.clone(),
            self.instance_event.clone(),
            &self.cas,
            CAPABLE,
            CREATED_AT,
        )
    }

    /// A faithful relay read-back for a built candidate: the relay stored and
    /// serves back exactly what we submitted.
    fn faithful_response(&self, candidate: &MigrationCandidate) -> AggregateResponse {
        AggregateResponse {
            event_id: candidate.signed_event.id.to_hex(),
            generation: self.cas.generation,
            state: "active".to_string(),
            accepted: true,
            inserted: true,
            private_event: candidate.signed_event.clone(),
            definition_event: Some(candidate.definition_event.clone()),
            instance_event: Some(candidate.instance_event.clone()),
            definition_revision: Some(self.cas.definition_revision),
        }
    }
}

// ----- Happy path -----

#[test]
fn happy_round_trip_yields_promotion_evidence() {
    let fx = Fixture::new();
    let candidate = fx.build().expect("candidate builds");
    let response = fx.faithful_response(&candidate);
    let evidence = verify_promotion(&candidate, &response, &fx.owner_keys)
        .expect("faithful read-back promotes");
    assert_eq!(evidence.head_event_id, candidate.signed_event.id.to_hex());
    assert_eq!(evidence.generation, 1);
    assert_eq!(evidence.previous_event_id, None);
    assert_eq!(evidence.definition_revision, 7);
}

#[test]
fn route_response_shape_deserializes_and_missing_projection_is_rejected() {
    let fx = Fixture::new();
    let candidate = fx.build().expect("candidate builds");
    let response_json = serde_json::json!({
        "event_id": candidate.signed_event.id.to_hex(),
        "generation": 1,
        "state": "active",
        "accepted": true,
        "inserted": true,
        "definition_revision": 7,
        "private_event": candidate.signed_event,
        "definition_event": candidate.definition_event,
        "instance_event": candidate.instance_event,
    });
    let response: AggregateResponse =
        serde_json::from_value(response_json).expect("route JSON deserializes");
    verify_promotion(&candidate, &response, &fx.owner_keys).expect("route response verifies");

    let mut missing = response;
    missing.instance_event = None;
    assert!(matches!(
        verify_promotion(&candidate, &missing, &fx.owner_keys),
        Err(MigrationError::VerificationFailed(_))
    ));
}

#[test]
fn verify_rejects_response_metadata_drift() {
    let fx = Fixture::new();
    let candidate = fx.build().expect("candidate builds");
    for mutate in 0..4 {
        let mut response = fx.faithful_response(&candidate);
        match mutate {
            0 => response.event_id = "0".repeat(64),
            1 => response.generation += 1,
            2 => response.state = "deleted".to_string(),
            3 => response.accepted = false,
            _ => unreachable!(),
        }
        assert!(matches!(
            verify_promotion(&candidate, &response, &fx.owner_keys),
            Err(MigrationError::VerificationFailed(_))
        ));
    }
}

#[test]
fn auth_tag_is_re_minted_not_copied_from_record() {
    let fx = Fixture::new();
    let candidate = fx.build().expect("candidate builds");
    let identity = &candidate.payload.active.as_ref().unwrap().identity;
    let minted = identity.auth_tag.as_deref().unwrap();
    // The stored tag is a distinct-owner sentinel; the mint must not equal it
    // and must be an unconditional attestation for the real owner.
    assert_ne!(minted, fx.record.auth_tag.as_deref().unwrap());
    let parts: Vec<String> = serde_json::from_str(minted).unwrap();
    assert_eq!(parts[0], "auth");
    assert_eq!(parts[1], fx.owner_keys.public_key().to_hex());
    assert!(parts[2].is_empty(), "attestation must be unconditional");
}

#[test]
fn backend_is_carried_as_versioned_envelope() {
    let fx = Fixture::new();
    let candidate = fx.build().expect("candidate builds");
    let backend = &candidate.payload.active.as_ref().unwrap().config.backend;
    let obj = backend
        .as_object()
        .expect("backend is a versioned envelope");
    assert_eq!(obj.get("version").and_then(|v| v.as_u64()), Some(1));
    assert!(
        obj.contains_key("backend"),
        "envelope carries inner backend"
    );
}

// ----- Build-time input rejections -----

#[test]
fn build_rejects_agent_key_not_matching_record_pubkey() {
    let fx = Fixture::new();
    let mut record = fx.record.clone();
    record.pubkey = Keys::generate().public_key().to_hex();
    let err = build_migration_candidate(
        &record,
        &fx.owner_keys,
        &fx.agent_keys,
        fx.definition_event.clone(),
        fx.instance_event.clone(),
        &fx.cas,
        CAPABLE,
        CREATED_AT,
    )
    .unwrap_err();
    assert!(matches!(err, MigrationError::InvalidInput(_)));
}

#[test]
fn build_rejects_projection_not_signed_by_owner() {
    let fx = Fixture::new();
    // A definition signed by someone other than the owner.
    let impostor = Keys::generate();
    let bad_def = signed_projection(&impostor, KIND_PERSONA, "def-slug", "{\"definition\":true}");
    let err = build_migration_candidate(
        &fx.record,
        &fx.owner_keys,
        &fx.agent_keys,
        bad_def,
        fx.instance_event.clone(),
        &fx.cas,
        CAPABLE,
        CREATED_AT,
    )
    .unwrap_err();
    assert!(matches!(err, MigrationError::InvalidInput(_)));
}

#[test]
fn build_rejects_wrong_kind_projection() {
    let fx = Fixture::new();
    // Instance slot fed a 30175 (persona) event.
    let wrong = signed_projection(&fx.owner_keys, KIND_PERSONA, "x", "{}");
    let err = build_migration_candidate(
        &fx.record,
        &fx.owner_keys,
        &fx.agent_keys,
        fx.definition_event.clone(),
        wrong,
        &fx.cas,
        CAPABLE,
        CREATED_AT,
    )
    .unwrap_err();
    assert!(matches!(err, MigrationError::InvalidInput(_)));
}

// ----- Readiness gating at build -----

#[test]
fn build_blocks_when_relay_lacks_capability() {
    let fx = Fixture::new();
    let err = build_migration_candidate(
        &fx.record,
        &fx.owner_keys,
        &fx.agent_keys,
        fx.definition_event.clone(),
        fx.instance_event.clone(),
        &fx.cas,
        ["some-other-token"],
        CREATED_AT,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        MigrationError::Blocked(super::super::authority::MigrationBlock::RelayCapabilityAbsent)
    ));
}

#[test]
fn build_blocks_on_oversize_codec_value() {
    let fx = Fixture::new();
    // A recovery event whose content pushes the serialized recovery Value past
    // the per-value cap forces a CodecValueTooLarge block.
    let huge = "x".repeat(super::super::authority::MIGRATION_MAX_VALUE_BYTES + 1024);
    let big_instance = signed_projection(
        &fx.owner_keys,
        KIND_MANAGED_AGENT,
        &fx.agent_keys.public_key().to_hex(),
        &huge,
    );
    let err = build_migration_candidate(
        &fx.record,
        &fx.owner_keys,
        &fx.agent_keys,
        fx.definition_event.clone(),
        big_instance,
        &fx.cas,
        CAPABLE,
        CREATED_AT,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        MigrationError::Blocked(super::super::authority::MigrationBlock::CodecValueTooLarge { .. })
    ));
}

// ----- Verification-time rejections (relay read-back is not faithful) -----

#[test]
fn verify_rejects_tampered_head_ciphertext() {
    let fx = Fixture::new();
    let candidate = fx.build().expect("candidate builds");
    let mut response = fx.faithful_response(&candidate);
    // Re-sign a head with mangled ciphertext: decrypt/validate must fail.
    response.private_event =
        EventBuilder::new(candidate.signed_event.kind, "not-the-real-ciphertext")
            .tags(candidate.signed_event.tags.iter().cloned())
            .custom_created_at(nostr::Timestamp::from(CREATED_AT))
            .sign_with_keys(&fx.owner_keys)
            .unwrap();
    let err = verify_promotion(&candidate, &response, &fx.owner_keys).unwrap_err();
    assert!(matches!(err, MigrationError::VerificationFailed(_)));
}

#[test]
fn verify_rejects_head_signed_by_wrong_owner() {
    let fx = Fixture::new();
    let candidate = fx.build().expect("candidate builds");
    let response = fx.faithful_response(&candidate);
    // Verifying under a different owner key: the envelope owner check fails.
    let stranger = Keys::generate();
    let err = verify_promotion(&candidate, &response, &stranger).unwrap_err();
    assert!(matches!(err, MigrationError::VerificationFailed(_)));
}

#[test]
fn verify_rejects_swapped_definition_projection() {
    let fx = Fixture::new();
    let candidate = fx.build().expect("candidate builds");
    let mut response = fx.faithful_response(&candidate);
    // Relay serves a different (validly owner-signed) definition than bound.
    response.definition_event = Some(signed_projection(
        &fx.owner_keys,
        KIND_PERSONA,
        "def-slug",
        "{\"definition\":\"SWAPPED\"}",
    ));
    let err = verify_promotion(&candidate, &response, &fx.owner_keys).unwrap_err();
    assert!(matches!(err, MigrationError::VerificationFailed(_)));
}

#[test]
fn verify_rejects_swapped_instance_projection() {
    let fx = Fixture::new();
    let candidate = fx.build().expect("candidate builds");
    let mut response = fx.faithful_response(&candidate);
    response.instance_event = Some(signed_projection(
        &fx.owner_keys,
        KIND_MANAGED_AGENT,
        &fx.agent_keys.public_key().to_hex(),
        "{\"instance\":\"SWAPPED\"}",
    ));
    let err = verify_promotion(&candidate, &response, &fx.owner_keys).unwrap_err();
    assert!(matches!(err, MigrationError::VerificationFailed(_)));
}

#[test]
fn verify_rejects_wrong_definition_revision() {
    let fx = Fixture::new();
    let candidate = fx.build().expect("candidate builds");
    let mut response = fx.faithful_response(&candidate);
    response.definition_revision = Some(fx.cas.definition_revision + 1);
    let err = verify_promotion(&candidate, &response, &fx.owner_keys).unwrap_err();
    assert!(matches!(err, MigrationError::VerificationFailed(_)));
}

#[test]
fn verify_rejects_stale_generation_head() {
    let fx = Fixture::new();
    let candidate = fx.build().expect("candidate builds");
    // Build a DIFFERENT candidate at generation 2 and have the relay serve that
    // head back for our generation-1 submission: metadata mismatch.
    let cas2 = CasMetadata {
        generation: 2,
        previous_event_id: Some("a".repeat(64)),
        definition_revision: fx.cas.definition_revision,
    };
    let candidate2 = build_migration_candidate(
        &fx.record,
        &fx.owner_keys,
        &fx.agent_keys,
        fx.definition_event.clone(),
        fx.instance_event.clone(),
        &cas2,
        CAPABLE,
        CREATED_AT,
    )
    .expect("gen-2 candidate builds");
    let mut response = fx.faithful_response(&candidate);
    response.private_event = candidate2.signed_event.clone();
    response.event_id = candidate2.signed_event.id.to_hex();
    response.generation = cas2.generation;
    let err = verify_promotion(&candidate, &response, &fx.owner_keys).unwrap_err();
    assert!(matches!(err, MigrationError::VerificationFailed(_)));
}
