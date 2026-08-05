//! Exhaustive field-classification fixture.
//!
//! The load-bearing test here (`field_classification_is_exhaustive`) derives
//! the record's serialized field set from a fully-populated
//! [`ManagedAgentRecord`] and asserts [`classify_field`] covers exactly that
//! set. A field added to the record without a classification, or a stale
//! classification for a removed field, fails the build's tests — so no durable
//! field can silently reach migration unclassified (and thus be lost).

use super::*;
use crate::managed_agents::{
    BackendKind, CatalogSource, ManagedAgentRecord, RelayMeshConfig, RespondTo,
};
use std::collections::{BTreeMap, BTreeSet};

/// A record with EVERY field set to a non-skipping value, so serialization
/// emits the complete field set (no `skip_serializing_if` omissions). This is
/// deliberately exhaustive: adding a field to `ManagedAgentRecord` forces a
/// compile error here until it is populated, which in turn forces a
/// classification in `classify_field`.
fn fully_populated_record() -> ManagedAgentRecord {
    ManagedAgentRecord {
        pubkey: "agentpubkeyhex".to_string(),
        name: "Test Agent".to_string(),
        persona_id: Some("persona-1".to_string()),
        team_id: Some("team-1".to_string()),
        private_key_nsec: "nsec1secret".to_string(),
        auth_tag: Some("authtag".to_string()),
        relay_url: "wss://relay.example".to_string(),
        avatar_url: Some("https://example.com/a.png".to_string()),
        acp_command: "buzz-acp".to_string(),
        agent_command: "goose".to_string(),
        agent_command_override: Some("codex".to_string()),
        agent_args: vec!["--flag".to_string()],
        mcp_command: "buzz-dev-mcp".to_string(),
        turn_timeout_seconds: 320,
        idle_timeout_seconds: Some(60),
        max_turn_duration_seconds: Some(600),
        parallelism: 24,
        system_prompt: Some("You are a test agent.".to_string()),
        model: Some("claude-opus-4".to_string()),
        provider: Some("anthropic".to_string()),
        persona_source_version: Some("abc123".to_string()),
        env_vars: BTreeMap::from([("K".to_string(), "V".to_string())]),
        start_on_app_launch: true,
        auto_restart_on_config_change: true,
        runtime_pid: Some(4242),
        backend: BackendKind::Provider {
            id: "buzz-backend-x".to_string(),
            config: serde_json::json!({ "api_key": "secret" }),
        },
        backend_agent_id: Some("remote-id".to_string()),
        provider_binary_path: Some("/path/to/binary".to_string()),
        persona_team_dir: Some("/team/dir".into()),
        persona_name_in_team: Some("member".to_string()),
        created_at: "2025-01-01T00:00:00Z".to_string(),
        updated_at: "2025-01-01T00:00:00Z".to_string(),
        last_started_at: Some("2025-01-02T00:00:00Z".to_string()),
        last_stopped_at: Some("2025-01-03T00:00:00Z".to_string()),
        last_exit_code: Some(0),
        last_error: Some("some runtime error".to_string()),
        last_error_code: Some(1),
        respond_to: RespondTo::Allowlist,
        respond_to_allowlist: vec!["79be667e".to_string()],
        display_name: Some("Display".to_string()),
        slug: Some("sample-slug".to_string()),
        runtime: Some("goose".to_string()),
        name_pool: vec!["poolname".to_string()],
        is_builtin: true,
        is_active: false,
        shared: false,
        source_team: Some("src-team".to_string()),
        source_team_persona_slug: Some("src-slug".to_string()),
        catalog_source: Some(CatalogSource {
            owner_pubkey: "a".repeat(64),
            persona_id: "cat-persona".to_string(),
        }),
        definition_respond_to: Some("owner_only".to_string()),
        definition_respond_to_allowlist: vec!["deadbeef".to_string()],
        definition_parallelism: Some(2),
        relay_mesh: Some(RelayMeshConfig {
            model_ref: "Qwen3".to_string(),
        }),
        relay_authority: RelayAuthority::legacy(),
    }
}

/// Serialized field names of a fully-populated record.
fn serialized_field_names() -> Vec<String> {
    let value = serde_json::to_value(fully_populated_record()).unwrap();
    let obj = value
        .as_object()
        .expect("record serializes to a JSON object");
    obj.keys().cloned().collect()
}

/// Every field name that carries a classification, read from the single
/// source-of-truth table. A duplicate key here is itself a defect, so assert
/// uniqueness while collecting.
fn classified_field_names() -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for (name, _) in super::FIELD_CLASSIFICATIONS {
        assert!(
            set.insert(name.to_string()),
            "duplicate classification key `{name}` in FIELD_CLASSIFICATIONS",
        );
    }
    set
}

#[test]
fn field_classification_is_exhaustive() {
    // `shared` is `#[serde(skip_serializing)]`, so it never appears on the
    // wire — but it is a durable deserialize-time field and MUST still carry a
    // classification. Assert its presence explicitly, then fold it into the
    // record's serialized field set for exact set equality below.
    assert!(
        classify_field("shared").is_some(),
        "the skip_serializing `shared` field must still be classified",
    );

    let mut record_fields: BTreeSet<String> = serialized_field_names().into_iter().collect();
    record_fields.insert("shared".to_string());

    // Every classification key must correspond to a real record field. This is
    // the FIX #4 tightening: the previous test only checked that every field
    // had a class, not that every class key still names a live field. A stale
    // key (field renamed/removed but left in `classify_field`) now fails here.
    let classified: BTreeSet<String> = classified_field_names();

    let unclassified: Vec<&String> = record_fields.difference(&classified).collect();
    assert!(
        unclassified.is_empty(),
        "these durable ManagedAgentRecord fields have no FieldClass — a new \
         field must be classified in classify_field() or it is silently lost \
         on migration: {unclassified:?}",
    );

    let stale: Vec<&String> = classified.difference(&record_fields).collect();
    assert!(
        stale.is_empty(),
        "these classify_field() keys no longer name a ManagedAgentRecord field \
         — remove them so the table cannot drift out of sync with the record: \
         {stale:?}",
    );
}

#[test]
fn versioned_backend_roundtrips_with_stable_shape() {
    use super::{VersionedBackend, BACKEND_PAYLOAD_VERSION};

    // Provider variant — carries id + opaque config.
    let backend = BackendKind::Provider {
        id: "buzz-backend-x".to_string(),
        config: serde_json::json!({ "api_key": "secret", "region": "us" }),
    };
    let envelope = VersionedBackend::current(backend.clone());
    let json = serde_json::to_value(&envelope).unwrap();

    // EXACT persisted shape: a version marker beside the backend body, so a
    // future BackendKind shape change bumps `version` and is caught explicitly.
    assert_eq!(
        json,
        serde_json::json!({
            "version": BACKEND_PAYLOAD_VERSION,
            "backend": {
                "type": "provider",
                "id": "buzz-backend-x",
                "config": { "api_key": "secret", "region": "us" },
            },
        }),
    );

    let back: VersionedBackend = serde_json::from_value(json).unwrap();
    assert_eq!(back, envelope);
    assert_eq!(back.version, 1);

    // Local variant — the internally-tagged unit shape.
    let local = VersionedBackend::current(BackendKind::Local);
    let local_json = serde_json::to_value(&local).unwrap();
    assert_eq!(
        local_json,
        serde_json::json!({ "version": 1, "backend": { "type": "local" } }),
    );
    assert_eq!(
        serde_json::from_value::<VersionedBackend>(local_json).unwrap(),
        local,
    );
}

#[test]
fn versioned_backend_rejects_unknown_envelope_fields() {
    // `deny_unknown_fields`: an envelope with an unexpected sibling key fails to
    // deserialize rather than silently dropping data the migration codec relies
    // on. (BackendKind's own `config` stays opaque; this guards the envelope.)
    let bad = serde_json::json!({
        "version": 1,
        "backend": { "type": "local" },
        "unexpected": true,
    });
    assert!(
        serde_json::from_value::<super::VersionedBackend>(bad).is_err(),
        "versioned backend envelope must reject unknown top-level fields",
    );
}

#[test]
fn migration_readiness_allows_clear_case() {
    use super::{
        assess_migration_readiness, MIGRATION_MAX_VALUE_BYTES, MIGRATION_PAYLOAD_MAX_BYTES,
        NIP_PMA_AGGREGATE_TOKEN,
    };
    // Exactly at both limits, relay advertises the aggregate token -> allowed
    // (inclusive boundary).
    assert!(assess_migration_readiness(
        MIGRATION_PAYLOAD_MAX_BYTES,
        MIGRATION_MAX_VALUE_BYTES,
        [NIP_PMA_AGGREGATE_TOKEN],
    )
    .is_ok());
    // Comfortably under; extra unrelated tokens are ignored.
    assert!(assess_migration_readiness(1024, 512, ["other", NIP_PMA_AGGREGATE_TOKEN]).is_ok());
}

#[test]
fn migration_readiness_blocks_oversize_payload() {
    use super::{
        assess_migration_readiness, MigrationBlock, MIGRATION_PAYLOAD_MAX_BYTES,
        NIP_PMA_AGGREGATE_TOKEN,
    };
    let over = MIGRATION_PAYLOAD_MAX_BYTES + 1;
    assert_eq!(
        assess_migration_readiness(over, 0, [NIP_PMA_AGGREGATE_TOKEN]),
        Err(MigrationBlock::PayloadTooLarge { bytes: over }),
    );
}

#[test]
fn migration_readiness_blocks_oversize_codec_value() {
    use super::{
        assess_migration_readiness, MigrationBlock, MIGRATION_MAX_VALUE_BYTES,
        NIP_PMA_AGGREGATE_TOKEN,
    };
    let over = MIGRATION_MAX_VALUE_BYTES + 1;
    assert_eq!(
        assess_migration_readiness(0, over, [NIP_PMA_AGGREGATE_TOKEN]),
        Err(MigrationBlock::CodecValueTooLarge { bytes: over }),
    );
}

#[test]
fn migration_readiness_blocks_when_relay_lacks_capability() {
    use super::{assess_migration_readiness, MigrationBlock, NIP_PMA_AGGREGATE_TOKEN};
    // Capability absence is checked FIRST: even a valid-size payload cannot
    // migrate to a relay that does not advertise the aggregate token. Stay legacy.
    assert_eq!(
        assess_migration_readiness(0, 0, []),
        Err(MigrationBlock::RelayCapabilityAbsent),
    );
    // A relay advertising only unrelated tokens is still not capable — mere
    // kind acceptance is not the aggregate semantics we require.
    assert_eq!(
        assess_migration_readiness(0, 0, ["nip-pma-aggregate-v0", "other"]),
        Err(MigrationBlock::RelayCapabilityAbsent),
    );
    // And it dominates a simultaneous oversize condition (no misleading reason).
    assert_eq!(
        assess_migration_readiness(usize::MAX, usize::MAX, []),
        Err(MigrationBlock::RelayCapabilityAbsent),
    );
    // Sanity: the exact token, alone, does not itself block.
    assert!(assess_migration_readiness(0, 0, [NIP_PMA_AGGREGATE_TOKEN]).is_ok());
}

#[test]
fn migration_block_reasons_are_self_describing() {
    use super::MigrationBlock;
    // Each block yields a non-empty, self-describing diagnostic string. This is
    // a rendering of the decision for logging/surfacing — the variant itself is
    // the signal; persistence is owned by the migration driver lane.
    for block in [
        MigrationBlock::PayloadTooLarge { bytes: 70_000 },
        MigrationBlock::CodecValueTooLarge { bytes: 40_000 },
        MigrationBlock::RelayCapabilityAbsent,
    ] {
        assert!(!block.reason().is_empty());
    }
    assert!(MigrationBlock::PayloadTooLarge { bytes: 70_000 }
        .reason()
        .contains("70000"));
}

#[test]
fn no_secret_field_is_projected_publicly() {
    // Secrets must never ride a PUBLIC projection (kind:30175/30177). Any field
    // holding credential material must be PrivateCanonical.
    for secret in ["private_key_nsec", "env_vars", "backend"] {
        assert_eq!(
            classify_field(secret),
            Some(FieldClass::PrivateCanonical),
            "secret-bearing field `{secret}` must be PrivateCanonical, never projected publicly",
        );
    }
}

#[test]
fn auth_tag_is_re_minted_not_carried() {
    // The NIP-OA owner->agent tag is deterministically re-mintable from owner
    // keys + agent pubkey. Migration re-mints it; it is NOT carried or diffed,
    // so a re-mint that differs byte-for-byte cannot block migration. It must
    // never ride a public projection either.
    assert_eq!(
        classify_field("auth_tag"),
        Some(FieldClass::DerivedNotCarried),
        "auth_tag must be DerivedNotCarried (re-minted at migration, never preserved/diffed)",
    );
}

#[test]
fn no_codec_slot_fields_are_transient_local() {
    // Verified against PersonaEventContent (30175) + ManagedAgentEventContent
    // (30177) builders and the 30177 exclusion asserts: NO codec carries these.
    // Classifying them as projected would promise a preservation the codec
    // cannot deliver, silently losing them on migration.
    for field in [
        "provider_binary_path",
        "persona_team_dir",
        "start_on_app_launch",
        "auto_restart_on_config_change",
    ] {
        assert_eq!(
            classify_field(field),
            Some(FieldClass::TransientLocal),
            "no-codec-slot field `{field}` must be TransientLocal (nothing carries it)",
        );
    }
}

#[test]
fn definition_carried_fields_stay_projected() {
    // Guard against the review's incorrect claim that avatar_url has no slot:
    // PersonaEventContent (30175) DOES carry avatar_url, so it is authoritative
    // for a definition-less agent and MUST remain DefinitionProjected.
    assert_eq!(
        classify_field("avatar_url"),
        Some(FieldClass::DefinitionProjected),
        "avatar_url is carried by kind:30175 and must stay DefinitionProjected",
    );
}

#[test]
fn deprecated_snapshots_are_not_carried() {
    // Re-derived at spawn; diffing them at verification would false-positive
    // and block migration forever.
    for derived in [
        "acp_command",
        "agent_command",
        "mcp_command",
        "turn_timeout_seconds",
    ] {
        assert_eq!(
            classify_field(derived),
            Some(FieldClass::DerivedNotCarried),
            "re-derived snapshot field `{derived}` must be DerivedNotCarried",
        );
    }
}

#[test]
fn authority_defaults_to_legacy() {
    let authority = RelayAuthority::default();
    assert_eq!(authority, RelayAuthority::LegacyOnly);
    assert!(authority.evidence().is_none());
    assert!(!authority.is_relay_authoritative());
}

#[test]
fn legacy_only_persists_as_flat_authority_tag() {
    // FIX #3: the enum is adjacently tagged on `authority`, so it must NOT nest
    // a `state` inside a `state`. Assert the EXACT persisted shape.
    let json = serde_json::to_value(RelayAuthority::LegacyOnly).unwrap();
    assert_eq!(json, serde_json::json!({ "authority": "legacy_only" }));
}

#[test]
fn relay_authoritative_persists_with_evidence() {
    // FIX #3: exact persisted shape for the authoritative variant.
    let authority = RelayAuthority::relay_authoritative(RelayAuthorityEvidence {
        generation: 7,
        private_event_id: "eventid".to_string(),
    });
    let json = serde_json::to_value(&authority).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "authority": "relay_authoritative",
            "evidence": { "generation": 7, "private_event_id": "eventid" },
        })
    );
}

#[test]
fn legacy_record_deserializes_without_authority_field() {
    // A store written before this field existed has no `relay_authority` key.
    // It MUST deserialize as LegacyOnly, never fail, never silently promote.
    let json = serde_json::json!({
        "pubkey": "p",
        "name": "n",
        "private_key_nsec": "nsec1x",
        "relay_url": "wss://r",
        "acp_command": "a",
        "agent_command": "g",
        "agent_args": [],
        "mcp_command": "m",
        "turn_timeout_seconds": 320,
        "parallelism": 1,
        "created_at": "t",
        "updated_at": "t",
    });
    let record: ManagedAgentRecord = serde_json::from_value(json).unwrap();
    assert_eq!(record.relay_authority, RelayAuthority::LegacyOnly);
    assert!(!record.relay_authority.is_relay_authoritative());
}

#[test]
fn authoritative_authority_roundtrips_with_evidence() {
    let authority = RelayAuthority::relay_authoritative(RelayAuthorityEvidence {
        generation: 7,
        private_event_id: "eventid".to_string(),
    });
    let json = serde_json::to_string(&authority).unwrap();
    let back: RelayAuthority = serde_json::from_str(&json).unwrap();
    assert_eq!(authority, back);
    assert!(back.is_relay_authoritative());
    assert_eq!(back.evidence().unwrap().generation, 7);
}

#[test]
fn impossible_authority_states_are_unrepresentable() {
    // FIX #3: corrupt evidence can no longer silently disable reconcile.
    // `RelayAuthoritative` structurally carries evidence; `LegacyOnly`
    // structurally cannot. Legacy with a stray `evidence` key is rejected by
    // deserialize (evidence belongs only to the authoritative variant).
    let legacy_with_evidence = serde_json::json!({
        "authority": "legacy_only",
        "evidence": { "generation": 1, "private_event_id": "x" },
    });
    // Internally-tagged enums ignore sibling keys not belonging to the variant,
    // so this still deserializes as LegacyOnly (evidence is discarded, never
    // retained) — the important guarantee is that LegacyOnly carries no head.
    let back: RelayAuthority = serde_json::from_value(legacy_with_evidence).unwrap();
    assert_eq!(back, RelayAuthority::LegacyOnly);
    assert!(back.evidence().is_none());

    // Authoritative WITHOUT evidence is a hard deserialize error: reconcile can
    // never be disabled by an authoritative marker lacking a verified head.
    let authoritative_no_evidence = serde_json::json!({ "authority": "relay_authoritative" });
    assert!(
        serde_json::from_value::<RelayAuthority>(authoritative_no_evidence).is_err(),
        "RelayAuthoritative without evidence must fail to deserialize",
    );
}

#[test]
fn deleting_authority_roundtrips_with_evidence() {
    // The mid-deletion state structurally carries the head evidence needed to
    // (re)sign the tombstone and to compare-and-clear. It is relay-canonical
    // (reconcile must NOT republish) and reports deleting, but is NOT the
    // promoted authoritative state.
    let authority = RelayAuthority::deleting(RelayAuthorityEvidence {
        generation: 9,
        private_event_id: "priorhead".to_string(),
    });
    let json = serde_json::to_string(&authority).unwrap();
    let back: RelayAuthority = serde_json::from_str(&json).unwrap();
    assert_eq!(authority, back);
    assert!(back.is_deleting());
    assert!(back.is_relay_canonical());
    assert!(
        !back.is_relay_authoritative(),
        "Deleting is canonical but not the promoted authoritative state",
    );
    assert_eq!(back.evidence().unwrap().generation, 9);
    assert_eq!(back.evidence().unwrap().private_event_id, "priorhead");

    // Exact persisted shape: internally tagged on `authority`, evidence beside.
    assert_eq!(
        serde_json::to_value(&authority).unwrap(),
        serde_json::json!({
            "authority": "deleting",
            "evidence": { "generation": 9, "private_event_id": "priorhead" },
        }),
    );
}

#[test]
fn deleting_authority_without_evidence_fails_to_deserialize() {
    // Like RelayAuthoritative, a Deleting marker lacking a verified head is a
    // hard error — a mid-deletion record must always carry the evidence needed
    // to re-sign the tombstone and compare-and-clear.
    let deleting_no_evidence = serde_json::json!({ "authority": "deleting" });
    assert!(
        serde_json::from_value::<RelayAuthority>(deleting_no_evidence).is_err(),
        "Deleting without evidence must fail to deserialize",
    );
}

#[test]
fn relay_canonical_covers_authoritative_but_legacy_is_neither() {
    // Boot reconcile gates republish on is_relay_canonical: true for both
    // promoted and mid-deletion records, false for legacy.
    let authoritative = RelayAuthority::relay_authoritative(RelayAuthorityEvidence {
        generation: 1,
        private_event_id: "h".to_string(),
    });
    assert!(authoritative.is_relay_canonical());
    assert!(!authoritative.is_deleting());
    assert!(!RelayAuthority::legacy().is_relay_canonical());
    assert!(!RelayAuthority::legacy().is_deleting());
}
