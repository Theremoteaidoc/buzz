//! Pure relay-canonical managed-agent migration codec (slice 3).
//!
//! This module turns one hydrated [`ManagedAgentRecord`] plus its owner/agent
//! keys, its exact signed public projections (kind:30175 definition and
//! kind:30177 instance), and the CAS coordinate the relay will assign into a
//! signed, inert `kind:30179` private managed-agent aggregate candidate — and
//! then verifies the relay's read-back response byte-exactly before it will
//! yield promotion evidence.
//!
//! It is deliberately **pure**: no HTTP, no persistence, no authority mutation.
//! The transport/driver lane (sibling) owns submission, retry, durable state,
//! and the actual [`RelayAuthority`](super::authority::RelayAuthority) write.
//! This module is the gate those lanes must pass through, so every check that
//! decides "is the relay head a faithful, owner-signed copy of this agent?"
//! lives here and is exercised by an adversarial fixture matrix.
//!
//! Design invariants (see PLANS/RELAY_ONLY_MANAGED_AGENTS_MIGRATION.md):
//!   * `PrivateConfig.backend` carries the *versioned* backend envelope
//!     ([`VersionedBackend`]), never a bare `BackendKind`, so a shape change is
//!     an explicit version bump rather than a silent byte mismatch.
//!   * `auth_tag` is **re-minted** unconditionally from the owner keys and the
//!     agent pubkey; the stored record string is never copied or trusted. A
//!     re-mint cannot byte-match a stored tag, so it is not carried/diffed.
//!   * Readiness gating derives the *actual* largest serialized codec `Value`
//!     the payload inserts (the projection recovery events dominate) rather
//!     than trusting a caller-supplied size.
//!   * Verification compares source-vs-roundtrip **only for carried field
//!     classes**; derived/transient/bookkeeping fields are never diffed.

use buzz_core_pkg::kind::{KIND_MANAGED_AGENT, KIND_PERSONA};
use buzz_core_pkg::private_managed_agent::{
    self as pma, ActivePayload, DefinitionBinding, InstanceBinding, Payload, PrivateConfig,
    PrivateIdentity, ProjectionRecoveryV1, State,
};
use nostr::{Event, Keys, PublicKey, ToBech32};
use serde::Deserialize;
use serde_json::Value;

use super::authority::VersionedBackend;
use super::types::ManagedAgentRecord;

/// A terminal failure while building or verifying a migration candidate.
///
/// These are decisions, not transient conditions: the transport lane must keep
/// the agent [`LegacyOnly`](super::authority::RelayAuthority::LegacyOnly) and
/// must not retry until an input changes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Consumed by the transport/driver lane (sibling); today only this module's tests read it.
pub enum MigrationError {
    /// A supplied key/projection is internally inconsistent (wrong pubkey,
    /// non-verifying signature, coordinate mismatch) before anything is built.
    InvalidInput(String),
    /// The re-minted owner→agent attestation could not be computed.
    AuthTag(String),
    /// The candidate payload could not be assembled/encrypted/signed by the
    /// shared codec. Carries the codec's own diagnostic.
    Codec(String),
    /// A pure migration-readiness block (capability/size). The agent stays
    /// legacy; the reason is a diagnostic rendering only.
    Blocked(super::authority::MigrationBlock),
    /// The relay read-back is not a faithful, owner-signed copy of the
    /// candidate. Carries which check failed. Promotion is refused.
    VerificationFailed(String),
}

impl From<pma::Error> for MigrationError {
    fn from(error: pma::Error) -> Self {
        MigrationError::Codec(error.to_string())
    }
}

/// The CAS coordinate the relay is expected to assign to this write.
///
/// Generation and predecessor are supplied by the driver lane from the relay's
/// current head (or `generation = 1`, `previous_event_id = None` for genesis);
/// this module binds them into the payload and later checks the read-back
/// echoes them exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct CasMetadata {
    /// Monotonic CAS generation for this write.
    pub generation: u64,
    /// Exact predecessor event ID; `None` only at generation one.
    pub previous_event_id: Option<String>,
    /// CAS-managed definition revision pinned by the bound kind:30175.
    pub definition_revision: u64,
}

/// A built, signed, inert migration candidate ready for the driver lane to
/// submit. Holds exactly what verification needs to compare the relay's
/// read-back against.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MigrationCandidate {
    /// The signed kind:30179 event to publish.
    pub signed_event: Event,
    /// The decrypted payload that was sealed into `signed_event`, retained so
    /// verification can compare the read-back against the exact source without
    /// re-decrypting the candidate.
    pub payload: Payload,
    /// The exact signed kind:30175 definition projection this candidate binds.
    pub definition_event: Event,
    /// The exact signed kind:30177 instance projection this candidate binds.
    pub instance_event: Event,
}

/// The relay's read-back response for a submitted aggregate.
///
/// This is a **local typed fixture** matching the documented aggregate route
/// JSON, not a buzz-db type: the transport lane deserializes the route response
/// into this shape and hands it here for verification. Keeping it local keeps
/// this slice free of the relay/persistence crates.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct AggregateResponse {
    /// Exact ID of the committed private head.
    pub event_id: String,
    /// Committed CAS generation.
    pub generation: u64,
    /// Committed lifecycle state.
    pub state: String,
    /// Whether the relay accepted the request.
    pub accepted: bool,
    /// Whether this request inserted a new generation rather than replaying one.
    pub inserted: bool,
    /// The signed kind:30179 event the relay stored and serves as the head.
    pub private_event: Event,
    /// The signed kind:30175 definition projection the relay serves.
    pub definition_event: Option<Event>,
    /// The signed kind:30177 instance projection the relay serves.
    pub instance_event: Option<Event>,
    /// The definition revision the relay reports for the served projection.
    pub definition_revision: Option<u64>,
}

/// Proof that a submitted migration was stored and served back byte-exactly.
///
/// Returned *only* after every verification check passes. The driver lane
/// treats this as the sole license to promote the agent to
/// [`RelayAuthoritative`](super::authority::RelayAuthority::RelayAuthoritative);
/// this module never performs that write itself.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct PromotionEvidence {
    /// The verified head event ID served by the relay.
    pub head_event_id: String,
    /// The verified CAS generation.
    pub generation: u64,
    /// The verified predecessor event ID (absent at genesis).
    pub previous_event_id: Option<String>,
    /// The verified definition projection event ID.
    pub definition_event_id: String,
    /// The verified instance projection event ID.
    pub instance_event_id: String,
    /// The verified definition revision.
    pub definition_revision: u64,
}

/// Proof that a deleted aggregate request was committed and read back exactly.
///
/// Deleted heads do not carry public projections or an active private body, so
/// their verification contract is intentionally smaller than promotion's but
/// just as strict about the submitted event and CAS metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletionEvidence {
    pub head_event_id: String,
    pub generation: u64,
    pub previous_event_id: String,
}

/// Build the next minimal deleted aggregate from verified relay-head evidence.
///
/// A tombstone carries no public projections or private active body. It advances
/// the same CAS chain by exactly one and is signed by the owner, so deletion can
/// use the aggregate route rather than legacy kind:5 mutation.
#[allow(dead_code)] // Consumed by the aggregate deletion driver in the next slice.
pub fn build_tombstone_event(
    owner_keys: &Keys,
    agent_pubkey: &str,
    current_generation: u64,
    current_private_event_id: &str,
    timestamp: &str,
    created_at: u64,
) -> Result<Event, MigrationError> {
    let agent = parse_pubkey("agent_pubkey", agent_pubkey)?;
    let previous = nostr::EventId::from_hex(current_private_event_id)
        .map_err(|e| MigrationError::InvalidInput(format!("private event id: {e}")))?;
    let generation = current_generation
        .checked_add(1)
        .ok_or_else(|| MigrationError::InvalidInput("aggregate generation overflow".into()))?;
    let payload = Payload {
        format: pma::FORMAT.to_string(),
        version: pma::VERSION,
        agent_pubkey: agent.to_hex(),
        owner_pubkey: owner_keys.public_key().to_hex(),
        generation,
        previous_event_id: Some(previous.to_hex()),
        state: State::Deleted,
        updated_at: timestamp.to_string(),
        active: None,
        deleted_at: Some(timestamp.to_string()),
        extensions: Default::default(),
    };
    pma::build_event(owner_keys, &payload, created_at).map_err(MigrationError::from)
}

/// Build a signed, inert kind:30179 migration candidate for one agent.
///
/// Assembles the encrypted aggregate payload from the record + keys + exact
/// signed projections + CAS coordinate, re-minting the owner→agent auth tag and
/// wrapping the backend in its versioned envelope. Gates on migration readiness
/// using the *actual* largest inserted codec value before sealing. Returns a
/// [`MigrationError`] on any inconsistency; never persists or promotes.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub fn build_migration_candidate<'a, I>(
    record: &ManagedAgentRecord,
    owner_keys: &Keys,
    agent_keys: &Keys,
    definition_event: Event,
    instance_event: Event,
    cas: &CasMetadata,
    advertised_nip11_tokens: I,
    created_at: u64,
) -> Result<MigrationCandidate, MigrationError>
where
    I: IntoIterator<Item = &'a str>,
{
    let owner_pubkey = owner_keys.public_key();
    let agent_pubkey = agent_keys.public_key();

    // The record's stored pubkey is the aggregate coordinate; the supplied
    // agent keys must derive it, or we would seal a payload the codec rejects.
    let record_agent = parse_pubkey("record.pubkey", &record.pubkey)?;
    if record_agent != agent_pubkey {
        return Err(MigrationError::InvalidInput(
            "agent keys do not derive record.pubkey".into(),
        ));
    }
    if owner_pubkey == agent_pubkey {
        return Err(MigrationError::InvalidInput(
            "owner and agent pubkeys must differ".into(),
        ));
    }

    // Bindings are only meaningful if the supplied projections are genuine
    // owner-signed events at the right coordinate. Fail fast before sealing.
    let definition_d =
        require_owner_projection("definition", &definition_event, KIND_PERSONA, &owner_pubkey)?;
    require_owner_projection(
        "instance",
        &instance_event,
        KIND_MANAGED_AGENT,
        &owner_pubkey,
    )?;

    // Re-mint the unconditional owner->agent attestation. The stored
    // record.auth_tag is deliberately ignored: a fresh mint cannot byte-match
    // it, and the codec requires an unconditional ("") attestation for this
    // exact owner. Never copy the stored string.
    let auth_tag = buzz_sdk_pkg::nip_oa::compute_auth_tag(owner_keys, &agent_pubkey, "")
        .map_err(|e| MigrationError::AuthTag(e.to_string()))?;

    let backend_value = serde_json::to_value(VersionedBackend::current(record.backend.clone()))
        .map_err(|e| MigrationError::Codec(format!("backend envelope: {e}")))?;

    let definition = DefinitionBinding {
        revision: cas.definition_revision,
        event_id: definition_event.id.to_hex(),
        content_sha256: pma::content_sha256(definition_event.content.as_bytes()),
        recovery: ProjectionRecoveryV1 {
            version: 1,
            signed_event: definition_event.clone(),
        },
    };
    let instance_projection = InstanceBinding {
        event_id: instance_event.id.to_hex(),
        content_sha256: pma::content_sha256(instance_event.content.as_bytes()),
        recovery: ProjectionRecoveryV1 {
            version: 1,
            signed_event: instance_event.clone(),
        },
    };

    let config = PrivateConfig {
        definition_coordinate: Some(format!("30175:{}:{definition_d}", owner_pubkey.to_hex())),
        relay_url: record.relay_url.clone(),
        agent_command_override: record.agent_command_override.clone(),
        agent_args: record.agent_args.clone(),
        idle_timeout_seconds: record.idle_timeout_seconds,
        max_turn_duration_seconds: record.max_turn_duration_seconds,
        env_vars: record.env_vars.clone().into_iter().collect(),
        backend: backend_value,
        backend_agent_id: record.backend_agent_id.clone(),
        team_id: record.team_id.clone(),
        persona_name_in_team: record.persona_name_in_team.clone(),
        relay_mesh: record
            .relay_mesh
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|e| MigrationError::Codec(format!("relay mesh envelope: {e}")))?,
    };

    let payload = Payload {
        format: pma::FORMAT.to_string(),
        version: pma::VERSION,
        agent_pubkey: agent_pubkey.to_hex(),
        owner_pubkey: owner_pubkey.to_hex(),
        generation: cas.generation,
        previous_event_id: cas.previous_event_id.clone(),
        state: State::Active,
        updated_at: record.updated_at.clone(),
        active: Some(ActivePayload {
            definition,
            instance_projection,
            identity: PrivateIdentity {
                private_key_nsec: agent_keys
                    .secret_key()
                    .to_bech32()
                    .map_err(|e| MigrationError::InvalidInput(format!("agent nsec encode: {e}")))?,
                auth_tag: Some(auth_tag),
            },
            config,
        }),
        deleted_at: None,
        extensions: Default::default(),
    };

    // Readiness gate: derive the ACTUAL largest inserted codec value (the two
    // recovery envelopes dominate) and the encrypted payload size, then let the
    // pure gate decide capability + size. Do not trust a caller number.
    let block = super::authority::assess_migration_readiness(
        serialized_len(&payload)?,
        largest_inserted_value_bytes(&payload)?,
        advertised_nip11_tokens,
    );
    if let Err(block) = block {
        return Err(MigrationError::Blocked(block));
    }

    // Seal + sign. build_event re-runs the codec's full payload validation, so
    // any semantic slip we made surfaces here rather than at the relay.
    let signed_event = pma::build_event(owner_keys, &payload, created_at)?;

    Ok(MigrationCandidate {
        signed_event,
        payload,
        definition_event,
        instance_event,
    })
}

/// Verify a relay read-back is a faithful, owner-signed copy of the candidate.
///
/// Runs, in order: decrypt+validate of the returned head; owner/agent/
/// generation/predecessor/state equality; binding event-id, content-hash, and
/// recovery equality against the returned signed projections; definition
/// revision equality; and source-vs-roundtrip equality for **carried field
/// classes only**. Returns [`PromotionEvidence`] only if every check passes.
#[allow(dead_code)]
pub fn verify_promotion(
    candidate: &MigrationCandidate,
    response: &AggregateResponse,
    owner_keys: &Keys,
) -> Result<PromotionEvidence, MigrationError> {
    // 1. The head must decrypt and self-validate under the owner key. This also
    //    re-checks both projection bindings inside the payload (signature, id,
    //    hash, coordinate) via the shared codec.
    let (envelope, roundtrip) = pma::validate_and_decrypt(&response.private_event, owner_keys)
        .map_err(|e| MigrationError::VerificationFailed(format!("head decrypt/validate: {e}")))?;

    let source = &candidate.payload;
    if !response.accepted {
        return Err(MigrationError::VerificationFailed(
            "relay did not accept aggregate".into(),
        ));
    }
    verify_eq(
        "response.event_id",
        &response.event_id,
        &response.private_event.id.to_hex(),
    )?;
    verify_eq(
        "response.generation",
        &response.generation,
        &source.generation,
    )?;
    verify_eq("response.state", &response.state.as_str(), &"active")?;

    let definition_event = response.definition_event.as_ref().ok_or_else(|| {
        MigrationError::VerificationFailed("read-back missing definition projection".into())
    })?;
    let instance_event = response.instance_event.as_ref().ok_or_else(|| {
        MigrationError::VerificationFailed("read-back missing instance projection".into())
    })?;

    if !response.private_event.verify_id() || !response.private_event.verify_signature() {
        return Err(MigrationError::VerificationFailed(
            "read-back head has invalid id or signature".into(),
        ));
    }
    if !definition_event.verify_id() || !definition_event.verify_signature() {
        return Err(MigrationError::VerificationFailed(
            "read-back definition has invalid id or signature".into(),
        ));
    }
    if !instance_event.verify_id() || !instance_event.verify_signature() {
        return Err(MigrationError::VerificationFailed(
            "read-back instance has invalid id or signature".into(),
        ));
    }

    // 2. CAS + identity metadata must echo the candidate exactly.
    verify_eq(
        "owner_pubkey",
        &roundtrip.owner_pubkey,
        &source.owner_pubkey,
    )?;
    verify_eq(
        "agent_pubkey",
        &roundtrip.agent_pubkey,
        &source.agent_pubkey,
    )?;
    verify_eq("generation", &roundtrip.generation, &source.generation)?;
    verify_eq(
        "previous_event_id",
        &roundtrip.previous_event_id,
        &source.previous_event_id,
    )?;
    if roundtrip.state != source.state {
        return Err(MigrationError::VerificationFailed("state differs".into()));
    }
    // The decrypted envelope's outer metadata already agreed with the inner
    // payload (validate_and_decrypt enforces it); assert it matches the source
    // generation too so a swapped-but-valid head cannot slip through.
    verify_eq(
        "envelope.generation",
        &envelope.generation,
        &source.generation,
    )?;

    let source_active = source
        .active
        .as_ref()
        .ok_or_else(|| MigrationError::VerificationFailed("source is not active".into()))?;
    let roundtrip_active = roundtrip
        .active
        .as_ref()
        .ok_or_else(|| MigrationError::VerificationFailed("read-back is not active".into()))?;

    // 3. The returned signed projections must be the exact events the bindings
    //    name — compare id + content hash + full recovery event, and check the
    //    returned projection events match the returned response events too.
    verify_binding_definition(source_active, roundtrip_active, definition_event)?;
    verify_binding_instance(source_active, roundtrip_active, instance_event)?;

    // 4. Definition revision the relay reports must match what we pinned.
    verify_eq(
        "definition_revision",
        &response.definition_revision,
        &Some(source_active.definition.revision),
    )?;

    // 5. Carried-class equality: the private config we sealed must round-trip
    //    byte-exact. Derived/transient/bookkeeping fields never enter the
    //    payload, so they are structurally impossible to diff here — the type
    //    only carries PrivateConfig, which is exactly the carried classes.
    if roundtrip_active.config != source_active.config {
        return Err(MigrationError::VerificationFailed(
            "carried private config differs".into(),
        ));
    }
    if roundtrip_active.identity != source_active.identity {
        return Err(MigrationError::VerificationFailed(
            "carried identity differs".into(),
        ));
    }

    Ok(PromotionEvidence {
        head_event_id: response.private_event.id.to_hex(),
        generation: source.generation,
        previous_event_id: source.previous_event_id.clone(),
        definition_event_id: source_active.definition.event_id.clone(),
        instance_event_id: source_active.instance_projection.event_id.clone(),
        definition_revision: source_active.definition.revision,
    })
}

/// Verify a relay read-back for an exact deleted aggregate request.
///
/// The submitted event is the immutable retry input retained by Desktop. The
/// response must return that byte-identical event and echo its deleted CAS head;
/// deleted heads must not grow public projections or a definition revision.
pub fn verify_deletion(
    submitted_event: &Event,
    response: &AggregateResponse,
    owner_keys: &Keys,
) -> Result<DeletionEvidence, MigrationError> {
    let (envelope, payload) = pma::validate_and_decrypt(submitted_event, owner_keys)
        .map_err(|e| MigrationError::VerificationFailed(format!("submitted tombstone: {e}")))?;

    let previous_event_id = payload.previous_event_id.clone().ok_or_else(|| {
        MigrationError::VerificationFailed("submitted deletion has no predecessor".into())
    })?;
    if payload.state != State::Deleted || payload.active.is_some() || payload.deleted_at.is_none() {
        return Err(MigrationError::VerificationFailed(
            "submitted aggregate is not a valid deletion".into(),
        ));
    }
    if !response.accepted {
        return Err(MigrationError::VerificationFailed(
            "relay did not accept aggregate deletion".into(),
        ));
    }
    if &response.private_event != submitted_event {
        return Err(MigrationError::VerificationFailed(
            "read-back deletion head differs from submitted event".into(),
        ));
    }
    verify_eq(
        "response.event_id",
        &response.event_id,
        &submitted_event.id.to_hex(),
    )?;
    verify_eq(
        "response.generation",
        &response.generation,
        &payload.generation,
    )?;
    verify_eq("response.state", &response.state.as_str(), &"deleted")?;
    if response.definition_event.is_some()
        || response.instance_event.is_some()
        || response.definition_revision.is_some()
    {
        return Err(MigrationError::VerificationFailed(
            "deleted read-back unexpectedly contains active projections".into(),
        ));
    }
    verify_eq(
        "envelope.generation",
        &envelope.generation,
        &payload.generation,
    )?;

    Ok(DeletionEvidence {
        head_event_id: submitted_event.id.to_hex(),
        generation: payload.generation,
        previous_event_id,
    })
}

fn verify_binding_definition(
    source: &ActivePayload,
    roundtrip: &ActivePayload,
    definition_event: &Event,
) -> Result<(), MigrationError> {
    verify_eq(
        "definition.event_id",
        &roundtrip.definition.event_id,
        &source.definition.event_id,
    )?;
    verify_eq(
        "definition.content_sha256",
        &roundtrip.definition.content_sha256,
        &source.definition.content_sha256,
    )?;
    if roundtrip.definition.recovery != source.definition.recovery {
        return Err(MigrationError::VerificationFailed(
            "definition recovery differs".into(),
        ));
    }
    // The response's standalone definition event must be the same one the
    // binding names, so a relay cannot serve a matching binding beside a
    // swapped public projection.
    if definition_event != &source.definition.recovery.signed_event
        || definition_event.id.to_hex() != source.definition.event_id
        || pma::content_sha256(definition_event.content.as_bytes())
            != source.definition.content_sha256
    {
        return Err(MigrationError::VerificationFailed(
            "served definition projection does not match binding".into(),
        ));
    }
    Ok(())
}

fn verify_binding_instance(
    source: &ActivePayload,
    roundtrip: &ActivePayload,
    instance_event: &Event,
) -> Result<(), MigrationError> {
    verify_eq(
        "instance.event_id",
        &roundtrip.instance_projection.event_id,
        &source.instance_projection.event_id,
    )?;
    verify_eq(
        "instance.content_sha256",
        &roundtrip.instance_projection.content_sha256,
        &source.instance_projection.content_sha256,
    )?;
    if roundtrip.instance_projection.recovery != source.instance_projection.recovery {
        return Err(MigrationError::VerificationFailed(
            "instance recovery differs".into(),
        ));
    }
    if instance_event != &source.instance_projection.recovery.signed_event
        || instance_event.id.to_hex() != source.instance_projection.event_id
        || pma::content_sha256(instance_event.content.as_bytes())
            != source.instance_projection.content_sha256
    {
        return Err(MigrationError::VerificationFailed(
            "served instance projection does not match binding".into(),
        ));
    }
    Ok(())
}

fn verify_eq<T: PartialEq + std::fmt::Debug>(
    label: &str,
    got: &T,
    expected: &T,
) -> Result<(), MigrationError> {
    if got != expected {
        return Err(MigrationError::VerificationFailed(format!(
            "{label} differs"
        )));
    }
    Ok(())
}

/// Serialized encrypted-plaintext size proxy: the payload JSON the codec seals.
fn serialized_len(payload: &Payload) -> Result<usize, MigrationError> {
    serde_json::to_vec(payload)
        .map(|bytes| bytes.len())
        .map_err(|e| MigrationError::Codec(format!("serialize payload: {e}")))
}

/// Largest single serialized codec `Value` the payload inserts. The projection
/// recovery envelopes (full signed events) dominate; the backend and any
/// extension values are also candidates. Mirrors what the codec's per-`Value`
/// size check (`MAX_VALUE_BYTES`) will measure.
fn largest_inserted_value_bytes(payload: &Payload) -> Result<usize, MigrationError> {
    let mut largest = 0usize;
    let mut consider = |value: &Value| -> Result<(), MigrationError> {
        let len = serde_json::to_vec(value)
            .map(|bytes| bytes.len())
            .map_err(|e| MigrationError::Codec(format!("serialize value: {e}")))?;
        largest = largest.max(len);
        Ok(())
    };
    if let Some(active) = &payload.active {
        consider(
            &serde_json::to_value(&active.definition.recovery)
                .map_err(|e| MigrationError::Codec(format!("definition recovery: {e}")))?,
        )?;
        consider(
            &serde_json::to_value(&active.instance_projection.recovery)
                .map_err(|e| MigrationError::Codec(format!("instance recovery: {e}")))?,
        )?;
        consider(&active.config.backend)?;
        if let Some(mesh) = &active.config.relay_mesh {
            consider(mesh)?;
        }
    }
    for value in payload.extensions.values() {
        consider(value)?;
    }
    Ok(largest)
}

fn parse_pubkey(label: &str, hex: &str) -> Result<PublicKey, MigrationError> {
    PublicKey::from_hex(hex)
        .map_err(|_| MigrationError::InvalidInput(format!("{label} is not a valid pubkey")))
}

/// Require a supplied projection to be a genuine owner-signed event at the
/// expected kind, returning its single non-empty `d` coordinate.
fn require_owner_projection(
    label: &str,
    event: &Event,
    expected_kind: u32,
    owner_pubkey: &PublicKey,
) -> Result<String, MigrationError> {
    if event.kind.as_u16() as u32 != expected_kind {
        return Err(MigrationError::InvalidInput(format!(
            "{label} projection has wrong kind"
        )));
    }
    if &event.pubkey != owner_pubkey {
        return Err(MigrationError::InvalidInput(format!(
            "{label} projection is not signed by the owner"
        )));
    }
    if !event.verify_id() || !event.verify_signature() {
        return Err(MigrationError::InvalidInput(format!(
            "{label} projection has an invalid id or signature"
        )));
    }
    let d_tags: Vec<&[String]> = event
        .tags
        .iter()
        .map(|tag| tag.as_slice())
        .filter(|parts| parts.first().map(String::as_str) == Some("d"))
        .collect();
    match d_tags.as_slice() {
        [parts] if parts.len() == 2 && !parts[1].is_empty() => Ok(parts[1].clone()),
        _ => Err(MigrationError::InvalidInput(format!(
            "{label} projection must have exactly one non-empty d tag"
        ))),
    }
}

/// The transport half of this seam: submits retained aggregates over HTTP and
/// verifies the read-back through [`verify_promotion`]. Kept in a sibling
/// module so the pure builder/verifier above stays free of HTTP/persistence.
pub(crate) mod activation;
mod driver;

#[cfg(test)]
mod tests;
