//! Per-agent relay-authority evidence and the exhaustive field-classification
//! table that governs which [`ManagedAgentRecord`](super::types::ManagedAgentRecord)
//! fields cross to the relay as canonical private managed-agent (kind:30179)
//! state.
//!
//! This module is the **safety foundation** for the relay-canonical managed
//! agent migration. It defines *state and classification only*: it neither
//! enables migration nor performs any destructive local mutation. The default
//! for every existing record is [`RelayAuthority::LegacyOnly`], so an
//! upgrade that predates any migration deserializes unchanged and keeps local
//! JSON + keyring authoritative.

use serde::{Deserialize, Serialize};

/// Per-agent relay-canonical authority: where an agent's canonical runnable
/// configuration currently lives, plus (when authoritative) the verified head
/// evidence.
///
/// Represented as a single internally-tagged enum so **impossible states are
/// unrepresentable**: `RelayAuthoritative` structurally carries its evidence
/// and `LegacyOnly` structurally cannot. There is no way to persist
/// "authoritative but no evidence" or "legacy but with a stale head", which
/// would otherwise let corrupt evidence silently disable boot reconcile.
///
/// Serialized inline on [`ManagedAgentRecord`](super::types::ManagedAgentRecord)
/// via `#[serde(default)]`, so a store written by a build that predates this
/// field deserializes as [`RelayAuthority::LegacyOnly`] — the only safe
/// default. No record is ever silently promoted; promotion happens exclusively
/// through the (not-yet-enabled) verified migration path.
///
/// Persisted JSON shape (internally tagged on `authority`, so it never nests a
/// `state` inside a `state`):
/// ```json
/// { "authority": "legacy_only" }
/// { "authority": "relay_authoritative", "evidence": { "generation": 7, "private_event_id": "…" } }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "authority", rename_all = "snake_case")]
pub enum RelayAuthority {
    /// Local `managed-agents.json` + OS keyring remain canonical. Boot
    /// reconcile still republishes this record's public projection.
    #[default]
    LegacyOnly,
    /// The relay kind:30179 aggregate is canonical for this agent. The local
    /// record is a derived compatibility cache and MUST NOT be republished by
    /// boot reconcile. Carries the verified head [`RelayAuthorityEvidence`].
    RelayAuthoritative { evidence: RelayAuthorityEvidence },
    /// Deletion has been enqueued for this relay-canonical agent but the
    /// authoritative tombstone has not yet been verified at the relay. The
    /// record is kept on disk in this terminal-pending state so a crash between
    /// enqueue and verified erase retries cleanly — and so the head
    /// [`RelayAuthorityEvidence`] needed to (re)sign the tombstone survives.
    /// Like [`RelayAuthoritative`](Self::RelayAuthoritative), this record MUST
    /// NOT be republished by boot reconcile: doing so could resurrect an agent
    /// that is mid-deletion.
    Deleting { evidence: RelayAuthorityEvidence },
}

/// Verified evidence that an agent has become relay-authoritative.
///
/// Present only inside [`RelayAuthority::RelayAuthoritative`], set after the
/// migration path has committed a kind:30179 head at `generation` /
/// `private_event_id` and read it back — this is the durable record of *which*
/// head the local cache mirrors, so a later mutation can supply the correct
/// predecessor for compare-and-swap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayAuthorityEvidence {
    /// CAS generation of the authoritative kind:30179 head this cache mirrors.
    pub generation: u64,
    /// Event id of the authoritative kind:30179 head. The predecessor for the
    /// next compare-and-swap mutation.
    pub private_event_id: String,
}

impl RelayAuthority {
    /// The default authority for a local-only agent.
    pub fn legacy() -> Self {
        Self::LegacyOnly
    }

    /// Construct a verified relay-authoritative authority from its head
    /// evidence. This is the only way to reach the authoritative state, so
    /// evidence is always present.
    ///
    /// Consumed by the verified migration path (sibling lane), not yet wired;
    /// exercised today by this module's tests.
    #[allow(dead_code)]
    pub fn relay_authoritative(evidence: RelayAuthorityEvidence) -> Self {
        Self::RelayAuthoritative { evidence }
    }

    /// Construct the terminal pending-deletion authority from the verified head
    /// evidence being tombstoned. Reached only from the delete path, which
    /// captures the evidence from the record's prior relay-authoritative state.
    #[allow(dead_code)]
    pub fn deleting(evidence: RelayAuthorityEvidence) -> Self {
        Self::Deleting { evidence }
    }

    /// Whether the relay is canonical for this agent. When `true`, boot
    /// reconcile must NOT republish the record's public projection.
    ///
    /// Consumed by the boot-reconcile gate (sibling lane), not yet wired.
    #[allow(dead_code)]
    pub fn is_relay_authoritative(&self) -> bool {
        matches!(self, Self::RelayAuthoritative { .. })
    }

    /// Whether the relay owns this agent's canonical state — either promoted
    /// ([`RelayAuthoritative`](Self::RelayAuthoritative)) or mid-deletion
    /// ([`Deleting`](Self::Deleting)). Boot reconcile must NOT republish the
    /// public projection in either case; a `Deleting` record left to reconcile
    /// would resurrect an agent whose tombstone is still confirming.
    #[allow(dead_code)]
    pub fn is_relay_canonical(&self) -> bool {
        matches!(
            self,
            Self::RelayAuthoritative { .. } | Self::Deleting { .. }
        )
    }

    /// Whether deletion has been enqueued and is awaiting verified relay
    /// confirmation.
    #[allow(dead_code)]
    pub fn is_deleting(&self) -> bool {
        matches!(self, Self::Deleting { .. })
    }

    /// The verified head evidence, present whenever the relay is canonical
    /// ([`RelayAuthoritative`](Self::RelayAuthoritative) or
    /// [`Deleting`](Self::Deleting)).
    ///
    /// Consumed by the compare-and-swap mutation path (sibling lane), not yet
    /// wired.
    #[allow(dead_code)]
    pub fn evidence(&self) -> Option<&RelayAuthorityEvidence> {
        match self {
            Self::RelayAuthoritative { evidence } | Self::Deleting { evidence } => Some(evidence),
            Self::LegacyOnly => None,
        }
    }
}

/// Current version of the `backend` field's encrypted-payload representation.
///
/// [`BackendKind`](super::types::BackendKind) is `PrivateCanonical`: it is
/// carried byte-exact into the kind:30179 payload and diffed at verification.
/// Its serde shape (`{"type":"provider","id":…,"config":…}`) is therefore a
/// wire contract — a future variant rename or field change would make an old
/// device's stored value mismatch a new device's re-encode and block migration
/// with no diagnostic. Wrapping it in a versioned envelope makes the shape
/// explicit and lets the migration codec reject/upgrade an unknown version
/// deterministically instead of silently mis-diffing.
pub const BACKEND_PAYLOAD_VERSION: u64 = 1;

/// Versioned envelope for the `backend` field inside the kind:30179 payload.
///
/// Serializes as `{"version":1,"backend":{…BackendKind…}}`. The migration codec
/// carries + verifies this envelope, not a bare `BackendKind`, so a shape
/// change bumps `version` and is caught explicitly rather than surfacing as an
/// opaque byte mismatch.
///
/// Foundation type — the migration payload codec (sibling lane) is the
/// consumer; only this module's tests exercise it today.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct VersionedBackend {
    /// Payload schema version. Migration rejects an envelope whose version it
    /// does not understand rather than mis-diffing an unexpected shape.
    pub version: u64,
    /// The carried backend configuration at that version.
    pub backend: super::types::BackendKind,
}

#[allow(dead_code)]
impl VersionedBackend {
    /// Wrap a backend in the current payload envelope.
    pub fn current(backend: super::types::BackendKind) -> Self {
        Self {
            version: BACKEND_PAYLOAD_VERSION,
            backend,
        }
    }
}

/// How a durable [`ManagedAgentRecord`](super::types::ManagedAgentRecord) field
/// relates to the relay kind:30179 aggregate during migration.
///
/// Every persisted record field is assigned exactly one class by
/// [`classify_field`]. The class decides two things during migration:
///   1. whether the field's value must be *carried* into the encrypted
///      kind:30179 payload (or a bound public projection), and
///   2. whether the field participates in the *byte-exact verification* that
///      gates promotion to [`RelayAuthority::RelayAuthoritative`].
///
/// Getting this wrong is the single largest "does an existing agent survive
/// migration intact?" risk: a durable field misclassified as transient is
/// silently lost; a derived/deprecated field misclassified as carried causes
/// spurious verification mismatches that block migration forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Consumed by the migration verification path (sibling lane); today only tests read it.
pub enum FieldClass {
    /// Portable canonical secret/config carried in the encrypted kind:30179
    /// payload and verified byte-exact. E.g. `private_key_nsec`, `relay_url`.
    PrivateCanonical,
    /// Canonical remote-identity value carried in kind:30179, but the concrete
    /// resource must be re-validated on each device before use and MUST NOT be
    /// blindly applied from the relay. Carried; verified for equality against
    /// the source, not applied to the device. E.g. `backend_agent_id`.
    DeviceValidated,
    /// Authoritative for a definition-*less* agent and carried through the
    /// bound kind:30175 definition projection (materialized at migration if the
    /// agent had none). For a definition-*linked* agent this mirrors the
    /// definition and is not independently canonical. Verified via the
    /// definition binding, not the private payload.
    DefinitionProjected,
    /// Authoritative instance behavior carried through the bound kind:30177
    /// public instance projection. Verified via the instance binding.
    InstanceProjected,
    /// Deprecated or re-derived-at-spawn snapshot. NOT carried and MUST NOT be
    /// diffed at verification — its stored value can legitimately differ from a
    /// freshly derived one, so diffing it would false-positive and block
    /// migration. E.g. `acp_command`, `mcp_command`, `turn_timeout_seconds`.
    DerivedNotCarried,
    /// Machine-local runtime/telemetry state OR device-local config that no
    /// codec slot carries (verified against the actual 30175/30177 builders).
    /// Never carried, never diffed, never reconstructed from the relay. E.g.
    /// `runtime_pid`, `last_error`, `start_on_app_launch`, `provider_binary_path`.
    TransientLocal,
    /// Local relay-authority bookkeeping introduced by this module. Never
    /// carried into the payload (it describes the payload); never diffed.
    AuthorityBookkeeping,
}

/// Exhaustive classification of every durable
/// [`ManagedAgentRecord`](super::types::ManagedAgentRecord) field by its serde
/// name.
///
/// The companion test `field_classification_is_exhaustive` asserts this table
/// covers exactly the record's serialized field set, so a future field added
/// to the record without a classification here fails the build's tests rather
/// than silently defaulting to "lost on migration".
#[allow(dead_code)] // Test-facing accessor; migration path reads FIELD_CLASSIFICATIONS directly (sibling lane).
pub fn classify_field(serde_field_name: &str) -> Option<FieldClass> {
    FIELD_CLASSIFICATIONS
        .iter()
        .find(|(name, _)| *name == serde_field_name)
        .map(|(_, class)| *class)
}

/// Single source of truth for the field → class mapping. Both
/// [`classify_field`] and the exhaustiveness test read this slice, so the class
/// table and the record's field set cannot drift apart without a test failure.
#[allow(dead_code)] // Consumed by the migration verification path (sibling lane); today only tests read it.
pub(crate) const FIELD_CLASSIFICATIONS: &[(&str, FieldClass)] = {
    use FieldClass::*;
    &[
        // --- Identity + private canonical config (encrypted kind:30179) ---
        ("pubkey", PrivateCanonical), // the d-tag coordinate itself
        ("private_key_nsec", PrivateCanonical),
        ("relay_url", PrivateCanonical),
        ("agent_command_override", PrivateCanonical),
        ("agent_args", PrivateCanonical),
        ("idle_timeout_seconds", PrivateCanonical),
        ("max_turn_duration_seconds", PrivateCanonical),
        ("env_vars", PrivateCanonical),
        ("backend", PrivateCanonical),
        ("team_id", PrivateCanonical),
        ("persona_name_in_team", PrivateCanonical),
        ("relay_mesh", PrivateCanonical),
        // --- Carried, but device-validated (never blindly applied) ---
        // A durable REMOTE identity that is meaningful across devices, so it
        // rides the encrypted kind:30179 payload and is verified-not-applied.
        ("backend_agent_id", DeviceValidated),
        // --- Definition-projected (kind:30175). Authoritative only when the
        //     agent is definition-less; else mirrors the linked definition. ---
        ("system_prompt", DefinitionProjected),
        ("model", DefinitionProjected),
        ("provider", DefinitionProjected),
        ("persona_source_version", DefinitionProjected),
        ("slug", DefinitionProjected),
        ("runtime", DefinitionProjected),
        ("name_pool", DefinitionProjected),
        ("is_builtin", DefinitionProjected),
        ("is_active", DefinitionProjected),
        ("display_name", DefinitionProjected),
        ("avatar_url", DefinitionProjected),
        ("source_team", DefinitionProjected),
        ("source_team_persona_slug", DefinitionProjected),
        ("catalog_source", DefinitionProjected),
        ("persona_id", DefinitionProjected),
        ("definition_respond_to", DefinitionProjected),
        ("definition_respond_to_allowlist", DefinitionProjected),
        ("definition_parallelism", DefinitionProjected),
        // --- Instance-projected (kind:30177) ---
        ("name", InstanceProjected),
        ("parallelism", InstanceProjected),
        ("respond_to", InstanceProjected),
        ("respond_to_allowlist", InstanceProjected),
        // --- Deprecated / re-derived at spawn or migration: carry NOT, diff NOT ---
        ("acp_command", DerivedNotCarried),
        ("agent_command", DerivedNotCarried),
        ("mcp_command", DerivedNotCarried),
        ("turn_timeout_seconds", DerivedNotCarried),
        ("shared", DerivedNotCarried), // legacy, `skip_serializing`
        // NIP-OA owner->agent authorization tag. Deterministically COMPUTED
        // from the owner keys + agent pubkey (compute_auth_tag), never a
        // free-standing secret. Migration MUST RE-MINT it (owner re-signs a
        // fresh owner->agent tag for the canonical record), never preserve or
        // trust the stored string — a re-mint would not byte-match the stored
        // value, so carrying + diffing it would false-positive and block
        // migration forever. Hence DerivedNotCarried, not PrivateCanonical.
        ("auth_tag", DerivedNotCarried),
        // --- Bookkeeping timestamps carried for audit but not conflict-resolving ---
        ("created_at", InstanceProjected),
        ("updated_at", InstanceProjected),
        // --- Transient machine-local: NO codec slot carries these today
        //     (verified against PersonaEventContent/ManagedAgentEventContent
        //     builders + the 30177 exclusion asserts). Classifying them as
        //     projected would promise a preservation the codec cannot provide.
        //     ---
        // Runtime/telemetry:
        ("runtime_pid", TransientLocal),
        ("last_started_at", TransientLocal),
        ("last_stopped_at", TransientLocal),
        ("last_exit_code", TransientLocal),
        ("last_error", TransientLocal),
        ("last_error_code", TransientLocal),
        // Device-local launch preferences — 30177 does NOT carry them:
        ("start_on_app_launch", TransientLocal),
        ("auto_restart_on_config_change", TransientLocal),
        // Absolute machine paths — meaningless across devices, carried by
        // nothing; re-derived per install:
        ("provider_binary_path", TransientLocal),
        ("persona_team_dir", TransientLocal),
        // --- Relay-authority bookkeeping introduced by this module ---
        ("relay_authority", AuthorityBookkeeping),
    ]
};

/// Maximum NIP-44 v2 plaintext size for the encrypted kind:30179 payload, in
/// bytes. A serialized migration payload larger than this cannot be locked, so
/// the agent stays [`RelayAuthority::LegacyOnly`]. Mirrors
/// `buzz_core_pkg::engram::NIP44_PLAINTEXT_MAX` (65_535); duplicated as a local
/// constant so the taxonomy is self-describing and unit-testable without the
/// crypto dependency.
pub const MIGRATION_PAYLOAD_MAX_BYTES: usize = 65_535;

/// Maximum size, in bytes, of a single serialized `Value` the private
/// managed-agent codec accepts (each extension / recovery / config entry the
/// payload builder inserts). This is the per-`Value` cap the codec enforces —
/// it is NOT an OS-keyring limit and NOT a combined recovery blob. Any single
/// codec value larger than this keeps the agent
/// [`RelayAuthority::LegacyOnly`]. Tracks the relay-side
/// `private_managed_agent::MAX_VALUE_BYTES` (32_768); duplicated locally until
/// the shared codec crate is a dependency of Desktop.
pub const MIGRATION_MAX_VALUE_BYTES: usize = 32_768;

/// The exact versioned NIP-11 capability token a relay must advertise before an
/// agent may migrate. The relay deliberately advertises *aggregate* semantics
/// (that it will maintain the kind:30179 aggregate and serve a readable head),
/// not mere kind acceptance — so gating checks for this precise token, never a
/// generic "accepts the kind" boolean.
pub const NIP_PMA_AGGREGATE_TOKEN: &str = "nip-pma-aggregate-v1";

/// A terminal reason an agent cannot migrate to relay-canonical authority on
/// the current attempt and MUST remain [`RelayAuthority::LegacyOnly`].
///
/// This is the *decision*, not the storage: it is the value
/// [`assess_migration_readiness`] returns so the migration driver can stop and
/// record why. Persisting it durably is the job of the migration record/state
/// in the driver lane (which owns the store); the `LegacyOnly` variant here
/// deliberately carries no reason, so this type makes no persistence claim it
/// cannot back.
///
/// Each variant is *terminal* for the current attempt: migration stops and
/// NEVER drives a retry-loop — retrying an oversize value or a relay that
/// lacks the capability just burns cycles and spams the relay. Migration is
/// re-attempted only when the underlying input changes (a value shrinks, the
/// relay begins advertising the capability), which is an external event, not a
/// timer.
///
/// Foundation type — the migration driver (sibling lane) is the consumer;
/// today only this module's tests exercise it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum MigrationBlock {
    /// The serialized encrypted payload exceeds [`MIGRATION_PAYLOAD_MAX_BYTES`].
    PayloadTooLarge { bytes: usize },
    /// A single serialized codec `Value` (extension / recovery / config entry)
    /// exceeds [`MIGRATION_MAX_VALUE_BYTES`].
    CodecValueTooLarge { bytes: usize },
    /// The relay's NIP-11 document does not advertise the exact
    /// [`NIP_PMA_AGGREGATE_TOKEN`] aggregate capability, so a published head
    /// could never be maintained and read back to verify. Stay legacy until the
    /// relay advertises it.
    RelayCapabilityAbsent,
}

impl MigrationBlock {
    /// A self-describing reason string the migration driver can surface or log
    /// when it stops. This is a diagnostic rendering of the decision, not a
    /// persistence mechanism — the variant itself is the signal.
    #[allow(dead_code)]
    pub fn reason(&self) -> String {
        match self {
            Self::PayloadTooLarge { bytes } => format!(
                "migration payload is {bytes} bytes; exceeds the \
                 {MIGRATION_PAYLOAD_MAX_BYTES}-byte encrypted limit"
            ),
            Self::CodecValueTooLarge { bytes } => format!(
                "a migration codec value is {bytes} bytes; exceeds the \
                 {MIGRATION_MAX_VALUE_BYTES}-byte per-value limit"
            ),
            Self::RelayCapabilityAbsent => format!(
                "relay does not advertise the {NIP_PMA_AGGREGATE_TOKEN} \
                 aggregate capability (NIP-11)"
            ),
        }
    }
}

/// Pure readiness gate: decide whether an agent MAY migrate given the concrete
/// encrypted-payload size, the largest single codec `Value` size, and the set
/// of NIP-11 capability tokens the target relay advertises.
///
/// Returns `Ok(())` only when every terminal condition is clear. On any
/// [`MigrationBlock`] the caller MUST keep the agent
/// [`RelayAuthority::LegacyOnly`] and NOT retry until an input changes. Size
/// boundaries are inclusive-safe: exactly-at-limit is allowed; strictly-over is
/// blocked. Capability is checked FIRST — a relay that cannot maintain the
/// aggregate can never verify a head, so size checks would be moot.
///
/// Foundation function — the migration driver (sibling lane) is the consumer.
#[allow(dead_code)]
pub fn assess_migration_readiness<'a, I>(
    payload_bytes: usize,
    max_codec_value_bytes: usize,
    advertised_nip11_tokens: I,
) -> Result<(), MigrationBlock>
where
    I: IntoIterator<Item = &'a str>,
{
    let relay_supports_aggregate = advertised_nip11_tokens
        .into_iter()
        .any(|token| token == NIP_PMA_AGGREGATE_TOKEN);
    if !relay_supports_aggregate {
        return Err(MigrationBlock::RelayCapabilityAbsent);
    }
    if payload_bytes > MIGRATION_PAYLOAD_MAX_BYTES {
        return Err(MigrationBlock::PayloadTooLarge {
            bytes: payload_bytes,
        });
    }
    if max_codec_value_bytes > MIGRATION_MAX_VALUE_BYTES {
        return Err(MigrationBlock::CodecValueTooLarge {
            bytes: max_codec_value_bytes,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
