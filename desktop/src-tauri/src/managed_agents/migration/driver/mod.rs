//! Desktop PMA aggregate submit/retry driver.
//!
//! This is the transport half of the relay-canonical migration seam. The pure
//! [builder/verifier](super) turns a hydrated record into a signed candidate
//! and gates the relay read-back; the durable [retention](crate::managed_agents::retention)
//! layer persists one immutable request per CAS generation. This driver is the
//! only code that moves a retained request across the wire: it validates the
//! retained row against its exact JSON before egress, POSTs those bytes, and
//! returns verified evidence plus the immutable attempt identity. The caller
//! owns authority/cache persistence and only then compare-and-clears the row.
//!
//! Design invariants:
//!   * **Exact bytes on the wire.** The body is `request_json` verbatim — the
//!     driver never re-serializes it, so a stored request and the request the
//!     relay authenticates are the same bytes. The verification source
//!     ([`MigrationCandidate`](super::MigrationCandidate)) is reconstructed from
//!     those same bytes (parse the events, decrypt the head under the owner
//!     key), so there is no candidate-vs-wire drift and no crypto duplication.
//!   * **Fresh owner NIP-98 per attempt.** Each submission mints a new
//!     [`build_nip98_auth_header_for_keys`](crate::relay::build_nip98_auth_header_for_keys)
//!     header (unique nonce), so a retry never replays a stale token.
//!   * **Caller-owned confirmation.** Successful verification returns the exact
//!     retained attempt identity. This transport never clears `pending_sync`;
//!     the caller first persists relay authority/cache and then compare-and-clears.
//!   * **Errors preserve retry.** Every failure path persists a diagnostic via
//!     [`record_managed_agent_aggregate_error`](crate::managed_agents::retention::record_managed_agent_aggregate_error)
//!     and leaves `pending_sync = 1`.

use std::path::Path;

use buzz_core_pkg::private_managed_agent::Payload;
use nostr::{Event, Keys};
use reqwest::Method;
use serde::Deserialize;

use super::{
    verify_deletion, verify_promotion, AggregateResponse, DeletionEvidence, MigrationCandidate,
    PromotionEvidence,
};
use crate::managed_agents::retention::{
    get_retained_managed_agent_aggregate, record_managed_agent_aggregate_error,
};

/// The route the relay mounts for atomic PMA aggregate commits. NIP-98 is
/// signed against this exact path (see `buzz-relay` router).
const AGGREGATE_PATH: &str = "/api/managed-agents/aggregate";

/// The wire body persisted as `request_json` and POSTed verbatim.
///
/// Mirrors the relay's `AggregateBody`; used here only to reconstruct the
/// verification candidate from the retained bytes, never to re-serialize the
/// request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedAggregateBody {
    private_event: Event,
    #[serde(default)]
    definition_event: Option<Event>,
    #[serde(default)]
    instance_event: Option<Event>,
    #[serde(default)]
    #[allow(dead_code)] // Bound into the head payload at build time; the relay re-derives it.
    expected_definition_revision: Option<u64>,
}

/// Immutable identity of the retained attempt that produced verified evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RetainedAttempt {
    pub owner_pubkey: String,
    pub agent_pubkey: String,
    pub generation: u64,
    pub private_event_id: String,
    pub state: String,
    /// Source record revision bound inside the encrypted retained payload.
    pub source_updated_at: String,
}

/// What one drive of a retained aggregate resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Consumed by the boot/reconcile lane (sibling); today only tests read it.
pub(crate) enum SubmitOutcome {
    /// No pending aggregate row for this agent — nothing to submit.
    Nothing,
    /// The relay served back a faithful active aggregate. Persistence and
    /// compare-and-clear remain the caller's responsibility.
    Verified {
        attempt: RetainedAttempt,
        evidence: PromotionEvidence,
    },
    /// The relay served back a faithful deleted aggregate (tombstone). The
    /// caller erases local record/key, durably marks local authority applied,
    /// then compare-and-clears the retry.
    VerifiedDeletion {
        attempt: RetainedAttempt,
        evidence: DeletionEvidence,
    },
    /// The attempt failed; a diagnostic was persisted and retry is preserved.
    Retained { error: String },
}

/// Submit (or retry) the latest retained aggregate for one owner→agent pair.
///
/// Reads the durable row, validates it against its strict `request_json` before
/// any network I/O, POSTs those exact bytes with fresh owner-signed NIP-98 auth,
/// strict-deserializes and verifies the response, then returns evidence with the
/// exact attempt identity. Every failure persists an exact-attempt diagnostic;
/// success deliberately leaves retry pending for caller-owned persistence and
/// compare-and-clear ordering.
#[allow(dead_code)] // Consumed by the boot/reconcile lane (sibling); exercised by this module's tests.
pub(crate) async fn submit_retained_aggregate(
    http_client: &reqwest::Client,
    relay_api_base_url: &str,
    db_path: &Path,
    owner_keys: &Keys,
    owner_pubkey: &str,
    agent_pubkey: &str,
) -> Result<SubmitOutcome, String> {
    let row = {
        let conn = crate::managed_agents::retention::open_retention_db(db_path)?;
        match get_retained_managed_agent_aggregate(&conn, owner_pubkey, agent_pubkey)? {
            Some(row) if row.pending_sync => row,
            _ => return Ok(SubmitOutcome::Nothing),
        }
    };

    // Fail-fast guard: the retained head id/generation is what we will confirm.
    // Capture them before any network work so a diagnostic always names the
    // exact attempt.
    let generation = row.generation;
    let private_event_id = row.private_event_id.clone();

    let record_failure = |error: String| -> Result<SubmitOutcome, String> {
        // A best-effort diagnostic write must not mask the real error; if the
        // update itself fails we still surface the original failure.
        if let Ok(conn) = crate::managed_agents::retention::open_retention_db(db_path) {
            let _ = record_managed_agent_aggregate_error(
                &conn,
                owner_pubkey,
                agent_pubkey,
                generation,
                &private_event_id,
                &error,
            );
        }
        Ok(SubmitOutcome::Retained { error })
    };

    // Branch on the retained state. Both paths validate the reconstructed head
    // against its coordinate BEFORE egress, so malformed or coordinate-drifted
    // disk bytes never leave the device.
    match row.state.as_str() {
        "active" => {
            let candidate = match reconstruct_candidate(row.request_json.as_bytes(), owner_keys) {
                Ok(candidate) => candidate,
                Err(error) => return record_failure(error),
            };
            if candidate.payload.state != buzz_core_pkg::private_managed_agent::State::Active
                || candidate.payload.generation != generation
                || candidate.signed_event.id.to_hex() != private_event_id
                || candidate.payload.owner_pubkey != owner_pubkey
                || candidate.payload.agent_pubkey != agent_pubkey
            {
                return record_failure(
                    "retained active request does not match its owner/agent/generation/event/state coordinate"
                        .to_string(),
                );
            }

            let response = match submit_to_relay(
                http_client,
                relay_api_base_url,
                owner_keys,
                row.request_json.as_bytes(),
            )
            .await
            {
                Ok(response) => response,
                Err(error) => return record_failure(error),
            };

            let evidence = match verify_promotion(&candidate, &response, owner_keys) {
                Ok(evidence) => evidence,
                Err(error) => return record_failure(format!("verification failed: {error:?}")),
            };

            // The relay's committed head must be the exact generation/event we
            // retained; confirming a different coordinate would desync durable
            // state from the relay. verify_promotion already proved the head is
            // a faithful copy, so a mismatch here is a protocol violation.
            if evidence.generation != generation || evidence.head_event_id != private_event_id {
                return record_failure(format!(
                    "read-back coordinate {}:{} does not match retained {generation}:{private_event_id}",
                    evidence.generation, evidence.head_event_id
                ));
            }

            let source_updated_at = candidate.payload.updated_at.clone();
            Ok(SubmitOutcome::Verified {
                attempt: RetainedAttempt {
                    owner_pubkey: row.owner_pubkey,
                    agent_pubkey: row.agent_pubkey,
                    generation,
                    private_event_id,
                    state: row.state,
                    source_updated_at,
                },
                evidence,
            })
        }
        "deleted" => {
            let (event, payload) =
                match reconstruct_deletion(row.request_json.as_bytes(), owner_keys) {
                    Ok(parsed) => parsed,
                    Err(error) => return record_failure(error),
                };
            // Mirror the active branch: validate the FULL decrypted coordinate
            // against the retained row before egress, not just the event id. A
            // drifted owner/agent/generation (or a tombstone missing its chain
            // predecessor) must never leave the device. `reconstruct_deletion`
            // already proved state=Deleted / no active body / deleted_at present
            // / null expected-definition-revision.
            if event.id.to_hex() != private_event_id
                || payload.generation != generation
                || payload.owner_pubkey != owner_pubkey
                || payload.agent_pubkey != agent_pubkey
                || payload.previous_event_id.is_none()
            {
                return record_failure(
                    "retained deleted request does not match its owner/agent/generation/event/predecessor coordinate"
                        .to_string(),
                );
            }
            let source_updated_at = payload.updated_at.clone();

            let response = match submit_to_relay(
                http_client,
                relay_api_base_url,
                owner_keys,
                row.request_json.as_bytes(),
            )
            .await
            {
                Ok(response) => response,
                Err(error) => return record_failure(error),
            };

            let evidence = match verify_deletion(&event, &response, owner_keys) {
                Ok(evidence) => evidence,
                Err(error) => {
                    return record_failure(format!("deletion verification failed: {error:?}"))
                }
            };
            if evidence.generation != generation || evidence.head_event_id != private_event_id {
                return record_failure(format!(
                    "deleted read-back coordinate {}:{} does not match retained {generation}:{private_event_id}",
                    evidence.generation, evidence.head_event_id
                ));
            }

            Ok(SubmitOutcome::VerifiedDeletion {
                attempt: RetainedAttempt {
                    owner_pubkey: row.owner_pubkey,
                    agent_pubkey: row.agent_pubkey,
                    generation,
                    private_event_id,
                    state: row.state,
                    source_updated_at,
                },
                evidence,
            })
        }
        other => record_failure(format!("retained aggregate has unknown state {other:?}")),
    }
}

/// POST the exact request bytes with fresh owner-signed NIP-98 auth and
/// strict-deserialize the aggregate response.
async fn submit_to_relay(
    http_client: &reqwest::Client,
    relay_api_base_url: &str,
    owner_keys: &Keys,
    body: &[u8],
) -> Result<AggregateResponse, String> {
    crate::egress_guard::assert_no_key_backup_bytes(body, "managed-agent aggregate submit")?;
    crate::relay_admission::wait_for_rate_limit().await;

    let url = format!(
        "{}{AGGREGATE_PATH}",
        relay_api_base_url.trim_end_matches('/')
    );
    let auth_header =
        crate::relay::build_nip98_auth_header_for_keys(owner_keys, &Method::POST, &url, body)?;

    let response = http_client
        .post(&url)
        .header("Authorization", auth_header)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| crate::relay::classify_request_error(&e))?;

    if !response.status().is_success() {
        let status = response.status();
        let message = crate::relay::relay_error_message(response).await;
        return Err(if status == reqwest::StatusCode::CONFLICT {
            format!("conflict: {message}")
        } else {
            message
        });
    }

    crate::relay::parse_json_response::<AggregateResponse>(response).await
}

/// Rebuild the verification [`MigrationCandidate`] from the retained request
/// bytes: parse the three signed events and decrypt the head under the owner
/// key. The result is the exact source the relay was asked to store, so
/// verification compares like against like.
fn reconstruct_candidate(body: &[u8], owner_keys: &Keys) -> Result<MigrationCandidate, String> {
    let parsed: RetainedAggregateBody = serde_json::from_slice(body)
        .map_err(|e| format!("retained request json is not a valid aggregate body: {e}"))?;
    let definition_event = parsed
        .definition_event
        .ok_or_else(|| "retained request is missing its definition projection".to_string())?;
    let instance_event = parsed
        .instance_event
        .ok_or_else(|| "retained request is missing its instance projection".to_string())?;

    let expected_definition_revision = parsed.expected_definition_revision.ok_or_else(|| {
        "retained active request is missing expected_definition_revision".to_string()
    })?;
    let (_, payload) = buzz_core_pkg::private_managed_agent::validate_and_decrypt(
        &parsed.private_event,
        owner_keys,
    )
    .map_err(|e| format!("retained head does not decrypt under the owner key: {e}"))?;
    let payload_revision = payload
        .active
        .as_ref()
        .ok_or_else(|| "retained active request head has no active payload".to_string())?
        .definition
        .revision;
    if expected_definition_revision != payload_revision {
        return Err(format!(
            "retained expected definition revision {expected_definition_revision} does not match head {payload_revision}"
        ));
    }

    Ok(MigrationCandidate {
        signed_event: parsed.private_event,
        payload,
        definition_event,
        instance_event,
    })
}

/// Rebuild the verification tombstone from the retained deleted request bytes:
/// parse the single signed private event and decrypt it under the owner key.
///
/// A deletion carries no public projections or active body, so — unlike
/// [`reconstruct_candidate`] — the definition/instance projections are absent by
/// contract; their presence would mean the retained bytes are not a valid
/// tombstone. A tombstone is also minted with a null `expected_definition_revision`
/// (there is no active head to gate against), so a present revision means the
/// bytes are not a valid deletion. Returns the signed head plus its decrypted
/// payload; the caller mirrors the active branch and validates the full
/// owner/agent/generation/predecessor coordinate before egress. `verify_deletion`
/// (called by the "deleted" branch) additionally re-checks state/`active`/`deleted_at`.
fn reconstruct_deletion(body: &[u8], owner_keys: &Keys) -> Result<(Event, Payload), String> {
    let parsed: RetainedAggregateBody = serde_json::from_slice(body)
        .map_err(|e| format!("retained request json is not a valid aggregate body: {e}"))?;
    if parsed.definition_event.is_some() || parsed.instance_event.is_some() {
        return Err("retained deleted request unexpectedly carries active projections".to_string());
    }
    if parsed.expected_definition_revision.is_some() {
        return Err(
            "retained deleted request unexpectedly carries an expected definition revision"
                .to_string(),
        );
    }
    let (_, payload) = buzz_core_pkg::private_managed_agent::validate_and_decrypt(
        &parsed.private_event,
        owner_keys,
    )
    .map_err(|e| format!("retained deletion head does not decrypt under the owner key: {e}"))?;
    if payload.state != buzz_core_pkg::private_managed_agent::State::Deleted
        || payload.active.is_some()
        || payload.deleted_at.is_none()
    {
        return Err("retained deleted request head is not a valid deletion".to_string());
    }
    Ok((parsed.private_event, payload))
}

#[cfg(test)]
mod tests;
