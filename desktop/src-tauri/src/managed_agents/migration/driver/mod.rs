//! Desktop PMA aggregate submit/retry driver.
//!
//! This is the transport half of the relay-canonical migration seam. The pure
//! [builder/verifier](super) turns a hydrated record into a signed candidate
//! and gates the relay read-back; the durable [retention](crate::managed_agents::retention)
//! layer persists one immutable request per CAS generation. This driver is the
//! only code that moves a retained request across the wire: it POSTs the exact
//! retained JSON, verifies the response through [`super::verify_promotion`], and
//! flips the durable row to synced only when the relay served back a faithful,
//! owner-signed copy.
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
//!   * **Only the exact generation/event is marked synced.** Confirmation binds
//!     to `(generation, private_event_id)`; a relay that echoes a different
//!     generation or head id is a verification failure, not a sync.
//!   * **Errors preserve retry.** Every failure path persists a diagnostic via
//!     [`record_managed_agent_aggregate_error`](crate::managed_agents::retention::record_managed_agent_aggregate_error)
//!     and leaves `pending_sync = 1`; nothing here clears retry except a fully
//!     verified read-back.

use nostr::{Event, Keys};
use reqwest::Method;
use rusqlite::Connection;
use serde::Deserialize;

use super::{verify_promotion, AggregateResponse, MigrationCandidate};
use crate::app_state::AppState;
use crate::managed_agents::retention::{
    get_retained_managed_agent_aggregate, mark_managed_agent_aggregate_synced,
    record_managed_agent_aggregate_error,
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

/// What one drive of a retained aggregate resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Consumed by the boot/reconcile lane (sibling); today only tests read it.
pub(crate) enum SubmitOutcome {
    /// No pending aggregate row for this agent — nothing to submit.
    Nothing,
    /// The relay served back a faithful copy and the row was marked synced.
    Synced {
        generation: u64,
        private_event_id: String,
    },
    /// The attempt failed; a diagnostic was persisted and retry is preserved.
    Retained { error: String },
}

/// Submit (or retry) the latest retained aggregate for one owner→agent pair.
///
/// Reads the durable row, POSTs its exact `request_json` with fresh owner-signed
/// NIP-98 auth, strict-deserializes the response, verifies it against the
/// candidate reconstructed from the same bytes, and — only on a fully verified
/// read-back — marks that exact generation/event synced. Every failure persists
/// an exact-attempt diagnostic without clearing retry.
#[allow(dead_code)] // Consumed by the boot/reconcile lane (sibling); exercised by this module's tests.
pub(crate) async fn submit_retained_aggregate(
    state: &AppState,
    conn: &Connection,
    owner_keys: &Keys,
    owner_pubkey: &str,
    agent_pubkey: &str,
) -> Result<SubmitOutcome, String> {
    let row = match get_retained_managed_agent_aggregate(conn, owner_pubkey, agent_pubkey)? {
        Some(row) if row.pending_sync => row,
        _ => return Ok(SubmitOutcome::Nothing),
    };

    // Fail-fast guard: the retained head id/generation is what we will confirm.
    // Capture them before any network work so a diagnostic always names the
    // exact attempt.
    let generation = row.generation;
    let private_event_id = row.private_event_id.clone();

    let record_failure = |error: String| -> Result<SubmitOutcome, String> {
        // A best-effort diagnostic write must not mask the real error; if the
        // update itself fails we still surface the original failure.
        let _ = record_managed_agent_aggregate_error(
            conn,
            owner_pubkey,
            agent_pubkey,
            generation,
            &private_event_id,
            &error,
        );
        Ok(SubmitOutcome::Retained { error })
    };

    let response = match submit_to_relay(state, owner_keys, row.request_json.as_bytes()).await {
        Ok(response) => response,
        Err(error) => return record_failure(error),
    };

    // Reconstruct the verification source from the *same bytes* we sent, so the
    // candidate and the wire request can never diverge.
    let candidate = match reconstruct_candidate(row.request_json.as_bytes(), owner_keys) {
        Ok(candidate) => candidate,
        Err(error) => return record_failure(error),
    };

    let evidence = match verify_promotion(&candidate, &response, owner_keys) {
        Ok(evidence) => evidence,
        Err(error) => return record_failure(format!("verification failed: {error:?}")),
    };

    // The relay's committed head must be the exact generation/event we retained;
    // confirming a different coordinate would desync durable state from the
    // relay. verify_promotion already proved the head is a faithful copy, so a
    // mismatch here is a protocol violation, not a sync.
    if evidence.generation != generation || evidence.head_event_id != private_event_id {
        return record_failure(format!(
            "read-back coordinate {}:{} does not match retained {generation}:{private_event_id}",
            evidence.generation, evidence.head_event_id
        ));
    }

    match mark_managed_agent_aggregate_synced(
        conn,
        owner_pubkey,
        agent_pubkey,
        generation,
        &private_event_id,
    ) {
        Ok(true) => Ok(SubmitOutcome::Synced {
            generation,
            private_event_id,
        }),
        // The row moved under us (superseded by a newer generation) between read
        // and confirm. Nothing verified was lost; the newer row drives next.
        Ok(false) => Ok(SubmitOutcome::Nothing),
        Err(error) => Err(error),
    }
}

/// POST the exact request bytes with fresh owner-signed NIP-98 auth and
/// strict-deserialize the aggregate response.
async fn submit_to_relay(
    state: &AppState,
    owner_keys: &Keys,
    body: &[u8],
) -> Result<AggregateResponse, String> {
    crate::egress_guard::assert_no_key_backup_bytes(body, "managed-agent aggregate submit")?;
    crate::relay_admission::wait_for_rate_limit().await;

    let base = crate::relay::relay_api_base_url_with_override(state);
    let url = format!("{}{AGGREGATE_PATH}", base.trim_end_matches('/'));
    let auth_header =
        crate::relay::build_nip98_auth_header_for_keys(owner_keys, &Method::POST, &url, body)?;

    let response = state
        .http_client
        .post(&url)
        .header("Authorization", auth_header)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| crate::relay::classify_request_error(&e))?;

    if !response.status().is_success() {
        return Err(crate::relay::relay_error_message(response).await);
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

    let (_, payload) = buzz_core_pkg::private_managed_agent::validate_and_decrypt(
        &parsed.private_event,
        owner_keys,
    )
    .map_err(|e| format!("retained head does not decrypt under the owner key: {e}"))?;

    Ok(MigrationCandidate {
        signed_event: parsed.private_event,
        payload,
        definition_event,
        instance_event,
    })
}

#[cfg(test)]
mod tests;
