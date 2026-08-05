//! Boot-time activation for relay-canonical managed-agent aggregates.
//!
//! Capability discovery is fail-closed. A relay must advertise the exact PMA
//! extension before Desktop snapshots legacy agents into immutable retained
//! requests. Submission is then replayable from SQLite; verified promotion is
//! persisted to the local compatibility cache before the exact retained attempt
//! is compare-and-cleared.

use std::path::Path;

use nostr::Keys;
use serde::Deserialize;
use tauri::Manager;

use super::{build_migration_candidate, CasMetadata, MigrationError};
use crate::managed_agents::authority::{
    RelayAuthority, RelayAuthorityEvidence, NIP_PMA_AGGREGATE_TOKEN,
};
use crate::managed_agents::retention::{
    get_pending_managed_agent_aggregates, get_retained_managed_agent_aggregate,
    mark_managed_agent_aggregate_synced, open_retention_db, record_managed_agent_aggregate_error,
    retain_managed_agent_aggregate, RetainedManagedAgentAggregate,
};
use crate::managed_agents::{load_managed_agents, save_managed_agents};
use crate::{app_state::AppState, managed_agents};

#[derive(Debug, Deserialize)]
struct RelayInformationDocument {
    #[serde(default)]
    supported_extensions: Vec<String>,
}

#[derive(serde::Serialize)]
struct AggregateRequest<'a> {
    private_event: &'a nostr::Event,
    definition_event: &'a nostr::Event,
    instance_event: &'a nostr::Event,
    expected_definition_revision: u64,
}

/// Discover relay extensions from the captured workspace HTTP origin.
pub(crate) async fn discover_relay_extensions(
    client: &reqwest::Client,
    relay_api_base_url: &str,
) -> Result<Vec<String>, String> {
    let url = format!("{}/info", relay_api_base_url.trim_end_matches('/'));
    let response = client
        .get(url)
        .header("Accept", "application/nostr+json")
        .send()
        .await
        .map_err(|error| crate::relay::classify_request_error(&error))?;
    if !response.status().is_success() {
        return Err(crate::relay::relay_error_message(response).await);
    }
    Ok(
        crate::relay::parse_json_response::<RelayInformationDocument>(response)
            .await?
            .supported_extensions,
    )
}

/// Snapshot every eligible legacy agent into a generation-one retained request.
/// Existing retained coordinates are immutable and left untouched.
pub(crate) fn enqueue_initial_migrations(
    app: &tauri::AppHandle,
    owner_keys: &Keys,
    db_path: &Path,
    advertised_extensions: &[String],
) -> Result<usize, String> {
    if !advertised_extensions
        .iter()
        .any(|extension| extension == NIP_PMA_AGGREGATE_TOKEN)
    {
        return Ok(0);
    }

    let state = app.state::<AppState>();
    let _store_guard = state
        .managed_agents_store_lock
        .lock()
        .map_err(|error| error.to_string())?;
    let records = load_managed_agents(app)?;
    let mut conn = open_retention_db(db_path)?;
    let owner_pubkey = owner_keys.public_key().to_hex();
    let mut enqueued = 0;

    for record in records
        .iter()
        .filter(|record| !record.relay_authority.is_relay_authoritative())
    {
        if record.private_key_nsec.is_empty()
            || get_retained_managed_agent_aggregate(&conn, &owner_pubkey, &record.pubkey)?.is_some()
        {
            continue;
        }
        let definition = record.to_definition_view();
        let definition_event = if let Some(definition) = definition {
            managed_agents::persona_events::build_persona_event(&definition)
                .map_err(|error| format!("failed to build migration definition: {error}"))?
                .custom_created_at(nostr::Timestamp::now())
                .sign_with_keys(owner_keys)
                .map_err(|error| format!("failed to sign migration definition: {error}"))?
        } else {
            let mut definition = record.clone();
            definition.pubkey.clear();
            definition.slug = Some(record.pubkey.clone());
            definition
                .to_definition_view()
                .ok_or_else(|| "failed to synthesize migration definition".to_string())
                .and_then(|definition| {
                    managed_agents::persona_events::build_persona_event(&definition)
                })?
                .custom_created_at(nostr::Timestamp::now())
                .sign_with_keys(owner_keys)
                .map_err(|error| format!("failed to sign migration definition: {error}"))?
        };
        let instance_event = managed_agents::agent_events::build_agent_event(record)?
            .custom_created_at(nostr::Timestamp::now())
            .sign_with_keys(owner_keys)
            .map_err(|error| format!("failed to sign migration instance: {error}"))?;
        let agent_keys = Keys::parse(&record.private_key_nsec)
            .map_err(|error| format!("agent key does not parse for migration: {error}"))?;
        let cas = CasMetadata {
            generation: 1,
            previous_event_id: None,
            definition_revision: 1,
        };
        let candidate = match build_migration_candidate(
            record,
            owner_keys,
            &agent_keys,
            definition_event,
            instance_event,
            &cas,
            advertised_extensions.iter().map(String::as_str),
            nostr::Timestamp::now().as_secs(),
        ) {
            Ok(candidate) => candidate,
            Err(MigrationError::Blocked(_)) => continue,
            Err(error) => {
                return Err(format!(
                    "failed to build managed-agent migration: {error:?}"
                ))
            }
        };
        let request_json = serde_json::to_string(&AggregateRequest {
            private_event: &candidate.signed_event,
            definition_event: &candidate.definition_event,
            instance_event: &candidate.instance_event,
            expected_definition_revision: cas.definition_revision,
        })
        .map_err(|error| format!("failed to serialize managed-agent aggregate: {error}"))?;
        retain_managed_agent_aggregate(
            &mut conn,
            &RetainedManagedAgentAggregate {
                owner_pubkey: owner_pubkey.clone(),
                agent_pubkey: record.pubkey.clone(),
                generation: cas.generation,
                private_event_id: candidate.signed_event.id.to_hex(),
                state: "active".to_string(),
                request_json,
                pending_sync: true,
                last_error: None,
            },
        )?;
        enqueued += 1;
    }
    Ok(enqueued)
}

/// Submit all pending active attempts for the captured workspace scope.
pub(crate) async fn flush_pending_migrations(
    app: &tauri::AppHandle,
    client: &reqwest::Client,
    relay_api_base_url: &str,
    owner_keys: &Keys,
    db_path: &Path,
) -> Result<usize, String> {
    let owner_pubkey = owner_keys.public_key().to_hex();
    let pending =
        get_pending_managed_agent_aggregates(&open_retention_db(db_path)?, &owner_pubkey)?;
    let mut promoted = 0;
    for row in pending.into_iter().filter(|row| row.state == "active") {
        let state = app.state::<AppState>();
        let current_owner = state.signing_keys()?.public_key().to_hex();
        let current_relay_api = crate::relay::relay_api_base_url_with_override(&state);
        if current_owner != owner_pubkey
            || current_relay_api.trim_end_matches('/') != relay_api_base_url.trim_end_matches('/')
        {
            return Ok(promoted);
        }
        let outcome = super::driver::submit_retained_aggregate(
            client,
            relay_api_base_url,
            db_path,
            owner_keys,
            &owner_pubkey,
            &row.agent_pubkey,
        )
        .await?;
        let super::driver::SubmitOutcome::Verified { attempt, evidence } = outcome else {
            continue;
        };

        let state = app.state::<AppState>();
        let persisted = {
            let _guard = state
                .managed_agents_store_lock
                .lock()
                .map_err(|error| error.to_string())?;
            let mut records = load_managed_agents(app)?;
            if let Some(index) = records.iter().position(|record| {
                record.pubkey == attempt.agent_pubkey
                    && record.updated_at == attempt.source_updated_at
                    && !record.relay_authority.is_relay_authoritative()
            }) {
                records[index].relay_authority =
                    RelayAuthority::relay_authoritative(RelayAuthorityEvidence {
                        generation: evidence.generation,
                        private_event_id: evidence.head_event_id.clone(),
                    });
                save_managed_agents(app, &records)?;
                true
            } else {
                // Crash replay: authority may have reached disk before the exact
                // retained attempt was cleared. Matching evidence makes this
                // idempotent; any different head remains pending and blocked.
                records.iter().any(|record| {
                    record.pubkey == attempt.agent_pubkey
                        && record.relay_authority.evidence().is_some_and(|authority| {
                            authority.generation == evidence.generation
                                && authority.private_event_id == evidence.head_event_id
                        })
                })
            }
        };

        let conn = open_retention_db(db_path)?;
        if persisted {
            if mark_managed_agent_aggregate_synced(
                &conn,
                &attempt.owner_pubkey,
                &attempt.agent_pubkey,
                attempt.generation,
                &attempt.private_event_id,
            )? {
                promoted += 1;
            }
        } else {
            let _ = record_managed_agent_aggregate_error(
                &conn,
                &attempt.owner_pubkey,
                &attempt.agent_pubkey,
                attempt.generation,
                &attempt.private_event_id,
                "local agent changed during relay promotion; retry preserved",
            );
        }
    }
    Ok(promoted)
}
