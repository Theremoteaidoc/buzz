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

#[derive(Deserialize)]
struct StoredAggregateRequest {
    definition_event: nostr::Event,
    expected_definition_revision: u64,
}

/// Build and durably retain the next authoritative instance-edit aggregate.
/// Called under the managed-agent store lock before any local record save.
pub(crate) fn enqueue_authoritative_edit(
    app: &tauri::AppHandle,
    state: &AppState,
    record: &crate::managed_agents::ManagedAgentRecord,
) -> Result<(), String> {
    let evidence = record
        .relay_authority
        .evidence()
        .ok_or_else(|| "authoritative edit is missing relay evidence".to_string())?;
    if record.relay_authority.is_deleting() {
        return Err("cannot edit an agent while deletion is pending".to_string());
    }
    let scope = crate::managed_agents::retention::active_retention_scope(app, state)?;
    let owner_pubkey = scope.owner_keys.public_key().to_hex();
    let mut conn = open_retention_db(&scope.db_path)?;
    let retained = get_retained_managed_agent_aggregate(&conn, &owner_pubkey, &record.pubkey)?
        .ok_or_else(|| "authoritative edit is missing its retained relay head".to_string())?;
    if retained.pending_sync {
        return Err("managed-agent relay synchronization is still pending; retry the edit shortly".to_string());
    }
    if retained.state != "active"
        || retained.generation != evidence.generation
        || retained.private_event_id != evidence.private_event_id
    {
        return Err("local relay evidence does not match the retained authoritative head".to_string());
    }
    let stored: StoredAggregateRequest = serde_json::from_str(&retained.request_json)
        .map_err(|error| format!("retained authoritative request is invalid: {error}"))?;
    let instance_event = managed_agents::agent_events::build_agent_event(record)?
        .custom_created_at(nostr::Timestamp::now())
        .sign_with_keys(&scope.owner_keys)
        .map_err(|error| format!("failed to sign authoritative instance edit: {error}"))?;
    let agent_keys = Keys::parse(&record.private_key_nsec)
        .map_err(|error| format!("agent key does not parse for authoritative edit: {error}"))?;
    let generation = evidence
        .generation
        .checked_add(1)
        .ok_or_else(|| "managed-agent aggregate generation overflow".to_string())?;
    let candidate = build_migration_candidate(
        record,
        &scope.owner_keys,
        &agent_keys,
        stored.definition_event,
        instance_event,
        &CasMetadata {
            generation,
            previous_event_id: Some(evidence.private_event_id.clone()),
            definition_revision: stored.expected_definition_revision,
        },
        [NIP_PMA_AGGREGATE_TOKEN],
        nostr::Timestamp::now().as_secs(),
    )
    .map_err(|error| format!("failed to build authoritative edit: {error:?}"))?;
    let request_json = serde_json::to_string(&AggregateRequest {
        private_event: &candidate.signed_event,
        definition_event: &candidate.definition_event,
        instance_event: &candidate.instance_event,
        expected_definition_revision: stored.expected_definition_revision,
    })
    .map_err(|error| format!("failed to serialize authoritative edit: {error}"))?;
    retain_managed_agent_aggregate(
        &mut conn,
        &RetainedManagedAgentAggregate {
            owner_pubkey,
            agent_pubkey: record.pubkey.clone(),
            generation,
            private_event_id: candidate.signed_event.id.to_hex(),
            state: "active".to_string(),
            request_json,
            pending_sync: true,
            last_error: None,
            local_authority_applied: false,
        },
    )
}

pub(crate) struct VerifiedAuthoritativeEdit {
    pub owner_pubkey: String,
    pub agent_pubkey: String,
    pub generation: u64,
    pub private_event_id: String,
    pub evidence: RelayAuthorityEvidence,
}

pub(crate) async fn submit_authoritative_edit(
    client: &reqwest::Client,
    relay_api_base_url: &str,
    owner_keys: &Keys,
    db_path: &Path,
    agent_pubkey: &str,
) -> Result<VerifiedAuthoritativeEdit, String> {
    let owner_pubkey = owner_keys.public_key().to_hex();
    match super::driver::submit_retained_aggregate(
        client,
        relay_api_base_url,
        db_path,
        owner_keys,
        &owner_pubkey,
        agent_pubkey,
    )
    .await?
    {
        super::driver::SubmitOutcome::Verified { attempt, evidence } => {
            Ok(VerifiedAuthoritativeEdit {
                owner_pubkey: attempt.owner_pubkey,
                agent_pubkey: attempt.agent_pubkey,
                generation: attempt.generation,
                private_event_id: attempt.private_event_id,
                evidence: RelayAuthorityEvidence {
                    generation: evidence.generation,
                    private_event_id: evidence.head_event_id,
                },
            })
        }
        super::driver::SubmitOutcome::Retained { error } => Err(error),
        other => Err(format!("authoritative edit did not verify: {other:?}")),
    }
}

pub(crate) fn confirm_authoritative_edit(
    db_path: &Path,
    edit: &VerifiedAuthoritativeEdit,
) -> Result<(), String> {
    let conn = open_retention_db(db_path)?;
    if mark_managed_agent_aggregate_synced(
        &conn,
        &edit.owner_pubkey,
        &edit.agent_pubkey,
        edit.generation,
        &edit.private_event_id,
    )? {
        Ok(())
    } else {
        Err("verified authoritative edit no longer matches retained attempt".to_string())
    }
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
                local_authority_applied: false,
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
                let authority_can_advance = record.relay_authority.evidence().is_some_and(|head| {
                    head.generation.checked_add(1) == Some(evidence.generation)
                        && evidence.previous_event_id.as_deref()
                            == Some(head.private_event_id.as_str())
                });
                record.pubkey == attempt.agent_pubkey
                    && record.updated_at == attempt.source_updated_at
                    && (!record.relay_authority.is_relay_authoritative() || authority_can_advance)
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

/// Submit all pending deleted attempts (tombstones) for the captured workspace
/// scope, erasing local record/key only after verified relay confirmation.
///
/// This is the async confirming half of the crash-safe deletion seam. The
/// delete command durably enqueues the deleted aggregate and flips the record to
/// [`RelayAuthority::Deleting`] BEFORE any erase; this flush verifies the
/// tombstone at the relay, then applies the erase in a strict crash-safe order:
///
///   1. verified read-back (`SubmitOutcome::VerifiedDeletion`),
///   2. erase record + key + session caches + archive request, and save,
///   3. durably set `local_authority_applied` (the terminal proof), then
///   4. compare-and-clear the retained row.
///
/// **Crash replay honors the durable marker, never mere record absence.** On
/// replay the `Deleting` record may already be gone. Only a set marker proves
/// the exact deletion reached local authority; absence alone could equally be an
/// unrelated/manual deletion, which must NOT license clearing the retry. So a
/// missing record with an unset marker leaves the row pending + records a
/// diagnostic, while a missing record with the marker already set is cleared
/// idempotently.
pub(crate) async fn flush_pending_deletions(
    app: &tauri::AppHandle,
    client: &reqwest::Client,
    relay_api_base_url: &str,
    owner_keys: &Keys,
    db_path: &Path,
) -> Result<usize, String> {
    use crate::managed_agents::retention::mark_managed_agent_deletion_local_authority_applied;

    let owner_pubkey = owner_keys.public_key().to_hex();
    let pending =
        get_pending_managed_agent_aggregates(&open_retention_db(db_path)?, &owner_pubkey)?;
    let mut deleted = 0;
    for row in pending.into_iter().filter(|row| row.state == "deleted") {
        let state = app.state::<AppState>();
        let current_owner = state.signing_keys()?.public_key().to_hex();
        let current_relay_api = crate::relay::relay_api_base_url_with_override(&state);
        if current_owner != owner_pubkey
            || current_relay_api.trim_end_matches('/') != relay_api_base_url.trim_end_matches('/')
        {
            return Ok(deleted);
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
        let super::driver::SubmitOutcome::VerifiedDeletion { attempt, evidence } = outcome else {
            continue;
        };

        let state = app.state::<AppState>();
        // Applied means the exact verified deletion reached local authority. The
        // crash-safe order is: (1) set the durable marker FIRST — it means
        // "verified deletion pending local application" and is the terminal proof
        // replay trusts — then (2) erase the record/key/caches/archive
        // idempotently. A crash BEFORE the marker replays verification and
        // re-attempts; a crash AFTER the marker but before the erase re-runs the
        // erase; a crash AFTER the erase clears on record absence + marker.
        // Record absence ALONE never licenses clearing — it could be an unrelated
        // or manual deletion; only the marker proves THIS deletion applied.
        let applied = {
            let _guard = state
                .managed_agents_store_lock
                .lock()
                .map_err(|error| error.to_string())?;

            // Step 1: durably set the marker (idempotent CAS on the exact
            // tombstone coordinate). Nothing is destroyed until this lands.
            let conn = open_retention_db(db_path)?;
            let marker_set = mark_managed_agent_deletion_local_authority_applied(
                &conn,
                &attempt.owner_pubkey,
                &attempt.agent_pubkey,
                attempt.generation,
                &attempt.private_event_id,
            )?;
            drop(conn);

            // Step 2: erase idempotently. Accept the record still authoritative
            // (RelayAuthoritative — enqueue landed but the authority flip/save
            // crashed, per the cascade self-heal contract) OR mid-deletion
            // (Deleting), but ONLY when its evidence is the tombstone's exact
            // predecessor: generation `attempt.generation - 1` at
            // `evidence.previous_event_id`. Binding to it prevents erasing a
            // record a racing workspace switch/edit re-created or advanced, and
            // leaves any nonmatching record in place so the retry stays blocked.
            let mut records = load_managed_agents(app)?;
            let prior_generation = attempt.generation.saturating_sub(1);
            let had_match = records.iter().any(|record| {
                is_exact_deletion_predecessor(
                    &record.pubkey,
                    record.relay_authority.evidence(),
                    &attempt.agent_pubkey,
                    prior_generation,
                    &evidence.previous_event_id,
                )
            });
            // A record at this pubkey that is NOT the exact predecessor blocks:
            // clearing would abandon a live/advanced identity.
            let has_blocking_record = records.iter().any(|record| {
                record.pubkey == attempt.agent_pubkey
                    && !is_exact_deletion_predecessor(
                        &record.pubkey,
                        record.relay_authority.evidence(),
                        &attempt.agent_pubkey,
                        prior_generation,
                        &evidence.previous_event_id,
                    )
            });
            if had_match {
                records.retain(|record| {
                    !is_exact_deletion_predecessor(
                        &record.pubkey,
                        record.relay_authority.evidence(),
                        &attempt.agent_pubkey,
                        prior_generation,
                        &evidence.previous_event_id,
                    )
                });
                save_managed_agents(app, &records)?;
                managed_agents::delete_agent_key(&attempt.agent_pubkey);
                state.clear_agent_session_caches(&attempt.agent_pubkey);
                crate::commands::agents::archive_managed_agent_pending(
                    app,
                    &state,
                    &attempt.agent_pubkey,
                );
            }

            // Cleared only when the marker is durable AND no foreign/advanced
            // record remains at this pubkey. On replay the record may already be
            // absent (erased in a prior run) — that plus the set marker clears
            // idempotently.
            deletion_apply_clears(marker_set, has_blocking_record)
        };

        let conn = open_retention_db(db_path)?;
        if applied {
            if mark_managed_agent_aggregate_synced(
                &conn,
                &attempt.owner_pubkey,
                &attempt.agent_pubkey,
                attempt.generation,
                &attempt.private_event_id,
            )? {
                deleted += 1;
            }
        } else {
            let _ = record_managed_agent_aggregate_error(
                &conn,
                &attempt.owner_pubkey,
                &attempt.agent_pubkey,
                attempt.generation,
                &attempt.private_event_id,
                "local deletion authority not applied; retry preserved",
            );
        }
    }
    Ok(deleted)
}

/// Pure erase-match predicate for the deletion flush: does a record with this
/// `pubkey` / relay-authority `evidence` name the exact record this verified
/// tombstone supersedes?
///
/// A tombstone advances the CAS chain by one, so the record it deletes carries
/// the tombstone's PREDECESSOR evidence: generation = `prior_generation`
/// (the tombstone generation minus one) at `previous_event_id`. This matches
/// EITHER authority state that keeps relay evidence — `RelayAuthoritative`
/// (enqueue landed but the authority flip/save crashed; the flush self-heals it)
/// or `Deleting` (the flip landed). A record without evidence (`LegacyOnly`)
/// never matches. Binding to the exact predecessor prevents erasing a record a
/// racing workspace switch/edit re-created or advanced.
fn is_exact_deletion_predecessor(
    record_pubkey: &str,
    record_evidence: Option<&RelayAuthorityEvidence>,
    agent_pubkey: &str,
    prior_generation: u64,
    previous_event_id: &str,
) -> bool {
    record_pubkey == agent_pubkey
        && record_evidence.is_some_and(|authority| {
            authority.generation == prior_generation
                && authority.private_event_id == previous_event_id
        })
}

/// Pure clear decision for the deletion flush, encoding the marker-before-erase
/// crash-replay contract. The retry's row is compare-cleared ONLY when:
///   * `marker_set` — the durable "verified deletion pending local application"
///     marker is set. It is set BEFORE any erase, so a crash before it replays
///     verification; a crash after it (before or during erase) replays the
///     idempotent erase. Record absence alone NEVER clears — it could be an
///     unrelated/manual deletion.
///   * `!has_blocking_record` — no foreign/advanced record remains at the
///     coordinate. A record that is not the exact predecessor means a racing
///     re-create/advance; clearing would abandon a live identity, so stay
///     blocked until it resolves.
fn deletion_apply_clears(marker_set: bool, has_blocking_record: bool) -> bool {
    marker_set && !has_blocking_record
}

#[cfg(test)]
mod deletion_apply_tests {
    use super::*;
    use crate::managed_agents::authority::{RelayAuthority, RelayAuthorityEvidence};

    const AGENT: &str = "agent-pubkey-hex";
    const PRED_ID: &str = "predecessor-event-id";
    const PRIOR_GEN: u64 = 4;

    fn evidence(gen: u64, id: &str) -> RelayAuthorityEvidence {
        RelayAuthorityEvidence {
            generation: gen,
            private_event_id: id.to_string(),
        }
    }

    /// Helper: run the predicate as the flush does, deriving the evidence from a
    /// concrete [`RelayAuthority`] so tests exercise the real accessor.
    fn matches(pubkey: &str, authority: &RelayAuthority) -> bool {
        is_exact_deletion_predecessor(pubkey, authority.evidence(), AGENT, PRIOR_GEN, PRED_ID)
    }

    #[test]
    fn deleting_record_at_exact_predecessor_matches() {
        assert!(matches(
            AGENT,
            &RelayAuthority::deleting(evidence(PRIOR_GEN, PRED_ID))
        ));
    }

    #[test]
    fn authoritative_record_at_exact_predecessor_matches_for_self_heal() {
        // Cascade enqueue-N/save-fail leaves the record RelayAuthoritative with a
        // pending tombstone. The flush must still recognize and erase it.
        assert!(matches(
            AGENT,
            &RelayAuthority::relay_authoritative(evidence(PRIOR_GEN, PRED_ID))
        ));
    }

    #[test]
    fn advanced_generation_record_does_not_match() {
        // A racing edit advanced the head past the tombstone's predecessor.
        assert!(!matches(
            AGENT,
            &RelayAuthority::relay_authoritative(evidence(PRIOR_GEN + 1, "newer-head"))
        ));
    }

    #[test]
    fn different_predecessor_id_does_not_match() {
        assert!(!matches(
            AGENT,
            &RelayAuthority::deleting(evidence(PRIOR_GEN, "other-event-id"))
        ));
    }

    #[test]
    fn legacy_record_never_matches() {
        assert!(!matches(AGENT, &RelayAuthority::legacy()));
    }

    #[test]
    fn different_agent_never_matches() {
        assert!(!matches(
            "someone-else",
            &RelayAuthority::deleting(evidence(PRIOR_GEN, PRED_ID))
        ));
    }

    #[test]
    fn crash_after_marker_before_erase_reclears_on_next_pass() {
        // Marker set, matching record still present (erase never ran): the flush
        // re-erases (had_match) and clears. No blocking record remains after the
        // in-run erase, so the decision clears.
        assert!(deletion_apply_clears(true, /*has_blocking=*/ false));
    }

    #[test]
    fn crash_after_erase_clears_on_absence_plus_marker() {
        // Record already gone from a prior run, marker set, nothing blocking:
        // absence + marker clears idempotently.
        assert!(deletion_apply_clears(true, false));
    }

    #[test]
    fn crash_before_marker_does_not_clear() {
        // Marker never landed (crash before step 1). The row must stay pending so
        // the next boot replays verification — record absence alone never clears.
        assert!(!deletion_apply_clears(/*marker_set=*/ false, false));
    }

    #[test]
    fn blocking_advanced_record_does_not_clear_even_with_marker() {
        // A foreign/advanced record at the coordinate blocks the clear.
        assert!(!deletion_apply_clears(true, /*has_blocking=*/ true));
    }
}
