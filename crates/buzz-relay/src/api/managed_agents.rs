//! Dedicated NIP-98 submission boundary for NIP-PMA aggregates.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
};
use serde::Deserialize;
use serde_json::Value;

use super::{api_error, internal_error};
use crate::state::AppState;

/// Maximum aggregate request body. The encrypted payload and two signed
/// projections fit below this cap while preventing unbounded JSON allocation.
const MAX_AGGREGATE_BODY_BYTES: usize = 256 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AggregateBody {
    private_event: nostr::Event,
    #[serde(default)]
    definition_event: Option<nostr::Event>,
    #[serde(default)]
    instance_event: Option<nostr::Event>,
    #[serde(default)]
    expected_definition_revision: Option<u64>,
}

/// Atomically install an encrypted PMA head and exact public projections.
pub async fn submit_aggregate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if body.len() > MAX_AGGREGATE_BODY_BYTES {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "aggregate body too large",
        ));
    }
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let tenant = crate::tenant::bind_community(&state.db, raw_host)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::NOT_FOUND,
                "relay: no community is configured for this host",
            )
        })?;
    let url = super::bridge::nip98_expected_url(
        &state.config.relay_url,
        &tenant,
        "/api/managed-agents/aggregate",
    );
    let (owner, replay_id) = super::bridge::verify_bridge_auth_with_options(
        &headers,
        "POST",
        &url,
        Some(&body),
        state.config.require_auth_token,
        true,
    )?;
    super::bridge::enforce_http_admission(&state, &tenant, &owner).await?;
    super::bridge::check_nip98_replay(&state, &tenant, replay_id).await?;
    super::relay_members::enforce_relay_membership(
        &state,
        tenant.community(),
        &owner.to_bytes(),
        None,
    )
    .await?;
    let parsed: AggregateBody = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid aggregate JSON"))?;
    if parsed.private_event.pubkey != owner {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "aggregate author must be authenticated owner",
        ));
    }
    let request = buzz_db::managed_agent::AggregateRequest {
        private_event: parsed.private_event,
        definition_event: parsed.definition_event,
        instance_event: parsed.instance_event,
        expected_definition_revision: parsed.expected_definition_revision,
    };
    let commit = state
        .db
        .commit_managed_agent_aggregate(tenant.community(), &request)
        .await
        .map_err(|e| match e {
            buzz_db::DbError::InvalidData(message) => api_error(StatusCode::BAD_REQUEST, &message),
            buzz_db::DbError::ManagedAgentConflict(message) => {
                api_error(StatusCode::CONFLICT, &message)
            }
            _ => internal_error(&format!("managed-agent aggregate commit failed: {e}")),
        })?;
    if !commit.head.active {
        state
            .disconnect_pubkey_clusterwide_awaited(
                &tenant,
                &commit.head.agent_pubkey,
                &hex::encode(&commit.head.event_id),
                "blocked: managed agent has been deleted",
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "managed-agent disconnect publication failed after durable tombstone commit");
                api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "managed-agent deletion committed; disconnect propagation failed, retry request",
                )
            })?;
    }
    let owner_hex = owner.to_hex();
    for stored in &commit.events {
        crate::handlers::event::dispatch_persistent_event(
            &tenant,
            &state,
            stored,
            buzz_core::kind::event_kind_u32(&stored.event),
            &owner_hex,
            None,
        )
        .await;
    }
    Ok(Json(serde_json::json!({
        "event_id": hex::encode(&commit.head.event_id),
        "generation": commit.head.generation,
        "state": if commit.head.active { "active" } else { "deleted" },
        "accepted": true,
        "inserted": commit.inserted,
        "definition_revision": commit.definition_revision,
        "private_event": commit.private_event,
        "definition_event": commit.definition_event,
        "instance_event": commit.instance_event
    })))
}
