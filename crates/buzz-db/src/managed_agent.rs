//! Transactional relay authority for NIP-PMA private managed agents.

use buzz_core::private_managed_agent::{self, Envelope, State};
use buzz_core::{CommunityId, StoredEvent};
use nostr::Event;
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::{DbError, Result};

/// Relay-verifiable aggregate submission. Plaintext and agent secrets never
/// cross this boundary: Desktop validates ciphertext/binding consistency after
/// writer-consistent read-back.
#[derive(Debug, Clone)]
pub struct AggregateRequest {
    /// Signed encrypted kind:30179 head.
    pub private_event: Event,
    /// Signed kind:30175 candidate, required for active heads.
    pub definition_event: Option<Event>,
    /// Signed kind:30177 candidate, required for active heads.
    pub instance_event: Option<Event>,
    /// Revision already embedded in the encrypted active payload. Required for
    /// active heads and rejected unless it matches the locked definition head.
    pub expected_definition_revision: Option<u64>,
}

/// Events committed by an aggregate submission, suitable for post-commit fan-out.
#[derive(Debug, Clone)]
pub struct AggregateCommit {
    /// Writer-consistent committed head metadata.
    pub head: ManagedAgentHead,
    /// Newly committed events. Empty for a byte-identical retry.
    pub events: Vec<StoredEvent>,
    /// Whether this call committed a new generation.
    pub inserted: bool,
    /// Transactionally confirmed definition revision for active heads.
    pub definition_revision: Option<u64>,
    /// Writer-consistent signed private head.
    pub private_event: Event,
    /// Writer-consistent signed definition binding.
    pub definition_event: Option<Event>,
    /// Writer-consistent signed instance binding.
    pub instance_event: Option<Event>,
}

/// Writer-consistent PMA authority head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedAgentHead {
    /// Owner pubkey.
    pub owner_pubkey: Vec<u8>,
    /// Agent pubkey.
    pub agent_pubkey: Vec<u8>,
    /// Current generation floor.
    pub generation: u64,
    /// Exact current private event ID.
    pub event_id: Vec<u8>,
    /// Whether the current head is active.
    pub active: bool,
}

fn invalid(message: impl Into<String>) -> DbError {
    DbError::InvalidData(message.into())
}

fn exact_d(event: &Event) -> Result<&str> {
    let values: Vec<_> = event
        .tags
        .iter()
        .filter_map(|tag| {
            let parts = tag.as_slice();
            (parts.first().is_some_and(|part| part == "d")).then_some(parts)
        })
        .collect();
    if values.len() != 1 || values[0].len() != 2 || values[0][1].is_empty() {
        return Err(invalid(
            "projection requires exactly one two-element non-empty d tag",
        ));
    }
    Ok(&values[0][1])
}

fn validate_projection(event: &Event, owner: &nostr::PublicKey, kind: u32) -> Result<String> {
    if event.kind.as_u16() as u32 != kind
        || &event.pubkey != owner
        || !event.verify_id()
        || !event.verify_signature()
    {
        return Err(invalid(format!(
            "invalid signed kind:{kind} owner projection"
        )));
    }
    Ok(exact_d(event)?.to_owned())
}

fn validate_request(request: &AggregateRequest) -> Result<(Envelope, Vec<Event>, Option<String>)> {
    let owner = request.private_event.pubkey;
    let envelope = private_managed_agent::validate_envelope(&request.private_event, &owner)
        .map_err(|e| invalid(e.to_string()))?;
    match envelope.state {
        State::Active => {
            request
                .expected_definition_revision
                .filter(|revision| *revision > 0 && *revision <= i64::MAX as u64)
                .ok_or_else(|| {
                    invalid("active aggregate requires a valid expected definition revision")
                })?;
            let definition = request
                .definition_event
                .as_ref()
                .ok_or_else(|| invalid("active aggregate missing definition projection"))?;
            let instance = request
                .instance_event
                .as_ref()
                .ok_or_else(|| invalid("active aggregate missing instance projection"))?;
            let definition_d = validate_projection(definition, &owner, 30175)?;
            let instance_d = validate_projection(instance, &owner, 30177)?;
            if instance_d != envelope.agent_pubkey.to_hex() {
                return Err(invalid(
                    "instance projection d does not match agent coordinate",
                ));
            }
            Ok((
                envelope,
                vec![definition.clone(), instance.clone()],
                Some(definition_d),
            ))
        }
        State::Deleted => {
            if request.definition_event.is_some()
                || request.instance_event.is_some()
                || request.expected_definition_revision.is_some()
            {
                return Err(invalid(
                    "deleted aggregate must not carry projections or a definition revision",
                ));
            }
            Ok((envelope, vec![], None))
        }
    }
}

fn decode_event(value: serde_json::Value, label: &str) -> Result<Event> {
    serde_json::from_value(value)
        .map_err(|error| invalid(format!("invalid stored {label}: {error}")))
}

async fn read_snapshot_tx(
    tx: &mut Transaction<'_, Postgres>,
    community: CommunityId,
    owner: &[u8],
    agent: &[u8],
    generation: u64,
    inserted: bool,
    events: Vec<StoredEvent>,
) -> Result<AggregateCommit> {
    let row = sqlx::query(
        "SELECT h.owner_pubkey,h.agent_pubkey,h.generation,h.event_id,h.state,\
                r.definition_revision,r.private_event,r.definition_event,r.instance_event \
           FROM managed_agent_heads h \
           JOIN managed_agent_revisions r ON r.community_id=h.community_id \
            AND r.owner_pubkey=h.owner_pubkey AND r.agent_pubkey=h.agent_pubkey \
            AND r.generation=h.generation \
          WHERE h.community_id=$1 AND h.owner_pubkey=$2 AND h.agent_pubkey=$3 \
            AND h.generation=$4",
    )
    .bind(community.as_uuid())
    .bind(owner)
    .bind(agent)
    .bind(generation as i64)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| invalid("committed aggregate snapshot missing"))?;
    let definition = row
        .try_get::<Option<serde_json::Value>, _>("definition_event")?
        .map(|value| decode_event(value, "definition event"))
        .transpose()?;
    let instance = row
        .try_get::<Option<serde_json::Value>, _>("instance_event")?
        .map(|value| decode_event(value, "instance event"))
        .transpose()?;
    Ok(AggregateCommit {
        head: ManagedAgentHead {
            owner_pubkey: row.try_get("owner_pubkey")?,
            agent_pubkey: row.try_get("agent_pubkey")?,
            generation: row.try_get::<i64, _>("generation")? as u64,
            event_id: row.try_get("event_id")?,
            active: row.try_get::<String, _>("state")? == "active",
        },
        events,
        inserted,
        definition_revision: row
            .try_get::<Option<i64>, _>("definition_revision")?
            .map(|value| value as u64),
        private_event: decode_event(row.try_get("private_event")?, "private event")?,
        definition_event: definition,
        instance_event: instance,
    })
}

/// Atomically CAS and persist a PMA head and its exact projections.
/// Serialization failures are retried at most twice with the same already-owned
/// request object. Validation is deterministic and no CAS conflict is retried.
pub async fn commit_aggregate(
    pool: &PgPool,
    community: CommunityId,
    request: &AggregateRequest,
) -> Result<AggregateCommit> {
    validate_request(request)?;
    for attempt in 0..=2 {
        match commit_aggregate_once(pool, community, request).await {
            Err(DbError::Sqlx(sqlx::Error::Database(error)))
                if error.code().as_deref() == Some("40001") && attempt < 2 => {}
            result => return result,
        }
    }
    unreachable!("bounded serialization retry always returns")
}

async fn commit_aggregate_once(
    pool: &PgPool,
    community: CommunityId,
    request: &AggregateRequest,
) -> Result<AggregateCommit> {
    let (envelope, projections, definition_d) = validate_request(request)?;
    let owner = envelope.owner_pubkey.to_bytes().to_vec();
    let agent = envelope.agent_pubkey.to_bytes().to_vec();
    let event_id = request.private_event.id.to_bytes().to_vec();
    let previous = envelope.previous_event_id.map(|id| id.to_bytes().to_vec());
    let definition_event_id = projections
        .first()
        .map(|event| event.id.to_bytes().to_vec());
    let definition_hash = projections
        .first()
        .map(|event| private_managed_agent::content_sha256(event.content.as_bytes()))
        .map(|hash| hex::decode(hash).expect("sha256 hex"));
    let instance_event_id = projections.get(1).map(|event| event.id.to_bytes().to_vec());
    let instance_hash = projections
        .get(1)
        .map(|event| private_managed_agent::content_sha256(event.content.as_bytes()))
        .map(|hash| hex::decode(hash).expect("sha256 hex"));

    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await?;
    let lock = super::event_replacement_lock_key(community, 30179, &owner, Some(&agent));
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock)
        .execute(&mut *tx)
        .await?;
    let current = sqlx::query("SELECT generation,event_id,state,definition_revision,definition_event_id,definition_content_sha256,instance_event_id,instance_content_sha256 FROM managed_agent_heads WHERE community_id=$1 AND owner_pubkey=$2 AND agent_pubkey=$3 FOR UPDATE")
        .bind(community.as_uuid()).bind(&owner).bind(&agent).fetch_optional(&mut *tx).await?;
    if let Some(row) = &current {
        let same_head = row.try_get::<i64, _>("generation")? as u64 == envelope.generation
            && row.try_get::<Vec<u8>, _>("event_id")? == event_id;
        if same_head {
            let same_bindings = row.try_get::<String, _>("state")?
                == match envelope.state {
                    State::Active => "active",
                    State::Deleted => "deleted",
                }
                && row.try_get::<Option<Vec<u8>>, _>("definition_event_id")? == definition_event_id
                && row.try_get::<Option<Vec<u8>>, _>("definition_content_sha256")?
                    == definition_hash
                && row.try_get::<Option<Vec<u8>>, _>("instance_event_id")? == instance_event_id
                && row.try_get::<Option<Vec<u8>>, _>("instance_content_sha256")? == instance_hash
                && row
                    .try_get::<Option<i64>, _>("definition_revision")?
                    .map(|revision| revision as u64)
                    == request.expected_definition_revision;
            if !same_bindings {
                return Err(DbError::ManagedAgentConflict(
                    "idempotent retry changed projection bindings".into(),
                ));
            }
            let snapshot = read_snapshot_tx(
                &mut tx,
                community,
                &owner,
                &agent,
                envelope.generation,
                false,
                vec![],
            )
            .await?;
            tx.commit().await?;
            return Ok(snapshot);
        }
    }
    match &current {
        None if envelope.generation == 1 && previous.is_none() => {}
        Some(row)
            if envelope.generation == row.try_get::<i64, _>("generation")? as u64 + 1
                && previous.as_deref()
                    == Some(row.try_get::<Vec<u8>, _>("event_id")?.as_slice()) => {}
        None => {
            return Err(DbError::ManagedAgentConflict(
                "genesis requires generation 1 without predecessor".into(),
            ))
        }
        Some(_) => {
            return Err(DbError::ManagedAgentConflict(
                "predecessor or generation conflict".into(),
            ))
        }
    }

    let instance_d = envelope.agent_pubkey.to_hex();
    let instance_lock =
        super::event_replacement_lock_key(community, 30177, &owner, Some(instance_d.as_bytes()));
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(instance_lock)
        .execute(&mut *tx)
        .await?;

    let definition_revision = if let (Some(d), Some(definition_id), Some(hash)) =
        (&definition_d, &definition_event_id, &definition_hash)
    {
        let definition_lock =
            super::event_replacement_lock_key(community, 30175, &owner, Some(d.as_bytes()));
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(definition_lock)
            .execute(&mut *tx)
            .await?;
        let definition_head: Option<(i64, Vec<u8>, Vec<u8>)> = sqlx::query_as("SELECT revision,event_id,content_sha256 FROM managed_agent_definition_heads WHERE community_id=$1 AND owner_pubkey=$2 AND definition_d=$3 FOR UPDATE")
            .bind(community.as_uuid()).bind(&owner).bind(d).fetch_optional(&mut *tx).await?;
        let revision = match definition_head {
            Some((revision, old_id, old_hash)) if old_id == *definition_id && old_hash == *hash => {
                revision
            }
            Some((revision, _, _)) => revision + 1,
            None => 1,
        };
        if request.expected_definition_revision != Some(revision as u64) {
            return Err(DbError::ManagedAgentConflict(format!(
                "expected definition revision does not match current definition head; expected {revision}"
            )));
        }
        sqlx::query("INSERT INTO managed_agent_definition_heads (community_id,owner_pubkey,definition_d,revision,event_id,content_sha256) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (community_id,owner_pubkey,definition_d) DO UPDATE SET revision=EXCLUDED.revision,event_id=EXCLUDED.event_id,content_sha256=EXCLUDED.content_sha256")
            .bind(community.as_uuid()).bind(&owner).bind(d).bind(revision).bind(definition_id).bind(hash).execute(&mut *tx).await?;
        Some(revision)
    } else {
        None
    };

    // Insert first, then atomically reactivate the exact submitted IDs while
    // retiring every competing live row at each coordinate.
    let mut stored = Vec::with_capacity(1 + projections.len());
    for event in projections
        .iter()
        .chain(std::iter::once(&request.private_event))
    {
        let was_deleted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM events WHERE community_id=$1 AND id=$2 AND deleted_at IS NOT NULL)")
            .bind(community.as_uuid()).bind(event.id.to_bytes()).fetch_one(&mut *tx).await?;
        let (row, inserted) = crate::event::insert_event_with_thread_metadata_tx(
            &mut tx, community, event, None, None,
        )
        .await?;
        let d = exact_d(event)?;
        let activated = sqlx::query("UPDATE events SET deleted_at=CASE WHEN id=$5 THEN NULL ELSE now() END WHERE community_id=$1 AND kind=$2 AND pubkey=$3 AND d_tag=$4 AND (deleted_at IS NULL OR id=$5)")
            .bind(community.as_uuid()).bind(event.kind.as_u16() as i32).bind(event.pubkey.to_bytes()).bind(d).bind(event.id.to_bytes()).execute(&mut *tx).await?;
        if activated.rows_affected() == 0 {
            return Err(DbError::ManagedAgentConflict(
                "submitted event ID is not stored at its signed coordinate".into(),
            ));
        }
        if inserted || was_deleted {
            stored.push(row);
        }
    }

    // Tombstones carry no projections, but their prior public instance must not
    // remain discoverable as an active managed agent. Definitions are shared
    // and revision-pinned, so deleting one agent must not retire that row.
    if envelope.state == State::Deleted {
        sqlx::query("UPDATE events SET deleted_at=now() WHERE community_id=$1 AND kind=30177 AND pubkey=$2 AND d_tag=$3 AND deleted_at IS NULL")
            .bind(community.as_uuid())
            .bind(&owner)
            .bind(envelope.agent_pubkey.to_hex())
            .execute(&mut *tx)
            .await?;
    }

    let state = match envelope.state {
        State::Active => "active",
        State::Deleted => "deleted",
    };
    sqlx::query("INSERT INTO managed_agent_heads (community_id,owner_pubkey,agent_pubkey,generation,event_id,state,definition_d,definition_revision,definition_event_id,definition_content_sha256,instance_event_id,instance_content_sha256) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (community_id,owner_pubkey,agent_pubkey) DO UPDATE SET generation=EXCLUDED.generation,event_id=EXCLUDED.event_id,state=EXCLUDED.state,definition_d=EXCLUDED.definition_d,definition_revision=EXCLUDED.definition_revision,definition_event_id=EXCLUDED.definition_event_id,definition_content_sha256=EXCLUDED.definition_content_sha256,instance_event_id=EXCLUDED.instance_event_id,instance_content_sha256=EXCLUDED.instance_content_sha256,updated_at=now()")
        .bind(community.as_uuid()).bind(&owner).bind(&agent).bind(envelope.generation as i64).bind(&event_id).bind(state).bind(&definition_d).bind(definition_revision).bind(&definition_event_id).bind(&definition_hash).bind(&instance_event_id).bind(&instance_hash).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO managed_agent_revisions (community_id,owner_pubkey,agent_pubkey,generation,event_id,previous_event_id,state,definition_d,definition_revision,definition_event_id,definition_content_sha256,instance_event_id,instance_content_sha256,private_event,definition_event,instance_event) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)")
        .bind(community.as_uuid()).bind(&owner).bind(&agent).bind(envelope.generation as i64).bind(&event_id).bind(&previous).bind(state).bind(&definition_d).bind(definition_revision).bind(&definition_event_id).bind(&definition_hash).bind(&instance_event_id).bind(&instance_hash)
        .bind(serde_json::to_value(&request.private_event)?).bind(request.definition_event.as_ref().map(serde_json::to_value).transpose()?).bind(request.instance_event.as_ref().map(serde_json::to_value).transpose()?).execute(&mut *tx).await?;
    let snapshot = read_snapshot_tx(
        &mut tx,
        community,
        &owner,
        &agent,
        envelope.generation,
        true,
        stored,
    )
    .await?;
    tx.commit().await?;
    Ok(snapshot)
}

/// Read a head from the writer pool, never a lagging replica.
pub async fn read_head(
    pool: &PgPool,
    community: CommunityId,
    owner: &[u8],
    agent: &[u8],
) -> Result<Option<ManagedAgentHead>> {
    let row = sqlx::query("SELECT owner_pubkey,agent_pubkey,generation,event_id,state FROM managed_agent_heads WHERE community_id=$1 AND owner_pubkey=$2 AND agent_pubkey=$3")
        .bind(community.as_uuid()).bind(owner).bind(agent).fetch_optional(pool).await?;
    row.map(|r| {
        Ok(ManagedAgentHead {
            owner_pubkey: r.try_get("owner_pubkey")?,
            agent_pubkey: r.try_get("agent_pubkey")?,
            generation: r.try_get::<i64, _>("generation")? as u64,
            event_id: r.try_get("event_id")?,
            active: r.try_get::<String, _>("state")? == "active",
        })
    })
    .transpose()
}

/// Whether a principal is revoked by a deleted PMA head in this community.
///
/// `proven_owner` is cryptographically verified NIP-OA evidence from the
/// current request. The durable user mapping is checked as an independent
/// owner binding so a caller cannot bypass an existing tombstone by presenting
/// a second delegation. Rows belonging only to unrelated owners or communities
/// never revoke the principal.
pub async fn participation_is_revoked(
    pool: &PgPool,
    community: CommunityId,
    agent: &[u8],
    proven_owner: Option<&[u8]>,
) -> Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS(\
             SELECT 1 FROM managed_agent_heads h \
              WHERE h.community_id=$1 AND h.agent_pubkey=$2 AND h.state='deleted' \
                AND (h.owner_pubkey=$3::bytea OR h.owner_pubkey=(\
                    SELECT u.agent_owner_pubkey FROM users u \
                     WHERE u.community_id=$1 AND u.pubkey=$2\
                ))\
         )",
    )
    .bind(community.as_uuid())
    .bind(agent)
    .bind(proven_owner)
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

/// Whether a projection coordinate is controlled by a PMA head.
pub async fn projection_coordinate_is_authoritative(
    pool: &PgPool,
    community: CommunityId,
    kind: u32,
    owner: &[u8],
    d_tag: &str,
) -> Result<bool> {
    let mut connection = pool.acquire().await?;
    projection_coordinate_is_authoritative_on(&mut connection, community, kind, owner, d_tag).await
}

pub(crate) async fn projection_coordinate_is_authoritative_on(
    connection: &mut sqlx::PgConnection,
    community: CommunityId,
    kind: u32,
    owner: &[u8],
    d_tag: &str,
) -> Result<bool> {
    let exists = match kind {
        30177 => {
            let agent = hex::decode(d_tag)
                .map_err(|_| invalid("invalid managed-agent d tag"))?;
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM managed_agent_heads WHERE community_id=$1 AND owner_pubkey=$2 AND agent_pubkey=$3)")
                .bind(community.as_uuid())
                .bind(owner)
                .bind(agent)
                .fetch_one(&mut *connection)
                .await?
        }
        30175 => sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM managed_agent_heads WHERE community_id=$1 AND owner_pubkey=$2 AND definition_d=$3)")
            .bind(community.as_uuid())
            .bind(owner)
            .bind(d_tag)
            .fetch_one(&mut *connection)
            .await?,
        _ => false,
    };
    Ok(exists)
}

/// Whether an ordinary projection write targets PMA-authoritative state.
pub async fn projection_is_authoritative(
    pool: &PgPool,
    community: CommunityId,
    event: &Event,
    d_tag: &str,
) -> Result<bool> {
    projection_coordinate_is_authoritative(
        pool,
        community,
        event.kind.as_u16() as u32,
        &event.pubkey.to_bytes(),
        d_tag,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Kind, Tag};

    fn projection(keys: &Keys, kind: u16, d: &str) -> Event {
        EventBuilder::new(Kind::Custom(kind), "projection")
            .tag(Tag::parse(["d", d]).expect("d tag"))
            .sign_with_keys(keys)
            .expect("sign projection")
    }

    #[test]
    fn active_projection_validation_binds_owner_kind_signature_and_agent_coordinate() {
        let owner = Keys::generate();
        let agent = Keys::generate();
        let definition = projection(&owner, 30175, "definition");
        let instance = projection(&owner, 30177, &agent.public_key().to_hex());
        assert_eq!(
            validate_projection(&definition, &owner.public_key(), 30175).unwrap(),
            "definition"
        );
        assert_eq!(
            validate_projection(&instance, &owner.public_key(), 30177).unwrap(),
            agent.public_key().to_hex()
        );
        assert!(validate_projection(&instance, &owner.public_key(), 30175).is_err());
        assert!(validate_projection(&instance, &Keys::generate().public_key(), 30177).is_err());
    }

    fn private_head(
        owner: &Keys,
        agent: &Keys,
        generation: u64,
        previous: Option<&nostr::EventId>,
        state: &str,
    ) -> Event {
        let mut tags = vec![
            Tag::parse(["d", agent.public_key().to_hex().as_str()]).unwrap(),
            Tag::parse(["g", generation.to_string().as_str()]).unwrap(),
            Tag::parse(["state", state]).unwrap(),
        ];
        if let Some(previous) = previous {
            tags.push(Tag::parse(["prev", previous.to_hex().as_str()]).unwrap());
        }
        EventBuilder::new(Kind::Custom(30179), "encrypted-ciphertext")
            .tags(tags)
            .sign_with_keys(owner)
            .unwrap()
    }

    async fn postgres_fixture() -> Option<(PgPool, CommunityId)> {
        let url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .ok()?;
        let pool = PgPool::connect(&url).await.ok()?;
        let id = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
            .bind(id)
            .bind(format!("pma-test-{}.example", id.simple()))
            .execute(&pool)
            .await
            .ok()?;
        Some((pool, CommunityId::from_uuid(id)))
    }

    #[tokio::test]
    #[ignore = "requires migrated Postgres via BUZZ_TEST_DATABASE_URL"]
    async fn aggregate_readback_retry_reactivation_retirement_and_shared_pinning() {
        let (pool, community) = postgres_fixture().await.expect("Postgres fixture");
        let owner = Keys::generate();
        let first_agent = Keys::generate();
        let second_agent = Keys::generate();
        let definition_v1 = projection(&owner, 30175, "shared");
        let first_instance = projection(&owner, 30177, &first_agent.public_key().to_hex());
        let first_private = private_head(&owner, &first_agent, 1, None, "active");
        let first = AggregateRequest {
            private_event: first_private.clone(),
            definition_event: Some(definition_v1.clone()),
            instance_event: Some(first_instance.clone()),
            expected_definition_revision: Some(1),
        };
        let committed = commit_aggregate(&pool, community, &first).await.unwrap();
        assert!(committed.inserted);
        assert_eq!(committed.definition_revision, Some(1));
        assert_eq!(committed.private_event, first_private);
        assert_eq!(committed.definition_event, Some(definition_v1.clone()));

        let retried = commit_aggregate(&pool, community, &first).await.unwrap();
        assert!(!retried.inserted);
        assert_eq!(retried.private_event, committed.private_event);
        assert_eq!(retried.definition_event, committed.definition_event);
        assert_eq!(retried.instance_event, committed.instance_event);
        let changed_binding = AggregateRequest {
            private_event: first.private_event.clone(),
            definition_event: Some(projection(&owner, 30175, "different-definition")),
            instance_event: first.instance_event.clone(),
            expected_definition_revision: first.expected_definition_revision,
        };
        assert!(matches!(
            commit_aggregate(&pool, community, &changed_binding).await,
            Err(DbError::ManagedAgentConflict(message))
                if message.contains("changed projection bindings")
        ));

        // A previously soft-deleted exact projection is made live again.
        sqlx::query("UPDATE events SET deleted_at=now() WHERE community_id=$1 AND id=$2")
            .bind(community.as_uuid())
            .bind(definition_v1.id.to_bytes())
            .execute(&pool)
            .await
            .unwrap();
        let first_v2 = AggregateRequest {
            private_event: private_head(&owner, &first_agent, 2, Some(&first_private.id), "active"),
            definition_event: Some(definition_v1.clone()),
            instance_event: Some(first_instance),
            expected_definition_revision: Some(1),
        };
        commit_aggregate(&pool, community, &first_v2).await.unwrap();
        let definition_live: bool = sqlx::query_scalar(
            "SELECT deleted_at IS NULL FROM events WHERE community_id=$1 AND id=$2",
        )
        .bind(community.as_uuid())
        .bind(definition_v1.id.to_bytes())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(definition_live);
        let first_private_live: bool = sqlx::query_scalar(
            "SELECT deleted_at IS NULL FROM events WHERE community_id=$1 AND id=$2",
        )
        .bind(community.as_uuid())
        .bind(first_private.id.to_bytes())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!first_private_live);

        // Advancing a shared definition for another agent does not invalidate
        // the first agent's pinned immutable revision bytes.
        let definition_v2 = EventBuilder::new(Kind::Custom(30175), "projection-v2")
            .tag(Tag::parse(["d", "shared"]).unwrap())
            .sign_with_keys(&owner)
            .unwrap();
        let second = AggregateRequest {
            private_event: private_head(&owner, &second_agent, 1, None, "active"),
            definition_event: Some(definition_v2.clone()),
            instance_event: Some(projection(
                &owner,
                30177,
                &second_agent.public_key().to_hex(),
            )),
            expected_definition_revision: Some(2),
        };
        let second_commit = commit_aggregate(&pool, community, &second).await.unwrap();
        assert_eq!(second_commit.definition_revision, Some(2));
        let pinned: serde_json::Value = sqlx::query_scalar("SELECT definition_event FROM managed_agent_revisions WHERE community_id=$1 AND owner_pubkey=$2 AND agent_pubkey=$3 AND generation=2")
            .bind(community.as_uuid()).bind(owner.public_key().to_bytes()).bind(first_agent.public_key().to_bytes()).fetch_one(&pool).await.unwrap();
        assert_eq!(
            decode_event(pinned, "pinned definition").unwrap(),
            definition_v1
        );

        // Two distinct candidates that both predict current+1 cannot both
        // commit. The loser observes the advanced definition under the lock and
        // gets a conflict before its own managed-agent generation is written.
        let race_agent_a = Keys::generate();
        let race_agent_b = Keys::generate();
        let race_a = AggregateRequest {
            private_event: private_head(&owner, &race_agent_a, 1, None, "active"),
            definition_event: Some(
                EventBuilder::new(Kind::Custom(30175), "race-a")
                    .tag(Tag::parse(["d", "shared"]).unwrap())
                    .sign_with_keys(&owner)
                    .unwrap(),
            ),
            instance_event: Some(projection(
                &owner,
                30177,
                &race_agent_a.public_key().to_hex(),
            )),
            expected_definition_revision: Some(3),
        };
        let race_b = AggregateRequest {
            private_event: private_head(&owner, &race_agent_b, 1, None, "active"),
            definition_event: Some(
                EventBuilder::new(Kind::Custom(30175), "race-b")
                    .tag(Tag::parse(["d", "shared"]).unwrap())
                    .sign_with_keys(&owner)
                    .unwrap(),
            ),
            instance_event: Some(projection(
                &owner,
                30177,
                &race_agent_b.public_key().to_hex(),
            )),
            expected_definition_revision: Some(3),
        };
        let (result_a, result_b) = tokio::join!(
            commit_aggregate(&pool, community, &race_a),
            commit_aggregate(&pool, community, &race_b)
        );
        assert_eq!(
            usize::from(result_a.is_ok()) + usize::from(result_b.is_ok()),
            1
        );
        let conflict = if let Err(error) = result_a {
            error
        } else {
            result_b.unwrap_err()
        };
        assert!(matches!(
            conflict,
            DbError::ManagedAgentConflict(message)
                if message.contains("expected definition revision")
        ));
        let race_heads: i64 = sqlx::query_scalar("SELECT count(*) FROM managed_agent_heads WHERE community_id=$1 AND owner_pubkey=$2 AND agent_pubkey IN ($3,$4)")
            .bind(community.as_uuid()).bind(owner.public_key().to_bytes()).bind(race_agent_a.public_key().to_bytes()).bind(race_agent_b.public_key().to_bytes()).fetch_one(&pool).await.unwrap();
        assert_eq!(race_heads, 1);

        // A generic instance ingest that starts before the first aggregate
        // commits must lose after the aggregate binds the coordinate. Hold the
        // aggregate on its definition lock after it has acquired the instance
        // replacement lock, then start the generic writer behind it.
        let ingest_race_agent = Keys::generate();
        let ingest_race_d = ingest_race_agent.public_key().to_hex();
        let ingest_race_definition = projection(&owner, 30175, "ingest-race-definition");
        let expected_ingest_race_definition_id = ingest_race_definition.id.to_bytes();
        let ingest_race_instance = projection(&owner, 30177, &ingest_race_d);
        let expected_ingest_race_instance_id = ingest_race_instance.id.to_bytes();
        let ingest_race_request = AggregateRequest {
            private_event: private_head(&owner, &ingest_race_agent, 1, None, "active"),
            definition_event: Some(ingest_race_definition),
            instance_event: Some(ingest_race_instance.clone()),
            expected_definition_revision: Some(1),
        };
        let definition_lock = super::super::event_replacement_lock_key(
            community,
            30175,
            &owner.public_key().to_bytes(),
            Some(b"ingest-race-definition"),
        );
        let instance_lock = super::super::event_replacement_lock_key(
            community,
            30177,
            &owner.public_key().to_bytes(),
            Some(ingest_race_d.as_bytes()),
        );
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(definition_lock)
            .execute(&mut *blocker)
            .await
            .unwrap();

        let aggregate_pool = pool.clone();
        let aggregate = tokio::spawn(async move {
            commit_aggregate(&aggregate_pool, community, &ingest_race_request).await
        });
        let mut aggregate_has_instance_lock = false;
        let mut probe = pool.acquire().await.unwrap();
        for _ in 0..1_000 {
            let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
                .bind(instance_lock)
                .fetch_one(&mut *probe)
                .await
                .unwrap();
            if acquired {
                sqlx::query("SELECT pg_advisory_unlock($1)")
                    .bind(instance_lock)
                    .execute(&mut *probe)
                    .await
                    .unwrap();
                tokio::task::yield_now().await;
            } else {
                aggregate_has_instance_lock = true;
                break;
            }
        }
        drop(probe);
        assert!(
            aggregate_has_instance_lock,
            "aggregate never reached the instance replacement lock"
        );

        let generic_db = crate::Db::from_pool(pool.clone());
        let generic_d = ingest_race_d.clone();
        let generic = tokio::spawn(async move {
            generic_db
                .replace_parameterized_event(community, &ingest_race_instance, &generic_d, None)
                .await
        });
        tokio::task::yield_now().await;
        blocker.commit().await.unwrap();
        assert!(aggregate.await.unwrap().is_ok());
        assert!(matches!(
            generic.await.unwrap(),
            Err(DbError::ManagedAgentConflict(message))
                if message.contains("projection is controlled")
        ));
        let live_instance: Vec<u8> = sqlx::query_scalar(
            "SELECT id FROM events WHERE community_id=$1 AND kind=30177 AND pubkey=$2 AND d_tag=$3 AND deleted_at IS NULL",
        )
        .bind(community.as_uuid())
        .bind(owner.public_key().to_bytes())
        .bind(&ingest_race_d)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(live_instance, expected_ingest_race_instance_id);

        // Both legacy kind:5 mutation shapes are fenced at the DB boundary:
        // a-tags delete by coordinate, while e-tags delete the resolved event ID.
        let first_agent_d = first_agent.public_key().to_hex();
        for (kind, d_tag, event_id) in [
            (
                30175,
                "ingest-race-definition",
                expected_ingest_race_definition_id.as_slice(),
            ),
            (
                30177,
                ingest_race_d.as_str(),
                expected_ingest_race_instance_id.as_slice(),
            ),
            (
                buzz_core::kind::KIND_PRIVATE_MANAGED_AGENT as i32,
                first_agent_d.as_str(),
                first_v2.private_event.id.as_bytes(),
            ),
        ] {
            assert!(
                !crate::event::soft_delete_by_coordinate(
                    &pool,
                    community,
                    kind,
                    &owner.public_key().to_bytes(),
                    d_tag,
                    chrono::Utc::now().timestamp() + 60,
                )
                .await
                .unwrap(),
                "a-tag deletion must not retire PMA-bound kind {kind}"
            );
            assert!(
                !crate::event::soft_delete_event_and_update_thread(
                    &pool, community, event_id, None, None,
                )
                .await
                .unwrap(),
                "e-tag deletion must not retire PMA-bound kind {kind}"
            );
            let live: bool = sqlx::query_scalar(
                "SELECT deleted_at IS NULL FROM events WHERE community_id=$1 AND id=$2",
            )
            .bind(community.as_uuid())
            .bind(event_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert!(live, "PMA-bound kind {kind} must remain live");
        }

        // Deletion advances the same private CAS chain, returns no public
        // bindings, and retires the instance projection. Neither a stale
        // pre-tombstone aggregate nor ordinary projection ingest may resurrect
        // an authority coordinate after the tombstone commits.
        let tombstone_private = private_head(
            &owner,
            &first_agent,
            3,
            Some(&first_v2.private_event.id),
            "deleted",
        );
        let tombstone = AggregateRequest {
            private_event: tombstone_private.clone(),
            definition_event: None,
            instance_event: None,
            expected_definition_revision: None,
        };
        let deleted = commit_aggregate(&pool, community, &tombstone)
            .await
            .unwrap();
        assert!(deleted.inserted);
        assert!(!deleted.head.active);
        assert_eq!(deleted.head.generation, 3);
        assert_eq!(deleted.private_event, tombstone_private);
        assert_eq!(deleted.definition_event, None);
        assert_eq!(deleted.instance_event, None);
        assert_eq!(deleted.definition_revision, None);

        let instance_live: bool = sqlx::query_scalar(
            "SELECT deleted_at IS NULL FROM events WHERE community_id=$1 AND id=$2",
        )
        .bind(community.as_uuid())
        .bind(first_v2.instance_event.as_ref().unwrap().id.to_bytes())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!instance_live);
        assert!(
            participation_is_revoked(
                &pool,
                community,
                first_agent.public_key().as_bytes(),
                Some(owner.public_key().as_bytes()),
            )
            .await
            .unwrap(),
            "the exact deleted owner-agent coordinate revokes participation"
        );
        let foreign_owner = Keys::generate();
        assert!(
            !participation_is_revoked(
                &pool,
                community,
                first_agent.public_key().as_bytes(),
                Some(foreign_owner.public_key().as_bytes()),
            )
            .await
            .unwrap(),
            "a foreign owner cannot use another owner's tombstone to revoke an agent"
        );
        let db = crate::Db::from_pool(pool.clone());
        db.ensure_user(community, owner.public_key().as_bytes())
            .await
            .unwrap();
        db.ensure_user(community, first_agent.public_key().as_bytes())
            .await
            .unwrap();
        assert!(db
            .set_agent_owner(
                community,
                first_agent.public_key().as_bytes(),
                owner.public_key().as_bytes(),
            )
            .await
            .unwrap());
        assert!(
            participation_is_revoked(&pool, community, first_agent.public_key().as_bytes(), None,)
                .await
                .unwrap(),
            "the durable owner mapping revokes without request delegation evidence"
        );
        assert!(
            !participation_is_revoked(
                &pool,
                community,
                second_agent.public_key().as_bytes(),
                Some(owner.public_key().as_bytes()),
            )
            .await
            .unwrap(),
            "an active head does not revoke participation"
        );
        let other_community = postgres_fixture().await.unwrap().1;
        assert!(
            !participation_is_revoked(
                &pool,
                other_community,
                first_agent.public_key().as_bytes(),
                Some(owner.public_key().as_bytes()),
            )
            .await
            .unwrap(),
            "a tombstone in another community does not revoke participation"
        );
        assert!(
            !participation_is_revoked(
                &pool,
                community,
                Keys::generate().public_key().as_bytes(),
                Some(owner.public_key().as_bytes()),
            )
            .await
            .unwrap(),
            "an absent head does not revoke participation"
        );
        assert!(
            projection_is_authoritative(
                &pool,
                community,
                first_v2.instance_event.as_ref().unwrap(),
                &first_agent.public_key().to_hex(),
            )
            .await
            .unwrap(),
            "deleted heads retain the authority fence"
        );

        let stale_resurrection = AggregateRequest {
            private_event: private_head(
                &owner,
                &first_agent,
                3,
                Some(&first_v2.private_event.id),
                "active",
            ),
            definition_event: Some(definition_v1),
            instance_event: first_v2.instance_event,
            expected_definition_revision: Some(1),
        };
        assert!(matches!(
            commit_aggregate(&pool, community, &stale_resurrection).await,
            Err(DbError::ManagedAgentConflict(message))
                if message.contains("predecessor or generation conflict")
        ));
        let head = read_head(
            &pool,
            community,
            &owner.public_key().to_bytes(),
            &first_agent.public_key().to_bytes(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(head.generation, 3);
        assert!(!head.active);
    }

    #[test]
    fn projection_rejects_ambiguous_d_tags() {
        let owner = Keys::generate();
        let event = EventBuilder::new(Kind::Custom(30175), "projection")
            .tags([
                Tag::parse(["d", "one"]).unwrap(),
                Tag::parse(["d", "two"]).unwrap(),
            ])
            .sign_with_keys(&owner)
            .unwrap();
        assert!(validate_projection(&event, &owner.public_key(), 30175).is_err());
    }
}
