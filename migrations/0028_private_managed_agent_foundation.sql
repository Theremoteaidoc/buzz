-- Relay-canonical authority for NIP-PMA kind:30179. The head retains the
-- generation floor after deletion; immutable revisions provide the audit/CAS
-- chain. Public projections are bound by exact signed event IDs and hashes.
CREATE TABLE managed_agent_definition_heads (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    owner_pubkey BYTEA NOT NULL CHECK (length(owner_pubkey) = 32),
    definition_d TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    event_id BYTEA NOT NULL CHECK (length(event_id) = 32),
    content_sha256 BYTEA NOT NULL CHECK (length(content_sha256) = 32),
    PRIMARY KEY (community_id, owner_pubkey, definition_d)
);

CREATE TABLE managed_agent_heads (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    owner_pubkey BYTEA NOT NULL CHECK (length(owner_pubkey) = 32),
    agent_pubkey BYTEA NOT NULL CHECK (length(agent_pubkey) = 32),
    generation BIGINT NOT NULL CHECK (generation > 0 AND generation <= 9007199254740991),
    event_id BYTEA NOT NULL CHECK (length(event_id) = 32),
    state TEXT NOT NULL CHECK (state IN ('active', 'deleted')),
    definition_d TEXT,
    definition_revision BIGINT,
    definition_event_id BYTEA,
    definition_content_sha256 BYTEA,
    instance_event_id BYTEA,
    instance_content_sha256 BYTEA,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (community_id, owner_pubkey, agent_pubkey),
    UNIQUE (community_id, event_id),
    CHECK ((state = 'active') =
      (definition_d IS NOT NULL AND definition_revision IS NOT NULL AND
       definition_event_id IS NOT NULL AND definition_content_sha256 IS NOT NULL AND
       instance_event_id IS NOT NULL AND instance_content_sha256 IS NOT NULL)),
    CHECK (definition_event_id IS NULL OR length(definition_event_id) = 32),
    CHECK (definition_content_sha256 IS NULL OR length(definition_content_sha256) = 32),
    CHECK (instance_event_id IS NULL OR length(instance_event_id) = 32),
    CHECK (instance_content_sha256 IS NULL OR length(instance_content_sha256) = 32)
);
CREATE INDEX managed_agent_heads_definition_binding
    ON managed_agent_heads (community_id, owner_pubkey, definition_d);

CREATE TABLE managed_agent_revisions (
    community_id UUID NOT NULL,
    owner_pubkey BYTEA NOT NULL,
    agent_pubkey BYTEA NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0 AND generation <= 9007199254740991),
    event_id BYTEA NOT NULL CHECK (length(event_id) = 32),
    previous_event_id BYTEA CHECK (previous_event_id IS NULL OR length(previous_event_id) = 32),
    state TEXT NOT NULL CHECK (state IN ('active', 'deleted')),
    definition_d TEXT,
    definition_revision BIGINT,
    definition_event_id BYTEA CHECK (definition_event_id IS NULL OR length(definition_event_id) = 32),
    definition_content_sha256 BYTEA CHECK (definition_content_sha256 IS NULL OR length(definition_content_sha256) = 32),
    instance_event_id BYTEA CHECK (instance_event_id IS NULL OR length(instance_event_id) = 32),
    instance_content_sha256 BYTEA CHECK (instance_content_sha256 IS NULL OR length(instance_content_sha256) = 32),
    private_event JSONB NOT NULL,
    definition_event JSONB,
    instance_event JSONB,
    committed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (community_id, owner_pubkey, agent_pubkey, generation),
    UNIQUE (community_id, event_id),
    FOREIGN KEY (community_id, owner_pubkey, agent_pubkey)
      REFERENCES managed_agent_heads (community_id, owner_pubkey, agent_pubkey)
      DEFERRABLE INITIALLY DEFERRED
);

-- NIP-PMA kind:30179 contains owner-encrypted runnable agent configuration and
-- is author-only. Preserve every installation's current FTS expression while
-- making existing and future private aggregate rows storage-level unsearchable.
DO $$
DECLARE
    existing_expression TEXT;
BEGIN
    SELECT pg_get_expr(d.adbin, d.adrelid)
      INTO existing_expression
      FROM pg_attrdef d
      JOIN pg_attribute a
        ON a.attrelid = d.adrelid
       AND a.attnum = d.adnum
     WHERE d.adrelid = 'events'::regclass
       AND a.attname = 'search_tsv';

    IF existing_expression IS NULL THEN
        RAISE EXCEPTION 'events.search_tsv generated expression not found';
    END IF;

    ALTER TABLE events DROP COLUMN search_tsv;
    EXECUTE format(
        'ALTER TABLE events ADD COLUMN search_tsv TSVECTOR GENERATED ALWAYS AS (CASE WHEN kind = 30179 THEN NULL::tsvector ELSE (%s) END) STORED',
        existing_expression
    );
    CREATE INDEX idx_events_search_tsv ON events USING GIN (search_tsv);
END $$;
