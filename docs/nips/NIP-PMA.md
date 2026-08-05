# NIP-PMA: Private Managed-Agent Aggregate

`draft` — protocol/codec reservation only. Relays MUST reject this kind until
privacy, transactional CAS, backup/restore, revocation, and capability gates are
deployed.

## Purpose and kind

Kind `30179` is an owner-authored, addressable, owner-readable aggregate for one
runnable managed agent. Its coordinate is `(owner pubkey, 30179, agent pubkey)`.
It is the only durable authority after a per-agent migration is independently
verified. Kinds `30175` and `30177` remain public/compatibility projections.

This reservation does not change current agent authority, storage, startup,
mutation, deletion, catalog, or sharing behavior.

## Signed outer envelope

Exactly these two-element tags are permitted:

- `d = <64 lowercase hex agent pubkey>` exactly once;
- `g = <canonical positive decimal generation>` exactly once;
- `prev = <64 lowercase hex predecessor event id>` exactly once after
  generation 1 and absent at generation 1;
- `state = active|deleted` exactly once.

Content is bounded NIP-44 v2 ciphertext encrypted owner-to-owner. Event ID and
signature, exact kind/author/tag grammar, canonical curve-valid agent keys, and size
are validated before decrypt. The decrypted payload repeats owner, agent,
generation, predecessor, and state; any mismatch is corruption.

## Decrypted v1 payload

Top-level and nested core schemas reject unknown and duplicate JSON member
names. Forward-compatible data is confined to namespaced `extensions` entries;
core semantics never depend on an extension. Projection recovery v1 contains
the complete signed public event; validation verifies its signature and ID,
owner, kind and `d` coordinate, and hashes its exact content bytes against the
binding. This makes reconstruction deterministic rather than an agreement over
an untyped JSON blob.

An active payload binds exact signed `30175` and `30177` event IDs, SHA-256 of
their exact content bytes, and complete versioned recovery material. It also
contains the preserved agent nsec and an optional NIP-OA attestation, plus
explicitly allowlisted private runnable configuration. When present, the
attestation MUST be a cryptographically valid unconditional (`conditions = ""`)
owner-to-agent authorization: its owner equals the aggregate author and its
agent equals the nsec-derived `d` coordinate. Conditional, malformed, wrong-owner,
or wrong-agent attestations are rejected. The nsec MUST derive the `d`
coordinate.

All active aggregates require a stable `30175` definition binding. Before a
legacy definition-less agent can be encoded, the migrator MUST deterministically
materialize its definition fields as a non-shared `30175` under the owner, with
a stable collision-safe slug derived from the agent pubkey. Materialization and
read-back verification are prerequisites: failure leaves the agent `LegacyOnly`
and preserves its local record/key unchanged. No client may synthesize a default
or mint a replacement identity to satisfy this schema.

A deleted payload is minimal: it contains no active body, advances generation
from its predecessor, and includes `deleted_at`. Relay anti-resurrection and
undelete rules are specified by the later transactional CAS contract; generic
NIP-33 LWW is explicitly insufficient.

## Field authority

- `30175` definition projection: display name, prompt, runtime/model/provider,
  name pool, definition behavior defaults, sharing/provenance, public avatar.
- `30177` instance projection: agent pubkey/name/definition linkage,
  parallelism, `respond_to`, and allowlist.
- private portable canonical: nsec, auth tag, env, durable timeout/team fields,
  and secret-bearing backend configuration.
- private but device-validated: relay URL, explicit command/args, backend remote
  identity, and any explicitly portable path/provider reference.
- local device policy/derived: start-on-launch, auto-restart, effective binary
  paths, installed team directory, and catalog-derived commands.
- legacy conversion only: create-time command/model/provider mirrors,
  deprecated MCP/turn timeout, source-version drift markers, and relay-mesh
  fallback markers where a definition is authoritative.
- transient local only: PID and all last start/stop/exit/error receipts/logs.

Adding a `ManagedAgentRecord` field must update an exhaustive Desktop
classification/conversion fixture before migration-writing code can merge. The
fixture is part of the relay-authority follow-up and fails when a durable field
has no explicit private, projection, local/derived, or transient classification.

## Aggregate submission boundary

Three ordinary Nostr `EVENT` writes cannot atomically commit an aggregate. The
relay contract accepts independently signed projection candidates plus the
signed encrypted private head through one authenticated aggregate submission
and one PostgreSQL transaction. The relay validates the outer envelope, owner
and agent coordinates, signed public candidates, relay-owned definition
revision, and CAS predecessor/generation before exposing any candidate. Fan-out
begins only after commit.

The relay cannot decrypt kind `30179` and MUST NOT receive the plaintext payload
or agent nsec. It therefore cannot prove that ciphertext-internal bindings match
the co-submitted public projections. It records the exact submitted projections
as the active bindings; Desktop performs the integrity gate by decrypting a
writer-consistent read-back and verifying those bindings before promoting the
agent to relay-authoritative state.

A definition edit shared by multiple authoritative agents advances each agent's
aggregate independently. Agents may transiently pin different revisions of the
same definition coordinate; each immutable aggregate revision retains its exact
bound recovery bytes while catalog browsing reads the latest active public
projection. Browsing never requires decrypting kind `30179`.

## Required deployment order

1. **Inert reservation:** codec and kind reservation while generic ingest still
   rejects `30179` (shipped in #4593).
2. **Relay-authority release:** author-only pre-pagination privacy and FTS gates,
   transactional CAS/authority storage, capability-advertised aggregate
   submission, tombstone revocation across every transport, and the Desktop
   reader with verified migration. Desktop keeps every agent `LegacyOnly` when
   the relay does not advertise the aggregate capability. Promotion requires a
   crash-safe writer-consistent decrypt-and-binding verification; PostgreSQL
   backup covers the authority tables and bound recovery bytes as one
   consistency domain.
3. **Independent later capabilities:** export/import and restore drills, owner
   rotation, and physical legacy cleanup.

No phase may publish secrets before the privacy gates are active or retire local
recovery evidence before the complete migration exit gate passes.
