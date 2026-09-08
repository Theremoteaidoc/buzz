# Upstream factory reliability intake

Goal: bring selected upstream reliability fixes onto factory baseline 50d96668, resolve integration blockers and verify the installed harness. Preserve fork lifecycle protections and canonical agent policy. Rust builds run on ci1 as buzzagent.

- [x] U1: adapt #6950 memory CLI guidance and isolated seeded-memory evaluation to the fork's DONE runtime. Fixture validation is not a live model success measurement.
- [x] U2: backport #7010 receive-boundary verification. Demonstrate tampered-content failure before fix; verify before routing, queues and replay state.
- [x] U3: backport #7325 targeted, capacity-aware replay. Retain best-effort replay semantics and existing bounded writes.
- [x] Independently verify clean b49f12df: 767 ACP tests, fmt, clippy; Python 41 tests. Build and verify candidate artifact without installing while gates fail.
- [ ] Resolve Security findings using patched h2/webbrowser and the upstream #6189 MeshLLM/Nostr migration, including mesh-enabled desktop compatibility.
- [ ] Route Docker build/cache/provenance to this fork's configured GHCR namespaces; retain build and publication gates.
- [ ] Run final scoped tests and GitHub CI on immutable final commit, independently review the delta, and integrate PR14 only with passing required checks.
- [ ] Build final immutable sprig, verify archive/manifest identity, install at safe idle boundaries, and verify all active seat processes use the expected executable. Keep rollback artifact and retired Codex disabled.
- [ ] Update reliability ledger and installation receipt with final source, checks and actual runtime state.

U4 thread-session migration remains separate; do not enable it without its base implementation and both follow-up fixes. No product or clinical behavior changes, live test messages, or product promotion are part of this harness intake.
