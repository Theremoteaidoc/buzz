# Upstream memory and event-validation intake

Goal: adapt U1 (#6950 memory retrieval) and U2 (#7010 receive-boundary verification) to factory baseline 50d96668 while retaining all fork behavior.
Architecture: use existing Buzz memory CLI and existing buzz_core::verify_event, with tests at actual prompt and relay boundaries. No wholesale upstream merge or session-policy change.
Tech stack: Rust/Tokio, Python benchmark fixtures, existing sprig build on ci-1 as buzzagent.

- [ ] Inspect upstream pinned patches and actual fork APIs; preserve source attribution.
- [ ] U1: adapt memory guidance and a meaningful seeded-memory retrieval evaluation using current benchmark harness. Keep canonical VPS memories authoritative; no production secrets in test fixtures.
- [ ] U2: port forged-event regressions first, demonstrate failure on baseline, then verify every incoming EVENT before routing/dedup/watermarks/queues. Keep observer defense in depth.
- [ ] Run cargo test -p buzz-acp, scoped clippy and formatting; run repository just ci where supported and record any genuine prerequisite limitation. Preserve heartbeat/WIP/turn-cap regressions.
- [ ] Independent review, fix findings, commit with upstream attribution and push fork PR(s), no coauthor trailer.
- [ ] Build immutable sprig artifact on ci-1 as buzzagent from reviewed commit. Verify manifest hash, canary at safe idle boundary, then roll out only if verified; don't restart active turns or remove prior rollback binary.
- [ ] Record what shipped, measured evaluation outcomes and any unverified runtime behavior. U3 replay recovery next; U4 remains separate opt-in migration with both followup fixes.
