# Cold-memory retrieval regression

Adapted from [block/buzz #6950](https://github.com/block/buzz/pull/6950), head
`1a2833f45fb68021277070507965757337c810fd` (merge
`f463e726dd173146c3c2bcbf7fdba03c9790dd3a`). The fork predates upstream's native
task harness, so this task uses the existing orchestrator/worker runtime and
`DONE:` completion protocol. It does not test upstream's threaded-reply grading.

Run with the existing benchmark command in the harness README, setting the task
path to this directory and the manifest condition to `memory-retrieval`. Use a
neutral orchestrator persona (for example: “Answer the user's task and follow its
requested response format.”), with its actual SHA256 in the manifest. Keep the
existing required worker roster entry. Use only trial-isolated identities and
an explicitly configured test relay. Do not use production agent credentials.

Before any agent starts, the host harness writes five synthetic cold memories
using the orchestrator's `buzz mem set <slug> -` credentials. Only one contains
the requested April total. Neither the instruction nor channel setup contains
the answer or slug. The agent must discover the data via its memory CLI. Seed
values stay host-side and are never uploaded to the task filesystem or persona.

The requested response is exactly `DONE: 352,345` (comma-free is accepted).
The runtime observes the orchestrator's own completion, grades it, and writes
the verifier reward. Wrong metrics, guesses, approximations, memory dumps, and
unrelated prose earn zero. The same grade is recorded as
`memory_retrieval_reward` in runtime metadata. A timed-out run is not a pass.
This checks observable retrieval behavior, not a tool-call trace. The fixed
synthetic number is suitable for regression use, not a contamination-resistant
leaderboard. Local Python tests validate fixtures and grading only. They do not
establish model retrieval success or improvement over the old prompt.
