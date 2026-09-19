# Phase 1 prompt review

Reviewed 2026-09-19 by Codex (self-review, not independent review).
Current outcome: [Phase 1 ACCEPTED](phase-1-acceptance.md), with A01-A16 PASS in qualification
`q-eeb8b07a`. The final line-by-line re-vetting and exact tested identity are linked there.
The review and bootstrap notes below are historical: the initial prompt review alone did not
accept Phase 1.

Reviewed against the user's requirements and the current intake config/prompt, artifact template,
staging helper, run state manager, CLI attempt archival, lane validator, process manifest,
registry authoring guide, and orchestrator ADR. A version hash is recorded in the bootstrap run's
`data/acceptance/prompt-vetting.json`. Re-vet after material changes.

| Requirement | Prompt coverage | Acceptance |
|---|---|---|
| Visual job wiring, repo-owned containers, old stack stopped | Task 1 | A02 |
| Polyglot/native applicability and whole-repository scope | Task 2 | A04, A14 |
| Initial readiness versus post-pregather completeness | Task 2 | A05 |
| Run-owned evidence, extraction, builds and logs | Task 3; run-data contract | A06 |
| Stateful idempotency, retries, start-over without staleness | Task 3 | A07-A09 |
| Personas, roles and compatible job contracts | Task 4 | A03 |
| Interjob dependencies, order, skips and stale descendants | Task 4; flow document | A08, A10, A15 |
| Pre/post validation with real downstream blocking | Task 4 | A10 |
| stdout/stderr, durable events, robust error propagation | Task 5 | A11-A12 |
| Legacy preservation and migration | Task 3 | A13 |
| Vetted prompt, evidence-backed acceptance and documentation closeout | Task 0; closeout | A01, A16 |

## Review findings resolved in the specification

- "Phase 1" is intake/recovery, not the older implementation plan's registry phase.
- The user confirmed "Dagster". Bootstrap setup is the first implementation task after prompt
  vetting; it is not proof that all intake requirements pass.
- The new run-data requirement supersedes shared scratch for migrated jobs. Existing producers
  still use legacy scratch; explicit migration and compatibility tests are required, not a silent
  documentation-only path switch.
- Intake plans partition discovery but cannot require its output in advance. This avoids a cycle.
- Validators use a nonrecursive bootstrap contract rather than infinitely wrapping validators.
- A skipped prerequisite is not automatically successful; consumer-specific applicability matters.
- Successful process exit does not publish an artifact without post-validation. A green UI alone
  is insufficient. Dagster checks default to nonblocking unless configured otherwise; the smoke
  graph uses explicit dependencies and exception propagation.
- Reuse must validate hashes and provenance; a failed newer attempt must not silently fall back
  to a stale successful attempt. LLM reruns are not assumed byte-for-byte deterministic.
- Acceptance documentation updates follow evidence-backed acceptance; no extra user approval gate
  is imposed on every engagement.

## Actual bootstrap verification

All four `appsec-review` containers were healthy, and localhost port 3000 returned HTTP 200.
The four old `lra-ingestion-harness` Dagster containers were stopped; volumes were preserved.

- Success execution: `e82a57f1-b986-4ac2-a82a-d26a8aa2e29f`.
- Injected failure execution: `a738a09c-f45e-4bc2-926f-f60dab400d38`; child exit 7 failed work and
  prevented post-validation execution.
- After restarting all four new services, both run statuses, separate stdout/stderr files, and
  the successful output hash remained available and correct.
- Compose configuration and Python compilation checked successfully.

Remaining: the complete Phase 1 runner, registry configurations for its new jobs, semantic
validators, same-run idempotency, crash/concurrency/IO failure tests, machine graph synchronization,
and the bounded Freeciv21 qualification. The bootstrap is intentionally not a rugged production
executor and does not pass A01-A16 on behalf of that future implementation.
