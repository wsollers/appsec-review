# Walk terms: multivuln at `bd69bfe8`

The user requested this fresh, job-by-job live walk on 2026-11-12. The
[walk charter](../processes/walk-charter.md), root `AGENTS.md`, and the
[testing working loop](../architecture/testing.md#working-loop) govern it.
The [state](multivuln-bd69bfe8-state.md) records progress; records use
`docs/tasks/2026-11-12-multivuln-walk-NN-<job>.md`. It advances T-057.

## Target and host

- Host: `WSOLLERS1`, WSL `Ubuntu-22.04`.
- Owning Linux checkout: `/home/wsollers/projects/appsec-review`, branch `main`.
- Target: `targets/appsec-multi-vuln-c094`, observed clean at
  `bd69bfe83fec49155366303604475512c98c4ce6`.
- Existing target tag: `appsec-multi-vuln-c094-v1`, observed at target HEAD.
  No new tag or other target mutation is authorized.
- Scope: the target checkout under the existing repository configuration; no
  additional path exclusions or scoped replay from an earlier walk are introduced.
- Compose project: `appsec-review-dagster-wsl`; use the existing native Linux
  Docker Engine, not Docker Desktop.
- Selected profile: `copilot-prod`. Overlay:
  `test/acceptance/prod-capacity-overlay.toml`, which sets four I/O slots and
  four scanner pool slots without changing the configured CPU or memory budgets.
- Image identities, signing policy and keys remain unchanged. No image build,
  rebuild, re-pin, host commissioning or push is authorized.

## Decisions

| Date | User's words | Effect |
| --- | --- | --- |
| 2026-11-12 | "Run the review jobs from the start, one job at a time, through the final report" | Fresh run, one job at a time; all four checks before each acceptance |
| 2026-11-12 | "Start the run now; do not run unit tests first." | Unit tests only for a blocking defect, under the documented bounded repair loop |
| 2026-11-12 | "Use the ubuntu: wsollers@WSOLLERS1:~/projects/appsec-review$" | Use this machine's named Linux checkout rather than the app session's feature worktree |
| 2026-11-12 | "you are supposed to run against multivuln" | This walk is multivuln, not Freeciv |
| 2026-11-12 | "Yes—start with no pre-approved gaps (Recommended)" | Initialize these missing terms and state; the first gap cause requires a user decision |
| 2026-11-12 | "copilot-prod with the existing prod-capacity overlay" | Select the profile and overlay above rather than the current `.env`'s `copilot-dev` |
| 2026-11-12 | "This is my explicit request for this live run. It doesn't authorize integration or acceptance suites, image rebuilds, pushing, or changes to the target." | Live walk only; preserve those limits |
| 2026-11-12 | "Commit the records and state on main; don't push. Keep each machine's baselines local and out of Git." | Serialize integration into local `main`; use a fresh, ignored host-local corpus namespace |
| 2026-11-12 | "stop all those other threads and monitors. only you should be running and monitoring the code. Those others were supposed to go away a long time ago but keep getting resurr3ected" | This walker is the sole active repository owner. Stop the legacy coordinator and integration monitor; withdraw their pending update and documentation handoff. Do not revive dormant threads or legacy monitors |

## Expected gaps

**None.** No gap cause is pre-approved. Do not copy Freeciv's expected gaps or
infer approval from an older multivuln baseline. Stop and ask at the first new
cause; add a dated decision in the user's words before proceeding.

## Blindness

Do not read answer keys, evaluator guides, fix-pair lists, the private
`appsec-review-answers` repository, `docs/reviews/fix-pair-corpus-candidates.md`,
or anything under `test/acceptance/fix-pairs-candidates/` to steer this walk.
Do not inspect later target revisions or advisories to explain its findings.
Do not fetch, clone, cache or copy answers onto the host. Grading belongs to the
user after the walk.

## Baselines and session boundaries

Each fresh run receives a previously unused namespace under
`test/acceptance/multivuln-bd69bfe8-wsollers1-v*/`. Those directories and their
seed manifests are ignored; seed bytes remain in ignored
`data/acceptance-seeds/`. Pass the existing target tag separately on acceptance.
Do not reuse or overwrite earlier `appsec-multi-vuln-c094-*` baselines.

Rotate to a fresh session after each accepted job and committed record/state.
The next session reads the charter's required documents, verifies the live host,
and does not rely on conversation summaries for decisions.
