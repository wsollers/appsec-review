# Agent briefs: common rules (read first)

Repo: `wsollers/appsec-review`. Base: `main` at the commit that contains this file (all Phase 0 merges are in).
Plan of record: `claude/batch-plan-2026-09-28.md` in the AppSec Review project (also summarised in each brief).

## Working rules
1. Work ONLY on your own branch, named in your brief, in your OWN git worktree (never edit the shared checkout).
   - Local (device VM) agents: `cd $HOME/mnt/appsec-review && git worktree add $HOME/wt-<name> -b <branch> main`, then work in `$HOME/wt-<name>` (fast disk; the mount is slow). Python: `$HOME/venv/bin/python` (3.12, has jsonschema, pyyaml, dagster).
   - Cloud agents: `git clone https://github.com/wsollers/appsec-review && git checkout -b <branch>`; install `jsonschema pyyaml dagster` with `pip install --break-system-packages`.
2. Commit early and often. Git identity for the local VM: set env `GIT_AUTHOR_NAME=William GIT_AUTHOR_EMAIL=wsollers@gmail.com GIT_COMMITTER_NAME=William GIT_COMMITTER_EMAIL=wsollers@gmail.com`. End commit messages with the attribution lines the harness gives you.
3. NEVER push from the local VM (no credentials). The controller pushes your branch. Cloud agents push their own branch only (never `main`).
4. Do not touch files owned by another brief (ownership listed in each brief). If you must, stop and report.
5. Shared generated/serial files conflict at merge: `appsec-review-process/TODO.md`, `docs/processes/job-catalog.md|json`, `docs/processes/tunables.md`, `appsec-review-process/design-parity-manifest.json`. Do not hand-edit generated files: regenerate with `python3 docs/processes/job_catalog.py` and `python3 appsec-review-process/validate_design_parity.py --write-generated-views` (then `--check-generated-views`). Put your TODO notes in ONE short section with your brief id as the heading so a merge is a clean append.
6. FINGERPRINTS: `IMPLEMENTATION_FILES` / `SHARED_RUNTIME` (includes `claude_cli_invoker.py`) feed job fingerprints. Editing a listed file invalidates finished jobs. That is fine when the change is intended, but do NOT edit `claude_cli_invoker.py` or any shared-runtime file unless your brief says so. When you add a new module a job depends on, add it to that job's implementation-file list as sibling modules do.
7. Pattern to follow (ADR-0013): the model supplies judgement only; Python derives every mechanical field (ids, hashes, lineage, vocabulary, citation types, counts). Persona results are validated independently; never add exception text to persona results.
8. Tests: every behavioural change gets a unit test in `appsec-review-process/tests/`. Run with `PHASE1_TEST_DATA=$(mktemp -d) python -m unittest tests.<module>` from `appsec-review-process/`. KNOWN PRE-EXISTING FAILURES on baseline (ignore, do not "fix" unless your brief says): `tests.test_threat_model_core...prohibited_conclusion_text...`, `test_vendor_prepass_graph` (16), `02-native-sast` registry check in `test_persona_invocation`. Everything else must pass.
9. Docs: update the relevant doc under `docs/` and add an ADR/decision note only when your brief asks. Keep TODO honest: list what is OPEN.
10. Docker/WSL are NOT available to you. Image builds and container smoke tests are done by the user in WSL. Where your work needs an image change, write the Dockerfile/registry change plus a `scripts/` smoke test the user can run, and say exactly which command to run.
11. Security posture: this is a defensive review pipeline. Nothing you write may execute target-controlled code outside the existing sandboxed containers, and no output may contain hostile payloads.
12. Final message: list commits, files changed, tests run (and result), what is OPEN, and any decision you made that the controller must confirm. Keep it under 60 lines.
