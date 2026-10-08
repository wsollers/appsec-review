# Documentation TODO

Write the operator and architecture documentation for the simplified review process as it is implemented, including run creation, configuration resolution, job/task configuration, retrieval, evidence handling, failure recovery, and acceptance checks. Keep documentation work independent from implementation, and document only behavior verified in the current code and generated artifacts.

Additional S2 topics discovered during implementation:

- the local-path/file-URI trust boundary and why network configuration schemes are rejected;
- daily run serial allocation, retained sequence state, and recovery from a failed first job;
- the immutable run-owned TOML/effective-config artifacts and canonical fingerprint;
- the staged retirement of `pipeline/tunables.json`, job-template tunables, `model-config.json`,
  operational environment defaults and job-local constants.

Document where AI configuration and rules belong, following
`docs/architecture/ai-guidance.md`:

- repository-agent rules live in root `AGENTS.md`, while `docs/agent-reader.md` is navigation only;
- tracked model, reasoning, budget, timeout and pool defaults live in
  `appsec-review-process/appsec-review.toml`, with job/task overrides under the predictable
  `[job_####.<step_name>.task_####]` hierarchy;
- shared model behavior rules live once in
  `appsec-review-process/pipeline/prompt-fragments/governing-rules.md`; personas, roles and task
  prompts contain only their specific viewpoint, responsibility and question;
- each run's resolved, immutable AI configuration remains under `data/configuration/`, and the exact
  hash-pinned instructions used for a model call belong under
  `data/guidance/<bundle-sha256>/`;
- target-owned guidance, continuation prompts, skills and repository `AGENTS.md` are not copied into
  run prompts. Document `prompt-cache/` as transitional until its last runtime reader migrates.
