# T-5022 fixtures: native repository resolution replies from run 2026-11-14-0005

Each file reduces one recording under `data/inference-recordings/job_dependency_intelligence/` of
smoke-cpp run `2026-11-14-0005` (host-local; `source` names the file) to the request's candidate,
evidence allowlist, typed budget and repair state, and the reply's text, stop reason and usage.

- `failed-first-attempt.json`: the first call for the `-lm` candidate. The worker answered with a
  fenced proposal object that has every field but `schema`; the parser found no schema-bearing
  object (`found 0`). This is the shape of all 79 failures in the run.
- `failed-second-attempt.json`: a repair call that failed the same way with an unfenced object and
  a non-null repository, citing the candidate's `native-evidence-*` ids that the run's allowlist
  did not offer.
- `succeeded-after-repair.json`: a repair call whose reply carried the `schema` field.
