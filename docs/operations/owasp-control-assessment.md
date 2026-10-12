# Operating the OWASP control-assessment stage

Run the `owasp_control_assessment` Dagster job only after the accepted component, evidence, build,
compiled, and retrieval manifests exist. In the full `wave1_review` graph it is placed after
evidence publication. The standalone job also accepts a hash-owned qualification input at
`runs/<run-id>/data/inputs/owasp-workbench.json`; that path is for deterministic integration tests,
not a way to bypass accepted production indexes.

Check these outputs after a run:

- `data/configuration/` for the immutable central TOML;
- `data/guidance/<sha256>/` for exact worker guidance bundles;
- `data/indexes/owasp/accepted.json` for the accepted shard manifest;
- the job attempt's `artifacts/owasp-workbench/` directory for selection, classification,
  applicability, validation work, verified results, join, and publication records; and
- `data/logs/pipeline.jsonl` for worker start/stop, model identity, token/duration/retry counts,
  retrieval use, gaps, and lifecycle events.

The abridged checked catalogs make offline tests deterministic. They do not represent full OWASP
coverage. Until a network-authorized refresh publishes and verifies complete catalogs, operators
must retain the standards-refresh gap. Live model inference is disabled by default; fixture runs
exercise deterministic workers. Enabling a model changes the immutable run configuration and must
use the configured provider/model/reasoning/budget/timeout/retry boundary.

## Settings

Everything lives under `[jobs.job_owasp_control_assessment.settings]` in `appsec-review.toml`. The
job's configuration validator rejects missing keys and out-of-range values before any unit runs.

| Key | Default | Allowed | Meaning |
|---|---|---|---|
| `asvs_level` | 2 | 1, 2, 3 | ASVS level selected for applicability |
| `masvs_profile` | `L2` | `L1`, `L2` | MASVS profile selected for applicability |
| `max_batch_size` | 12 | 1–64 | control-component rows per validation batch |
| `max_components_per_batch` | 5 | 1–16 | distinct components per validation batch |
| `max_components` | 128 | 1–128 | components accepted for classification |
| `dynamic_authorized` | false | boolean | when false, dynamic-runtime and manual-observation controls become `unsupported_missing_evidence` with a named gap |
| `model.*` | `enabled = false`, `claude-cli`, `claude-haiku-5-5`, `medium`, 24000 / 6000 tokens, 120 s, 1 retry | `provider`, `model`, `reasoning`, `max_input_tokens`, `max_output_tokens`, `timeout_seconds`, `retries` are required | worker model identity, logged with each worker and folded into the global fingerprint; the current validator cells run deterministic workers |
| `parser_versions.*` | `component_rules`, `applicability_rules`, `batching_rules`, `result_validator` = `"1"` | strings | rule and validator versions folded into the global fingerprint |
| `standards.<family>` | see TOML | pinned path and SHA-256 | catalog sources (see the architecture document) |

If one validator cell fails, do not discard successful siblings. Re-run the same application run;
the runtime reuses unchanged unit receipts and executes only the failed/dependent work. A completed
join must account for every selected control-component row exactly once. Any duplicate, missing, or
unexpected row blocks publication.
