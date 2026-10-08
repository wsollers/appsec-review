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

If one validator cell fails, do not discard successful siblings. Re-run the same application run;
the runtime reuses unchanged unit receipts and executes only the failed/dependent work. A completed
join must account for every selected control-component row exactly once. Any duplicate, missing, or
unexpected row blocks publication.
