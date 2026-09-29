# Brief K: registry JSON moves into the pipeline folder (branch `registry-move`) - CLOUD agent
START ONLY AFTER briefs I and J are merged (both touch loaders and the registry).

Goal: the job definition data (`registry/job-templates`, `output-contracts`, `domains`, `tooling-profiles`,
`permission-capabilities`, `container-images`, `tunables.json`) lives next to `job-graph.json` under one
`appsec-review-process/pipeline/` folder, so a job is found in one place. NOTE: the repository root already has a
`pipeline/` folder (Layer 1 evidence scripts); do not merge with it. Use `appsec-review-process/pipeline/` and state
the naming difference in `appsec-review-process/pipeline/README.md`. If you think another name is clearer, do not
rename anything: report it. (Personas and roles are already in `personas/` from brief J; leave them.)

Rules: ZERO behaviour change. Commit 1 = pure `git mv` only. Commit 2 = path fixes, all path constants centralised in
one module (`registry_paths.py`), no string paths scattered. Commit 3 = regenerate catalogs/manifests and docs. Prove:
`job_catalog.py`, `validate_design_parity.py --check-generated-views`, `catalog_personas.py check`,
`tunables.py check` pass; every job's fingerprint before/after is identical (fingerprints must hash content, not
path; if a path leaks into a fingerprint, report it, do not paper over it); full suite matches baseline.
## You own
The moved directories, `registry_paths.py`, every loader and doc path reference, `registry/README.md` (moves too).
## Do not touch
Any logic, schema content, or persona files.
