# Wave 1 review operations

The direct CLI and Dagster share the application-owned job lifecycle, receipts, validation, and
accepted handoffs, but they do not currently expose the same review topology.

The direct `start`, `plan-resume`, and `resume` commands run this linear graph:

```text
review_intake -> target_catalog -> design_artifact_discovery -> target_analysis_plan
  -> project_build -> language_build
  -> artifact_indexing -> artifact_security_analysis -> cpp_compiled_analysis
  -> codeql_analysis -> evidence_collection
```

The direct graph does not include CI configuration analysis, tree-sitter AST production,
post-build security assessment, or OWASP control assessment. Use Dagster's `wave1_review` when
those branches are required. Its current dependency graph is assembled from the registered,
configured jobs and is summarized in [`../../deploy/dagster/README.md`](../../deploy/dagster/README.md).

In both surfaces, the application handoff is the checkpoint of record; Dagster metadata links to
it but does not replace it. Target content, target guidance, configuration values, and generated
evidence are data and cannot change worker authority or execution policy.

From the repository root, with the package installed (or `PYTHONPATH=src` during development):

```powershell
appsec-review start --target targets/appsec-multi-vuln
appsec-review plan-resume --run-id 2026-10-08-0001 --target targets/appsec-multi-vuln
appsec-review resume --run-id 2026-10-08-0001 --target targets/appsec-multi-vuln
appsec-review resume --run-id 2026-10-08-0001 --target targets/appsec-multi-vuln --force-from job_target_catalog
```

`plan-resume` is read-only apart from its audit event. It explains `REUSE`, `RUN`, and downstream
`INVALIDATE` decisions. A job is reused only when its configuration, implementation, schema,
validator, target, upstream handoffs, accepted handoff, and run-owned artifacts resolve and match.
Failed and interrupted attempts remain immutable; only a validated success updates `latest.json`.

Read the global log without `jq`:

```powershell
appsec-review logs --run-id 2026-10-08-0001
appsec-review logs --run-id 2026-10-08-0001 --job job_target_catalog --level ERROR --raw
appsec-review logs --run-id 2026-10-08-0001 --follow
```

The writer repairs a torn final JSONL record before appending the next record. A missing log prints
no records. If a resume reports that its claim lock is held, another application process owns that
run; wait for it to finish or investigate that process rather than deleting run state.

For Dagster, start the documented stack in `deploy/dagster/README.md`, set
`APPSEC_REVIEW_TARGET` when the target is not the default acceptance target, and launch
`wave1_review`. Dagster exposes each application's intake, catalog, analysis, producer,
normalization, indexing, manifest, and publication units as nodes. Scanner timeout, OOM, nonzero
exit, unavailable image/prerequisite, missing
output, or parser incompatibility is persisted as a bounded producer disposition and coverage gap;
the node succeeds after recording that truth and the review may end `COMPLETED_WITH_GAPS`.
Configuration corruption, unsafe paths, changed handoffs, receipt persistence/locking failures,
artifact hash mismatch, invalid manifests, and index corruption fail the Dagster run.

```powershell
$dagsterRunId = [guid]::NewGuid().ToString()
docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml exec -T webserver dagster job launch -w /opt/dagster/home/workspace.yaml -l appsec_review -j wave1_review --run-id $dagsterRunId
python deploy/dagster/bin/verify.py --run-id $dagsterRunId
```

To resume an existing application run through Dagster, launch the same job with
`--tags '{"appsec/application_run_id":"<application-run-id>"}'`. A successful launch writes a new
accepted manifest while preserving old attempt receipts and reusing unaffected producer checkpoints
and shards. Dagster step selection can rerun a producer branch and its manifest/publication closure
without rerunning independent branches.

Checkov 3.3.19 is bounded to typed Terraform/HCL, exact Dockerfile names, structurally recognized
GitHub Actions workflows, and structurally recognized CloudFormation templates. Arbitrary YAML is
not IaC merely by extension. Unsupported Checkov families are named gaps. Hadolint, Trivy, Checkov,
and Zizmor retain separate producer scopes and shard identities so overlapping coverage is visible.

Derive operational metrics without mutating authoritative counters:

```powershell
appsec-review metrics --run-id 2026-10-08-0001
```
