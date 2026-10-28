# Wave 1 review operations

The direct CLI and Dagster share the application-owned job lifecycle, receipts, validation, and
accepted handoffs, but they do not currently expose the same review topology.

The direct `start`, `plan-resume`, and `resume` commands run this linear graph:

```text
model_connectivity -> image_pin_verification -> review_intake -> target_catalog -> source_history_analysis
  -> target_analysis_plan
  -> tree_sitter_ast -> project_build -> language_build
  -> artifact_indexing -> test_coverage -> profile_data -> artifact_security_analysis
  -> cpp_compiled_analysis -> clang_static_analysis
  -> svf_alias_analysis (opt-in; only when enabled) -> sanitizer_build -> cpp_symbol_index
  -> [cpg_analysis only when enabled] -> evidence_collection -> dependency_intelligence
  -> change_context_analysis -> codeql_analysis -> review_prioritization
  -> code_graph_index -> security_tagging
  -> owasp_control_assessment (enabled by default)
  -> review_data_indexing -> review_package_assembly
  -> document_issue_analysis -> inference_security_review -> final_publication_gate
  -> poc_generation (opt-in; only when enabled) -> final_report_publication
```

Both surfaces verify in `image_pin_verification`, after the model gate and before intake, that every
enabled catalog image, build profile and CodeQL source image resolves on the local daemon to exactly
its pin; any missing image or moved tag fails the run (see
[`image-pin-verification.md`](image-pin-verification.md)). The pipeline never builds images. Setting
`jobs.job_image_pin_verification.settings.enabled = false` removes that step from both graphs.

The direct graph does not include CI configuration analysis or post-build security assessment,
even when enabled. `third_party_data_sync` runs separately (`appsec-review
run job_third_party_data_sync`). Both surfaces run change-context analysis after Tree-sitter AST
production, review prioritization after CodeQL, review-package assembly after data indexing, and
document issue analysis after package assembly. Use Dagster's
`wave1_review`, which includes every registered job whose job-level `settings.enabled` is not false,
except the standalone `third_party_data_sync` job, when its additional branches are required.
`final_report_publication` is its single terminal job; the gate and the report are described in
[`final-report.md`](final-report.md). `poc_generation` is an optional job between the gate and the report; it is
shipped disabled, so it is absent from both graphs unless `jobs.job_poc_generation.settings.enabled = true`, and it is
normally run by hand on a finished run ([`poc-generation.md`](poc-generation.md)). Enabled, it adds the dependency
`gate -> poc_generation -> report` to `wave1_review` and to the direct graph. Dagster's current dependency graph is assembled from the registered,
configured jobs and is summarized in [`../../deploy/dagster/README.md`](../../deploy/dagster/README.md).

The shared enabled direct/Dagster OWASP chain is **prioritization → code graph → security tagging/tag cloud →
OWASP → review data indexing → package assembly → hunt and red/blue/independent verification**,
with accepted source/component/build/static evidence also feeding OWASP. Tagging and prioritization
do not wait for OWASP; their accepted products are bounded routing/context, never control proof.
OWASP is enabled by default with `mode = "assessment"` in all shipped profiles. Assessment uses configured worker
inference plus a fresh blinded reviewer; qualification must be explicitly selected with both
profiles disabled and is never production-eligible. See
[`owasp-control-assessment.md`](owasp-control-assessment.md).

Direct `start`, `resume` and `plan-resume` select this chain through the normal enabled-job filter.
`resume`/`plan-resume --force-from` accept either tagging or OWASP when enabled and reject either
when disabled. Set `jobs.job_owasp_control_assessment.settings.enabled = false` before freezing
a run to opt out. Shared chain
ordering does not add CI/post-build jobs or standalone third-party sync to the direct graph.

The direct sequence includes the engineering-signal producers and the code-graph normalizer. It is
linear for deterministic resume semantics: adjacency does not widen a job's declared inputs. In
particular, coverage and profile ingestion consume accepted catalog/build/artifact handoffs;
Clang consumes accepted C/C++ scopes; dependency intelligence consumes accepted catalog, build,
artifact, and evidence handoffs (including compiler/linker/loader facts resolved from their
hash-bound artifacts); and code-graph indexing consumes accepted CodeQL exports plus its declared
cross-check inputs. Dagster additionally orders dependency intelligence after compiled C/C++
analysis when that branch is enabled, but that barrier does not add a fifth accepted handoff.

On both surfaces, `target_catalog.retrieval_indexes.build_target_documents` starts after
`target_catalog.repository_discovery.partition_repository`. It selects Markdown design and threat
documents, materialized OpenAPI JSON, Postman collections, and unit-test source from that accepted
hash-pinned inventory. The resulting `documents` shard is published with the catalog handoff and
carried into review-data indexing. The bounds live in `[jobs.job_target_catalog.settings]`.

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
Source history analysis also re-probes the target's mainline history identity, so a rewritten
commit message reruns it and invalidates the plan even when the tree bytes are unchanged.
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

Guarded scripts for starting and stopping the stack, launching, watching and ending a review, and
cleaning test state are described in [`operator-scripts.md`](operator-scripts.md).

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

Checkov 3.3.19 is bounded to typed Terraform/HCL, Dockerfile names (`Dockerfile`, `Dockerfile.*`,
`*.dockerfile`, `Containerfile*`), structurally recognized GitHub Actions workflows, and
structurally recognized CloudFormation templates (see the open question on the last two in
[`static-analysis.md`](static-analysis.md)). Arbitrary YAML is
not IaC merely by extension. Unsupported Checkov families are named gaps. Hadolint, Trivy, Checkov,
and Zizmor retain separate producer scopes and shard identities so overlapping coverage is visible.

Derive operational metrics without mutating authoritative counters:

```powershell
appsec-review metrics --run-id 2026-10-08-0001
```
