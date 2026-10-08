# Deterministic static-analysis evidence collection

`job_evidence_collection` is the single semantic job for the accepted narrow static tools. It runs
after `job_target_catalog` through the generic application runner and Dagster adapter. Applicability
comes only from the accepted target-catalog handoff: cataloged languages, manifests/projects,
Dockerfiles, IaC files, workflows, and accepted built artifacts. The job does not walk the target to
decide which scanners to run.

## Capabilities and dispositions

| Capability | Tools | Applicability |
| --- | --- | --- |
| secrets | Gitleaks | Any bounded cataloged worktree; history is explicitly excluded |
| source SAST | Semgrep, Gosec, MobSFScan, ShellCheck, PHPCS, PHPStan, Psalm, Cppcheck, PMD | Cataloged source languages; Cppcheck uses a sanitized compile database or reports source-mode gaps, while PMD reports missing classpath/bytecode coverage |
| source SAST | SpotBugs | Accepted JVM bytecode only; the scanner never compiles target source |
| software inventory | Syft | Cataloged directory/manifests; directory, artifact, and OCI/archive coverage are distinct |
| vulnerability matching | OSV Scanner, Grype | Cataloged manifests/SBOM plus a verified immutable local database; Grype also requires the Syft SBOM |
| configuration | Hadolint, Checkov, Trivy, Zizmor | Explicit Dockerfiles, typed Terraform/HCL, structurally identified CloudFormation, and GitHub workflows; arbitrary YAML is excluded |
| binary hardening | BLint | Accepted cataloged built binaries only |

Every enabled `kind = "tool"` entry in `containers/catalog.toml` must have exactly one adapter. A
catalog/adapter mismatch fails job validation; it cannot silently omit a tool. `tool-cve-bin-tool`
remains deferred because the catalog still records an unresolved GPL policy decision. The completed
NVD-derived database lineage removes the former database blocker, but it does not resolve that
license acceptance. The scan adapter is therefore not enabled and the contract was not weakened.

## Runtime boundary

The application resolves tags only through `containers/catalog.toml`, inspects the local image to
obtain its immutable `sha256:` image ID, verifies any catalog-pinned ID, and executes that ID. It
uses argv arrays and the central `containers/runtime-policy.toml`: no network, numeric non-root
user, read-only root and target, run-owned writable scratch, all capabilities dropped,
`no-new-privileges`, and bounded CPU, memory, PIDs, tmpfs, time, stdout, and stderr. Scanner
containers never receive the Docker socket and never execute target programs.

Each execution receipt records image tag/ID/digest, a secret-free argv identity, mounts, limits,
timestamps, exit/timeout/OOM state, truncation, and resolving raw-output/log paths. Raw output is
preserved within bounds and normalized separately. Unexpected exit, timeout, OOM, parse failure, or
missing output produces a durable producer `FAILED` disposition and gap without claiming clean
coverage. An inapplicable scope produces `NOT_APPLICABLE`; an applicable tool with an unavailable
prerequisite produces `BLOCKED`. Artifact, receipt, handoff, manifest, index, and path integrity
violations remain framework failures.

## Evidence and retrieval

The `appsec-review/static-tool-evidence/1` envelope contains tool/image identity, target fingerprint,
applicability, coverage scope, exclusions/gaps, hashed raw artifacts, parser identity, normalized
records, locations, and terminal status. Native rule IDs/messages are retained, severities are
normalized, and secret values are redacted before persistence with stable SHA-256 correlation IDs.
Record, field, raw-stream, and total normalized byte bounds are enforced; truncation becomes a gap.
Tool observations remain evidence/leads and the envelope deliberately contains no accepted findings.

Every producer emits an immutable SQLite shard. Retrieval fans out deterministically across shards
by target-relative path, native rule, component, package, advisory, language, and evidence ID. A
cheap final barrier verifies every shard and disposition before publishing the combined manifest.
Complete target files and raw scanner output are never placed in indexes or prompts.

## Rules, databases, CLI, and resume

The repository-authored MIT Semgrep bundle lives under `rules/semgrep/`; `rules.lock.json` pins its
SHA-256 and provenance. The adapters do not install PHP dependencies or invent project security
configuration. OSV and Grype execute only with verified immutable local snapshots and never update at
scan time. The data-sync pipeline publishes OSV. `tools/publish_grype_snapshot.py` separately imports
an already-downloaded Grype v6 database only after verifying the upstream archive checksum, then
publishes it through the same immutable feed manifest/current-pointer contract. Neither path permits
a scanner to update its database at scan time.

Run the full graph and inspect planned applicability with:

```text
appsec-review start --target targets/appsec-multi-vuln
appsec-review plan-tools --run-id <run-id>
appsec-review plan-resume --run-id <run-id> --target targets/appsec-multi-vuln
appsec-review resume --run-id <run-id> --target targets/appsec-multi-vuln
```

Each applicable tool publishes an immutable task checkpoint keyed by target fingerprint, catalog
handoff, relevant cataloged file hashes, job/task settings, image ID, rules/database inputs, parser,
and validator. A failed retry reuses unrelated successful tool checkpoints and reruns the failed tool
plus index/handoff publication. The run-wide claim lock and per-tool checkpoint locks prevent
duplicate concurrent execution. Central and task events continue to use the Wave 1 logging API.

Deep CodeQL, native/IR/CPG analysis, language build environments, document conversion, and report
generation remain deferred. Acceptance requires narrow licensed artifacts, typed inputs/outputs,
offline runtime proof, deterministic fixtures, and no target-code execution.

## Live acceptance record

Dagster run `87fffd7b-a14f-4fd5-9cef-97b5b9862a08` completed the 94-node `wave1_review` graph for
application run `2026-10-08-0023` against `targets/appsec-multi-vuln`. All 19 producer branches
published immutable shards; 17 scanners executed successfully and SpotBugs/BLint were explicitly
`NOT_APPLICABLE`. Checkov scanned typed Dockerfile and GitHub Actions inputs, returned 14 records,
and excluded unrelated YAML. Cppcheck and PMD returned 3 and 2 records respectively.

The run receipts show a peak of six overlapping scanner intervals. The manifest barrier began only
after the last of all 19 producer indexes completed, and this correlated rerun reused all 19
unaffected producer shards. The automated recovery test injects a
ShellCheck-only failure and proves that the retry reruns that producer while reusing unaffected
checkpoints and shards; the failed attempt remains an explicit gap rather than clean coverage.

The bidirectional Dagster/application correlation, handoff hashes, shard dispositions, concurrency
proof, and manifest identity are recorded in
`deploy/dagster/verification/wave1-live-acceptance.json`. Bulk scanner output, databases, and run
receipts remain ignored run-owned data.
