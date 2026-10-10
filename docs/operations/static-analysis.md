# Deterministic static-analysis evidence collection

`job_evidence_collection` is the single semantic job for the accepted narrow static tools. It
requires both the accepted target catalog and accepted target-analysis plan. The catalog supplies
the bounded files, languages, manifests/projects, Dockerfiles, IaC files, workflows, and accepted
built artifacts; the plan selects scanner scopes. The job does not walk the target to decide which
scanners to run. In Dagster's `wave1_review`, it runs after `job_target_analysis_plan`.

## Capabilities and dispositions

| Capability | Tools | Applicability |
| --- | --- | --- |
| secrets | Gitleaks | Any bounded cataloged worktree; history is explicitly excluded |
| source SAST | Semgrep, Gosec, MobSFScan, ShellCheck, PHPCS, PHPStan, Psalm, Cppcheck, PMD | Cataloged source languages; Cppcheck uses a sanitized compile database or reports source-mode gaps, while PMD reports missing classpath/bytecode coverage |
| source SAST | SpotBugs | Accepted JVM bytecode only; the scanner never compiles target source |
| source SAST | OpenGrep | Cataloged C, C++, and Java files; runs only the SEI CERT rule pack, which Semgrep also runs |
| software inventory | Syft | Cataloged directory/manifests; directory, artifact, and OCI/archive coverage are distinct |
| vulnerability matching | OSV Scanner, Grype | Cataloged manifests/SBOM plus a verified immutable local database; Grype also requires the Syft SBOM |
| configuration | Hadolint, Checkov, Trivy, Zizmor | Explicit Dockerfiles, typed Terraform/HCL, structurally identified CloudFormation, and GitHub workflows; arbitrary YAML is excluded |
| binary hardening | BLint | Accepted cataloged built binaries only |

Every enabled `kind = "tool"` entry whose tool manifest does not set `static_adapter = false` must
have exactly one adapter. The opt-out reserves tools owned by other jobs; a static catalog/adapter
mismatch fails job validation and cannot silently omit an in-scope tool. `tool-cve-bin-tool`
remains deferred because the catalog still records an unresolved GPL policy decision. The completed
NVD-derived database lineage removes the former database blocker, but it does not resolve that
license acceptance. The scan adapter is therefore not enabled and the contract was not weakened.

The shared `[tools].disable_grype` Boolean applies to this job and produced-artifact analysis. Its
repository default is `true`: neither a process nor container is launched, and the producer emits
an explicit configured-disabled `NOT_APPLICABLE` gap. Setting it to `false` restores the normal
Syft/database prerequisite and launch contract; disabled coverage is never interpreted as clean.

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
SHA-256 and provenance. Semgrep runs both `security.yml` and the review-prioritization pattern pack
`review-signals.yml`, whose matches `job_review_prioritization` consumes as observed-syntax signals
(see [`review-prioritization.md`](review-prioritization.md)). Semgrep and OpenGrep also run the SEI CERT rule pack from `rules/sei-cert/`
after verifying its rule files against `pack.lock.json`; a mismatch blocks both tools with an explicit
gap. Their records carry the CERT mapping and source hash, and engine errors or skipped files become
gaps. See [`sei-cert-rule-pack.md`](sei-cert-rule-pack.md). The adapters do not install PHP dependencies or invent project security
configuration. OSV and Grype execute only with verified immutable local snapshots and never update at
scan time. The data-sync pipeline publishes OSV. `tools/publish_grype_snapshot.py` separately imports
an already-downloaded Grype v6 database only after verifying the upstream archive checksum, then
publishes it through the same immutable feed manifest/current-pointer contract. Neither path permits
a scanner to update its database at scan time.

Run the direct CLI graph and inspect planned applicability with:

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

CodeQL, native/IR/CPG analysis, language builds, produced-artifact analysis, and post-build
assessment are separate jobs with their own accepted handoffs; they are not capabilities of
`job_evidence_collection`. Document conversion and report generation remain outside this job.

## Acceptance evidence

Repository reports under `deploy/dagster/verification/` are historical evidence for their recorded
runs and code state. They are useful for resolving those claims, but they do not establish that the
current checkout or deployment is healthy. Follow `deploy/dagster/README.md` to verify the live
workspace and write a fresh bounded receipt when current acceptance evidence is required. Bulk
scanner output, databases, and application run receipts remain ignored run-owned data.
