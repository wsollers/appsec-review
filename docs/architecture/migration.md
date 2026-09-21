# Migration from the vendor-audit toolbox

Everything under `scripts/` and `images/audit-static/` was copied verbatim from the previous
toolbox on 2026-09-11. Nothing has been refactored yet. This file tracks what has to change
and why; each item becomes its own commit.

Migration rule: `scripts/` is not the destination for new review-work logic. Active review scripts
should be ported into `pipeline/` when they are part of the legacy deterministic engagement package,
or into Dagster/run-owned workers under `appsec-review-process/` when they produce accepted job
evidence. After the replacement is qualified and callers are updated, delete the old script
outright. No thin compatibility wrapper, no deprecation shim -- no tech debt.

## Known breakage in the as-copied state

- **`images/audit-static/Dockerfile` `COPY` paths are wrong for this layout.** It expects
  `build_symbol_index.py`, `build_semantic_index.py`,
  `query_semantic_index.py`, `scrub_evidence.py`, `php_parse_coverage.py`, `run-sast-php.sh`,
  `run-dockerfile-lint.sh`, and `psalm.xml` at the build-context root. They now live in
  `scripts/` (and `psalm.xml` alongside the Dockerfile). Fix: change the `COPY` lines to
  `scripts/...` and build with the repo root as context, or move the scripts the image
  needs into `images/audit-static/`. Do not build until this is fixed.
- `scripts/Build-AuditToolbox.ps1` and `scripts/Invoke-VendorAuditPrePass.ps1` assume the
  old flat directory and the image tag from the old build. Treat them as reference for step
  semantics only until the Python orchestrator exists.

## Planned changes

| # | Change | Reason | Design ref |
|---|---|---|---|
| 1 | Rename image to `audit-static`; strip `clang`, `clang-tidy`, `clang-tools`, `cppcheck`, Joern into `audit-native` | Native tooling must not share a container with evidence writers | §2.2, §17 |
| 2 | Pin Joern to a release tag (currently `releases/latest`) | Joern is the Tier C fallback; its C frontend changes between releases | ADR-0001 |
| 3 | Pin Trivy and Syft to release versions (currently `curl \| sh` from `main`) | Reproducibility | header note in Dockerfile |
| 4 | Pin the remaining Go/pip floats (gosec, osv-scanner, govulncheck, scc, bandit, pip-audit, lizard, code2flow in `audit-static`; tfsec, kube-linter, checkov in `audit-iac`; Trivy in `audit-iac`/`audit-container`) | Same | same |
| 5 | **Corrected 2026-09-19**: `Invoke-VendorAuditPrePass.ps1`/`.sh` is not replaced by a single `orchestrator/` Python component. It is broken apart into separate per-tool Dagster jobs under `appsec-review-process/` that communicate the same way every other job in the graph does (`accepted.json`/`attempts/<id>/` immutable evidence, `job-graph.json` dependencies), orchestrated by Dagster like `build_discovery`/`build_execution`. Language-SAST tools (Semgrep, Bandit, gosec, cppcheck, PHP parse coverage) map onto the already-declared `02-source-sast` node. Secrets (gitleaks, binary cert/key inventory), IaC (checkov, tfsec, trivy-config, kube-linter, hadolint, base-image inventory), SBOM/SCA (osv-scanner), binary hardening (BinSkim) and mobile SAST (mobsfscan) have **no declared `job-graph.json` node yet** -- deciding whether each becomes its own node or folds into an existing one's contract is open work, not yet decided. | Linux-host requirement; PowerShell→docker.exe argv marshalling bit four steps | ADR-0002 |
| 6 | `build_symbol_index.py` and Joern parse move to `audit-native` | They read C/C++ semantics; keep `audit-static` language-agnostic | §17 |
| 7 | ~~Split `audit-iac` (terraform, checkov, tfsec, kube-linter, hadolint) out of `audit-static`~~ — **done 2026-09-17**, split into two images instead of one: `audit-iac` (terraform, checkov, tfsec, kube-linter, trivy config) and `audit-container` (hadolint, docker-base-images), matching how the README's build-order table already scaffolded them separately | Image-per-lane matches §17 | §17 |
| 8 | Retire `scripts/build_symbol_index.py`'s C++ handling in favor of Joern/SVF outputs from `audit-native` | Symbol index is now a byproduct of the native pipeline | ADR-0001 |
| 9 | Record every scan's rule-pack versions (Semgrep `p/*`) into `run-manifest.json` | Rule packs float at scan time regardless of binary pin | §9 |
| 10 | Build `audit-report` (LaTeX -> PDF), adapted from the LRA governance project's standalone LaTeX image | Lane 10 needs a report build environment; format/styleguide open (see TODO) | new, 2026-09-17 |

## Completed script migrations

- `check_ossf_scorecard.py` was replaced on 2026-09-19 by the registered `ossf_scorecard` Dagster
  job backed by `appsec-review-process/ossf_scorecard.py`; the old helper remains deleted. The job
  ingests published JSON2 from a fixed OpenSSF endpoint only after explicit run authorization,
  retains raw response hashes and repository/commit/tool provenance, records 404 as a coverage gap,
  and fails closed on all other request or validation errors. It does not claim a live repository
  scan or promote a score to a finding.
- `Get-ComponentLocations.ps1` moved to `pipeline/extract_component_locations.py` on 2026-09-19.
  This is a deterministic legacy CycloneDX/Syft normalization transform, not an accepted evidence
  job: it emits one CSV row per package/location (including explicit no-location rows) and bounded
  path/cataloger summaries without claiming that a component ships, is reachable, or is vulnerable.
  Focused fixtures and a Windows semantic comparison against the old PowerShell implementation
  qualified the replacement. The old script had no executable callers and was deleted without a
  wrapper.
- `md_to_sarif.py` moved out of the scanner toolbox on 2026-09-19. The replacement is the
  registered `critical_findings_sarif` Dagster job backed by
  `appsec-review-process/critical_findings_sarif.py`. It consumes the fixed run-owned
  `inputs/critical-findings.md`, writes immutable attempts under
  `data/jobs/10-critical-findings-sarif/whole/`, validates the SARIF envelope and hashes before
  publishing `accepted.json`, and is not baked into `audit-static`.
- `fix-binskim.ps1` was retired on 2026-09-19. It was a one-time patcher for the old flat-layout
  Dockerfile, not a review job. Its intended pinned self-contained BinSkim `4.4.9.11` installation
  is already present in both maintained static-image Dockerfiles. The existing
  `vendor-audit-toolbox:latest` image (`sha256:b6db37a36d575b01b3f4ce85929b8d9e56f1b12676ec8bbf9e6da912d51bb4f2`)
  reports that version, and preserved EASTL evidence records a successful BinSkim step with SARIF
  output. The patcher had no executable callers and was deleted without a wrapper. This retirement
  does not implement or qualify the future run-owned binary-hardening evidence job.

## Files not carried over

Engagement-specific documents (process reviews, CVE triage, session status, continuation
prompts, the vendor playbook prompts) stay in the engagement's own project. This repo is the
tool, not the engagement. `vendor-audit-playbook.html` was copied because it documents the
prompt structure the lane prompts will be derived from; it will be superseded by
`prompts/`.
