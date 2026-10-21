# Lead coverage audit

Status: audit of lane A intake, with the fixes that came out of it. Sample run: `2026-10-21-0007` (cpp-multivuln
corpus), read-only. The decision table lives in code, `OBSERVATION_PRODUCERS` in
`src/appsec_review/review/lead_families.py`; `tests/review/test_lead_coverage.py` fails when a producer in the code has
no decision.

## The defect

The seeded hard-coded key (`generic-api-key`, `src/config.cpp:6`, gitleaks) was in the accepted observation index with
a resolved location, but no lead family took it. `observation_family()` mapped an observation to a family only when its
*category* classified as `source_sast`, from a CI/artifact/CodeQL shard, or as a dependency. Gitleaks records carry the
generic category `static_analysis`, which classifies as `other`, so the row was counted in `non_lead_counts` and never
became a lead, a package or a review (`no_lead_at_location`). The same generic category silently dropped shellcheck and
psalm findings, the hadolint and zizmor adapters' findings, and Infer findings (job `job_cpp_compiled_analysis`) matched
no producer at all. The manifest recorded the drop only as a class count (`other: 1`), which no gate read.

## Audit of the sample run

Observation producers present in the accepted index of `2026-10-21-0007`, and what lane A did with their rows
**before** and **after** this change.

| Producer (job / shard) | Scanner | Obs. | Family before | Family now | Reason |
|---|---|---|---|---|---|
| `job_evidence_collection` / `gitleaks` | `tool-gitleaks` | 1 | **NONE (silent loss)** | `secret` | Generic `static_analysis` category; no secrets family. Now `secret`, reported severity `unknown`. |
| `job_evidence_collection` / `semgrep` | `tool-semgrep` | 16 | `source_sast` | `source_sast` | Category `source_sast`. |
| `job_evidence_collection` / `opengrep` | `tool-opengrep` | 16 | `source_sast` | `source_sast` | Category `source_sast`. |
| `job_evidence_collection` / `cppcheck` | `tool-cppcheck` | 13 | `source_sast` | `source_sast` | Category `source_sast`. |
| `job_clang_static_analysis` / `clang-static-*` | `tool-clang-static-analysis` (Clang Static Analyzer, clang-tidy) | 12 | `source_sast` | `source_sast` | Category `source_sast`. |
| `job_codeql_analysis` / `codeql-*` (3 query profiles) | `codeql` | 7 | `codeql` | `codeql` | CodeQL shard. |
| `job_artifact_security_analysis` / `artifact-security` | `tool-blint`, `tool-syft`, `builtin-native/1`, `builtin-inventory/1` | 34 (8, 9, 8, 9) | `artifact_scanner` | `artifact_scanner` | Artifact shard; every record is a lead (see "Not fixed"). |
| `job_cpp_compiled_analysis` / `cpp-*-infer` | `infer` | 0 | **NONE (no producer matched)** | `source_sast` | Payload has `tool: infer`, empty category; the shard matched no producer, so Infer was neither a lead nor source-SAST coverage. |
| `job_evidence_collection` / `shellcheck` | `tool-shellcheck` | 0 | **NONE** (generic category) | `source_sast` | `_record` default category `static_analysis`. |
| `job_evidence_collection` / `psalm` | `tool-psalm` | 0 | **NONE** (generic category) | `source_sast` | Same. |
| `job_evidence_collection` / `hadolint` | `tool-hadolint` | 0 | **NONE** | `config_scanner` | Dockerfile lint; generic category. |
| `job_evidence_collection` / `checkov` | `tool-checkov` | 0 | **NONE** (class `configuration`) | `config_scanner` | IaC misconfiguration. Checkov reports no severity: `unknown`. |
| `job_evidence_collection` / `trivy` | `tool-trivy` | 0 | **NONE** (class `configuration`) | `config_scanner` | Dockerfile and IaC misconfiguration. |
| `job_evidence_collection` / `semgrep`-class tools: `gosec`, `mobsfscan`, `pmd`, `phpstan`, `phpcs`, `spotbugs` | `tool-*` | 0 | `source_sast` | `source_sast` | Category `source_sast`. PMD's `tool_diagnostic` rows stay non-leads. |
| `job_evidence_collection` / `osv_scanner`, `grype` | `tool-osv-scanner`, `tool-grype` | 0 | `dependency_advisory` | `dependency_advisory` | Dependency class. |
| `job_evidence_collection` / `zizmor` | `tool-zizmor` | 0 | NONE (accident) | NONE (**decided**) | The CI job (`ci_github_zizmor`, family `ci_rule`) runs zizmor on the same workflow files; mapping both duplicates every lead. |
| `job_evidence_collection` / `syft` | `tool-syft` | 0 | NONE (accident) | NONE (**decided**) | SBOM inventory: context for dependency review, not findings. |
| `job_evidence_collection` / `blint` | `tool-blint` | 0 | NONE (accident) | NONE (**decided**) | Binary hardening of catalog binaries: no source line, per-check severities nested inside one record. Built-artifact hardening is reviewed as `artifact_scanner` and `post_build_hardening`. Follow-up: normalize the nested severities, then admit. |
| `job_ci_configuration_analysis` / `ci_*` (14 shards) | `ci-*`, `tool-actionlint`, `tool-zizmor`, `tool-checkov` | 0 | `ci_rule` | `ci_rule` | CI shards. |
| `job_post_build_security_assessment` / `build_security` index | `deterministic-build-security-rules` | 10 (FAIL leads) | `post_build_hardening` | `post_build_hardening` | Not in the `observations` index; FAIL checks are leads, PASS and UNKNOWN are coverage. Model-proposed observations are model output and never leads (decided). |
| `job_code_graph_index` / `graph` index | clang-tidy diagnostics, CPG functions | n/a | NONE (by design) | NONE (**decided**) | Derived code-graph context reached through the package neighborhood. |
| `job_cpg_analysis` / `joern-*` | none | 0 | NONE | NONE (**decided**) | Joern publishes evidence-artifact and CPG function rows, no tool observations. |

Class-level decisions (rows of any scanner): `diagnostic` (scanner diagnostics describe a run, not the target; they
surface as coverage gaps), `inventory` and `binary` are not leads. A scanner the table does not name falls back to its
class (`source_sast`, `secret`, `configuration` map to a family) and otherwise to an `unmapped_observations` gap.

## What changed

- New lead family `secret` (`appsec-review/lead-family/secret/1`): reported severity `unknown` (basis
  `no-native-severity`), rule CWE `CWE-798`, producer `secret_scanner` (the `tool-gitleaks` shard). The sanitized index
  blanks the rule id `generic-api-key` (it matches the credential-name redaction), so the entity name restores it.
- New lead family `config_scanner` (`.../config_scanner/1`): hadolint, checkov, trivy; severity by
  `normalize_reported_severity`.
- `source_sast` is now `.../source_sast/2`: also shellcheck, psalm and Infer; severity unchanged.
- Producer selectors: `secret_scanner`, `config_scanner`; the `source_sast` selector no longer counts gitleaks,
  hadolint, checkov, trivy, zizmor, syft or blint shards as source-SAST coverage, and counts the Infer shard.
- `OBSERVATION_PRODUCERS`, `producer_decision`, `non_lead_key`: the explicit decision per producer; unlisted scanner
  rows are an `unmapped_observations` gap.
- Secret redaction (`review/secret_redaction.py`, `secret-redaction/1`) in lead messages and in the model-facing source
  excerpt (`package-view/2`).
- Versions: `assemble-review-packages/7` (new families in the manifest rules and audit; invalidates published package
  manifests and package reuse), `package-obligations/2` (two new obligation rows), `package-view/2` (secret redaction;
  views are built at cell time, so only cell reuse keyed on the view rule is invalidated), `source_sast/2`. The package
  schema stays `review-package/6`: its `inference_lead_family` enum widened, nothing else changed.

## Not fixed (decisions)

1. **Artifact-scanner records are per-artifact scan runs, not findings.** All 34 `artifact-security` rows of the sample
   run are `artifact_scanner` leads at `unknown`, admitted by default, including 18 `builtin-inventory` and syft rows with
   nothing to review, while the blint rows nest `critical` and `high` per-check findings (`CHECK_NX`, `CHECK_PIE`) inside
   one record that is reported `unknown`. This is over-admission and severity collapse, not a silent loss; fixing it
   needs per-finding leads from the nested records, which changes lead identity. Recommended follow-up.
2. **Scanner correlation does not index shellcheck, psalm or Infer.** `indexing/sast.py` selects rows by category, so
   duplicate and suppression state for these leads is `unknown`. Widening it changes the `scanner_correlation` rule and
   its accepted shards. The better fix is producer-side: give the shellcheck, psalm, hadolint, zizmor and gitleaks
   parsers their true categories (bumping their parser versions), after which the class fallback covers them.
3. **Checkov and other severity-less scanners produce `unknown` leads**, all admitted. That is the repository's rule
   (unknown is never low); lane budgets (`lead_budget_share`, `budget_team_packages`) bound the volume.
4. **Typed retrieval tools are not redacted.** `read_excerpt` and the path-and-line locators read the target file
   themselves. A cell that asks for the flagged line through them receives the literal. Redacting there needs a
   per-run map of secret locations in the retrieval layer; recommended before a model run on a target with live secrets.
5. **Standalone blint rows** stay non-leads until the nested severities are normalized (item 1).
