# Agent navigation

Repository-wide authority and trust rules live only in [`../AGENTS.md`](../AGENTS.md).

Relevant bounded procedures and design references:

- [`architecture/README.md`](architecture/README.md) — full architecture navigation.
- [`operations/review-startup.md`](operations/review-startup.md) — required review inputs, full-review launch examples, startup flags and TOML-only feature gates.
- [`operations/wave1-review.md`](operations/wave1-review.md) — direct CLI scope, resume behavior, and the Dagster entrypoint.
- [`operations/operator-scripts.md`](operations/operator-scripts.md) — `scripts/` for the Dagster stack, starting, watching and ending reviews, cleaning `test/tmp` and running named test suites, with the active-run guard.
- [`../scripts/README.md`](../scripts/README.md) — every script in `scripts/`; [`operations/codeql-analysis.md#compiling-codeql-queries`](operations/codeql-analysis.md#compiling-codeql-queries) — recompiling the CodeQL graph-export packs into the shared compile cache with `scripts/compile-codeql-queries.sh`.
- [`operations/wsl-native-docker.md`](operations/wsl-native-docker.md) — native WSL Docker migration lessons: preservation, cross-shell inspection, image and volume identity, resource gates, and launch provenance.
- [`operations/image-pin-verification.md`](operations/image-pin-verification.md) — mandatory pre-intake verification that local images match their pins, its failure report, and the host rebuild/re-pin/reload procedure.
- [`operations/model-profiles.md`](operations/model-profiles.md) — the `dev` (default) and `prod` runtime profiles: selection with `APPSEC_REVIEW_PROFILE` or `--profile`, the exact prod models and limits, the distinct verifier model, and how fingerprints and the model contract treat a profile.
- [`operations/inference-security-review.md`](operations/inference-security-review.md) — model selection and upgrade, local capacity overlay, and outcomes for the inference security review; design in [`architecture/inference-security-review.md`](architecture/inference-security-review.md).
- [`operations/lead-severity-triage.md`](operations/lead-severity-triage.md) — deterministic-first severity ordering for scanner leads that reported no severity, its bounded Haiku fallback, audit artifact, and recovery.
- [`operations/review-data-indexing.md`](operations/review-data-indexing.md) — dataset inventory and publication audit, lead menus, stage-1 products, and offline FTS validation; design in [`architecture/indexing-and-query-reuse.md`](architecture/indexing-and-query-reuse.md).
- [`architecture/code-graph-precomputation.md`](architecture/code-graph-precomputation.md) — code-graph strategy, `graph` index, `query_code_graph`, R3 admissibility update, job topology, rollout, the chunked implementation and test plan (implemented through C9, offline-verified), and the partially implemented Clang phase (K4 static analysis is complete; K1-K3 and optional K5 remain planned).
- [`tasks/seeded-clang-neighborhoods-prompt.md`](tasks/seeded-clang-neighborhoods-prompt.md) — task prompt and acceptance requirements for seeded Clang AST/IR, static-analyzer and CPG producers.
- [`architecture/seeded-neighborhoods.md`](architecture/seeded-neighborhoods.md) — seeded neighborhoods for the Clang AST/IR, Clang-Tidy/Static Analyzer and CPG producers: shared seeding module, card `producers`, flow, diagnostics and symbol exposure.
- [`architecture/seeded-codeql-neighborhoods.md`](architecture/seeded-codeql-neighborhoods.md) — seeded, bounded-depth CodeQL neighborhoods around findings, database cards and their MCP tools.
- [`operations/code-graph-index.md`](operations/code-graph-index.md) — `job_code_graph_index` inputs, units, shards, resume and verification.
- [`architecture/svf-alias-producer.md`](architecture/svf-alias-producer.md) — SVF points-to cross-check producer (opt-in): image, job, cross-check rules, memory-object accessor index, finding-lead memory and caller context, tunables and verification tiers.
- [`operations/svf-alias-analysis.md`](operations/svf-alias-analysis.md) — `job_svf_alias_analysis` settings, image pin, coverage rows, resume and verification commands.
- [`operations/sanitizer-build.md`](operations/sanitizer-build.md) — `job_sanitizer_build`: ASan/UBSan rebuild of accepted native units, sanitizer settings, the no-execution invariant, ELF runtime evidence, named gaps, and how a later execution stage would consume the handoff.
- [`operations/test-targets.md`](operations/test-targets.md) — where to get the repositories the reviews and acceptance tests run against (`appsec-multi-vuln`, the pinned commit, the evaluator guide kept outside the repository).
- [`operations/poc-generation.md`](operations/poc-generation.md) — `job_poc_generation`: the `poc_writer` turn, AST/compile checks, immutable protected attempt outputs, pre-gate `/2` outcomes and explicit manual admission.
- [`architecture/openvex-export.md`](architecture/openvex-export.md) — planned affected-only OpenVEX
  export: issuer/action inputs, source-snapshot/full-configuration identity, protected companion,
  deterministic validation and telemetry (design only, not implemented).
- [`operations/openvex-export.md`](operations/openvex-export.md) — draft OpenVEX configuration,
  trust/dataflow and optional-tail diagrams, output/report states, privacy and recovery.
- [`operations/final-report.md`](operations/final-report.md) — `job_final_publication_gate` and `job_final_report_publication`: re-verification of the accepted review handoff, publishable / verification backlog / withheld accounting, named limitations, `final-report.json` and the deterministic Markdown (PDF is a later step).
- [`architecture/evidence-completion-and-remediation.md`](architecture/evidence-completion-and-remediation.md) —
  delivered completion source and approved dossier decisions: compile-only PoC before one final gate,
  chains before review seal, confirmed-only remediation and nonexecuting validation.
- [`architecture/dossier-data-inventory.md`](architecture/dossier-data-inventory.md) — source-verified
  effective dossier inputs, bounded queries, indexes/shards, all producer dataset visibility,
  provenance, evidence ceilings and architectural change map.
- [`operations/dossier-publication.md`](operations/dossier-publication.md) — implemented protected
  dossier job, one dossier per confirmed finding regardless of origin and per PoC outcome,
  retained deterministic artifacts, render gaps and public-reference boundary.
- [`operations/remediation.md`](operations/remediation.md) — confirmed-only inert exact patches,
  bounded nonexecuting static/native syntax validation, manual outcomes, protected receipts and
  new-run defaults versus frozen historical configurations.
- [`reviews/evidence-completion-documentation-inventory.md`](reviews/evidence-completion-documentation-inventory.md) —
  documentation inventory/reconciliation record and checks, with implementation gaps kept explicit.
- [`architecture/graph-alias-slice-layout-modes.md`](architecture/graph-alias-slice-layout-modes.md) — proposed alias, slice, type-layout and buffer-bound `query_code_graph` modes and sink CFG context (design only, not implemented).
- [`reviews/detector-coverage-checklist.md`](reviews/detector-coverage-checklist.md) — detector coverage checklist (use after free, double free, null dereference, overflows, uninitialized reads, integer overflow, format string, TOCTOU, command injection, taint, bounds checks) against the registered rule packs and configured scanners, with proposed remediations.
- [`reviews/code-graph-precomputation-implementation.md`](reviews/code-graph-precomputation-implementation.md) — code-graph implementation record: decisions, chunks and merges, reconciliations, C9 integration fixes, verification, live-unverified items, and next work.
- [`../deploy/dagster/README.md`](../deploy/dagster/README.md) — deployment lifecycle and live verification.
- [`../pipeline/skills/target-analysis-planning/SKILL.md`](../pipeline/skills/target-analysis-planning/SKILL.md) — model-side proposal constraints for target analysis ambiguity.
- [`../pipeline/skills/build-image-repair/SKILL.md`](../pipeline/skills/build-image-repair/SKILL.md) — typed, bounded repair proposals (apt packages, allowlisted environment, pinned package manager, manifest restores) for failed project-build image probes.
- [`../pipeline/skills/post-build-security-assessment/SKILL.md`](../pipeline/skills/post-build-security-assessment/SKILL.md) — bounded guidance for the post-build security inference task.
- [`../pipeline/skills/binary-evidence/SKILL.md`](../pipeline/skills/binary-evidence/SKILL.md) — review-cell guidance on how decompiled binary evidence differs from source and how to cite it (binary hash, function address, pseudo-C line).
- [`../.claude/skills/parallel-implementation/SKILL.md`](../.claude/skills/parallel-implementation/SKILL.md) — development skill (repository agents only) for splitting an approved design into parallel agent chunks and merging them.
- [`../.claude/skills/multi-session-coordination/SKILL.md`](../.claude/skills/multi-session-coordination/SKILL.md) — development skill (repository agents only) for working alongside other agent sessions: claims, single owners of host-specific pins, shared hosts, and handoffs.
- [`../.claude/skills/docs-sync/SKILL.md`](../.claude/skills/docs-sync/SKILL.md) — development skill (repository agents only) for reconciling the docs with the code delta since the commit recorded in [`docs-sync.json`](docs-sync.json).
- [`../.agents/skills/repository-development-skills/SKILL.md`](../.agents/skills/repository-development-skills/SKILL.md) — pointer that sends Codex, Gemini CLI, Copilot and Cursor to the canonical `.claude/skills/`.
- [`reviews/inference-security-review-implementation.md`](reviews/inference-security-review-implementation.md) — slice 1 implementation record: readiness decisions, partition, merges, reconciliations, verification, and outstanding work.
- [`architecture/jobs-and-runtime.md`](architecture/jobs-and-runtime.md) — semantic jobs and orchestration.
- [`architecture/build-environments-and-execution-capture.md`](architecture/build-environments-and-execution-capture.md) — shared capture architecture, conditional-control design status, and the pinned fixture matrix.
- [`architecture/engineering-security-signals.md`](architecture/engineering-security-signals.md) — canonical end-to-end design for Clang static analysis, coverage and profile ingestion, dependency identity, OpenSSF Scorecard context, and their review handoffs.
- [`operations/language-build.md`](operations/language-build.md) — operator behavior for generic language builds and conditional applicability.
- [`architecture/python-and-retrieval.md`](architecture/python-and-retrieval.md) — accepted immutable retrieval indexes.
- [`operations/target-analysis-planning.md`](operations/target-analysis-planning.md) — operator behavior and recovery.
- [`operations/cpp-compiled-analysis.md`](operations/cpp-compiled-analysis.md) — isolated C/C++ build, deep-analysis, licensing, evidence, and recovery.
- [`SEI-CERT.md`](SEI-CERT.md) — SEI CERT coverage overview and links to the official standards.
- [`operations/sei-cert-rule-pack.md`](operations/sei-cert-rule-pack.md) — validating, extending, and evaluating the SEI CERT rule pack under Semgrep and OpenGrep.

Operations, one page per job or service:

- [`operations/third-party-data-sync.md`](operations/third-party-data-sync.md) — NVD, OSV, MITRE, and cve-bin-tool feed publication.
- [`operations/source-history-analysis.md`](operations/source-history-analysis.md) and
  [`operations/change-context-analysis.md`](operations/change-context-analysis.md) — history and change-context signals.
- [`operations/ci-configuration-analysis.md`](operations/ci-configuration-analysis.md) — CI/CD configuration analysis.
- [`operations/tree-sitter-ast.md`](operations/tree-sitter-ast.md) — Tree-sitter image and AST shards.
- [`operations/project-build.md`](operations/project-build.md) — project-image resolution, probes, and image repair.
- [`operations/wasm-build.md`](operations/wasm-build.md) — WebAssembly output-family builds.
- [`operations/artifact-indexing.md`](operations/artifact-indexing.md) and
  [`operations/artifact-security-analysis.md`](operations/artifact-security-analysis.md) — produced-artifact indexing and analysis.
- [`operations/clang-static-analysis.md`](operations/clang-static-analysis.md),
  [`operations/test-coverage-ingestion.md`](operations/test-coverage-ingestion.md),
  [`operations/profile-data.md`](operations/profile-data.md), and
  [`operations/dependency-intelligence.md`](operations/dependency-intelligence.md) — engineering
  security-signal production and recovery.
- [`operations/cpp-index-jobs.md`](operations/cpp-index-jobs.md) — clangd symbol index and Joern CPG jobs.
- [`operations/target-acquisition.md`](operations/target-acquisition.md) — multi-component review systems:
  the `job_target_acquisition` gate and `acquire-target` acquire pinned Git (default, with submodules),
  Perforce, and GitLab/Gerrit/Azure DevOps review-export components in parallel into `targets/<system>/`.
- [`operations/binary-decompilation.md`](operations/binary-decompilation.md) — pre-run Ghidra decompilation of
  third-party binaries, publications, review intake, `job_binary_evidence_indexing`, and the
  known-binary efficacy check; design in
  [`architecture/binary-decompilation.md`](architecture/binary-decompilation.md).
- [`operations/post-build-security-assessment.md`](operations/post-build-security-assessment.md) — build-hardening assessment.
- [`operations/static-analysis.md`](operations/static-analysis.md) — deterministic static evidence collection.
- [`operations/codeql-analysis.md`](operations/codeql-analysis.md) — cross-language CodeQL.
- [`operations/owasp-control-assessment.md`](operations/owasp-control-assessment.md) — default-enabled assessment
  versus synthetic qualification, pre-hunt ordering, typed bounds, receipts and unresolved coverage;
  [architecture and flow diagram](architecture/owasp-control-workbench.md).
- [`operations/review-prioritization.md`](operations/review-prioritization.md) — review prioritization.
- [`operations/security-tagging.md`](operations/security-tagging.md) — security tagging.
- [`operations/document-issue-analysis.md`](operations/document-issue-analysis.md) — source-mapped document candidate ledger.
- [`operations/retrieval-mcp.md`](operations/retrieval-mcp.md) — local retrieval MCP gateway.
- [`architecture/retrieval-surfaces.md`](architecture/retrieval-surfaces.md) — retrieval tools vs the MCP adapter vs review-cell retrieval vs runtime skills.
- [`operations/swift-execution-policy.md`](operations/swift-execution-policy.md) — the global
  `tools.enable_swift` gate (`src/appsec_review/swift_policy.py`) and its durable coverage gap.
- [`operations/metrics.md`](operations/metrics.md) — derived run metrics.

Records, task prompts, and schemas:

- Reviews: [`reviews/container-migration.md`](reviews/container-migration.md),
  [`reviews/archived-container-assets.md`](reviews/archived-container-assets.md),
  [`reviews/cppcheck-pmd-producers.md`](reviews/cppcheck-pmd-producers.md),
  [`reviews/inference-security-review-migration.md`](reviews/inference-security-review-migration.md).
- Implementation task prompts: [`tasks/review-data-indexing-prompt.md`](tasks/review-data-indexing-prompt.md),
  [`tasks/review-graph-precomputation-prompt.md`](tasks/review-graph-precomputation-prompt.md).
- JSON schemas for run artifacts and model proposals: [`schemas/`](schemas/).
- Historical handoff: [`handoffs/2026-10-09-build-execution-capture-restart.md`](handoffs/2026-10-09-build-execution-capture-restart.md).
- Open work: [`TODO.md`](TODO.md) and [`windows-native-analysis-todo.md`](windows-native-analysis-todo.md).

This file is navigation only and introduces no additional instructions.
