# Agent navigation

Repository-wide authority and trust rules live only in [`../AGENTS.md`](../AGENTS.md).

Relevant bounded procedures and design references:

- [`architecture/README.md`](architecture/README.md) — full architecture navigation.
- [`operations/wave1-review.md`](operations/wave1-review.md) — direct CLI scope, resume behavior, and the Dagster entrypoint.
- [`operations/inference-security-review.md`](operations/inference-security-review.md) — model selection and upgrade, local capacity overlay, and outcomes for the inference security review; design in [`architecture/inference-security-review.md`](architecture/inference-security-review.md).
- [`operations/review-data-indexing.md`](operations/review-data-indexing.md) — dataset inventory and publication audit, lead menus, stage-1 products, and offline FTS validation; design in [`architecture/indexing-and-query-reuse.md`](architecture/indexing-and-query-reuse.md).
- [`../deploy/dagster/README.md`](../deploy/dagster/README.md) — deployment lifecycle and live verification.
- [`../pipeline/skills/target-analysis-planning/SKILL.md`](../pipeline/skills/target-analysis-planning/SKILL.md) — model-side proposal constraints for target analysis ambiguity.
- [`../pipeline/skills/build-image-repair/SKILL.md`](../pipeline/skills/build-image-repair/SKILL.md) — bounded apt-package proposals for failed project-build image probes.
- [`../pipeline/skills/post-build-security-assessment/SKILL.md`](../pipeline/skills/post-build-security-assessment/SKILL.md) — bounded guidance for the post-build security inference task.
- [`../.claude/skills/parallel-implementation/SKILL.md`](../.claude/skills/parallel-implementation/SKILL.md) — development skill (repository agents only) for splitting an approved design into parallel agent chunks and merging them.
- [`../.agents/skills/repository-development-skills/SKILL.md`](../.agents/skills/repository-development-skills/SKILL.md) — pointer that sends Codex, Gemini CLI, Copilot and Cursor to the canonical `.claude/skills/`.
- [`reviews/inference-security-review-implementation.md`](reviews/inference-security-review-implementation.md) — slice 1 implementation record: readiness decisions, partition, merges, reconciliations, verification, and outstanding work.
- [`architecture/jobs-and-runtime.md`](architecture/jobs-and-runtime.md) — semantic jobs and orchestration.
- [`architecture/build-environments-and-execution-capture.md`](architecture/build-environments-and-execution-capture.md) — shared capture architecture, conditional-control design status, and the pinned fixture matrix.
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
- [`operations/cpp-index-jobs.md`](operations/cpp-index-jobs.md) — clangd symbol index and Joern CPG jobs.
- [`operations/post-build-security-assessment.md`](operations/post-build-security-assessment.md) — build-hardening assessment.
- [`operations/static-analysis.md`](operations/static-analysis.md) — deterministic static evidence collection.
- [`operations/codeql-analysis.md`](operations/codeql-analysis.md) — cross-language CodeQL.
- [`operations/owasp-control-assessment.md`](operations/owasp-control-assessment.md) — OWASP control assessment.
- [`operations/review-prioritization.md`](operations/review-prioritization.md) — review prioritization.
- [`operations/security-tagging.md`](operations/security-tagging.md) — security tagging.
- [`operations/document-issue-analysis.md`](operations/document-issue-analysis.md) — source-mapped document candidate ledger.
- [`operations/retrieval-mcp.md`](operations/retrieval-mcp.md) — local retrieval MCP gateway.
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
