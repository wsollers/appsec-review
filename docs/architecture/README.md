# Architecture navigation

Repository authority remains in [`../../AGENTS.md`](../../AGENTS.md). This page is navigation only.

- [`jobs-and-runtime.md`](jobs-and-runtime.md) — semantic jobs, resumability, Dagster, and current analysis lanes.
- [`build-environments-and-execution-capture.md`](build-environments-and-execution-capture.md) —
  shared and project-derived build images, conditional capture control design, the pinned
  `appsec-multi-vuln` project-type matrix, envp redaction, and per-command gitleaks evidence.
- [`../operations/language-build.md`](../operations/language-build.md) — generic real-build execution, protected provenance, and checkpoints.
- [`../operations/artifact-security-analysis.md`](../operations/artifact-security-analysis.md) — generic bounded security analysis of accepted produced artifacts.
- [`../operations/wasm-build.md`](../operations/wasm-build.md) — WebAssembly output-family execution across accepted source-language recipes.
- [`../operations/metrics.md`](../operations/metrics.md) — receipt-resolved review scope, build, artifact, and CodeQL timing metrics.
- [`python-and-retrieval.md`](python-and-retrieval.md) — immutable accepted retrieval indexes and bounded MCP access.
- [`tree-sitter-ast.md`](tree-sitter-ast.md) — locked concrete-syntax-tree production and partitioned AST shards.
- [`owasp-control-workbench.md`](owasp-control-workbench.md) — OWASP applicability, validation, and coverage design.
- [`ci-configuration-analysis.md`](ci-configuration-analysis.md) — CI/CD configuration analysis architecture.
- [`source-history-analysis.md`](source-history-analysis.md) — Git and GitHub history instability
  signals for churn-led review prioritization; Perforce remains planned.
- [`../operations/source-history-analysis.md`](../operations/source-history-analysis.md) — history
  job configuration, GitHub enrichment, image build, and recovery.
- [`cross-language-codeql.md`](cross-language-codeql.md) — cross-language CodeQL scope and integration design.
- [`telemetry.md`](telemetry.md) — structured event and redaction design.
- [`windows-native-analysis-vm.md`](windows-native-analysis-vm.md) — proposed Windows-native analysis isolation.
- [`inference-security-review.md`](inference-security-review.md) — near-terminal red/blue/verification,
  evidence-qualified adjudication, independent scoring, benign proof-of-trigger, attack-chain, and
  quorum design.
