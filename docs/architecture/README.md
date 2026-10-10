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
- [`security-tag-taxonomy.md`](security-tag-taxonomy.md) — faceted, basis-qualified security
  tag vocabulary, crosswalk, and tag-cloud rollup produced by `job_security_tagging`.
- [`ci-configuration-analysis.md`](ci-configuration-analysis.md) — CI/CD configuration analysis architecture.
- [`source-history-analysis.md`](source-history-analysis.md) — Git and GitHub history instability
  signals for churn-led review prioritization; Perforce remains planned.
- [`../operations/source-history-analysis.md`](../operations/source-history-analysis.md) — history
  job configuration, GitHub enrichment, image build, and recovery.
- [`change-context-analysis.md`](change-context-analysis.md) — review-speed, deployment-proximity,
  scope-sprawl, repeated-repair, test-churn, and ownership signals with a review-priority index.
- [`../operations/change-context-analysis.md`](../operations/change-context-analysis.md) —
  change-context sources, export pinning, configuration, and retrieval.
- [`cross-language-codeql.md`](cross-language-codeql.md) — cross-language CodeQL scope and integration design.
- [`../SEI-CERT.md`](../SEI-CERT.md) — SEI CERT coverage overview, official-standard links, and status totals.
- [`sei-cert-rule-pack.md`](sei-cert-rule-pack.md) — SEI CERT Semgrep/OpenGrep rule pack, CERT
  mapping statuses, portability constraints, and evidence integration.
- [`evidence-sources-and-dataflow-retrieval.md`](evidence-sources-and-dataflow-retrieval.md) — input
  inventory, authority classes, precomputed dataflow, model-facing formats, MCP tools, and job flow.
- [`telemetry.md`](telemetry.md) — structured event and redaction design.
- [`windows-native-analysis-vm.md`](windows-native-analysis-vm.md) — proposed Windows-native analysis isolation.
- [`inference-security-review.md`](inference-security-review.md) — near-terminal red/blue/verification,
  evidence-qualified adjudication, independent scoring, benign proof-of-trigger, attack-chain, and
  quorum design.
