# Architecture navigation

Repository authority remains in [`../../AGENTS.md`](../../AGENTS.md). This page is navigation only.

- [`../operations/report-rendering.md`](../operations/report-rendering.md) — the LaTeX/PDF and single-page HTML report renderer, its box legend, scripts and image.
- [`jobs-and-runtime.md`](jobs-and-runtime.md) — semantic jobs, resumability, Dagster, and current analysis lanes.
- [`build-environments-and-execution-capture.md`](build-environments-and-execution-capture.md) —
  shared and project-derived build images, conditional capture control design, the pinned
  `appsec-multi-vuln` project-type matrix, envp redaction, and per-command gitleaks evidence.
- [`../operations/language-build.md`](../operations/language-build.md) — generic real-build execution, protected provenance, and checkpoints.
- [`../operations/artifact-security-analysis.md`](../operations/artifact-security-analysis.md) — generic bounded security analysis of accepted produced artifacts.
- [`engineering-security-signals.md`](engineering-security-signals.md) — end-to-end Clang,
  coverage, profile hotness, dependency identity and exposure, OpenSSF Scorecard, provenance,
  handoff, and downstream-consumer architecture.
- [`clang-static-analysis.md`](clang-static-analysis.md) — Clang-Tidy and Clang Static Analyzer over accepted C/C++ compile scopes.
- [`test-coverage-ingestion.md`](test-coverage-ingestion.md) — bounded LCOV, Cobertura, JaCoCo, and LLVM coverage normalization and source binding.
- [`profile-data.md`](profile-data.md) — bounded folded-stack, perf-script, Callgrind, and LLVM sample-profile ingestion with context-only hotness ranks.
- [`dependency-intelligence.md`](dependency-intelligence.md) — declared, SBOM, linker, loader, and metadata dependency resolution with OpenSSF Scorecard context.
- [`../operations/wasm-build.md`](../operations/wasm-build.md) — WebAssembly output-family execution across accepted source-language recipes.
- [`../operations/metrics.md`](../operations/metrics.md) — receipt-resolved review scope, build, artifact, and CodeQL timing metrics.
- [`python-and-retrieval.md`](python-and-retrieval.md) — immutable accepted retrieval indexes and bounded MCP access.
- [`retrieval-surfaces.md`](retrieval-surfaces.md) — retrieval tools, the MCP adapter, review-cell retrieval and
  runtime skills: which consumer reaches the data how.
- [`tree-sitter-ast.md`](tree-sitter-ast.md) — locked concrete-syntax-tree production and partitioned AST shards.
- [`owasp-control-workbench.md`](owasp-control-workbench.md) — pre-hunt OWASP flow/diagram, full pinned
  catalogs versus four Python procedures, evidence custody, blinded review and provisional downstream context.
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
- [`review-prioritization.md`](review-prioritization.md) — function-level cyclomatic and cognitive
  complexity, import coupling, boundary/privilege/suppression heuristics, CodeQL source-to-sink
  paths, and the LLM Prioritization Score.
- [`../operations/review-prioritization.md`](../operations/review-prioritization.md) — prioritization
  configuration, outputs, retrieval examples, and coverage limits.
- [`seeded-codeql-neighborhoods.md`](seeded-codeql-neighborhoods.md) — CodeQL graph export seeded
  from finding locations to a configured depth, the per-database card, and the
  `list_codeql_databases` / `query_codeql_neighborhood` MCP tools (phase 3 of the code graph).
- [`seeded-neighborhoods.md`](seeded-neighborhoods.md) — the seeded rule for the Clang AST/IR,
  Clang-Tidy/Static Analyzer and CPG producers, the shared seeding module, the card's `producers` list
  and the flow, diagnostics and symbols exposure.
- [`cross-language-codeql.md`](cross-language-codeql.md) — cross-language CodeQL scope and integration design.
- [`../SEI-CERT.md`](../SEI-CERT.md) — SEI CERT coverage overview, official-standard links, and status totals.
- [`sei-cert-rule-pack.md`](sei-cert-rule-pack.md) — SEI CERT Semgrep/OpenGrep rule pack, CERT
  mapping statuses, portability constraints, and evidence integration.
- [`evidence-sources-and-dataflow-retrieval.md`](evidence-sources-and-dataflow-retrieval.md) — input
  inventory, authority classes, precomputed dataflow, model-facing formats, MCP tools, and job flow.
- [`document-evidence-analysis.md`](document-evidence-analysis.md) — target document collection,
  route and boundary analysis, inference access, and the finding handoff design.
- [`binary-decompilation.md`](binary-decompilation.md) — pre-run Ghidra decompilation of third-party
  binaries: inputs, the hash-addressed publication store, gaps, how a review references a
  publication, and the known-binary efficacy comparison.
- [`../operations/binary-decompilation.md`](../operations/binary-decompilation.md) — registering a
  binary, starting and verifying a decompilation, failures, and the efficacy command.
- [`telemetry.md`](telemetry.md) — structured event and redaction design.
- [`windows-native-analysis-vm.md`](windows-native-analysis-vm.md) — proposed Windows-native analysis isolation.
- [`windows-host-runner.md`](windows-host-runner.md) — native Windows host build runner (scripts under `deploy/windows/`).
- [`inference-security-review.md`](inference-security-review.md) — near-terminal red/blue/verification,
  evidence-qualified adjudication, independent scoring, benign proof-of-trigger, attack-chain, and
  quorum design.
- [`review-package-contract.md`](review-package-contract.md) — versioned finding-lead, scanner hunt, and document hunt
  package inputs, membership gates, retrieval scopes, and implementation dependencies.
- [`red-discovery-output.md`](red-discovery-output.md) — red-pool proposal, taint-path, chain-seed,
  evidence, and lead-accounting contract.
- [`review-protocol-v2.md`](review-protocol-v2.md) — the model-facing layer of the review: labelled
  package v2 with embedded neighborhood facts, retrieval and `expand`, compact red, blue and verifier
  answers, and how stances become ledger states.
- [`review-judge-and-poc.md`](review-judge-and-poc.md) — the judge role (A/B shuffled sides), PoC candidates, and
  `job_poc_generation`: a never-executed, compile-checked unit-test function for developers.
- [`../operations/poc-generation.md`](../operations/poc-generation.md) — `job_poc_generation`: compile-checked proof-of-concept unit-test functions (no `main`, never run) for findings the judge agreed with; shipped disabled and run by hand.
- [`indexing-and-query-reuse.md`](indexing-and-query-reuse.md) — review-data indexing and reusable
  query design.
- [`code-graph-precomputation.md`](code-graph-precomputation.md) — the authoritative code-graph
  strategy: CodeQL-first producers with C/C++ cross-checks, the `graph` index and
  `query_code_graph` tool, fact families and R3 admissibility, job topology, language rollout,
  and the parallel implementation and test plan (implemented through C9 for C/C++, offline-verified;
  record in [`../reviews/code-graph-precomputation-implementation.md`](../reviews/code-graph-precomputation-implementation.md);
  operations in [`../operations/code-graph-index.md`](../operations/code-graph-index.md)).
- [`svf-alias-producer.md`](svf-alias-producer.md) — SVF points-to cross-check producer (opt-in):
  pinned `tool-svf` image, `job_svf_alias_analysis`, and `svf-cross-check/1` rules for indirect
  calls and guard operand aliasing, a memory-object accessor index, and memory and caller context in
  C/C++ finding-lead packages, with depth and fan-out as TOML tunables (operations in
  [`../operations/svf-alias-analysis.md`](../operations/svf-alias-analysis.md)).
- [`graph-alias-slice-layout-modes.md`](graph-alias-slice-layout-modes.md) — proposed
  `query_code_graph` modes `aliases`, `slice_backward`/`slice_forward`, `type_layout` and
  `buffer_bounds` over precomputed CodeQL and SVF facts, the internal `control_flow` family and
  sink CFG context, and why no raw CFG mode is added (design only, not implemented); the detector
  coverage checklist is in [`../reviews/detector-coverage-checklist.md`](../reviews/detector-coverage-checklist.md).

Operations pages not listed above:

- [`../operations/model-profiles.md`](../operations/model-profiles.md) — the `dev` and `prod` runtime profiles: selection, the closed-allowlist `profiles/prod.toml` layer, and the effect on fingerprints and the model contract.
- [`../operations/inference-security-review.md`](../operations/inference-security-review.md) — inference review model selection and upgrade, capacity overlay, and outcomes.
- [`../operations/wave1-review.md`](../operations/wave1-review.md) — direct CLI and `wave1_review` scope.
- [`../operations/third-party-data-sync.md`](../operations/third-party-data-sync.md) — feed synchronization.
- [`../operations/target-analysis-planning.md`](../operations/target-analysis-planning.md) — analysis planning.
- [`../operations/project-build.md`](../operations/project-build.md) — project-image resolution, probes, and repair.
- [`../operations/ci-configuration-analysis.md`](../operations/ci-configuration-analysis.md) — CI/CD configuration analysis.
- [`../operations/tree-sitter-ast.md`](../operations/tree-sitter-ast.md) — Tree-sitter image and AST shards.
- [`../operations/artifact-indexing.md`](../operations/artifact-indexing.md) — produced-artifact indexing.
- [`../operations/cpp-compiled-analysis.md`](../operations/cpp-compiled-analysis.md) and
  [`../operations/cpp-index-jobs.md`](../operations/cpp-index-jobs.md) — C/C++ analysis, clangd, and Joern.
- [`../operations/post-build-security-assessment.md`](../operations/post-build-security-assessment.md) — build-hardening assessment.
- [`../operations/sanitizer-build.md`](../operations/sanitizer-build.md) — ASan/UBSan rebuild of accepted native units; instrumented outputs are catalogued, never executed.
- [`../operations/final-report.md`](../operations/final-report.md) — final publication gate and final report: bucket accounting, limitations, `final-report.json` and the deterministic Markdown (PDF is a later step).
- [`../operations/static-analysis.md`](../operations/static-analysis.md) — deterministic static evidence collection.
- [`../operations/codeql-analysis.md`](../operations/codeql-analysis.md) — cross-language CodeQL.
- [`../operations/swift-execution-policy.md`](../operations/swift-execution-policy.md) — disabled-by-default Swift execution and durable coverage gap.
- [`../operations/owasp-control-assessment.md`](../operations/owasp-control-assessment.md) — OWASP control assessment.
- [`../operations/security-tagging.md`](../operations/security-tagging.md) — security tagging.
- [`../operations/review-data-indexing.md`](../operations/review-data-indexing.md) — dataset inventory and publication audit.
- [`../operations/retrieval-mcp.md`](../operations/retrieval-mcp.md) — local retrieval MCP gateway.
- [`../operations/sei-cert-rule-pack.md`](../operations/sei-cert-rule-pack.md) — SEI CERT rule-pack operation.

Other records: decision and migration reviews in [`../reviews/`](../reviews/), implementation task
prompts in [`../tasks/`](../tasks/), JSON schemas in [`../schemas/`](../schemas/), and the full
documentation index in [`../agent-reader.md`](../agent-reader.md).
