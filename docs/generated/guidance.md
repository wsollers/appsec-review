---
title: "Model guidance registry"
kind: "generated"
subsystem: "review inference and guidance"
status: "current"
jobs: []
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
# Model guidance registry

Assignments below are allowed or routed job candidates, not evidence that a task selected them.
Undeclared per-task selections remain [T-147](../TODO.md).

## roles adjudication_judge

Jobs: `job_inference_security_review`.

```json
{
  "lens": "skeptical",
  "output_schema": "judge-result-compact",
  "outputs": [
    "supports",
    "contradicts",
    "qualifies"
  ],
  "path": "pipeline/prompt-fragments/roles/adjudication_judge.md",
  "prohibited": [
    "accept_claim",
    "assign_severity",
    "execute_code",
    "propose_claim",
    "read_target_guidance",
    "request_unlisted_tool",
    "set_claim_state",
    "widen_scope"
  ],
  "responsibility": "Decide which of two labelled sides is correct about one claim, citing resolvable evidence.",
  "tools": [
    "find",
    "list_codeql_databases",
    "query_code_graph",
    "query_codeql_neighborhood",
    "query_debug_symbols",
    "query_syntax",
    "read_excerpt",
    "resolve_evidence",
    "trace"
  ]
}
```

## roles applicability_router

Jobs: No dispatched job declaration.

```json
{
  "responsibility": "Resolve one bounded control-component applicability question."
}
```

## roles attack_chain_analyst

Jobs: `job_inference_security_review`.

```json
{
  "lens": "generative",
  "output_schema": "attack-chain",
  "outputs": [
    "attack_chain",
    "component_of_chain",
    "requests_evidence"
  ],
  "path": "pipeline/prompt-fragments/roles/attack_chain_analyst.md",
  "prohibited": [
    "accept_claim",
    "assign_severity",
    "execute_code",
    "propose_claim",
    "read_target_guidance",
    "request_unlisted_tool",
    "set_claim_state",
    "widen_scope"
  ],
  "responsibility": "Propose attack chains composed only of existing adjudicated claims.",
  "tools": [
    "find",
    "read_excerpt",
    "resolve_evidence",
    "trace"
  ]
}
```

## roles blue_team_refuter

Jobs: `job_inference_security_review`.

```json
{
  "lens": "skeptical",
  "output_schema": "blue-compact",
  "outputs": [
    "contradicts",
    "qualifies",
    "requests_evidence"
  ],
  "path": "pipeline/prompt-fragments/roles/blue_team_refuter.md",
  "prohibited": [
    "accept_claim",
    "assign_severity",
    "execute_code",
    "propose_claim",
    "read_target_guidance",
    "request_unlisted_tool",
    "see_other_cell_output",
    "see_red_reasoning",
    "set_claim_state",
    "widen_scope"
  ],
  "responsibility": "Seek resolvable evidence that one claim's predicates do not hold.",
  "tools": [
    "find",
    "list_codeql_databases",
    "query_artifacts",
    "query_build_security",
    "query_ci_configuration",
    "query_code_graph",
    "query_codeql_neighborhood",
    "query_debug_symbols",
    "query_syntax",
    "read_excerpt",
    "resolve_evidence",
    "trace"
  ]
}
```

## roles build_engineer_dotnet

Jobs: `job_project_build`, `job_target_analysis_plan`.

```json
{
  "responsibility": "Produce bounded reproducible .NET and MSBuild recipes."
}
```

## roles build_engineer_go

Jobs: `job_project_build`, `job_target_analysis_plan`.

```json
{
  "responsibility": "Produce bounded reproducible Go module and workspace build recipes."
}
```

## roles build_engineer_java

Jobs: `job_project_build`, `job_target_analysis_plan`.

```json
{
  "responsibility": "Produce bounded reproducible JVM build-system recipes."
}
```

## roles build_engineer_native

Jobs: `job_project_build`, `job_target_analysis_plan`.

```json
{
  "responsibility": "Produce bounded reproducible C/C++ and native build-system recipes."
}
```

## roles build_engineer_node

Jobs: `job_project_build`, `job_target_analysis_plan`.

```json
{
  "responsibility": "Produce bounded reproducible JavaScript and TypeScript build recipes."
}
```

## roles build_engineer_php

Jobs: `job_project_build`, `job_target_analysis_plan`.

```json
{
  "responsibility": "Produce bounded reproducible PHP and Composer recipes."
}
```

## roles build_engineer_python

Jobs: `job_project_build`, `job_target_analysis_plan`.

```json
{
  "responsibility": "Produce bounded reproducible Python packaging recipes."
}
```

## roles build_engineer_rust

Jobs: `job_project_build`, `job_target_analysis_plan`.

```json
{
  "responsibility": "Produce bounded reproducible Rust and Cargo build recipes."
}
```

## roles build_engineer_wasm

Jobs: `job_project_build`, `job_target_analysis_plan`.

```json
{
  "responsibility": "Produce bounded reproducible WebAssembly build recipes."
}
```

## roles build_security_assessor

Jobs: `job_post_build_security_assessment`.

```json
{
  "responsibility": "Explain supplied deterministic build-security checks through requested settings, observed compile/link evidence and actual artifact properties; missing or failed producers remain gaps."
}
```

## roles completeness_reviewer

Jobs: No dispatched job declaration.

```json
{
  "lens": "generative",
  "output_schema": "completeness-result",
  "outputs": [
    "coverage_gap",
    "requests_evidence"
  ],
  "path": "pipeline/prompt-fragments/roles/completeness_reviewer.md",
  "prohibited": [
    "accept_claim",
    "assign_severity",
    "execute_code",
    "propose_claim",
    "read_target_guidance",
    "refute_claim",
    "request_unlisted_tool",
    "set_claim_state",
    "widen_scope"
  ],
  "responsibility": "Identify review-coverage gaps across units, strategies, and personas.",
  "tools": [
    "coverage",
    "find",
    "query_dataset_inventory"
  ]
}
```

## roles component_classifier

Jobs: No dispatched job declaration.

```json
{
  "responsibility": "Classify bounded component purpose and trust roles from cited evidence."
}
```

## roles control_assessor

Jobs: `job_owasp_control_assessment`.

```json
{
  "responsibility": "Assess assigned proof obligations and return observations with citations."
}
```

## roles evidence_verifier

Jobs: No dispatched job declaration.

```json
{
  "responsibility": "Resolve cited observations to accepted source or run artifacts."
}
```

## roles finding_adjudicator

Jobs: No dispatched job declaration.

```json
{
  "lens": "skeptical",
  "output_schema": "adjudication",
  "outputs": [
    "supported",
    "confirmed",
    "contradicted",
    "not_reachable",
    "not_exploitable_in_observed_configuration",
    "insufficient_evidence",
    "duplicate",
    "out_of_scope",
    "coverage_gap"
  ],
  "path": "pipeline/prompt-fragments/roles/finding_adjudicator.md",
  "prohibited": [
    "assign_severity",
    "execute_code",
    "override_score",
    "propose_claim",
    "read_target_guidance",
    "refute_claim",
    "request_unlisted_tool",
    "widen_scope"
  ],
  "responsibility": "Apply the deterministic adjudication table to recorded evidence relations.",
  "tools": []
}
```

## roles hypothesis_hunter

Jobs: `job_inference_security_review`.

```json
{
  "lens": "generative",
  "output_schema": "red-compact",
  "outputs": [
    "proposed"
  ],
  "path": "pipeline/prompt-fragments/roles/hypothesis_hunter.md",
  "prohibited": [
    "accept_claim",
    "assign_severity",
    "execute_code",
    "read_target_guidance",
    "refute_claim",
    "request_unlisted_tool",
    "see_other_cell_output",
    "set_claim_state",
    "widen_scope"
  ],
  "responsibility": "Propose evidence-cited hypotheses for one hunt package through one strategy lens.",
  "tools": [
    "coverage",
    "find",
    "list_codeql_databases",
    "query_code_graph",
    "query_codeql",
    "query_codeql_neighborhood",
    "query_debug_symbols",
    "query_hotspots",
    "query_observations",
    "query_precomputed",
    "query_syntax",
    "read_excerpt",
    "search",
    "trace"
  ]
}
```

## roles independent_reviewer

Jobs: `job_owasp_control_assessment`.

```json
{
  "responsibility": "Independently review elevated or ship-blocking proposed claims."
}
```

## roles independent_scorer

Jobs: No dispatched job declaration.

```json
{
  "lens": "skeptical",
  "output_schema": "score-package",
  "outputs": [
    "score"
  ],
  "path": "pipeline/prompt-fragments/roles/independent_scorer.md",
  "prohibited": [
    "accept_claim",
    "execute_code",
    "override_score",
    "propose_claim",
    "read_target_guidance",
    "refute_claim",
    "request_unlisted_tool",
    "set_claim_state",
    "widen_scope"
  ],
  "responsibility": "Apply a configured deterministic scoring provider to one adjudicated claim.",
  "tools": []
}
```

## roles independent_verifier

Jobs: `job_inference_security_review`.

```json
{
  "lens": "skeptical",
  "output_schema": "verifier-compact",
  "outputs": [
    "supports",
    "contradicts",
    "qualifies",
    "requests_evidence"
  ],
  "path": "pipeline/prompt-fragments/roles/independent_verifier.md",
  "prohibited": [
    "accept_claim",
    "assign_severity",
    "execute_code",
    "propose_claim",
    "read_target_guidance",
    "request_unlisted_tool",
    "see_other_cell_output",
    "see_red_reasoning",
    "set_claim_state",
    "widen_scope"
  ],
  "responsibility": "Blindly check each predicate of one claim against resolvable direct evidence.",
  "tools": [
    "find",
    "list_codeql_databases",
    "query_code_graph",
    "query_codeql_neighborhood",
    "query_debug_symbols",
    "query_syntax",
    "read_excerpt",
    "resolve_evidence",
    "trace"
  ]
}
```

## roles lead_triager

Jobs: `job_inference_security_review`.

```json
{
  "lens": "skeptical",
  "output_schema": "lead-triage-result",
  "outputs": [],
  "path": "pipeline/prompt-fragments/roles/lead_triager.md",
  "prohibited": [
    "accept_claim",
    "execute_code",
    "override_score",
    "propose_claim",
    "read_target_guidance",
    "refute_claim",
    "request_unlisted_tool",
    "set_claim_state",
    "widen_scope"
  ],
  "responsibility": "Assign one priority severity to each scanner lead whose scanner reported none, from the rule and a bounded excerpt.",
  "tools": []
}
```

## roles native_dependency_resolver

Jobs: `job_dependency_intelligence`.

```json
{
  "responsibility": "Resolve one bounded native dependency candidate to plausible public repository context."
}
```

## roles native_sbom_investigator

Jobs: `job_dependency_intelligence`.

```json
{
  "responsibility": "Curate bounded native component candidates and propose component-local metadata from supplied source evidence."
}
```

## roles poc_designer

Jobs: No dispatched job declaration.

```json
{
  "lens": "generative",
  "output_schema": "poc-plan",
  "outputs": [
    "poc_plan"
  ],
  "path": "pipeline/prompt-fragments/roles/poc_designer.md",
  "prohibited": [
    "accept_claim",
    "assign_severity",
    "change_configuration",
    "execute_code",
    "read_target_guidance",
    "request_unlisted_tool",
    "set_claim_state",
    "widen_scope"
  ],
  "responsibility": "Design one benign, policy-bounded proof-of-trigger plan for one eligible finding.",
  "tools": [
    "find",
    "query_artifacts",
    "query_build_security",
    "read_excerpt"
  ]
}
```

## roles poc_verifier

Jobs: No dispatched job declaration.

```json
{
  "lens": "skeptical",
  "output_schema": "poc-result",
  "outputs": [
    "poc_result",
    "supports",
    "contradicts",
    "requests_evidence"
  ],
  "path": "pipeline/prompt-fragments/roles/poc_verifier.md",
  "prohibited": [
    "accept_claim",
    "assign_severity",
    "execute_code",
    "propose_claim",
    "read_target_guidance",
    "request_unlisted_tool",
    "set_claim_state",
    "widen_scope"
  ],
  "responsibility": "Check one proof-of-trigger result against its plan and run-owned artifacts.",
  "tools": [
    "query_artifacts",
    "read_excerpt",
    "resolve_evidence"
  ]
}
```

## roles poc_writer

Jobs: `job_poc_generation`.

```json
{
  "responsibility": "Write one benign, bounded unit-test function with a negative control that demonstrates an agreed finding; never run by the pipeline."
}
```

## roles red_team_analyst

Jobs: `job_inference_security_review`.

```json
{
  "lens": "generative",
  "output_schema": "red-compact",
  "outputs": [
    "proposed"
  ],
  "path": "pipeline/prompt-fragments/roles/red_team_analyst.md",
  "prohibited": [
    "accept_claim",
    "assign_severity",
    "execute_code",
    "read_target_guidance",
    "refute_claim",
    "request_unlisted_tool",
    "see_other_cell_output",
    "set_claim_state",
    "widen_scope"
  ],
  "responsibility": "Propose evidence-cited claims for one admitted finding lead through one assigned lens.",
  "tools": [
    "find",
    "list_codeql_databases",
    "query_build_security",
    "query_ci_configuration",
    "query_code_graph",
    "query_codeql",
    "query_codeql_neighborhood",
    "query_debug_symbols",
    "query_observations",
    "query_syntax",
    "read_excerpt",
    "search",
    "trace"
  ]
}
```

## roles remediation_reviewer

Jobs: `job_remediation_validation`.

```json
{
  "responsibility": "Independently assess one inert correction and bounded static or compile-check evidence without declaring a runtime fix."
}
```

## roles remediation_writer

Jobs: `job_remediation_planning`.

```json
{
  "responsibility": "Propose inert exact-byte corrections and safe regression specifications for accepted confirmed findings only."
}
```

## roles result_adjudicator

Jobs: No dispatched job declaration.

```json
{
  "responsibility": "Apply deterministic acceptance rules while preserving disagreement."
}
```

## personas api_web

Jobs: `job_owasp_control_assessment`.

```json
{
  "viewpoint": "Web and API attack surfaces and protocol boundaries."
}
```

## personas authentication_session

Jobs: `job_inference_security_review`, `job_owasp_control_assessment`.

```json
{
  "path": "pipeline/prompt-fragments/personas/authentication_session.md",
  "viewpoint": "Authentication, session, and identity boundaries."
}
```

## personas authorization_access_control

Jobs: `job_inference_security_review`, `job_owasp_control_assessment`.

```json
{
  "path": "pipeline/prompt-fragments/personas/authorization_access_control.md",
  "viewpoint": "Authorization and access-control boundaries."
}
```

## personas build_supply_chain

Jobs: `job_inference_security_review`, `job_owasp_control_assessment`, `job_post_build_security_assessment`.

```json
{
  "path": "pipeline/prompt-fragments/personas/build_supply_chain.md",
  "viewpoint": "Build provenance, dependency, and supply-chain integrity."
}
```

## personas business_logic_abuse

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/personas/business_logic_abuse.md"
}
```

## personas ci_cd_pipeline

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/personas/ci_cd_pipeline.md"
}
```

## personas cloud_container_deployment

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/personas/cloud_container_deployment.md"
}
```

## personas cryptography_data_protection

Jobs: `job_inference_security_review`, `job_owasp_control_assessment`.

```json
{
  "path": "pipeline/prompt-fragments/personas/cryptography_data_protection.md",
  "viewpoint": "Cryptography, key handling, and data protection."
}
```

## personas dependency_repository_investigator

Jobs: `job_dependency_intelligence`.

```json
{
  "viewpoint": "Resolve bounded native package observations to plausible public repository context."
}
```

## personas deployment_operations

Jobs: `job_owasp_control_assessment`.

```json
{
  "viewpoint": "Deployment, configuration, and operational controls."
}
```

## personas devops_engineer

Jobs: `job_project_build`, `job_target_analysis_plan`.

```json
{
  "viewpoint": "Reproducible automation, immutable containers, dependencies, CI behavior, and diagnosable operational failures."
}
```

## personas filesystem_resources

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/personas/filesystem_resources.md"
}
```

## personas generalist

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/personas/generalist.md"
}
```

## personas injection_interpreters

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/personas/injection_interpreters.md"
}
```

## personas memory_safety_native

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/personas/memory_safety_native.md"
}
```

## personas mobile_platform

Jobs: `job_inference_security_review`, `job_owasp_control_assessment`.

```json
{
  "path": "pipeline/prompt-fragments/personas/mobile_platform.md",
  "viewpoint": "Android and iOS platform security behavior."
}
```

## personas native_dependency_analyst

Jobs: `job_dependency_intelligence`.

```json
{
  "viewpoint": "Native dependency identity, component-local release evidence, physical packaging, and provenance without conflating SDK parents or separate copies."
}
```

## personas network_api_surface

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/personas/network_api_surface.md"
}
```

## personas parsing_deserialization

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/personas/parsing_deserialization.md"
}
```

## stacks android

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/stacks/android.md"
}
```

## stacks c_systems_embedded

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/stacks/c_systems_embedded.md"
}
```

## stacks ci_pipeline

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/stacks/ci_pipeline.md"
}
```

## stacks cpp_native_service

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/stacks/cpp_native_service.md"
}
```

## stacks cpp_rpc_service

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/stacks/cpp_rpc_service.md"
}
```

## stacks dotnet_service

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/stacks/dotnet_service.md"
}
```

## stacks generic

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/stacks/generic.md"
}
```

## stacks go_service

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/stacks/go_service.md"
}
```

## stacks iac_kubernetes

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/stacks/iac_kubernetes.md"
}
```

## stacks ios

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/stacks/ios.md"
}
```

## stacks jvm_service

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/stacks/jvm_service.md"
}
```

## stacks node_web

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/stacks/node_web.md"
}
```

## stacks php_web

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/stacks/php_web.md"
}
```

## stacks python_service

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/stacks/python_service.md"
}
```

## stacks rust_service

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/stacks/rust_service.md"
}
```

## stacks wasm

Jobs: `job_inference_security_review`.

```json
{
  "path": "pipeline/prompt-fragments/stacks/wasm.md"
}
```

## runtime_skills binary-evidence

Jobs: `job_inference_security_review`.

```json
{
  "jobs": [
    "job_inference_security_review"
  ],
  "path": "pipeline/skills/binary-evidence/SKILL.md"
}
```

## runtime_skills build-image-repair

Jobs: `job_project_build`.

```json
{
  "jobs": [
    "job_project_build"
  ],
  "path": "pipeline/skills/build-image-repair/SKILL.md"
}
```

## runtime_skills conflict-resolution

Jobs: `job_inference_security_review`, `job_owasp_control_assessment`.

```json
{
  "jobs": [
    "job_inference_security_review",
    "job_owasp_control_assessment"
  ],
  "path": "pipeline/skills/conflict-resolution/SKILL.md"
}
```

## runtime_skills effective-control-verification

Jobs: `job_inference_security_review`, `job_owasp_control_assessment`.

```json
{
  "jobs": [
    "job_inference_security_review",
    "job_owasp_control_assessment"
  ],
  "path": "pipeline/skills/effective-control-verification/SKILL.md"
}
```

## runtime_skills generative-investigation

Jobs: `job_inference_security_review`.

```json
{
  "jobs": [
    "job_inference_security_review"
  ],
  "path": "pipeline/skills/generative-investigation/SKILL.md"
}
```

## runtime_skills native-dependency-resolution

Jobs: `job_dependency_intelligence`.

```json
{
  "jobs": [
    "job_dependency_intelligence"
  ],
  "path": "pipeline/skills/native-dependency-resolution/SKILL.md"
}
```

## runtime_skills native-sbom-investigation

Jobs: `job_dependency_intelligence`.

```json
{
  "jobs": [
    "job_dependency_intelligence"
  ],
  "path": "pipeline/skills/native-sbom-investigation/SKILL.md"
}
```

## runtime_skills poc-writer

Jobs: `job_poc_generation`.

```json
{
  "jobs": [
    "job_poc_generation"
  ],
  "path": "pipeline/skills/poc-writer/SKILL.md"
}
```

## runtime_skills post-build-security-assessment

Jobs: `job_post_build_security_assessment`.

```json
{
  "jobs": [
    "job_post_build_security_assessment"
  ],
  "path": "pipeline/skills/post-build-security-assessment/SKILL.md"
}
```

## runtime_skills predicate-verification

Jobs: `job_inference_security_review`, `job_owasp_control_assessment`.

```json
{
  "jobs": [
    "job_inference_security_review",
    "job_owasp_control_assessment"
  ],
  "path": "pipeline/skills/predicate-verification/SKILL.md"
}
```

## runtime_skills stateful-invariant-analysis

Jobs: `job_inference_security_review`, `job_remediation_planning`, `job_remediation_validation`.

```json
{
  "jobs": [
    "job_inference_security_review",
    "job_remediation_planning",
    "job_remediation_validation"
  ],
  "path": "pipeline/skills/stateful-invariant-analysis/SKILL.md"
}
```

## runtime_skills target-analysis-planning

Jobs: `job_target_analysis_plan`.

```json
{
  "jobs": [
    "job_target_analysis_plan"
  ],
  "path": "pipeline/skills/target-analysis-planning/SKILL.md"
}
```
