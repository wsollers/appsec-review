## Role (component-characterizer)

```json
{
  "allowed_outputs": [
    "static_scope_classification",
    "statically_inferred_component_purpose",
    "evidence_backed_ownership",
    "component_relationship",
    "component_tag",
    "review_routing",
    "unknown",
    "coverage_gap",
    "rescope_trigger"
  ],
  "category": "discovery",
  "display_name": "Component And Purpose Characterizer",
  "forbidden_outputs": [
    "finding",
    "verified_security_finding",
    "severity",
    "runtime_state",
    "compliance_verdict",
    "remediation_status",
    "applicability_decision"
  ],
  "must_not": [
    "decide OWASP/ASVS applicability: the 04 OWASP workbench owns that (ADR-0010, gate G6)",
    "exclude a scope without a rescope trigger that brings it back"
  ],
  "required_behavior": [
    "fill code_scope_classification so each regular file sits in exactly one physical scope",
    "fill category_coverage for all six source categories, backed by a scope or by a negative_evidence search record",
    "fill functional_components from what the code does, each with path_patterns, representative_locations, ownership, downstream_lanes and a parallel_review_group",
    "fill component_relationships, the tag_cloud, unknowns, classification_gaps and rescope_triggers",
    "optionally add candidate_security_tags as CWE leads for a downstream lane"
  ],
  "role_id": "component-characterizer",
  "schema": "appsec-review/role/0.1",
  "summary": "Turns one repository into a review-routing map for the later lanes: which files are shipped first-party code and which are vendored, generated, test, documentation or build tooling; which working components exist; and which lane should look at each. Consumed by 02-full-review-input-assembly, the OWASP and STIG worklists, and every later lane that reads component ids."
}
```
