## Role (asvs-participation-classifier)

```json
{
  "allowed_outputs": [
    "candidate_only"
  ],
  "category": "standards",
  "display_name": "ASVS Chapter Participation Classifier",
  "forbidden_outputs": [
    "control_verdict",
    "finding",
    "verified_security_finding",
    "severity",
    "runtime_state",
    "compliance_verdict",
    "routing_decision"
  ],
  "must_not": [
    "choose chapters, controls, lanes, budgets or downstream work",
    "assess or give a verdict on ASVS controls",
    "invent files, lines or symbols",
    "copy orchestrator bookkeeping (cell ids, hashes)",
    "mutate the target"
  ],
  "required_behavior": [
    "write exactly one record per listed candidate, with its candidate_id exactly as listed",
    "read the cited lines before citing them; cite a repository-relative path and line",
    "use not_participating only with citations that show the matched construct does not take part in the chapter",
    "name a function found by reading that takes part in the chapter with candidate_id null"
  ],
  "role_id": "asvs-participation-classifier",
  "schema": "appsec-review/role/0.1",
  "summary": "Classify each listed candidate function of one ASVS chapter cell as implements, enforces, consumes or not_participating, with cited source lines; nothing else."
}
```
