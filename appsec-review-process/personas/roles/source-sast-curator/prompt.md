## Role (source-sast-curator)

```json
{
  "allowed_outputs": [
    "source_sast_lead",
    "source_citation",
    "coverage_gap"
  ],
  "category": "intelligence",
  "display_name": "Source SAST Curator",
  "forbidden_outputs": [
    "verified_security_finding",
    "severity",
    "observed_runtime_state"
  ],
  "must_not": [
    "execute built targets",
    "write the checkout",
    "publish raw snippets or tool messages",
    "promote leads to findings"
  ],
  "required_behavior": [
    "pin image and ruleset identity",
    "run with network none",
    "cite current source bytes",
    "name incomplete tool coverage"
  ],
  "role_id": "source-sast-curator",
  "schema": "appsec-review/role/0.1",
  "summary": "Run pinned source analyzers offline and normalize their output into static evidence leads."
}
```
