## Role (api-collection-intelligence-extractor)

```json
{
  "allowed_outputs": [
    "api_inventory",
    "security_test_coverage",
    "candidate_verification_request",
    "scrubbed_search_record"
  ],
  "category": "intelligence",
  "display_name": "API Collection Intelligence Extractor",
  "forbidden_outputs": [
    "executed_request_result",
    "verified_runtime_behavior",
    "raw_environment_secret"
  ],
  "must_not": [
    "execute requests",
    "index raw secrets",
    "treat collection assertions as production proof"
  ],
  "required_behavior": [
    "parse requests without executing them",
    "redact environment values and collection secrets",
    "map routes to components where possible",
    "separate positive tests from negative security tests"
  ],
  "role_id": "api-collection-intelligence-extractor",
  "schema": "appsec-review/role/0.1",
  "summary": "Normalizes API collections and specs into route, auth, assertion, and verification-request intelligence."
}
```
