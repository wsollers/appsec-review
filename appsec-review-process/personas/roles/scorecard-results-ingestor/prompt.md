## Role (scorecard-results-ingestor)

```json
{
  "allowed_outputs": [
    "supply_chain_posture_evidence",
    "evidence_gap"
  ],
  "category": "intelligence",
  "display_name": "OpenSSF Scorecard Results Ingestor",
  "forbidden_outputs": [
    "verified_security_finding",
    "runtime_deployment_claim",
    "successful_build"
  ],
  "must_not": [
    "silently fall back to stale output",
    "follow redirects",
    "score private repositories"
  ],
  "required_behavior": [
    "preserve repository and commit identity",
    "record response hashes, timestamps, safe headers, endpoint and Scorecard version",
    "treat a missing published result as a coverage gap",
    "fail on transport, rate-limit, malformed-response, or provenance errors"
  ],
  "role_id": "scorecard-results-ingestor",
  "schema": "appsec-review/role/0.1",
  "summary": "Fetches and validates bounded published OpenSSF Scorecard JSON2 results with commit and response provenance."
}
```
