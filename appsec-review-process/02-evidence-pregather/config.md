# Config — Evidence Pregather

## Required Inputs

- target repo path
- output directory
- compile database for native targets, if available
- `CODEQL_LICENSE_BASIS`

## Early Discovery Job

Use `02-repository-partition-discovery` to identify coarse client, server, API, IaC, CI/CD,
deployment, and operations areas and route them to developer, DevOps, or SRE review.
The job prompt is `repository-partition-discovery.md`; its registry template specifies the
composition and output contract. Run it before specialist discovery when partitioned scope is
needed. Its map is an optional downstream input until automatic job dispatch is implemented.

## Required Outputs

- `job-status.md`
- `job-manifest.jsonl`
- `llm/ENGAGEMENT_LLM_INPUT.md`
- `llm/coverage-ledger.json`
- `llm/correlated-findings.json`
- `llm/deep-confirmation.json`
- `llm/retrieval-plan.json`
