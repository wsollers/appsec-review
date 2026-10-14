---
id: native_repository_resolution
version: 1
roles: ["native_dependency_resolver"]
requests_tools: []
max_tokens: 500
---
## Question
Given one unresolved native dependency candidate, determine whether its cited linker, loader,
pkg-config, or CMake evidence supports a plausible repository on the supplied host allowlist.

## Expected result
Return only `appsec-review/native-dependency-resolution-proposal/1` JSON. Include the exact supplied
`candidate_id`, a `repository` object with `host`, `owner`, `name`, and canonical HTTPS `url`, a
numeric `confidence` from 0 through 0.95, one or more `evidence_refs` drawn exactly from the supplied
allowlist, and a short `rationale`. If the evidence is insufficient, return a null repository with
confidence zero; never invent an exact identity.
