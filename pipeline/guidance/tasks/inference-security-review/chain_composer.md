---
id: chain_composer
version: 2
roles: ["attack_chain_analyst"]
requests_tools: ["find", "query_call_paths", "query_cpg_slice", "query_doc_drift", "query_threat_boundaries", "read_excerpt", "resolve_evidence", "trace"]
max_tokens: 700
---
## Question
Which ordered multi-step paths (up to six steps) through the supplied component claims achieve a
higher-impact objective across units or trust boundaries in this observed environment? Compose from
seed hints first, then admitted pairs whose predicates chain?explicitly including standalone moderate
claims (such as `info_disclosure`, `ssrf`, spec-versus-handler drift, or `authn_bypass`/`authz_bypass`)
whose output state enables a downstream sink or privilege boundary crossing. Name exact
`output_entity` and `input_entity` ids from the components' `affected_entities`. Retrieve only to
settle one specific doubt about an edge; continuity is verified deterministically after you answer.

## Expected result
The `chain-composer-result` object: `candidates` with `objective`, `component_claim_ids`, `edges`
(`output_entity` and `input_entity`), `prerequisites` and `rationale`, plus named `gaps`. Do not
treat rationale as continuity proof. Identity, privilege, trust boundary, artifact/deployment and
temporal continuity remain separate obligations.
