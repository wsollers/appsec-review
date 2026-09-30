# Knowledge packs

One file per pack, `<pack_id>.json`, schema `appsec-review/knowledge-pack/0.1`
([`schemas/knowledge-pack.schema.json`](../../../schemas/knowledge-pack.schema.json);
[ADR-0034](../../../docs/decisions/ADR-0034-knowledge-packs.md)). A pack gives an attacker or
domain-specialist persona its exploit-class focus: what to look for, preconditions, proof obligations,
false-positive traps, and ATT&CK / CAPEC / CWE **ids only** (names come from the pinned MITRE table).

Packs are assigned per job: a job template's `knowledge_packs` map (persona id -> pack ids) gives a
persona exactly those packs (`[]` removes them); a persona the map does not name falls back to its
`persona.json` `knowledge_packs` default (normally `[]`). Resolution: `persona_registry.resolve_pack_ids`.
Either source is capped by the shared tunable `knowledge_packs_per_persona_max` (default 2), and only
attacker and domain-specialist personas may have packs. The prompt renders each resolved pack after the
persona section, under a fixed statement that a pack is focus and vocabulary, never evidence. Every job
that hashes a `persona.json` also hashes the packs it resolves for that persona.

Current assignments (`job-templates/claim-review-pool-cell.json`): `cloud-initial-access-operator` ->
`cloud-exposure`; `opportunistic-public-web-attacker`, `api-contract-abuser` -> `injection`;
`supply-chain-attacker`, `insider-developer` -> `supply-chain`.

Check: `python3 -B appsec-review-process/knowledge_packs.py check` (also run by
`validate_design_parity.py`).
