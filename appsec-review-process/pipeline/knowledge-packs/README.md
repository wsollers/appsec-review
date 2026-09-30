# Knowledge packs

One file per pack, `<pack_id>.json`, schema `appsec-review/knowledge-pack/0.1`
([`schemas/knowledge-pack.schema.json`](../../../schemas/knowledge-pack.schema.json);
[ADR-0034](../../../docs/decisions/ADR-0034-knowledge-packs.md)). A pack gives an attacker or
domain-specialist persona its exploit-class focus: what to look for, preconditions, proof obligations,
false-positive traps, and ATT&CK / CAPEC / CWE **ids only** (names come from the pinned MITRE table).

A persona lists at most two packs in its `knowledge_packs` key. The prompt renders each listed pack
after the persona section, under a fixed statement that a pack is focus and vocabulary, never
evidence. Every job that hashes a `persona.json` also hashes the packs it lists.

Check: `python3 -B appsec-review-process/knowledge_packs.py check` (also run by
`validate_design_parity.py`).
