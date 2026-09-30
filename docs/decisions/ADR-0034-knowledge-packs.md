# ADR-0034: Knowledge packs focus attacker personas; a MITRE lookup tool supplies the detail

Status: **Accepted** (2026-09-30, William). Builds on ADR-0024 (per-stage review roles), ADR-0026 (MITRE
ATT&CK / CAPEC reference feed) and ADR-0032 (structural query tools). Closes the "prompt-side technique
menu" follow-up left open by ADR-0026 §5.

## Context

Attacker personas are defined by a point of view (public web attacker, malicious tenant, insider,
supply chain) and a `looks_for` list. They carry no attack-class knowledge: nothing tells
`cloud-initial-access-operator` which techniques, CAPEC patterns or CWE classes its area covers, or what
evidence would prove one. ADR-0026 gave the pipeline a pinned, validated ATT&CK / CAPEC / CWE table,
but left the prompt side open: "give lane 14's composer and lane 07 vendor/insider mode a
tactic-filtered technique menu or an `attack_reference` lookup tool, never the whole matrix in a
prompt" (`appsec-review-process/TODO.md`, section O).

Three places could hold that knowledge:

- **Roles** (`personas/roles/`) are contracts: allowed and forbidden outputs, required behaviour. Two
  workers with the same role can need entirely different attack knowledge, so it does not belong there.
- **Persona records** are points of view. Copying attack knowledge into each one duplicates it (SSRF
  belongs to `api-contract-abuser`, `cloud-initial-access-operator` and `opportunistic-public-web-attacker`)
  and couples "who is attacking" to "which exploit class".
- **A separate record** that personas reference keeps the two apart: persona = vantage point, pack =
  exploit-class focus. The same persona with a different pack is a differently focused red-team worker
  without a new persona.

Hand-written technique ids in prompt prose would go stale on a re-pin and bypass the validator
(`standards-mapping-auditor`: "null is better than a guessed mapping").

## Decision

1. **A knowledge pack is a new registry record kind.** `appsec-review-process/pipeline/knowledge-packs/<pack_id>.json`,
   schema `appsec-review/knowledge-pack/0.1` (`knowledge-pack.schema.json`, next to the other registry
   schemas). Every key present, in this order:

   | key | content |
   |---|---|
   | `schema` | `appsec-review/knowledge-pack/0.1` |
   | `pack_id` | `^[a-z0-9][a-z0-9-]*$`, equals the file name |
   | `display_name` | short name |
   | `summary` | one sentence: the exploit class this pack focuses on |
   | `applies_to` | target traits the pack is relevant to (`terraform`, `kubernetes`, `http-api`, `native`, `ci-cd` ...); informational until item 7 |
   | `looks_for` | ≤ 12 short strings: sinks, misconfigurations, code patterns |
   | `preconditions` | ≤ 8: what an attacker needs for the class to be exploitable |
   | `proof_obligations` | ≤ 8: the evidence that would establish a claim in this class |
   | `false_positive_traps` | ≤ 8: common reasons a lead in this class is not real |
   | `refs` | `{attack_tactics, attack_techniques, capec, cwe}`: arrays of ids, ≤ 15 each, `attack_tactics` as ATT&CK tactic shortnames |
   | `must_not` | pack-specific prohibitions (may be empty) |

   The text is hand-written and reviewed. `refs` holds **ids only**; names, descriptions and tactics come
   from the pinned table (ADR-0026 §4).

2. **Personas reference packs; roles do not.** `persona.json` gains a `knowledge_packs` key (array of
   pack ids, at most 2, placed immediately before `provenance`). Every persona carries the key; only
   `attacker` and `domain-specialist` personas may list packs. Verifiers, defenders, scorers and report
   personas keep `[]` so they judge evidence, not whether it matches a pack. The persona catalog gains a
   `Knowledge packs:` label that `catalog_personas.py` carries into generated records.

3. **Packs render into the prompt as registry records.** When the persona in a composition lists packs,
   the prompt gets a `knowledge_packs` section after the persona section: each pack rendered as the same
   labelled, fenced canonical JSON the other record sections use (`persona_prompt_assembly`), never
   paraphrased. The section is a pure function of the registry, so the per-template prompt cache stays
   valid. A persona folder's `prompt.md` includes it. Every place that hashes a `persona.json` into a
   job's input identity also hashes the packs that persona lists, so editing a pack re-executes the stages
   that use it.

4. **A pack frames the search; it is not a checklist or evidence.** The rendered section is headed with a
   fixed statement: the pack is focus and vocabulary; a claim still needs cited evidence from the target;
   a pack id is never evidence; a pack's class not being observed is recorded as not observed (a coverage
   gap), never as "no issues found". ATT&CK / CAPEC / CWE ids a worker takes from a pack still go through
   `attack_reference.screen()` and the CWE checks unchanged.

5. **A read-only MITRE lookup tool supplies the detail.** `mitre_technique`, `mitre_capec` and `mitre_cwe`
   tools, served over the resolved MITRE snapshot (`mitre_feed.resolve()`, `attack_reference`,
   `cwe_catalog`), following the ADR-0032 pattern: granted only when a tooling profile lists
   `query tool: <name>` and its tunable family (`mitre_query_*_enabled`, default on) is on;
   `--allowedTools` and the prompt's Tool Guides come from one granted list. Each answer states the
   snapshot identity or the gap (`MITRE_REFERENCE_MISSING` / `_STALE` / `_INVALID`); a missing snapshot is
   an answer with a gap, never an error and never a guessed name. Answers are untrusted data. Granted to
   `claim-review-static` (lane 07 cells and lane 14 composer) and `hypothesis-hunt-static`.

6. **Validation.** `knowledge_packs.py check` validates every pack against its schema, id formats
   (`attack_reference.TECHNIQUE_ID` / `CAPEC_ID` / `CWE_ID`, tactic shortnames from
   `CHAIN_STAGE_TACTICS` or the resolved table), caps, that every persona's `knowledge_packs` names an
   existing pack, the category rule in item 2, and — when a MITRE snapshot resolves — that every id is
   `OK` in it. With no snapshot it checks format only and says so. It runs in the tests and from
   `validate_design_parity.py`.

7. **Deferred: target-driven selection.** Intake adding packs from detected target traits (`applies_to`)
   needs a run-specific prompt and so a change to the prompt cache key. Phase 1 uses persona defaults
   only; phase 2 is tracked in the TODO.

Initial packs and assignments (lane 07 attacker personas in `claim-review-pool-cell.stage_personas`):

| pack | personas |
|---|---|
| `cloud-exposure` | `cloud-initial-access-operator` |
| `injection` | `opportunistic-public-web-attacker`, `api-contract-abuser` |
| `supply-chain` | `supply-chain-attacker`, `insider-developer` |

Other attacker personas keep `[]` until a pack for their class is written.

## Consequences

- Attacker workers start with their exploit class in the prompt and look up details on demand; prompts
  grow by at most two small records, never by the ATT&CK matrix.
- Pack edits are reviewed like persona edits and re-execute the stages whose personas use them.
- On a host without a MITRE snapshot the lookup tool returns gaps; pack ids stay usable as vocabulary but
  every tag is still withheld by `screen()` (ADR-0026 §2).
- Adding a pack for a new class (authn/session, deserialization, memory safety, IAM escalation, LLM tool
  abuse) is a new JSON file plus a persona catalog line.

## Addendum (2026-09-30, William): packs per job, MITRE version recorded for reporting

1. **Packs are assigned in the job config.** A job template may carry `knowledge_packs`: a map of
   persona id -> pack ids. Red-team pools hold several personas, so the pool's job template is where they
   are focused (for `claim-review-pool-cell`, next to `stage_personas`). A persona named in the map gets
   exactly those packs (`[]` removes them); a persona not named falls back to its `persona.json`
   `knowledge_packs` default. The item 2 category rule applies to both sources. The W3 assignments move
   from the five `persona.json` files into `claim-review-pool-cell.json`; the persona defaults return
   to `[]`. The job template is already part of each job's input identity, and the prompt stays a pure
   function of the registry (template + variant), so the prompt cache key does not change.
2. **The cap is a tunable.** `knowledge_packs_per_persona_max` (default 2) replaces the fixed limit in
   item 2; the schema no longer hard-codes `maxItems`, and `knowledge_packs.py check` enforces the tunable
   on both sources.
3. **The MITRE snapshot is recorded, not bound.** It stays out of job inputs: jobs use the current
   snapshot. Every job granted MITRE lookup tools records a structured `mitre_reference` entry
   (snapshot id, derived-table hash, ATT&CK / CAPEC / CWE versions, or the gap code) in its job record,
   and the report shows which versions the run used. Binding it into job inputs is a TODO.
