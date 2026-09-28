# ADR-0018: Code-reading hypothesis discovery feeds the claim ledger

Status: **Proposed** (branch `ws-hunt`, 2026-09-28; awaiting William)

## Context

After ADR-0015 the claim ledger has three candidate sources: deterministic STRIDE items
(`threat_model_core`), OWASP candidate routes, and static-tool leads. Nothing in the pipeline reads
target code to propose a vulnerability. A bug no scanner rule names (for example `eval(argv[2])` in
`projects/javascript/case-010/index.js` of appsec-multi-vuln, which no tool flagged in run be3585)
never becomes a claim, so 07/08/09 never review it and the report cannot mention it. The red-team
prompts `general-red-team.md` and `known-list-red-team.md` existed but no job loaded them.

## Decision

1. **New job `07-hypothesis-discovery`** (lane `07-red-team-adversarial`, which owns the red-team
   prompts and the claim ledger; the `07-` prefix follows the graph's lane-number convention and
   sorts it before `claim-ledger-routing` and `07-red-team-adversarial` in the same lane). It depends
   on `01-component-characterization`, `02-evidence-assembly`, `02-source-sast` and `02-native-sast`.
   `claim-ledger-routing` depends on it (required: with no readable source the hunter publishes
   OK_WITH_GAPS with zero instances and zero hypotheses, never SKIPPED).
2. **A persona pool** built with `pool_specification` / `pool_rendezvous` / `deterministic_pool_merge`.
   Python shards the checkout by component from the accepted component map. It packs the shards into
   `shard_groups` groups (default 3), components with the most P1/P2 tool leads first, and sorts each
   group's files so files with leads are pinned first, up to `target_pin_bytes_max`. Files over the
   budget and binary files are listed as unpinned; hunters reach them through `evidence_search` /
   `evidence_read`. Each group gets one hunter, alternating general and known-list; with
   `modes_per_group: 2` each group gets both. The two hunter cells are:
   - `hypothesis-hunt-general`: persona `general-red-team-hunter`, task
     `task-hypothesis-hunt-general.md` (formerly `general-red-team.md`);
   - `hypothesis-hunt-known-list`: persona `known-list-red-team-hunter`, task
     `task-hypothesis-hunt-known-list.md` (formerly `known-list-red-team.md`), plus
     `known-issue-catalog.md` pinned under root `hunt-guides`.
   Both cells use role `vulnerability-hypothesis-hunter`, domain `vulnerability-hypothesis-discovery`
   and tooling profile `hypothesis-hunt-static`. The registry has no language or domain specialist
   hunter personas yet, so none are dispatched.
3. **What a hunter can read.** Readable input 0 is a hash-pinned brief: shard, components, pinned
   and unpinned files, the P1/P2 lead menu with totals, and limits. After it come the shard's target
   files (root `target-repository`), the supporting-evidence menu and the files it pins, and the
   lookup tools (`input_read`, `input_grep`, `input_jq`, `evidence_*`). The prompt and a trusted
   runtime block both state that the tool leads are a menu, not a limit.
4. **The persona writes judgment; Python keeps the books.** The reply schema
   (`hypothesis-hunt-persona.schema.json`) has path, line range, class, optional CWE, mechanism,
   attacker preconditions, the evidence read, and confidence.
   `hypothesis_hunt_derive` handles the rest:
   - normalizes the shapes models actually send (aliases, `lines: "5-7"`, CWE strings, echoed ids,
     hashes and severity, which are ignored);
   - takes the hunter identity from the brief;
   - resolves each location against the pinned bytes, and never invents one. An absolute path is
     suffix-mapped onto exactly one pinned path. A path containing `..` or `.git`, a line past the
     end of the file, or a range wider than `max_line_span` becomes a `dropped` record with its
     reason. A path that exists but is not pinned is `deferred`;
   - classifies each evidence ref;
   - derives `subject_id` from the location identity and `candidate_id` from the canonical record;
   - applies the per-instance limit.
   A malformed reply goes through the invoker's bounded repair loop. The reply's wording is not
   parsed for grammar (ADR-0013).
5. **After the pool** (`build_result`, pure):
   - re-reads every path from the checkout, refusing symlinks and `.git`; checks the file hash and
     line range; resolves deferred records;
   - turns anything unresolvable into a gap (`not-in-checkout`, `file-changed`,
     `line-out-of-range`, `dropped-by-derive`, `worker-missing`, `merge-conflict`);
   - deduplicates across hunters by `(path, start_line, CWE or class)`, keeping the union of
     hunters, preconditions and evidence and the highest confidence;
   - records overlap with tool leads, tiers each hypothesis (P1 for medium or high confidence, P2
     for low), orders the list, and publishes `hypothesis-discovery.json`.
6. **The ledger's fourth source** (`claim_ledger.hunter_source` / `hunter_candidates`). The ledger
   loads the result through the accepted-pointer and hash verification. If the result is stale
   for the threat model's source or component generation, the ledger is Blocked. An absent or
   SKIPPED result becomes a coverage row.
   - When a hypothesis's range covers a P1/P2 tool-lead location, the hypothesis is attached to
     that lead claim as corroboration. The claim gains the hunter citation and the
     "Corroborated by N code-reading hypothesis(es)" text, and its confidence rises to at least
     medium. No duplicate claim is admitted.
   - Every other hypothesis is a `hunter:<tier>:` claim. It is `candidate_only`, has three proof
     obligations and one citation that carries path, lines and file sha256, and is ordered with the
     tool leads by tier. Routing reports `source_kind: hunter`.
   - The draft report lists hunter claims next to the tool leads (`source` column).
   - If model words would trip the ledger's promotion guard, they stay out of the ledger text and
     remain in the hunter artifact.
7. **Budgets.** Tunables live in `registry/job-templates/07-hypothesis-discovery.json`. Each instance
   is one `claude -p` call capped at `budget_max_usd_per_call` for the cell's budget tier (standard,
   2.0 USD today; the cap includes repair). The default pool is 3 instances, so a run spends at most
   about 6 USD. `modes_per_group: 2` doubles that. The persona result cache avoids paying again on a
   relaunch.

## Consequences

- The ledger can hold hypotheses no tool emitted. Like every claim, they are candidates until
  07/08/09.
- Code hashes change for `07-hypothesis-discovery` (new), `claim-ledger-routing` (`claim_ledger.py`
  and the hunter schema) and `10-synthesis-report` (`synthesis_report.py`). Because the menu module
  changed, the reviewer pools of 07, 08, 09 and 12 (`deterministic-pool-merge` per stage) also get
  new hashes.
- The Python side was replayed read-only on be3585 with canned replies. strcpy at
  `case-001/main.cpp:7` corroborates the merged source- and native-SAST P1 lead claim. The PHP
  include at `case-018/index.php:2-3` corroborates the P2 lead at line 3. The unflagged `eval` at
  `case-010/index.js:2` becomes the only hunter claim. A hallucinated file is a gap. The ledger
  validates with 151 claims.
- Open: when a hypothesis names a different weakness class at the same line as a tool lead, it
  still attaches to the lead as corroboration (its class goes into the text). Specialist hunter
  personas and lead-cluster-only shards remain future work.
