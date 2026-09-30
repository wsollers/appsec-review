# Brief V: lead-context job, materialised and indexed code flows for P1 leads (branch `lead-context`) - CLOUD agent
William, 2026-09-29: a pre-answer job that looks at the highest-priority findings from SAST and CodeQL and materialises
each one's code flow and surrounding context, indexed, so hunters and reviewers do not rediscover it call by call.
Depends on brief U (the code index and query tools). If brief U is not on `main`, stop and report. Governing rules:
ADR-0013, ADR-0015 (leads are candidates), evidence first, gaps never read as clean, tool output is untrusted data, and
INDEPENDENCE: the bundle states where things are, never a conclusion; red team, blue team and independent verification
all receive the same bundle and must still form their own judgement.

Read first: `docs/agent-briefs/00-common.md`, `U-structural-query-tools.md` and the code index it produces
(`02-code-index`), `claim_ledger.py` (`LEAD_PRODUCERS`, `normalize_leads`, `lead_tier` P1/P2/P3, `lead_candidates`),
`codeql_sast.py` and its per-language producers (`schemas/codeql-language.schema.json`), `source_sast.py`,
`native_sast` producer, `reachability.py` (`CallGraph`, `analyze`, escapes), `entry_exports.py`,
`code_snippets.py` and `evidence_redaction.py` (hash-verified, redacted snippets), `supporting_evidence_menu.py`,
`hypothesis_discovery.py` and `claim_reviewer_pool.py` (where workspaces and menus are built), `docs/decisions/DECISION-LOG-2026-09-29.md`
(D-02 item 6: SARIF message text is withheld from model-facing text).

## V0. Finding: today a lead is a single location (verify first)
`claim_ledger.normalize_leads` keeps `path`, `start_line`, `end_line`, rule id, category, tier for each lead. No CodeQL
`codeFlows` or Semgrep taint traces survive into the lead shape, and no producer job publishes flow steps. So step 1 is to
keep the flow the tools already computed:
- Extend the CodeQL per-language producers (and native SAST / Semgrep taint mode where the tool emits traces) to publish, per
  lead, an optional `flow` array: ordered steps of `{path, start_line, end_line, kind (source|propagation|sink), function
  when the tool gives it}`, count-capped and truncation recorded. Locations and structure only. Do NOT carry SARIF message
  or step-message prose into any field a model reads (D-02). Optional key: older results stay valid; regenerate schemas and
  catalogs, never hand-edit generated files.
- Leads with no tool flow get a `flow_source: none`, and V2 computes one.

## V1. Which leads (deterministic selection)
Selection by claim-ledger tier, not tool severity (tool severities are not comparable): all P1 leads, then the highest
ranked P2 up to a per-run cap, per-language and per-component caps so one noisy rule cannot consume the budget. Reuse
`lead_tier` and the ledger ordering; do not invent a second ranking. Everything cut is listed as a gap with the count.
Tunables in `pipeline/tunables.json`: `lead_context_p1_max`, `lead_context_p2_max`, `lead_context_hops`,
`lead_context_flow_steps_max`, `lead_context_snippet_lines`. A lead cited later by a claim but not selected can be built on
demand through the V4 tool.

## V2. The bundle (one record per selected lead, deterministic, no model)
New job `07-lead-context` (deterministic_python; register in `job-graph.json`; after the SAST/CodeQL/CPG/code-index jobs,
before `07-hypothesis-discovery` and the claim reviewers; contract, schema, lineage and receipts like sibling jobs; records-
file pattern for size). Per lead, all from accepted artifacts, every item carrying `source` (producer job, attempt, sha256):
1. **Flow:** tool-reported steps if present (`flow_source: tool`), else a computed path (`flow_source: computed`) from the
   nearest program or exported entry to the lead's enclosing function using `reachability.CallGraph` (bounded; every escape
   listed; `complete=false` with reasons when an escape could hide a path). Never present a computed path as tool-reported.
2. **Step context:** for each flow step and for the sink: enclosing function (name, signature, span), a hash-verified
   redacted snippet (bounded lines), and the argument text at the sink call when the CPG has it.
3. **Neighbourhood:** callers and callees of the enclosing function to `lead_context_hops` with resolution values and
   unresolved-call escapes; overrides and address-taken status when relevant (native).
4. **Locators for known facts:** the reachability state and witness if `06-reachability-*` produced one, the component and
   partition, the data classes of the component from the threat model, related leads in the same function and component,
   and tests that touch the file or function (from test coverage records when present).
5. **Labels:** `authority: derived_evidence`, `tool_derived: true`, `not_a_finding: true`, and the tool's own confidence only
   as a category, not prose.
Index the bundle: add its records to the code index (or publish alongside it) and to `evidence_index_enrichment.PROFILES`
so `evidence_derived` finds a lead's context by rule, path, function or component; add the job to the supporting-evidence
menu.

## V3. Consumers (small, careful prompt changes; other personas' bytes stay identical)
- Hunter, claim-review pools (07/08/09/12), attack-chain composition and refutation, and the poc-fix author receive the bundle
  for the leads they are shown, as read-only context in their workspace (not inside instructions). Update only those
  personas' task text, plus the U4 tool guide for `lead_context`, with: this is location and structure derived by tools; it is
  not a verdict; verify it against the source; a missing or `complete=false` field is a gap to state, not a reason to conclude.
- The verifier (`09`) must not be able to see red or blue team conclusions from the bundle; it receives the same neutral bundle
  they did.

## V4. `lead_context` tool (through the U1 tool family)
Tool `lead_context(lead_ref)`: returns the stored bundle; for a lead not selected in V1 it builds the bundle on demand from the
same accepted artifacts with the same caps (deterministic and audited like every other query tool; recorded in the retrieval
ledger). Unknown ref -> gap row.

## V5. Tests (per 00-common.md as currently in force)
Fixtures: a CodeQL lead with a tool flow (steps preserved, message prose absent), a Semgrep lead with no flow (computed path,
labelled computed), a lead with an escape on the path (`complete=false`), selection caps and the recorded cut, a lead in a
component with no CPG (gap), redaction of a secret in a snippet, and a test that no SARIF message text appears in any
model-facing field. A test that the bundle carries no field named or valued like a verdict.

## Rules
- Deterministic code plus small prompt additions; no new model call. Every new key in schemas and closed vocabularies.
- Follow the current `00-common.md` on fingerprints and tests. List fingerprints that move by job id.
- ADR-0033 (proposed): lead context is a neutral, tool-derived bundle; independence of red/blue/verifier preserved.
- Final message: per the format in 00-common.md, plus per-tier counts on the fixture, bundle size and build time, and one
  worked example bundle for a native memory-safety lead.
