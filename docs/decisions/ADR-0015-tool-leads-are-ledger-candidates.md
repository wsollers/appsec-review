# ADR-0015: Tool leads are ledger candidates; reviewers get the evidence menu

Status: **Proposed** (branch `claim-ledger-leads`, 2026-09-28; awaiting William)

## Context

Run `20260928T034921Z-be3585` (appsec-multi-vuln, a deliberately vulnerable corpus) produced 41
source-SAST leads (for example `strcpy` at `projects/cpp/case-001/main.cpp:7`), 119 native-SAST leads,
2 secret locations and 15 IaC rule hits. The claim ledger admitted only the threat model's STRIDE
hypotheses and OWASP candidate routes, so red team, blue team and verification (07/08/09) reviewed 60
generic hypotheses about build flows, and the report would have been empty. Reviewers could also
read only the stage's upstream JSON: none of the IR, code property graph, debug symbols, build or
SBOM evidence the run had already accepted, and nothing told them how to use the lookup tools
(`input_jq`, `evidence_*`) the invoker exposes. Retrieval audits showed heavy `input_read` paging
and almost no index use.

## Decision

1. **Every accepted tool lead is a candidate claim.** `claim-ledger-routing` has a third
   candidate source besides the threat model and OWASP routes: the accepted results of
   `02-source-sast`, `02-native-sast`, `02-secrets-inventory`, `02-sca-vulnerability-match`,
   `02-iac-config-scan` and `02-mobile-sast`, loaded through the same accepted-pointer and hash
   verification. An absent or SKIPPED producer adds no candidates and is recorded as lead coverage;
   it is never a failure.
2. **A lead is not a finding.** Tool-lead claims are `candidate_only` like every other admission.
   Only the 07 → 08 → 09 chain can move one, and only independent verification can verify it.
   Scoring and the report's findings section still read verified claims only.
3. **A manageable menu, nothing dropped.** Leads at one `(path, start_line)` merge across tools into
   one claim listing every tool and rule. A deterministic rule/category map sets a review tier:
   P1 security sinks and security checkers, P2 other reviewable rules, P3 code-quality checks
   (grouped per file). Tool-lead claims follow the threat-model and OWASP claims, ordered by tier.
   Claim text, proof obligations, ids and citations are derived without a model. Citations point
   at the producer artifact, with the lead's path, lines and `source_sha256` in the locator.
4. **Reviewers get a supporting-evidence menu.** Every 07/08/09/12 reviewer request carries
   `evidence-menu:supporting-evidence-menu.json`. It is deterministic and hash-bound, and lists the
   run's accepted non-finding evidence: component map, build index and compile databases,
   native-build units, IR capture/link/facts, code property graph, debug-symbol index,
   binary/SBOM/dependency/licence, test and document evidence, and the tool-lead source artifacts.
   Each entry has its ref, sha256, bytes, record counts and a one-line description. Unavailable
   producers appear with the reason. Every pinned file is in the request's `readable_inputs` under
   the `supporting-evidence` root (the run's `data/jobs`), so the persona may read it. Per claim
   profiles order the most relevant items first, for example IR facts, CPG and debug symbols for a
   native lead.
5. **The task prompt carries a lookup-tool guide.** `claim-review-pool-task.md` says what each
   tool is for: `input_jq` (the Python jq wrapper) over large JSON, `input_read` only for
   located lines, `input_grep` with a narrow prefix, and `evidence_search`/`evidence_read`/
   `evidence_similar`/`evidence_derived` over the index. It gives examples on menu refs. The ledger is
   a menu, not a limit: reviewers remain free to look elsewhere.
6. **Visibility.** The ledger summary counts claims by source and tier and lists lead coverage. The
   work routing marks `source_kind` and `review_priority`. The draft report counts unverified
   tool leads by tier and lists them in an appendix.

## Consequences

- Review cost grows with lead count: every ledger claim goes through 07/08/09/12 in one reviewer
  instance per stage (there is no count cap, and report assembly requires every claim to be
  decided). be3585 goes from 60 to 150 claims. Large targets will need sharding or a P3 policy.
- The threat-model jobs (`03-threat-model-dfd-stride`, `03-threat-model-reconciliation`) are
  deterministic Python with no model request, so they get no menu. Their STRIDE hypotheses become
  ledger claims whose reviewers do get it.
- The reviewer request pins up to 96 MiB of evidence (32 MiB per file). Larger files are listed
  with `pinned: false` and are not readable in that call.
- Changed code hashes: `claim-ledger-routing`, `deterministic-pool-merge` (07/08/09/12 reviewer
  pools), `10-synthesis-report` and report-input assembly.
