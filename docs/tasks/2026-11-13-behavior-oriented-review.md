---
title: "Behavior-oriented review and subject-complete OWASP evidence"
kind: "task"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_inference_security_review", "job_owasp_control_assessment", "job_security_tagging"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Behavior-oriented review

T-146 implements the user's 2026-11-13 direction to improve finding quality through a
component/concept map, relevant evidence selection and a coherent bounded review process.
The user explicitly requests unit, integration and acceptance tests, and explicitly forbids
running integration and acceptance tests during this implementation.

## Outcome and boundaries

The product is an independently supported, developer-actionable finding, not a tag count,
control-matrix completion rate or number of agreeing models. OWASP controls supply review
questions and reporting classifications. They do not prove vulnerabilities or component safety.

This change reuses accepted source, syntax, code-graph and generated threat-model data. It does
not add a scanner, launch a container, change target checkouts, commission runtime evidence,
reload the deployment or grant workers new authority. Existing frozen runs are not rewritten.
No new control family is declared supported merely because a question can be generated for it.

## Numbered implementation decisions

1. **One evidence authority.** Original accepted source/producer records remain evidence.
   Generated diagrams, operation maps, security tags and control assessments remain routing
   context. Consumers retain exact source and publication identities and independently
   re-resolve final claims. A missing optional producer is a named gap; corrupt supplied
   evidence is an integrity failure.
2. **Subject-complete OWASP selection.** Select bounded, complete named source subjects instead
   of a prefix of each source file. Accepted syntax/graph locations prioritize discovery;
   bounded parsing of accepted Python source is the fallback for the four existing reviewed
   Python procedures. Complete function/module subjects preserve decorators, absolute lines
   and content identity. No substring/keyword match establishes control satisfaction.
3. **Finite discovery.** New typed optional settings bound candidate files and total source
   bytes per component. Discovery defaults are 512 files and 8 MiB per component. Existing
   `max_source_lines`, `max_evidence_per_component` and `max_subjects_per_control` still bound
   delivered work. Every cap, oversized subject, parse failure, unknown language, redaction
   and unresolved ownership is accounted. Smaller complete subjects may be assessed without
   claiming coverage of the omitted file or component.
4. **Separate omission from damaged evidence.** A complete, independently re-resolved subject
   may support a scoped assessment even when other subjects were omitted. A clipped subject,
   missing prerequisite, redacted security-relevant content or ambiguous ownership cannot.
   Scope is established by the application, not by a model asserting that an excerpt is complete.
5. **Behavioral tags.** Extend the existing tagging job with a bounded reader of accepted
   `graph-fact/1` entry and sink facts. Emit only vocabulary-backed capabilities supported by
   those facts, with exact source/site evidence. `invoked` means the operation is observed,
   never that a weakness exists. An unresolved/disagreeing fact cannot become a stronger tag.
   Remote input alone does not establish a public HTTP route or deployed exposure.
6. **Single vocabulary.** Correct component-role routing to the canonical `func:authn:*`,
   `func:crypto:*` and other existing capability families. Retain declared, invoked, reported
   and derived bases. Do not promote speculative CWE/CAPEC/ATT&CK crosswalk outputs.
7. **Operation-oriented review units.** Prefer accepted operation/function anchors and
   evidenced boundary context over arbitrary path batches. Keep deterministic bounded path
   batches for files without operation evidence, explicitly marked as fallback. Preserve
   every source file and lead in the scope accounting, including units below the hunt cutoff.
   Unsupported or absent operation evidence must not remove fallback coverage.
8. **Use the generated map, do not duplicate it.** Read the optional generated DFD/threat-model
   publication through typed admitted inputs. Validate its origin, snapshot, hashes and source
   reference membership. Attach bounded map context to matching review units/packages;
   generated boundary and threat identities never become direct evidence. Original source
   citations remain the route to verification.
9. **Rank opportunities, not labels.** Replace raw tag density with deduplicated evidenced
   security-operation opportunities. Language, gap, catalog and derived tags contribute no
   opportunity points. Multiple tags or producers describing the same site do not multiply
   the score. Retain independent prioritization/history/advisory signals and named unknowns.
   Version the ranking/assembly identities so prior package/cell results cannot be reused
   under changed semantics.
10. **Proof obligations remain authoritative.** Preserve deterministic adjudication and
    independent verification. Family-specific questions describe actor/resource/policy for
    authorization, input/interpreter/control for injection, size/lifetime/ownership for memory,
    interleaving for races, and attacker work/resource bounds for exhaustion. A question
    without a commissioned evidence path remains unresolved, never automatically confirmed.
11. **Do not remove reviewers without efficacy evidence.** The previous assessment recommended
    evaluating smaller panels and disagreement-only judging, not claiming they are better.
    Keep current role counts and judge/PoC dependencies in this implementation. The design
    records a controlled comparison rather than silently reducing coverage or PoC eligibility.
12. **Actionability is observed, not inferred from absence.** Derive path availability from
    counted reachability evidence, not from a missing-predicate list lacking the word
    reachability. Populate remediation presence/validation from exact certified attachments.
    Unknown owner, attacker position and runtime validation stay unknown unless supported.
13. **One developer projection.** Reuse protected dossiers for source locations, mechanism,
    preconditions, counterevidence, remediation and regression guidance. Public reports retain
    sanitized references. Do not create a second finding state, report authority or ticket store.
14. **No automatic live validation.** Unit tests exercise actual parsers, mappings, selection,
    validators, fingerprints, handler wiring and metric projections with canned boundaries.
    Integration tests cover real local index/publication joins; acceptance checks consume an
    explicitly supplied run and verify the outcome contract. Neither tier runs in this change.

## Data flow and the review job

```mermaid
flowchart TD
  S[Accepted source and syntax] --> O[Complete source subjects]
  G[Accepted graph entry and sink facts] --> T[Observed behavioral tags]
  G --> U[Operation-oriented review units]
  T --> U
  D[Accepted generated DFD and threat model] -->|routing context only| U
  O --> W[Supported OWASP control questions]
  W -->|provisional leads and counterevidence| P[Bounded review packages]
  U --> P
  P --> H[Hypothesis and counterexample investigation]
  H --> V[Independent verification against original evidence]
  V --> A[Existing deterministic adjudication]
  A --> R[Protected developer dossier and certified report]
  R --> Q[Independent quality and actionability measurements]
```

Each operation map identifies the component/build scope, original source anchors, operation
kind, entry/input class when established, candidate boundary, applicable questions, and
unknowns. A package never states deployment exposure, ownership policy or asset sensitivity
that its sources did not establish.

The lifecycle is: establish scope and readiness; discover supported operations; construct a
bounded question; collect original evidence and seek counterevidence; request specific missing
evidence within the existing capability; verify independently; adjudicate; publish a useful
developer brief. An unanswered evidence request is a gap, not agreement.

The existing job contract, task receipts, execution limits, canonical gaps and publication gates
remain the execution protocol. Commissioning uses the walk charter's input, independent
comparison, gap-cause and baseline checks. This design does not change the walk's user-owned
stop/acceptance rules or authorize a routine unattended review.

## Implementation ownership and sequence

| Slice | Owned surfaces | Dependency |
| --- | --- | --- |
| A: subject evidence | `config/owasp.py`, `owasp_workbench/evidence.py`, `assessment.py`, `obligations.py`, focused new OWASP tests | this design |
| B: observed capabilities | security-tagging producers/job/taxonomy and pinned capability rules, component-role routing, focused new tagging tests | this design |
| C: operation planning | review units/ranking/packages/views, optional generated-map consumer and typed contracts, associated schemas and focused tests | A/B public contracts where used |
| D: quality feedback and integration | finding run adapter, central TOML/pins, registry entry, this document, cross-surface regressions | A/B/C |

The coordinator owns shared configuration and schemas. Agents do not independently change
central TOML, common test maps, registry entries or another slice's files. Isolated Linux
worktrees prevent edits to mounted main sources. Ready commits are handed to the designated
main owner for serialized integration; no push is authorized.

## Verification matrix

| Tier | Required behavior |
| --- | --- |
| Unit: OWASP | Sites after line 120; complete functions in large files; decorators/nesting; multiple controls/sites; deterministic caps; no recognized subject; unsupported language; malformed/truncated/redacted input; original reference re-resolution; unrelated/forged reference rejection; scoped omission never component-wide satisfaction |
| Unit: tags | Each supported graph mapping; unchanged declared package facts; exact evidence/basis; unresolved/disagreeing/unknown graph facts; component ambiguity; duplicate sites; missing graph and bounded reads; handler wiring |
| Unit: planning | Stable operation identity; different operations separated; bounded fallback; no lost files/leads; source ids below cutoff; zero score for gap/language/derived tags; no score multiplication; missing/tampered/generated foreign context; schema and fingerprint invalidation |
| Unit: quality | Counted path versus irrelevant/absent predicate; exact finding-to-attachment binding; unknown versus false; compile-only never runtime-validated; absent optional capabilities; unchanged finding state |
| Integration, authored only | Accepted source/graph/tag/OWASP/package joins through real local indices and publication custody; scoped evidence survives projection; stale/foreign/tampered inputs fail; no fabricated confirmed finding |
| Acceptance, authored only | Operator-supplied run exhibits operation coverage, complete subject accounting, original citations, exact output partitions, protected actionability and explicit gaps; execution success is not a correctness label |

All new unit tests belong under `tests/unit/`, remain independent and under ten seconds, and
do not use containers, external tools, models, network or Dagster. Test the actual logic; fake
only external interfaces. Coverage targets every added decision/failure branch rather than
inflating counts with import or constant checks. Full-repository unit coverage is not claimed
by a focused change.

Integration and acceptance tests are excluded from implicit unit collection and carry explicit
time budgets and named prerequisites. They are **NOT RUN** under this authorization. Independent
real-target finding precision/recall, developer acceptance and model-panel comparisons remain
manual efficacy work tracked by T-146 and the existing finding-metrics registry items.

## Implementation and verification record

Implemented on isolated Linux worktrees, starting at
`750278483e86dd44a1be88a5039b7f58f194d59b` and incorporating the coordinated unit-tier baseline
`04e99d02c845abfd48763394621cf7a37559c9c2`. The documentation-only design landed separately as
`5926171238607e27a948bc7d40ce190a853b3d0c`. No deployment reload, review, container execution or
push is part of this work.

| Delivered surface | Exact behavior |
| --- | --- |
| OWASP subjects | Supported Python sources precede unsupported files, then accepted index locations prioritize bounded discovery; unrelated indexed native files cannot consume the supported-subject quota first. Complete AST subjects retain absolute lines, source hashes and omitted outside scope. Complete short HTTP modules retain their policy context; function-only authorization from an oversized module stays unresolved. |
| Evidence projection | Configured evidence up to 200 records reaches the worker; proof obligations use exactly the projected records, never an omitted record after the old hard-coded 100-record cut. |
| Invoked capabilities | Fourteen pinned graph mapping rules; canonical native language aliases; neutral `surface:entry:remote-input` rather than inferred public HTTP exposure. Original graph producers, byte spans and generated-source custody remain available. |
| Operation planning | Exact graph sites form bounded operation units; whole-file fallback remains for unmodeled scope. Each located lead is assigned at most once to an operation or fallback. Source identities remain recorded below the hunt cutoff. |
| Ranking | `review-unit-rank/3` counts distinct invoked operation sites. Language, gap, reported and derived labels do not add site points. The existing `tag_density` setting names are retained for frozen-configuration compatibility; they no longer count tags or multiply by file count. |
| Generated map | Optional typed DFD/model/evidence/result inputs join by original graph identity, not prose. Context remains routing-only. Package-manifest verification and final-gate bindings reverify the exact generated artifacts. |
| Worker view | `package-view/5` includes bounded operation questions, original source windows and generated boundary context; windows are explicitly not complete control proof. Generated identities acquire no evidence labels or retrieval grants. |
| Compatibility | Fresh packages use `assemble-review-packages/13`. Readers still accept the preceding `/12`, rank `/2` and view `/4` publications; old bytes are not rewritten or reused as the new semantic output. |
| Quality feedback | Counted complete reachability, rather than absence from a missing-predicate list, determines path availability. Certified exact-finding remediation attachments determine plan availability. Compile/static checks never count as a runtime-validated fix. Operation-only review is not whole-file coverage. |

Two implementation agents delivered `669a9244` plus alias correction `2086646a`, and `47b3954e`
plus complete-HTTP-module correction `4501c805`. The coordinator integrated those exact changes,
implemented operation planning and quality wiring, and repaired the evidence-projection mismatch.
No new proof family, runtime adapter, role-count reduction or judge-policy change is claimed.
The existing T-001, T-073, T-076, T-086 and T-107 entries retain their broader/manual scope.

### Focused unit execution

The final changed-area command was:

```sh
COVERAGE_FILE=test/tmp/t146-final.coverage scripts/run-tests.sh \
  --expect-tests 367 --max-tests 367 --timeout-seconds 180 \
  --parallel --test-workers 4 --shuffle-seed 1468 \
  --coverage appsec_review.review.behavior -- \
  tests/test_000_unit_environment_guard.py \
  tests/unit/review_behavior/test_contract_and_view.py \
  tests/unit/review_behavior/test_handler_wiring.py \
  tests/unit/review_behavior/test_coverage.py \
  tests/unit/review_behavior/test_model_context.py \
  tests/unit/review_behavior/test_operations.py \
  tests/unit/review_behavior/test_publication_bindings.py \
  tests/unit/observability_findings/test_actionability_evidence.py \
  tests/unit/job_security_tagging/test_behavioral_tags.py \
  tests/unit/job_security_tagging/test_handler.py \
  tests/unit/job_security_tagging/test_reader.py \
  tests/unit/job_security_tagging/test_rules_and_roles.py \
  tests/unit/job_security_tagging/test_native_language_aliases.py \
  tests/unit/job_owasp_control_assessment/test_subject_selection.py \
  tests/unit/job_owasp_control_assessment/test_subject_acceptance.py \
  tests/unit/job_owasp_control_assessment/test_discovery_boundaries.py \
  tests/unit/job_owasp_control_assessment/test_subject_settings.py \
  tests/unit/job_owasp_control_assessment/test_package_projection.py
```

Result: **367 passed, 12.95 seconds**, four shuffled workers, no test over ten seconds. The
preceding 366-case gate passed in 12.73 seconds; its slowest case was the environment guard,
0.658 seconds, and its slowest new case was 0.286 seconds.
`review/behavior.py`: **172/172 executable lines and 68/68 branch edges covered**. The subject
selection helper and added tagging decisions also have complete focused executable-line/branch
coverage in the agents' retained reports. This does not claim whole-repository coverage.

Directly affected existing units used the same wrapper with `--parallel --test-workers 4`:

| Exact selectors after `--` | Count guard / shuffle seed | Result |
| --- | --- | --- |
| `tests/review/test_units.py tests/review/test_packages_graph_context.py tests/test_finding_run_adapter.py tests/test_finding_coverage_adapter.py tests/test_todo_registry.py` | `--expect-tests 81 --max-tests 81 --timeout-seconds 180 --shuffle-seed 148` | 81 passed, 22.96 s; no slow cases |
| `tests/review/test_packages_dataflow_bound.py tests/test_job_test_selection.py::test_shipped_metadata_covers_registered_jobs_and_resolves_every_category tests/test_job_test_selection.py::test_shipped_recovery_maps_preserve_narrow_fixture_scopes_and_manual_categories 'tests/test_consumes_parity.py::test_consumes_are_registered_producers[job_inference_security_review]' 'tests/test_consumes_parity.py::test_consumes_are_scheduled_before_the_consumer[job_inference_security_review]' tests/test_consumes_parity.py::test_owasp_evidence_import_does_not_depend_on_registry_preload` | `--expect-tests 37 --max-tests 37 --timeout-seconds 180 --shuffle-seed 1466` | 37 passed, 12.72 s; no slow cases |

The three disjoint final selections total **485 passing unit cases**. Ruff and whitespace checks
passed over changed code and authored tests, including static checks of the unexecuted heavy tiers.
Wrapper logs, exact command arrays, collection manifests, junit, per-case timings and branch
reports remain host-local under the isolated checkout's `test/tmp/`; run identifiers are
`tests-custom-20261113-171200-944045-76541`,
`tests-custom-20261113-165325-056772-13884`, and
`tests-custom-20261113-170313-258724-48924`.

Failures retained during development: a fresh environment lacked pytest/pip and the parallel
guard's Dagster import dependency (resolved by installing declared dependencies only in the
isolated environments); one reader fixture omitted `size_bytes`; the bounded ShardSet location
projection does not carry a per-row snapshot, so operation discovery now uses the already-verified
scope snapshot and rejects an explicitly conflicting one. The first existing-regression attempt
on the wrong checkout was not credited; the isolated rerun exposed that projection defect, which
was fixed and covered. Seven short-module authorization failures were reproduced before the
agent correction. These were not converted to skips, larger timeouts or weaker proof checks.

Single-file coordinator probes also passed: actionability (23, 1.65 s), operation selection (37,
0.99 s), model context after fixture repair (19, 1.71 s), evidence projection (5, 0.45 s), and
publication bindings (6, 0.75 s), actual lane-handler wiring (2, 0.70 s), and the combined
projection/supported-language-priority probe (6, 0.45 s). The final static
test-map checks also passed (2, 8.99 s). The intermediate 92-case combined unit gate passed in 6.44 s;
its three uncovered model-context branches were then covered by the final selection above.

The Stage 2 documentation boundary `f4c2c14c068158a00cf3e0b6c0ec76ed8a8f6a2f` was merged with
explicit resolution of the T-146 record: the canonical frontmatter and T-147/T-148 entries were
preserved. Four directly related narratives were corrected and `scripts/generate-docs.sh`
regenerated the inventory and three affected job pages; `--check` reported no drift.
The 85-case documentation/TODO wrapper selection (`--expect-tests 85 --max-tests 85
--timeout-seconds 180 --parallel --test-workers 4 --shuffle-seed 1469`, selecting
`tests/docs/test_docs_frontmatter.py`, `test_docs_identifiers.py`, `test_docs_ledger.py`,
`test_docs_links.py`, `test_generated_docs.py`, `tests/test_documentation.py`, and
`tests/test_todo_registry.py`) produced 82 passes, two failures and one T-148 archive skip in
8.56 seconds, with no slow cases. Both failures name the same two pre-existing links to the
operator-owned `targets/appsec-multi-vuln` checkout, absent from the isolated worktree.
No target was cloned, copied or modified to satisfy them; those links require the final
main-checkout check. Report: `tests-custom-20261113-171609-586641-90985`.

### Manual validation boundary

Integration cases are authored under `tests/integration/job_security_tagging/`,
`tests/integration/job_owasp_control_assessment/` and `tests/integration/review_behavior/`.
Acceptance cases are authored in the corresponding `tests/acceptance/` directories and require
explicit operator-supplied run/evidence prerequisites. All are registered in `tests/job-test-map.json`.
**Integration, acceptance, live model efficacy and real-target review execution: NOT RUN.**
Historical run observations motivated this change; neither those observations nor the unit
coverage establish improved real-target precision, recall or developer acceptance.
