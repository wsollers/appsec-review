---
title: "OWASP control-assessment value review, 2026-11-14"
kind: "review"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_inference_security_review", "job_owasp_control_assessment", "job_review_data_indexing", "job_security_tagging"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# OWASP control-assessment value review (2026-11-14)

Review of `job_owasp_control_assessment` for the value it delivers to a developer or a security
reviewer, as it stands on `origin/main` `810d837cd9a40609ebe3f909dbbf035f7932e65d` (fetched
2026-11-14, worktree branch `owasp-value`). The companion correctness review
(`docs/reviews/owasp-process-review-2026-11-14.md`, branch `owasp-review`, findings F1 to F13)
covers contracts and defects; this document does not repeat it and cites its findings by number.
Run evidence comes from smoke-cpp run `2026-11-14-0003` on this host (run source `515300d5`,
pre-T-146 evidence binding; the T-146 code reviewed here changes subject selection, not the
value questions below). The smoke answer key was not read. No code was changed and no TODO
entries were added; the integration owner allocates ids for the change list at the end.

## Verdict

On the one real run available the job answers no question anyone downstream asked. It selected
277 ASVS/MASVS rows for a C/C++ command-line target, classified its single component with no
roles at `low` confidence, found no supported proof subject, dispatched three worker cells that
made zero model calls, and published 277 rows of `not_assessed`/`cannot_verify` that review data
indexing turned into 277 `control_evidence` facts, five of which were copied into every one of
the 562 review packages (7.9 MB, 21 % of hunt-package bytes and 62 % of lead-package bytes),
each saying "no reviewed versioned proof procedure for this selected control". No review cell
called the workbench query tool (it cannot be granted to cells), no `owasp_control` lead was
produced, and the final report has no OWASP section to receive one. The two things the job does
that could carry value are not where they should be: component classification (language,
framework, entry points, auth, crypto, storage, network) is the routing fact every hunter,
persona router and applicability rule wants, and it is computed inside the workbench from an
input that the catalog and tagging jobs left empty (`components` payload had only `root`,
`manifest`, `component_id`; the `tags` index held 55 `lang:*` tags and 1,131 gap tags); and
the four Python proof procedures are the right shape for a developer-facing control result but
reach no target this host reviews. Recommendation: **reshape**. Gate the whole stage on a
target class derived from tags (web/API, mobile, or neither), exit in seconds with a one-line
"not applicable" ledger for CLI and library targets, move component role classification into
security tagging as `component:*`/`surface:*` tags that the existing `tags` index and package
`tag_context` already carry, project only assessed rows into packages, and, for web/API targets,
turn ASVS controls into `control_gap` hunt obligations on tagged entry-point units reviewed by
the existing red/blue/verifier cells instead of a separate assessor/reviewer stage.

## Answers

### 1. What question does the job answer today, and did anything downstream use it?

**The question.** "For every selected ASVS level-2 and MASVS control, crossed with every
component, is there a named Python source subject whose obligation a model can assess, and what
did the model and a blinded reviewer conclude?" (`engine.py:226-311` builds the control ×
component matrix; `obligations.py:85-250` holds the five procedures, four static Python
recognisers for `V1.2.4`, `V6.2.1`, `V8.2.1`, `V8.3.1` and one MASVS runtime placeholder;
`assessment.py` runs worker and reviewer.) For a target with Python route handlers, password
checks or SQL calls, that is a worthwhile model call: the procedure text in
`obligations.py:95-126` is a precise analyst question with explicit `satisfied`/`not_satisfied`/
`cannot_verify` criteria, and an accepted result cites an `owasp-evidence-reference/1` bound to
a named AST subject with file hash and line span (`obligations.py:384-395`).

**On run 2026-11-14-0003 the question was never askable.**

| Item | Value | Where |
|---|---:|---|
| Components / roles / confidence | 1 / `[]` / `low` | `artifacts/owasp-workbench/component-classifications.json` |
| Selected rows | 277 (253 ASVS L2, 24 MASVS) | `control-results.json`, `coverage.selected_rows` |
| Applicability | 273 `unsupported_missing_evidence`, 4 `conditional` | `applicability.json` |
| Control status | 273 `not_assessed`, 4 `cannot_verify` | `control-results.json` |
| Batches dispatched / model calls / assessed rows | 3 / 0 / 0 | `owasp-workbench-result.json` `coverage`, pipeline events |
| Job duration | 119.6 s (standards 5.9, characterization 17.1, batching 5.8, validation 6.1, verification 4.5, publication 7.5) | `status.json`, task statuses |
| Gaps published | 614 | `owasp-workbench-result.json` |

The four `cannot_verify` rows each carry a 6 KB gap string that lists every one of the 61 files in
the target with "reviewed site recognition supports only Python source", including `LICENSE`,
`README.md` and `.editorconfig`, and zero obligations with subjects.

**Downstream use.**

- `control_evidence` precompute: 277 facts, 273 relations, 0 gaps
  (`job_review_data_indexing/.../precompute/tasks/control_evidence/result.json`). Every fact is
  a `not_assessed` or `cannot_verify` row.
- Review packages: `review/packages.py:1162-1170` loads every assessment-mode row into
  `control_context` per component, and `packages.py:1415-1416,1523-1524` appends them to every
  lead and hunt package. The 64-entry cap at `packages.py:1300-1322` balances context roles, so
  five OWASP entries survive in every package. Measured on the run: 505 hunt packages each with
  exactly 5 `control_context` entries (ASVS `V1.1.1`, `V1.1.2`, `V1.2.1`, `V1.2.2`, `V1.2.3`:
  the first five by sort order, all `not_assessed`), 7,072,525 of 33,253,015 package bytes
  (21.3 %); 57 lead packages each with 5, 798,285 of 1,285,444 bytes (62.1 %). The four rows
  that at least name a procedure (`V1.2.4`, `V6.2.1`, `V8.2.1`, `V8.3.1`) sort after `V1.2.3`
  and never reach a package.
- `owasp_control` leads: 0 (`lead_families.py:666-708` requires `not_satisfied` and
  `production_eligible`).
- `query_owasp_workbench`: 0 calls. It is excluded from `IN_PROCESS_TOOLS`
  (`review/capability.py:47`), so no cell could call it (F11). The run's 73,378 `RETRIEVAL_QUERY`
  events break down as `find` 70,976, `search` 582, `trace` 550, `read_excerpt` 482,
  `query_syntax` 447, `query_observations` 125, `query_codeql` 85, `query_build_security` 76,
  `resolve_evidence` 25, `query_precomputed` 21, `query_debug_symbols` 5, `query_hotspots` 2,
  `query_ci_configuration` 2 (`data/logs/pipeline.jsonl`, `details.mcp_tool`).
- Report: nothing. `src/appsec_review/reporting/` and the final report/dossier jobs contain no
  reference to OWASP, ASVS or `control_evidence`; the only other consumer is the threat-model
  job, which lists `owasp_control_result` as a mitigation evidence kind
  (`threat_model/reference.py:37`) and did not run in this run.

So the honest answer: today the job's output is a 277-row coverage ledger, and the one place it
is consumed (package context) consumes the least informative five rows of it.

### 2. Is component classification the most valuable thing it produces, and should it be an index shard?

**Yes, and it already half-exists elsewhere.** `engine.py:66-108` (`_deterministic_roles`) derives
roles from component `paths`, `languages`, `frameworks` and `tags`; `engine.py:29-46,137-146`
maps `func:*` capability tags with `declared`/`invoked` basis onto roles. These roles are exactly
what the rest of the review wants:

- Persona routing (`guidance/routing.py:69-91`) ranks personas by lead CWE, then location tags,
  then the component tag cloud.
- Stack routing (`guidance/routing.py:128-173`) keys on `lang:*`, `component:*-mobile`,
  `component:deployment-operations`, `func:net:grpc`, `infra:*`.
- Hunt panels (`guidance/routing.py:220-250`) pick `sink_up`/`entry_down`/`control_gap`
  strategies from unit tags and available sources.
- Package assembly already carries `tag_assignment` context and a `tag_context.cloud`
  (`packages.py:1171-1182`; 4,545 tag entries across the 505 hunt packages, 9 per package).

The security-tag taxonomy (`docs/architecture/security-tag-taxonomy.md`, namespace registry)
already reserves `component:*` ("reuses the workbench `COMPONENT_ROLES`"), `surface:entry:*`,
`surface:priv:*`, `surface:boundary:*`, `func:*` and `lang:*`, and the capability rules file
`data/reference/taxonomy/capability-rules.json` has `path_rules` (14), `package_rules` (25, e.g.
`pkg-jwt` emits `func:authn:jwt` for 13 package names across six ecosystems),
`observation_rules` (14) and `graph_rules` (14, e.g. `graph-remote-input` emits
`surface:entry:remote-input`). What is missing is not a new shard but population of the existing
one and a consumer contract:

- On the run, the `components` index payload was `{"component_id", "manifest": null, "root":
  "."}` (`data/indices/components/*.sqlite`), so `frameworks` and `tags` reached the workbench
  empty (`evidence.py:562-565`), `languages` came only from source files, and `_deterministic_roles`
  had nothing to match. The `tags` code-facts shard held 55 assignments, all `lang:*` with basis
  `declared`; the gap shard held 1,131 rows (1,077 `gap:crosswalk-unmapped`). No `component:*`,
  `surface:*` or `func:*` tag was minted for a C/C++ target with a `main()`, sockets or parsers.
- The workbench therefore classified from nothing, recorded `confidence: low`, and
  `build_applicability` (`engine.py:245-248`) would have said `cannot_determine` for every row,
  except that assessment mode overrides the outcome with `unsupported_missing_evidence` whenever
  no procedure exists (`engine.py:274-277`), which is 273 of 277 rows regardless of the
  classification. Classification changed nothing on this run.

**Proposed shard.** Do not add a `components`/`tags`-style index beside `tags`; extend the
existing `tags` index (producer `job_security_tagging`, already in every package's
`retrieval.indexes`, queried through `find`, `search` and the package `tag_context`) with
component-scoped assignments, and have the target catalog supply the facts the rules need:

| Tag family | Source | Basis | Examples |
|---|---|---|---|
| `lang:*` per component (weighted by file count) | catalog language census per component | `declared` | `lang:cpp`, `lang:python` |
| `component:*` role | path rules, package rules, graph entry/sink classes, build facts (the logic now in `engine.py:66-108,137-146`) | `declared`/`invoked` | `component:application-api-server`, `component:cli-tool`, `component:library`, `component:android-mobile`, `component:test-development-only` |
| `surface:entry:*` | graph entry points, route decorators, `main`/argv parsing, file/env readers | `invoked` | `surface:entry:http-public`, `surface:entry:cli`, `surface:entry:file-input` |
| `func:*` per component (authn, session, authz, crypto, data, net, exec, fs) | package rules on lockfiles/manifests (`declared`), graph call sites (`invoked`) | both | `func:authn:jwt`, `func:data:sql-query`, `func:net:tls-client` |
| `framework:*` (new leaf under `component` or `platform`) | manifests and imports | `declared` | `framework:flask`, `framework:spring-boot`, `framework:express` |

Consumers and how they read it:

- `job_owasp_control_assessment` applicability: reads the component's `component:*` and
  `surface:entry:*` tags through `accept_manifest`/`RetrievalCore` (it already opens the `tags`
  index, `evidence.py:21-24`), drops `_deterministic_roles`, and decides the target class
  (section 4) before selecting any control.
- `job_inference_security_review` routing (`teams.py:747-790`) already reads `tag_assignment`
  context entries; `component:*` and `surface:entry:*` tags would make `route_stack` and
  `hunt_panel` choose `cpp_native_service`/`entry_down` on evidence rather than on language alone.
- `job_review_package_assembly`/`packages.py` scoping: `scoped_tags` already attaches tags by
  component, source id and path; a `surface:entry:*` tag on a unit is the natural trigger for a
  `control_gap` hunt.
- `job_threat_model_generation`: entry points and trust boundaries for DFD generation.
- Operators: `find kind=tag_assignment name=component:*` and the `tag_context.cloud` in the
  package view answer "what is this target" in one query.

The workbench keeps nothing of its own classifier; the `component-classification` shard family
becomes a projection of tags with the citations it already records.

### 3. Does the OWASP process need its own queries?

**No new retrieval tool, and a much smaller precomputed set.** Judged by what workers requested
on the run (section 1): cells used `find`, `search`, `trace`, `read_excerpt` and `query_syntax`
to reach source, and `query_precomputed` 21 times in 1,226 cells. Nobody could or did call
`query_owasp_workbench`; every `workbench_reference.query` string in 2,810 package context
entries pointed at a tool the reader cannot run (F11). The workbench's deep records (obligations,
citations, reviewer dissent) are read application-side by `load_control_assessment`
(`indexing/products.py:1102-1130`) when leads and packages are built, which is the right place.

What should exist:

- `control_evidence` precomputed set, restricted to rows with `control_status` in
  `{satisfied, not_satisfied, cannot_verify}` **and** at least one bound subject
  (`obligations` non-empty). On this run that is 0 facts instead of 277, and 0 package entries
  instead of 2,810. Unassessed rows belong in the coverage ledger
  (`owasp-workbench-result.json` `coverage`), not in `query_precomputed`.
- Package context: `control_context` entries only for the package's own component **and** only
  for rows whose subject intersects the package's `scope.source_ids` or unit paths, the way
  `scoped_tags` already scopes tags (`packages.py:1181-1182`). A hunt over `src/request.cpp`
  gains nothing from a `V1.1.1` row about documentation.
- `workbench_reference.query` rewritten to `query_precomputed query_set=control_evidence
  subject=<component>` (F11) so the reference is executable by the reader that sees it.
- No `query_owasp_workbench` in `datasets.py:27` routes or docs for review cells; keep the MCP
  tool (`mcp/owasp.py`) for operators only.

Feeding `query_syntax`, `search` and `expand` needs no change: once a control result cites a
subject by file hash and line span, the existing `read_excerpt`/`expand` path resolves it. The
value is in the citation, not in a dedicated query.

### 4. Applicability on a C/C++ CLI or library target

ASVS 5.0 is a web application and web service standard; MASVS is a mobile standard. On a C/C++
command-line tool or library with no HTTP route, no session, no browser and no mobile platform,
the correct answer to 345 ASVS controls and 24 MASVS controls is "not applicable", established
once, cheaply, from positive evidence of what the target is (section 2 tags), and recorded as a
single ledger row per family. Today the job cannot say that: `build_applicability` requires
`confidence != low` and positive roles for `not_applicable` (`engine.py:245-258,286-287`), and
with the empty classification it fell through to 273 `unsupported_missing_evidence` rows plus 4
`conditional` rows whose only basis was that a procedure exists for the control
(`engine.py:283`), which then produced three dispatched batches, three "failed" workers (F2)
and 614 gaps, all of them about the wrong language.

Expected value by target class, given the current procedures:

| Target class (smoke set, `docs/operations/test-targets.md`) | Applicable standard | What the job could assess today | What it should do |
|---|---|---|---|
| C/C++ CLI/library (`smoke-cpp`, Freeciv, CASTLE) | none of ASVS/MASVS; CERT C/C++ and the review's own memory-safety predicates apply | nothing | exit after target-class gating with one `not_applicable` row per family; publish no `control_evidence`; seconds, 0 model calls |
| Rust, Go, C# CLI/library | same | nothing | same |
| Web/API in Python (`smoke-python`) | ASVS L2 chapters V1, V2, V4, V6, V7, V8, V10, V11, V12, V13, V14, V16 | the four procedures, if the target has Flask/Django/FastAPI routes, SQL calls or password checks | select only chapters routed by tags (`func:net:http-route` → V4/V8; `func:authn:*` → V6/V7; `func:data:sql-query` → V1.2); dispatch only rows with bound subjects |
| Web/API in Java, JavaScript, Go, PHP, Ruby, C# (`smoke-java`, `-javascript`, `-go`, `-php`, `-ruby`, `-csharp`) | ASVS L2 as above | nothing: recognisers are Python-only | either add recognisers per language (large, section 6 change 7) or hand the control question to the hunt lane (change 6), where language is handled by the existing syntax/graph tools |
| Mobile (none in the smoke set) | MASVS 2.1 | nothing: `MASVS-NETWORK-1` has no runtime adapter and no static recogniser exists | gate on `component:*-mobile`; until a procedure exists, publish `not_assessed` coverage only, never package context |

The gating decision is cheap: the catalog and tagging jobs already run before OWASP in both
graphs (`docs/architecture/owasp-control-workbench.md:17-46`), so the target class is a tag
lookup, not a model call.

### 5. Developer actionability: what a result must contain

A line in the final report is worth its space when a developer can act on it without opening the
run directory. The minimum is:

1. control id and the control text (one sentence), with the standard version;
2. the verdict (`not_satisfied` or `satisfied`), who agreed (worker and blinded reviewer) and the
   provisional label;
3. the first-party subject: `path:first-last` of the complete function or module, its content
   hash, and the cited lines that implement or fail the control;
4. the one-paragraph rationale and the unresolved prerequisites (e.g. "middleware not resolved");
5. what to change, or for `satisfied`, what must not change;
6. for anything else (`cannot_verify`, `not_assessed`, `not_applicable`), a coverage sentence per
   standard and chapter, not a row per control.

Compare `control-results.json` on the run (`artifacts/owasp-workbench/control-results.json`,
628,040 bytes, 277 records): each record has `control_identity`, `control_status`,
`applicability`, `coverage_completeness`, `evidence_used` (the component reference, or for the four
`cannot_verify` rows 60 whole-file references whose excerpt is the first 120 lines),
`obligations` (empty for all 277), `observations` (empty), `gaps` (a 6 KB string naming every
file), `limitations`, worker/reviewer attempt counts. Items 1 and 2 are present, items 3 to 5 are
structurally present (`obligations[].subject`, `observations[].citations`,
`observations[].rationale` on an assessed row, `obligations.py:384-395`, `assessment.py:63-107`)
but empty on every row this host has ever produced, and item 6 does not exist: the ledger is per
row, and the first five rows of it are what every reviewer cell sees. The redesign below adds a
`control-report/1` projection with exactly items 1 to 6 and makes it the only OWASP input to the
final report.

### 6. Cost versus value, and the recommendation

| Cost on run 2026-11-14-0003 | Measured | Value delivered |
|---|---:|---|
| Job wall time | 119.6 s of a run whose review stage took 19,341 s | none |
| Model calls (worker + reviewer) | 0 (budget would have been 24,000 in / 6,000 out tokens per batch) | none; with a Python target F1 shows the packages could not fit the budget anyway |
| Artifacts written | 3.2 MB under `artifacts/owasp-workbench/`, 1.5 MB of it finding packages for 4 rows | audit trail of nothing assessed |
| Index shards published | 10 (standards 1, classification 1, applicability 1, control-result 1, validation-work 3, finding-package 3) | consumed by review data indexing only |
| `control_evidence` facts | 277 facts, 273 relations | 0 usable |
| Package context | 2,810 entries, 7,870,810 bytes across 562 packages (21 % of hunt bytes, 62 % of lead bytes); every entry says a procedure does not exist | negative: budget taken from source, graph and scanner context under the 64-entry cap |
| Contract breadth | 26 declared producers, about 110 input requirements (F3) | scheduling and read receipts that overstate consumption |
| Gaps | 614 in the result, 6 generic `producer_reported_gap` records in the outcome (F4) | noise an operator must dismiss per run |
| Review-cell retrievals of OWASP data | 0 of 73,378 queries | none |

**Recommendation: reshape, with gating by target class on by default.** Keep the job enabled,
but make its first decision "is any ASVS or MASVS family applicable to this target?" from tags.
When the answer is no (every C/C++, Rust, Go and C# CLI or library in the smoke set), the job
publishes a one-row-per-family `not_applicable` ledger with its tag citations, no
`control_evidence`, no package context, no batches, no model calls, and finishes in a few
seconds. When the answer is yes, the job selects only the chapters its tags route, dispatches only
rows with bound first-party subjects, and publishes a developer-facing projection. Keeping the
job as it is costs little wall time but pollutes every review package and produces a ledger
nobody reads; disabling it outright loses the one well-designed piece (subject-bound control
procedures) for the web targets where it would pay.

## Proposed target design

**What the job produces.**

1. `target-class/1`: one record per component: `{component_id, classes: [web_api | mobile |
   cli | library | build_tooling | test_only], basis: [tag assignment ids], confidence}`
   derived from `component:*`, `surface:entry:*`, `lang:*` and `platform:*` tags. Published as
   an `applicability` shard row and cited by every other record.
2. `applicability` rows only for families whose class matches (ASVS for `web_api`, MASVS for
   `mobile`), and only for chapters routed by the component's `func:*` tags; every unrouted
   chapter gets one `not_applicable` or `not_routed` row per chapter, not per control.
3. `control-result` rows only for dispatched obligations, each with a bound first-party subject
   (`subject_selection` already produces `path`, `lines`, `ast_sha256`), the worker and reviewer
   turn results, and the `control-report/1` projection of section 5 items 1 to 6.
4. `coverage`: per family and chapter, counts of `not_applicable`, `not_routed`,
   `no_procedure`, `no_subject`, `cannot_verify`, `satisfied`, `not_satisfied`, replacing the
   614 free-text gaps with `producer-gap/1` records (F4).

**Component-tag index and consumers.** As in section 2: the `tags` index gains component-scoped
`component:*`, `surface:entry:*`, `func:*` and `framework:*` assignments produced by
`job_security_tagging` from catalog facts (languages and manifests per component), package rules
and graph entry/sink classes; `job_target_catalog` publishes `languages` and `frameworks` in the
`components` payload. Consumers: OWASP applicability (reads tags, drops its own classifier),
`route_stack`/`route_persona`/`hunt_panel` in the review job, package scoping, threat-model
boundaries, and operators through `find`/`search`. No new retrieval tool.

**Queries.** `control_evidence` precomputed set contains only assessed, subject-bound rows and is
scoped into packages by component and source id; `workbench_reference.query` names
`query_precomputed`; `query_owasp_workbench` stays an operator MCP tool and is removed from
package references and dataset routes. Review workers keep `find`, `search`, `trace`,
`read_excerpt`, `query_syntax`, `expand`.

**Applicability gating.** Class → family table above; a `cli`/`library`/`build_tooling`/
`test_only` only component ends the job after the `applicability` step with `SUCCEEDED` (the
not-applicable ledger is a result, not a gap). `mobile` without a static MASVS procedure ends with
coverage rows and no package context. `web_api` proceeds to dispatch.

**Where the model call goes.** For `web_api` components, prefer attaching the ASVS control as a
`control_gap` obligation to the hunt package of the entry-point unit (the strategy already exists
in `hunt_panel`, `guidance/routing.py:238`, and the package already carries `proof_obligations`
of the form "establish input control", "evaluate guards and configuration"). The red cell then
answers "is `V8.2.1` enforced on this route" with the same syntax and graph tools it uses for
everything else, the blue/verifier cells check it, and the judge decides. This retires the
duplicated finding-package evidence (F1), the separate assessor/reviewer pools (F12), and the
Python-only recogniser bottleneck, because subject discovery becomes "units tagged
`surface:entry:http-*`" rather than "Python AST decorators". The standalone assessor path stays
for the four existing Python procedures until the hunt path is proven on `smoke-python`.

**What reaches the report.** Exactly the `control-report/1` rows with a `satisfied` or
`not_satisfied` verdict (one line each: control, subject `path:lines`, verdict, agreement,
change), followed by one coverage sentence per applicable family ("ASVS 5.0 L2: 3 of 12 routed
chapters assessed; 9 chapters have no procedure") and, for non-applicable targets, one sentence
("ASVS and MASVS not applicable: C/C++ command-line tool, no HTTP or mobile entry points, basis
tag:…").

## Sequenced change list

Sizes: small (one module, one test file, under a day), medium (two or three jobs or a schema,
a few days), large (a new path through the review, more than a week). Each test is a focused
unit regression under 10 seconds unless noted.

1. **Project only assessed, subject-bound rows into `control_evidence` and package context**
   (small; F10). `indexing/products.py:_build_control_evidence` skips rows whose
   `control_status` is `not_assessed` or whose `obligations` are empty; `packages.py:1162-1170`
   additionally scopes `control_context` by source id. Test: a fixture control-result shard with
   273 `not_assessed`, 4 `cannot_verify` without subjects and 1 `not_satisfied` with a subject
   yields 1 fact and a package for that subject's file carrying 1 entry; a package for another
   file carries 0.
2. **Target-class applicability gate** (small to medium). New `target_class` step before
   `applicability.build_matrix` reads `component:*`/`surface:entry:*`/`lang:*` tags; when no
   component is `web_api` or `mobile`, publish one `not_applicable` row per family with tag
   citations, skip batching, validation and verification, and finish `SUCCEEDED`. Test: a
   fixture with one component tagged `lang:cpp`, `surface:entry:cli` produces 2 applicability
   rows, 0 batches, 0 `OWASP_WORKER_STARTED` events, 0 `control_evidence` facts, no gap
   mentioning Python; a fixture tagged `surface:entry:http-public` still produces the matrix.
3. **Rewrite package references and routes to executable queries** (small; F11).
   `workbench_reference.query` becomes `query_precomputed query_set=control_evidence`;
   `datasets.py:27` drops `query_owasp_workbench` from review routes. Test: every
   `workbench_reference.query` in a projected package names a tool in `IN_PROCESS_TOOLS`.
4. **Component facts from the catalog** (medium). `job_target_catalog` publishes `languages`
   (with file counts) and `frameworks` (from manifests and lockfiles via `cataloging.py`
   ecosystem detection) in each `components` entity payload. Test: the topology monorepo fixture
   yields a Python component with `languages: [{python: n}]` and `frameworks: [flask]`, and a
   C component with `frameworks: []`.
5. **Component and surface tags in security tagging** (medium). Move `_deterministic_roles` and
   `_CAPABILITY_TAG_ROLES` (`engine.py:29-108`) into `capability-rules.json` as `component_rules`
   emitting `component:*`, add `surface:entry:cli`/`file-input` rules for `main` and argv/file
   readers, emit per-component `lang:*` weights; the workbench reads these tags and deletes its
   classifier. Tests: tagging fixture with a Flask route decorator and `requests` import mints
   `component:application-api-server`, `surface:entry:http-public`, `func:net:http-client` with
   basis and evidence spans; the OWASP applicability test from change 2 passes against tags
   only; `tests/test_skill_separation.py` and the taxonomy hash tests still pass.
6. **Control questions as `control_gap` hunt obligations** (large). For `web_api` components,
   `job_review_package_assembly`/`packages.py` attaches the routed ASVS control's obligation
   (invariant, prerequisites, criteria from `obligations.py`) to hunt packages of units tagged
   `surface:entry:http-*`; the red cell's turn contract gains the `control_status` field; the
   judge's accepted claim carries the control id; the workbench records the outcome as a
   `control-result` row. Tests: a hunt package for a route unit carries exactly one control
   obligation and its serialized request stays under the configured input budget (contrast F1);
   an accepted `not_satisfied` claim produces a `control-report/1` row with `path:lines`; a unit
   without an entry tag carries no control obligation.
7. **`control-report/1` projection and report section** (medium). The workbench publishes the
   section-5 projection; `reporting/` renders one line per verdict row and one coverage sentence
   per family, nothing else. Tests: a result set with one `not_satisfied` and 276 other rows
   renders one finding line and one coverage sentence; a `not_applicable` ledger renders one
   sentence naming the basis tags.
8. **Typed gaps and terminal status** (small; F4). `ProducerStatus` members and
   `interchange.producer_gap` records with `strict_gaps=True`; remove the job from the legacy
   list in `tests/test_gap_contract.py`. Test: the outcome holds one `producer-gap/1` record per
   coverage class, none free-text.
9. **Shrink the declared contract to what the resolver reads** (medium; F3). After changes 2
   and 5 the workbench needs `source`, `components`, `tags`, `analysis`, `graph`, `priority` and
   their producers only. Test: "declares what it opens" replaces the mirror test in
   `tests/test_consumes_parity.py:57-66`.
10. **Per-language recognisers** (large; alternative to change 6, not in addition). Only if the
    hunt-lane path is rejected: route decorators, SQL calls and password checks for Java,
    JavaScript/TypeScript, Go, PHP, Ruby and C# in `subject_selection.py`, each with the subject
    acceptance tests of `tests/unit/job_owasp_control_assessment/test_subject_selection.py`
    extended per language.

Suggested order: 1, 3 and 8 (stop the harm and the noise), then 2 and 4 and 5 (gate and
populate the tags that everything routes on), then 7, then 6, with 9 after 5 and 10 only if 6
is not taken.

## Not verified

- No run on a Python, web or mobile target exists on this host, so the value of the four
  procedures when a subject is found is argued from the code, not measured.
- The hunt-lane design (change 6) is not prototyped; the budget claim rests on the measured hunt
  package size (65,847 bytes average on this run) against the 24,000-token worker budget.
- Retrieval counts come from `RETRIEVAL_QUERY` events in `data/logs/pipeline.jsonl`; the
  companion review quotes different per-tool totals from cell records (`query_syntax` 703,
  `query_observations` 205, …). Both agree on zero `query_owasp_workbench` calls.
- No unit tests were run for this documentation-only change.
