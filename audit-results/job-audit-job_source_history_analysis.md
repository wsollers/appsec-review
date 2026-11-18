# Job 6/47 correctness audit — job_source_history_analysis

## Source, authority and result

- Audited **main at `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, exclusively in `/home/wsollers/projects/appsec-review`, through `ssh wsl-ubuntu` and the brief's Ubuntu-22.04 UNC root.
- HEAD and clean `git status --porcelain` were verified before validation and after the audit. The checkout-local interpreter imported `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`.
- Read-only correctness audit: no repository-source changes, commits, target execution, real Git history acquisition, containers, providers, service operations, integration/acceptance/live runs, or nested auditors.
- **Five defects reproduced offline:** one high and four medium. All 17 declared tasks were traced. **439 unit cases passed** (436 job cases plus 3 environment-guard cases), in **10.85 s** pytest time / **19.03 s** supervised-wrapper total; zero failures, skips or cases over 10 s. Five reproducers completed in **1.340 s** after imports.
- These results establish the stated code-level behavior, not live review quality or end-to-end acceptance.

## Registration and intended contract

`runtime/registry.py:74,123` registers the actual builder. `appsec-review.toml:655-789` declares four steps and 17 tasks; the dev recipe enables the job. `datasets.py:39-78` declares `REVIEW_GRAPH`, checkout access, `always_execute=False`, and propagating handoffs, scheduled after `job_target_catalog`. `orchestration/topology.py:46-79` projects graph edges from contracts, including consumed producers.

The required handoff envelopes are `job_review_intake` and `job_target_catalog`, both `appsec-review/job-handoff/2`. Optional payload declarations cover intake's model preflight, binary evidence and intake document, and catalog's artifact inputs, source files, declaration symbols, components, target documents, build units and catalog document. Optionality does not make the concrete intake/catalog documents dispensable to `_load_inputs`.

`job.py:185-217` reads accepted envelopes through `accepted_upstream`, verifies referenced JSON SHA-256s, checks intake/catalog schemas and equal source fingerprints, and loads partition/component/acquisition identities. `runtime/consume.py:162-205` requires declared handoff permission and admitted pins inside runtime scope and records reads. No direct other-job `latest.json` read was found in this job.

The intended outputs are source-bound, bounded review-routing context: first-parent Git change records; classification; file/component/symbol churn, ownership and complexity; per-source SII rankings; hotspot references; and separate, explicitly weaker change-log signals. They must not become vulnerability evidence. Missing metrics remain unavailable rather than proving a clean target.

### Publication and consumers

| Declaration | Actual output and scope |
|---|---|
| `history_documents`, artifact-only, `appsec-review/source-history-analysis/2` | Final `source-history.json` plus intermediate JSON under `steps/*/tasks/*/artifacts/*.json` or source-lane equivalents. Intermediates intentionally retain their own payload schema IDs; the artifact-family declaration is not a claim that all JSON has the final schema. Raw signals/co-change are plain structured payloads. |
| `history_signals`, indexed, `appsec-review/retrieval-index/2` | Fingerprinted SQLite `history/git-history[-<source-key>]` shards containing changes, component/file/symbol history signals, hotspots, relationships, resolving locations, coverage and separate location-free change-log records. |
| `raw_git_history`, protected, octet stream | Retained `log.bin`/`messages.bin` beneath the acquisition task's `protected` directory, including source/image/argv/receipt identities. |
| `history_tool_io`, protected, container-execution family | Per-task/source scratch trees for Git and Tree-sitter requests, raw responses and execution material. |

Actual emitted artifact directories match the declared globs (`datasets.py:15-36`). Publication composes verified upstream manifests and keeps unrelated shards (`job.py:1544-1556`; `source_lanes.py:92-112`). Source-history identity is recomputed before publication (`job.py:1559-1563`); fingerprint inputs cover configuration and normalized/ranked/hotspot/GitHub/change-log artifacts, raw stream hashes, parser/ranking rules and image identity (`job.py:290-315`). Reuse and drift paths have focused tests; live resume was not run.

Downstream interfaces inspected:

- Analysis plan checks the history snapshot and projects only matching catalog hashes/components, retaining change-log ranks separately: `job_target_analysis_plan/job.py:277-282`, `planning.py:184-225`.
- Change-context reads accepted history plus normalized/classified/raw-log outputs, builds bounded lifetime ownership and carries source-local gaps: `job_change_context_analysis/job.py:165-274`.
- Prioritization consumes all SII-scored file/symbol signals, not merely the selected hotspot list, and preserves per-source paths: `job_review_prioritization/job.py:555-594`.
- Indexed `history_context` consumes location-bound signals/hotspots and intentionally ignores location-free change-log records: `indexing/products.py:995-1065`; metric-vector joins were inspected in `indexing/metrics.py:56-133`.
- Additional registered dataset consumers include review-data indexing, review-package assembly, inference review, security tagging, document-issue analysis and OWASP assessment. Their declarations were searched; their complete implementations were not audited here.

## Every declared step/task

All task IDs match `TOPOLOGY`, TOML and the concrete `Unit` graph (`job.py:69-74,1663-1697`). The legacy `UnitExecutor` records exceptions as failed receipts and blocks dependent tasks (`runtime/units.py:83-178`). Source-lane wrappers preserve peer results for ordinary lane errors, while publication integrity errors propagate (`source_lanes.py:57-88`).

| Step/task | Actual implementation, processing/output | Result or coverage boundary |
|---|---|---|
| `resolve_sources.resolve_history_source` | `job.py:447-526`, `discovery.py`, `sources.py`: accepted intake/catalog, exclusions/Swift policy, bounded acquisition/local Git discovery, source-root ownership, acquisition pins, GitHub identity and review exports. | HEAD binding, unsupported layouts, policy/no-target, source isolation and export errors tested. Real targets/acquisitions not used. |
| `resolve_sources.bind_snapshot` | `job.py:527-594`: fixed `ls-tree`, accepted SHA-256 verification, Git blob comparison, exact/divergent/untracked/submodule accounting and `binding.json`. | Real runner replaced by fake boundary; byte mismatch, unrelated history and bounds covered. |
| `acquire.git_history` | `job.py:596-655`, `git.py:174-186`: first-parent log/messages with `max_changes+1`, protected bounded retention, receipts and integrity identities. | **SH-01:** extra detection record is not consistently delimited at classification. Real execution and RLIMIT behavior not run. |
| `acquire.normalize_changes` | `job.py:658-688`, `signals.py:43-99`: bounded stream parse, source-path mapping, window/author/rename/bulk normalization and `changes.json`. | **SH-01, SH-05:** commit-order truncation and destination-alias leakage. Shallow/anomalous/window/parser bounds otherwise tested. |
| `acquire.github_enrichment` | `job.py:690-716`, `github.py`: credential/policy gate, snapshot verification, bounded PR/review pagination, derived facts/timestamps and `github-enrichment.json`. | **SH-02:** head-commit transport failure escapes containment. All test transports fake; no credentials or requests used. |
| `acquire.changelog_history` | `job.py:1094-1201`, `changelog.py`: all four format parsers, accepted-byte verification, per-file/source containment, bounded path/date/classification summaries and typed gaps. | All four synthetic formats, privacy, limits, integrity refusals and multi-source separation tested. **SH-03** occurs later when selecting its role. |
| `analyze.classify_changes` | `job.py:726-748`, `signals.py:124-163`: parse messages, join GitHub labels, fix/security/revert/format classification, incomplete-message tracking. | **SH-01:** a boundary commit receives another commit's labels with `message_complete=True`. |
| `analyze.compute_signals` | `job.py:750-769`, `signals.py:172-298`: churn/frequency/author/recency/fix/revert/review/test metrics, filtering, component ownership and `raw-signals.json`. | Real algorithm tests. **SH-05** corrupts its upstream attribution and therefore totals. |
| `analyze.blame_age` | `job.py:774-802`, `git.py:198-200,377-396`: highest-churn exact bounded files, committer-time parsing, young-line shares. | Fake execution; bounds, failures, empty data and shares covered. Unavailable per-file shares remain null in ranking. |
| `analyze.co_change` | `job.py:804-816`, `signals.py:312-334`: non-bulk/non-formatting pair support, confidence, component relation and top-K. | Real algorithm tests; no external operation. |
| `analyze.line_history` | `job.py:818-863`, `git.py:191-197`, `lines.py`: bounded per-file `--follow -U0`, status map and `line-history.json`. | Fake tool output; execution/truncation/parser/file/count/divergence paths covered. No live Git diff verification. |
| `analyze.symbol_spans` | `job.py:865-985`, `symbols.py`: supported exact bounded files, locked per-file Tree-sitter requests, output identity checks, function spans/complexity and `symbols.json`. | Fake parser/image boundary, synthetic Python nodes, stored Ruby grammar output. Real grammar execution and all-language fidelity remain unverified. |
| `analyze.fix_on_fix` | `job.py:1007-1033`, `lines.py:175-236`: bounded-interval later fixes, mapped line overlap or shared innermost function, events/undetermined records. | Real region/interval algorithms tested; missing evidence does not become a confirmed zero. |
| `analyze.symbol_signals` | `job.py:1035-1094`, `lines.py:151-172`: hunk-to-symbol attribution and per-symbol churn/frequency/author/fix data. | Real attribution tests plus handler wiring; incomplete mapping named. |
| `analyze.rank` | `job.py:1215-1400`, `hotspots.py`: independent file/symbol populations, transformed min-max weighted SII, deterministic ties/tiers, best-file component priority, hotspot selection. | **SH-04:** supported proportional settings disagree with schema and published cap. Empty rankings feed **SH-03**. |
| `publish.index_history` | `job.py:1402-1557`: content-addressed SQLite, change/signal/hotspot relations and locations, coverage rows, upstream composition. | Handler tests fake builder/manifest boundary; change-log indexing tests build real local SQLite. Whole-job/admitted manifest publication not executed. |
| `publish.publish_handoff` | `job.py:1557-1661`: identity recheck, final per-source/aggregate document, ranking/hotspot/change-log references and retry dispositions. | **SH-03, SH-04** reproduced through the real handler. Aggregate projections covered; no live accepted run. |

No model invocation or runtime prompt assembly occurs in these handlers. Git runs in `tool-git`; symbol extraction conditionally runs `tool-tree-sitter`; GitHub enrichment uses the bounded application HTTPS client. Both tool declarations are enabled in `containers/catalog.toml:524-538,573-586`. The generated docs' undeclared execution bindings are the existing **T-147** gap, not evidence of nonexecution.

## Reproduced findings

### SH-01 — Medium: the extra history-bound commit contaminates the last retained commit's message

- **Evidence:** `src/appsec_review/jobs/job_source_history_analysis/job.py:602,678,733-736`; `src/appsec_review/jobs/job_source_history_analysis/git.py:326-352`.
- **Trigger:** Git returns more than `max_changes` commits, so acquisition stores the requested extra record. The last retained commit must still be in the analysis window for the classification to affect results.
- **Expected:** classify each retained change using only its own message; the extra record detects history truncation and cannot supply text to another change.
- **Actual:** normalization truncates `walked_commits` to the cap; classification passes that shorter order to the parser. Its last-record branch consumes everything to EOF, including the next hash and message.
- **Reproduced:** `max_changes=1`, retained commit message `refactor only`, extra commit message `fix security CVE-2024-12345`. The retained commit acquires `fix=heuristic`, `security_fix=heuristic`, that CVE, `message_complete=True`, and an empty classification gap list.
- **Impact:** false per-change fix/security/revert context, downstream file/fix-on-fix/change-context signals, or false message truncation. The separate history-window gap does not make the misattribution correct.
- **Confidence:** high; real normalize/classify handlers and stream parser, synthetic retained bytes only.
- **Smallest correction:** retain the full acquired message order or an explicit next-record boundary for parsing while keeping the admitted history/change set capped. Add a cap-plus-one handler regression.
- **Existing TODOs:** no matching item found. T-029 concerns deferred classification/redaction/symbol identity, not this delimiter error.

### SH-02 — High: an optional GitHub head-timestamp transport failure aborts otherwise usable Git analysis

- **Evidence:** `src/appsec_review/jobs/job_source_history_analysis/github.py:111-113,374-385`; `job.py:690-705,1683-1687`; `src/appsec_review/jobs/source_lanes.py:59-61,71-81`.
- **Trigger:** snapshot, PR and review requests succeed, but the extra request for a valid PR head SHA raises an ordinary transport error, such as a connection failure or timeout represented by `OSError`.
- **Expected:** publish a named unavailable/retryable enrichment gap, preserving local Git-derived analysis.
- **Actual:** `GitHubClient.request` converts the transport exception to `ValueError`; this particular caller catches only `BudgetExhausted`. `enrich` propagates the error. The normal single-root path bypasses source-lane exception containment, so enrichment fails and dependent classification/ranking/publication are blocked. In multiple-source mode the wrapper marks that entire lane failed rather than only its optional timestamp/enrichment.
- **Reproduced:** fake HTTP transport raised `OSError` only for `/commits/<PR-head>`; `enrich` raised `ValueError("github_transport_unavailable:OSError")` instead of returning a gap.
- **Impact:** failure to produce the job's otherwise available local history output because an optional enrichment request fails.
- **Confidence:** high. The escaping exception was reproduced; full-job scheduling impact is statically traced, not a live run.
- **Smallest correction:** contain `ValueError` at the head-commit fetch like the other enrichment boundaries; return appropriately scoped indeterminate facts and a retryable gap. Test transport failure at this stage, not just budget exhaustion.
- **Existing TODOs:** no matching item found; T-029/T-097 do not defer this error handling.

### SH-03 — Medium: empty Git rankings incorrectly make change-log history a supplement

- **Evidence:** `src/appsec_review/jobs/job_source_history_analysis/job.py:349-350,1216-1400,1585-1587`; intended semantics in `docs/architecture/source-history-analysis.md:315-323`.
- **Trigger:** Git history is bound and normalized, but every in-window change is formatting/bulk or every affected path is excluded; the change log independently ranks at least one accepted file.
- **Expected:** without a Git file ranking, the change-log ranking has `role=primary`.
- **Actual:** `rank` writes an artifact even for a zero-size ranked population. Publication tests `"artifact" in ranked` instead of whether a Git file ranking exists and sets `role=supplement`.
- **Reproduced:** real `compute_signals` with formatting-only changes, real rank handler and real publication handler produced `ranking.files=[]`, `ranked_file_count=0`, but `changelog.role="supplement"`.
- **Impact:** the final document and analysis-plan projection give the only usable file ranking the wrong precedence.
- **Confidence:** high; actual handlers, only history identity probing mocked.
- **Smallest correction:** use actual ranked file count/nonempty file population for `git_ranked`; add the empty-population/valid-change-log regression.
- **Existing TODOs:** related to in-progress T-097, but its enumerated deferred work does not include this already-implemented precedence rule failing on empty populations.

### SH-04 — Medium: valid proportional hotspot settings produce schema-invalid, contradictory publication

- **Evidence:** `src/appsec_review/jobs/job_source_history_analysis/settings.py:186-200`; `job.py:1365-1392,1603-1604,1635-1637`; `docs/schemas/history-hotspots.schema.json:14,32`.
- **Trigger:** accepted proportional settings select more than 100 hotspots, and/or file and symbol populations require different caps.
- **Expected:** a supported configuration produces a hotspot artifact satisfying its advertised schema, with truthful selection/count metadata in the final document.
- **Actual:** proportional caps may exceed 100, but schema `/1` restricts `hotspot_count<=100` and single-source `entries<=200`. Final source-history metadata still copies the legacy fixed `settings.hotspot_count`, not the effective cap. A single selection string also claims the same cap for both populations although separate effective caps are computed.
- **Reproduced:** `proportional_ratio=1.0`, `min_hotspots=50`, `max_hotspots=2000`, 201 eligible files. Job settings validation succeeded; real rank produced 201 entries and `hotspot_count=201`; JSON Schema reported `entries/maxItems=200` and `hotspot_count/maximum=100`; real publication reported `hotspot_count=10`.
- **Impact:** strict schema readers reject a supported output, and consumers/operators cannot rely on the advertised cap. Existing permissive readers do not prove schema compatibility. This audit did not claim a live runtime rejection.
- **Confidence:** high; real rank/publication plus `Draft202012Validator`.
- **Smallest correction:** reconcile versioned schema limits with typed configuration, publish effective per-population/per-source selection metadata, and validate a proportional output above the old limit in unit tests.
- **Existing TODOs:** directly related to **T-171**, marked done at `docs/TODO.md:2808-2815`. Current tests exercise the helper arithmetic and settings but not schema-valid proportional publication.

### SH-05 — Medium: rewinding a rename retains the obsolete destination alias and imports unrelated history

- **Evidence:** `src/appsec_review/jobs/job_source_history_analysis/signals.py:55,73-78,197-201`.
- **Trigger:** a destination path existed historically, was deleted, and is later reused by renaming another file into it.
- **Expected:** the present file follows the renamed source's lineage before the rename, not the deleted former occupant of the destination name.
- **Actual:** the normalizer adds `alias[renamed_from]=current` but never removes the destination alias. Older modifications/deletion of both names are attributed to the current destination.
- **Reproduced:** initial `a.py` has 2 added lines and unrelated `b.py` has 9; `b.py` is deleted; `a.py` is then renamed to `b.py`. Parsed valid synthetic numstat records yield 20 churn lines for current `b.py` rather than 2, including the old occupant's deletion.
- **Impact:** incorrect file/component churn, change/author counts, co-change and SII inputs; the same normalizer is used by change-context lifetime analysis.
- **Confidence:** high for the pure parser/normalizer behavior; no real Git command was run.
- **Smallest correction:** consume/rewind destination aliases when crossing renames, using a coherent per-commit alias transition so aliases cannot leak across distinct file lineages. Add destination-name-reuse coverage.
- **Existing TODOs:** no matching item found. T-029's deferred renamed/deleted *symbol* identity is distinct from this file-path normalization defect.

## Drift, known limits and nonfindings

1. **Proportional mode is opt-in, not the claimed new default.** No `proportional_ratio`, `min_hotspots` or `max_hotspots` occurs in the central TOML or shipped profiles. `HistorySettings.proportional_ratio` defaults to `None`, which selects the fixed cap. T-171's task document describes default proportional scaling while its TODO entry is done; those claims need reconciliation. This is distinguished from SH-04's reproduced opt-in output defect, not asserted as an authorized configuration change.
2. **Test-map drift:** `tests/job-test-map.json:698-714` lists 14 unit files, omitting `test_proportional_hotspots.py` and its 3 cases. This audit included all 15 actual job files; omission is not missing tests.
3. T-027 Perforce history, T-028 submodule-history decisions, and T-029 exact OSV fix classification, redacted subjects, historical symbol identity and further grammar/complexity proof remain explicitly deferred.
4. T-097 already tracks change-log nonconsumption by review prioritization/`history_context`, lack of inferred file lists or exact span binding, no Git cross-deduplication, legacy gap migration and acceptance rebaselining. These are not new findings.
5. Typed change-log gaps deliberately remain on their observing unit; final documents expose them in the separate change-log section. I did **not** treat absence from the Git-only aggregate gap list as lost canonical coverage, because operation docs describe that arrangement.
6. Current unit contract tests confirm no job/unit payload output validators and `strict_gaps=False`; control-envelope/status/gap checks do not validate arbitrary payload JSON (`interchange.py:521-567`). That limits what passing contract tests prove; SH-04 supplies a concrete schema violation.
7. Previous session reports for jobs 1–5 and relevant TODO/history references were searched. No duplicate of SH-01–SH-05 was found. Existing source-history history includes the HEAD-pinning repair and T-171 work; no branch was changed or merged.

## Focused validation record

All Linux commands used this PowerShell transport, substituting the Bash block:

```powershell
$script = @'
# Bash block
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Common preamble:

```bash
set -eu
cd /home/wsollers/projects/appsec-review
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
while IFS= read -r name; do unset "$name"; done < <(
  compgen -v | grep -E '^(APPSEC_|DAGSTER_HOME$|PYTEST_ADDOPTS$|PYTHONPATH$|GITHUB_TOKEN$|GH_TOKEN$)'
)
export PYTHONDONTWRITEBYTECODE=1
```

### 1. Collection

```bash
.venv/bin/python -m pytest --collect-only -q -p no:cacheprovider \
  --basetemp=test/tmp/job-audit-job_source_history_analysis-collect-20261118 \
  tests/test_000_unit_environment_guard.py tests/unit/job_source_history_analysis | tail -7
```

**439 collected in 2.48 s.** One harmless warning: configured `cache_dir` is unknown when cacheprovider is disabled. No tests executed in this collection pass.

### 2. Exact inspected unit set

```bash
set -o pipefail
scripts/run-tests.sh --parallel --test-workers 4 --shuffle-seed 61118 \
  --max-tests 439 --expect-tests 439 -- \
  tests/test_000_unit_environment_guard.py \
  tests/unit/job_source_history_analysis/test_*.py | sed '/^  tests\//d'
```

The shell glob expands to the 15 files read in this audit: `test_algorithms.py`, `test_artifacts.py`, `test_changelog.py`, `test_contract.py`, `test_edge_cases.py`, `test_fingerprint.py`, `test_git.py`, `test_github.py`, `test_handlers.py`, `test_legacy_hotspots.py`, `test_proportional_hotspots.py`, `test_publication.py`, `test_settings.py`, `test_sources.py`, `test_symbols_handler.py`.

**439 passed in 10.85 s; wrapper total 19.0298 s; exit 0; failures 0; skips 0; >10 s cases 0.** Collection and execution completed; process cleanup confirmed no remaining supervised processes. Default 30 s collection/300 s overall limits were retained; the count guard was set to the inspected 439, not raised after failure.

Evidence retained under the authorized checkout:

- `test/tmp/logs/tests-custom-20261118-104903-886671-2277159.log`
- `test/tmp/logs/tests-custom-20261118-104903-886671-2277159.collection.log`
- `test/tmp/tests-custom-20261118-104903-886671-2277159.junit.xml`
- `test/tmp/tests-custom-20261118-104903-886671-2277159.timings.sqlite`
- `test/tmp/tests-custom-20261118-104903-886671-2277159.collection.json`
- `test/tmp/reports/tests-custom-20261118-104903-886671-2277159.json`

Scratch naming: explicit collection and reproducers used the requested job-prefixed descendant. The mandatory wrapper rejects basetemp overrides and generated its own unique `tests-custom-*` descendant under `test/tmp`; no guard was bypassed.

### 3. Offline defect reproducers

Executed one `.venv/bin/python - <<'PY'` block after the same preamble. It imported the already-inspected job test fixtures and real implementation functions, used the generated unit host pins, and put handler artifacts under `test/tmp/job-audit-job_source_history_analysis-repro-20261118`. Only HTTP transport and the publication history-identity probe were faked; no Git, parser container or model was invoked.

The exact substantive reproducer body follows; its printed results are recorded in the findings above:

```python
import io, json, os, time
from pathlib import Path
from copy import deepcopy
from dataclasses import replace
from unittest.mock import patch
from jsonschema import Draft202012Validator
from appsec_review.config.host_pins import HOST_PINS_ENV
os.environ[HOST_PINS_ENV] = str(Path(
    'test/tmp/job-audit-job_source_history_analysis-collect-20261118.host-pins.toml').resolve())
from tests.unit.job_source_history_analysis.support import HEAD, PARENT, STAMP, artifact, context, document, header
from tests.unit.job_source_history_analysis.test_handlers import baseline, invoke
from tests.unit.job_source_history_analysis.test_github import client, PATH
from appsec_review.jobs.job_source_history_analysis import job, git, github, signals, changelog
from appsec_review.jobs.job_source_history_analysis.settings import parse_settings
root = Path('test/tmp/job-audit-job_source_history_analysis-repro-20261118').resolve()
start = time.perf_counter()

u = baseline(context(root / 'messages', 'acquire.normalize_changes', overrides={'max_changes': 1}))
u.outputs['acquire.git_history']['raw_log'] = artifact(u, 'bound-log.bin',
    header(HEAD) + b'1\t0\ta.py\0' + header(PARENT, STAMP - 86400) + b'1\t0\tother.py\0')
u.outputs['acquire.git_history']['raw_messages'] = artifact(u, 'bound-messages.bin',
    HEAD.encode() + b'\0refactor only\n\0' + PARENT.encode() + b'\0fix security CVE-2024-12345\n\0')
normalized = invoke(u)
u.outputs['acquire.normalize_changes'] = normalized
classified = invoke(replace(u, unit_id='analyze.classify_changes'))
label = document(u, classified)['classes'][HEAD]
assert label['fix'] == label['security_fix'] == 'heuristic' and label['message_complete'] is True
print('SH-01', json.dumps({'retained_commits': document(u, normalized)['walked_commits'],
    'expected_security_fix': None, 'actual': label, 'classify_gaps': classified['gaps']}))

pull = {'number': 7, 'merged_at': '2024-01-03T00:00:00Z',
        'user': {'login': 'author'}, 'head': {'sha': PARENT}}
responses = {
    f'/repos/acme/repo/commits/{HEAD}': (200, {}, {'sha': HEAD}),
    PATH + '?per_page=2&page=1': (200, {}, [pull]),
    '/repos/acme/repo/pulls/7': (200, {}, {'head': {'sha': PARENT}}),
    '/repos/acme/repo/pulls/7/reviews?per_page=2&page=1': (200, {}, []),
    f'/repos/acme/repo/commits/{PARENT}': OSError('offline fixture'),
}
try:
    github.enrich(client(responses)[0], HEAD, [HEAD])
except ValueError as exc:
    print('SH-02', json.dumps({'expected': 'retryable named enrichment gap', 'raised': str(exc)}))
else:
    raise AssertionError('head request did not reproduce the uncaught exception')

u = baseline(context(root / 'empty-ranking', 'analyze.rank'))
settings = parse_settings(u.job.config.settings)
changes = document(u, u.outputs['acquire.normalize_changes'])['changes']
metrics = signals.compute_signals(
    changes, {c['change_id']: {'formatting': 'heuristic'} for c in changes}, {},
    eligible=u.outputs['resolve_sources.bind_snapshot']['eligible'], roots=[('.', 'component')],
    anchor_time=STAMP, window_months=6, half_life_days=90, minor_author_share=0.05,
    fix_interval_days=30, filters=settings.filters)
u.outputs['analyze.compute_signals'] = {
    'artifact': artifact(u, 'formatting-signals.json', metrics), 'rank_exclusions': {}}
ranked = invoke(u)
u.outputs['analyze.rank'] = ranked
parsed = changelog.parse(b'2023-11-14 Author\n  * a.py: fixed crash\n',
                         settings.changelog, signals.classify_text)
summary = changelog.summarize([{'path': 'ChangeLog', 'parsed': parsed}],
    catalog={'a.py': u.outputs['resolve_sources.bind_snapshot']['eligible']['a.py']['sha256']},
    root='.', window_months=6, bulk_threshold=500)
u.outputs['acquire.changelog_history'] = {
    'terminal_status': 'SUCCEEDED', 'gaps': [], 'gap_codes': [],
    'artifact': artifact(u, 'changelog.json', summary),
    'ranked_file_count': 1, 'entry_count': 1, 'bound_file_count': 1}
with patch.object(job, '_run_history_identity', return_value='identity'):
    published = invoke(replace(u, unit_id='publish.publish_handoff'))
doc = document(u, published)
assert doc['ranking']['files'] == [] and doc['changelog']['role'] == 'supplement'
print('SH-03', json.dumps({'git_ranked_files': ranked['ranked_file_count'],
    'expected_role': 'primary', 'actual_role': doc['changelog']['role']}))

u = baseline(context(root / 'proportional', 'analyze.rank', overrides={
    'proportional_ratio': 1.0, 'min_hotspots': 50, 'max_hotspots': 2000}))
metrics = document(u, u.outputs['analyze.compute_signals'])
base_file = metrics['files']['a.py']
base_facts = u.outputs['resolve_sources.bind_snapshot']['eligible']['a.py']
metrics['files'] = {
    f'f{i:03}.py': {**deepcopy(base_file), 'path': f'f{i:03}.py'} for i in range(201)}
u.outputs['resolve_sources.bind_snapshot']['eligible'] = {
    p: {**deepcopy(base_facts), 'source_path': p} for p in metrics['files']}
u.outputs['analyze.compute_signals']['artifact'] = artifact(u, 'many-files.json', metrics)
job._validate(u.job, None)
ranked = invoke(u)
u.outputs['analyze.rank'] = ranked
hotspots = document(u, ranked, 'hotspots')
schema = json.loads(Path('docs/schemas/history-hotspots.schema.json').read_text())
errors = [{'path': '.'.join(map(str, e.absolute_path)),
           'validator': e.validator, 'limit': e.validator_value}
          for e in Draft202012Validator(schema).iter_errors(hotspots)]
with patch.object(job, '_run_history_identity', return_value='identity'):
    published = invoke(replace(u, unit_id='publish.publish_handoff'))
assert len(hotspots['entries']) == 201 and len(errors) == 2
print('SH-04', json.dumps({'configured_settings_valid': True,
    'artifact_cap': hotspots['hotspot_count'], 'actual_entries': len(hotspots['entries']),
    'schema_errors': errors, 'publication_cap': document(u, published)['hotspots']['hotspot_count']}))

old = 'c' * 40
raw = (header(HEAD) + b'0\t0\t\0a.py\0b.py\0' +
       header(PARENT, STAMP - 86400) + b'0\t9\tb.py\0' +
       header(old, STAMP - 2 * 86400) + b'2\t0\ta.py\0' + b'9\t0\tb.py\0')
normalized = signals.normalize(git.parse_log(raw), current_paths=['b.py'], shallow=(),
    window_months=6, max_changes=20, bulk_threshold=500)
actual = [(c['change_id'][0], [(f['path'], f['current_path'], f['added'] + f['deleted'])
           for f in c['files']]) for c in normalized['changes']]
assert normalized['changes'][1]['files'][0]['current_path'] == 'b.py'
print('SH-05', json.dumps({'expected_old_destination_binding': None, 'actual_changes': actual,
    'expected_current_lineage_churn': 2, 'actual_current_lineage_churn': sum(
        f['added'] + f['deleted'] for c in normalized['changes'] for f in c['files']
        if f['current_path'] == 'b.py')}))
print(f'reproducer_elapsed_seconds={time.perf_counter() - start:.3f}')
```

**All five expected discrepancies reproduced; process exit 0; elapsed body 1.340 s.** These assertions confirm observed faulty behavior, not that it is correct. No test assertions or repository files were changed.

One source-inventory command encountered absent WSL `rg` (exit 127); subsequent searches used the authorized UNC tools. No dependency was installed. This was an inspection-tool limitation, not a failed test.

## Read scope and unverified material

**Read fully:** authorized `AGENTS.md` and multi-session skill; all 15 Python modules in `src/appsec_review/jobs/job_source_history_analysis/`; `jobs/source_lanes.py`; all 15 job unit test files, `support.py`, `syntax_fixture.py`; canonical `docs/operations/job_source_history_analysis.md`; hotspot JSON Schema; T-171 task document; `tests/conftest.py`; environment guard; `scripts/run-tests.sh` and `scripts/lib/common.sh`.

**Read relevant ranges or searched:** source-history architecture lines 1–445; central TOML job block and profile proportional settings; registry and topology; runtime unit dispatch, accepted-upstream and control validation; Tree-sitter shared output verifier; dataset consumers and indexing interfaces identified above; test-map entry; tool catalog entries; test-wrapper parser/execution/report code; TODO T-027/T-028/T-029/T-097/T-147/T-171 and relevant matches; preceding session reports and local history for this job.

**Material unread/unexecuted scope:** real integration fixtures and their executions; later architecture sections beyond the sampled range; full independent operations guide; remaining shared runtime/storage/signing/retrieval internals; real Git stdout across platforms, merge/rename varieties and resource-limit enforcement; all-language Tree-sitter execution/grammar fidelity; actual GitHub payloads, permissions and rate behavior; full composed-source live acquisition/resume/publication; complete downstream jobs and real review findings/output usefulness. No answer keys or target checkouts were read.

Cleanup completed: removed only this audit's reproducer, pytest working directory and explicit collection directory. Retained the wrapper evidence listed above and the small unit host-pins fixture used by the reproducer. Final HEAD remained the authorized revision and `git status --porcelain` remained empty. No source correction or manual validation is implied by this handoff. Stop point: **job_source_history_analysis only**.
