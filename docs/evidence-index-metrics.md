# Evidence-index language/size metrics (V15 / F01)

ADR-0010 decision G10 = B: one language/size enrichment inside `02-evidence-index` replaces the
legacy `cloc` and `scc` runner steps. This document is the design, the rule tables' rationale, the
build-time bound and the requalification record. The legacy steps themselves are **not** removed
here; that is V14, and only after the requalification below is completed.

## What is published, and where

`manifest.json` of every `02-evidence-index` attempt gains two additive members:

| Member | Meaning |
|---|---|
| `metrics` | the metrics document; must satisfy `schemas/evidence-index-metrics.schema.json` |
| `metrics_sha256` | sha256 of the document's one canonical byte form (`evidence_store.metrics_bytes`) |

No existing manifest member changes and no file is added to the attempt. The contract
(`registry/output-contracts/evidence-index.json`) declares the member under `member_schemas` and
adds validation rules; its `required_files` are unchanged.

Why inside `manifest.json` and not a sibling `metrics.json`: `job_graph.composition` requires a
contract's `required_files` to be a subset of the job template's `outputs.files`, and the parity
manifest pins `schema_file: null` for this job, so a *required* sibling artifact or a
`result_schema` declaration needs edits to the job template and to
`design-parity-manifest.json`, both outside this slice. A sibling that the contract could not
truthfully call required would be worse than a member of a file that already is required and is
already covered by the accepted pointer's tree hashes. The canonical byte form plus
`metrics_sha256` keeps the property a sibling file would have given: two attempts, on any two
hosts, measured the same snapshot the same way exactly when their `metrics_sha256` agree.

Document shape (all objects closed, every property required):

```text
schema            "appsec-review/evidence-index-metrics/0.1"
rules_version     "1"
descriptive_only  true
line_rule         "bytes-bom-crlf-lf-cr"
snapshot          { source_fingerprint, file_set_sha256, files }
excluded_files    number of manifest.json excluded[] entries (not indexed, so not measured)
overall           { files, bytes, text_files, lines, blank_lines }
by_scope[]        { scope, files, bytes, text_files, lines, blank_lines }      sorted by scope
by_language[]     { language, files, bytes, text_files, lines, blank_lines }   sorted by language
groups[]          { scope, language, content, files, bytes, lines|null, blank_lines|null }
```

`groups` is the dataset, keyed and sorted by `(scope, language, content)`; `overall`, `by_scope`
and `by_language` are projections of it and are verified as such. A per-language map with dynamic
keys does not fit a closed-object schema, hence arrays of records. Sorting is by Unicode code
point (Python `sorted` on `str`), never locale collation.

There is deliberately **no per-file record**. File names in a reviewed repository are
attacker-controlled; the document is aggregate only, and path identity enters solely through the
`file_set_sha256` digest. There is no timestamp, host path, tool version or duration in it.

## Descriptive only

Metrics describe the size and composition of what was indexed. They are not evidence of review
coverage, code quality, reachability or analysis; they introduce no claim class, assertion or
claim type (the contract's `claim_types` is unchanged) and can promote nothing. No member is named
so that a consumer could read it as "analyzed", "scanned" or "covered". Their one intended use is
budgeting and orientation.

## Determinism rules (rules version 1)

Metrics are a pure function of the indexed `(path, exact bytes)` pairs: they are accumulated in
`collect` from the very bytes that were just hash-verified and stored as `objects/<sha256>`, in
the same pass, and can be recomputed later from `index.sqlite` `files` plus `objects/`. No live
tree is walked, and insertion order does not matter.

### Line counting: on bytes

1. If the content begins with the UTF-8 BOM `EF BB BF`, those three bytes are not line content.
   They still count in `bytes`. A BOM anywhere else is ordinary content.
2. A line terminator is `CR LF` (one terminator), a lone `LF`, or a lone `CR`. So `LF CR` is two.
3. `lines` = number of terminators, plus one if the bytes after the last terminator are non-empty.
   An empty file, or a BOM-only file, has 0 lines. A final line without a terminator counts.
4. A line is blank when its content is empty or only `0x20`, `0x09`, `0x0B`, `0x0C`. Non-ASCII
   whitespace (for example NBSP) is content.
5. Nothing else splits a line. In particular `VT`, `FF`, `FS/GS/RS`, `NEL` and `U+2028/2029` do
   not, so these counts can differ from the line numbers of the full-text index, which uses
   `str.splitlines()` on decoded text. Metrics are not citations; citations keep using the index.

Git newline conversion therefore changes the snapshot (different bytes, different `sha256`,
different `file_set_sha256`), never the rule. An identical snapshot gives an identical document on
Windows and Linux; a checkout that converted `LF` to `CRLF` is not an identical snapshot, but its
`lines`/`blank_lines` still agree because of rule 2.

### Content kind

| `content` | Rule | `lines`, `blank_lines` |
|---|---|---|
| `binary` | contains a `0x00` byte (this includes UTF-16/32 text) | `null` |
| `undecodable` | no NUL, but not strict UTF-8 (Latin-1, CP1252, encoded surrogates, …) | `null` |
| `text` | everything else, including empty files | integers |

Binary and undecodable files are counted as files and bytes under their language label and scope;
they are never skipped. In the projections, `lines` sums text files only and `text_files` says how
many files that was. This is independent of the index's `text_status`: a text file over the
full-text byte or line-length limit is not searchable but is still measured as text.

### Language table

Closed, in-module (`_LANGUAGE_BY_FILENAME`, `_LANGUAGE_EXTENSIONS`), mirrored as the schema `enum`,
with a test that the two agree. Order of rules: exact lower-cased file name (`Makefile`,
`CMakeLists.txt`, `Dockerfile`, `go.mod`, …); then a `dockerfile.` prefix; then the extension after
the last dot when the name has a non-empty stem (so `.gitignore` has no extension, `.eslintrc.json`
is JSON); otherwise `unclassified`. Lower-casing is ASCII-only, so no Unicode case rule or locale
can move a file. Every extension maps to exactly one label (tested).

Rationale: labels follow the names `cloc`/`scc` users expect (`C/C++ Header`, `Protocol Buffers`)
so the numbers are recognisable, but the table is a label by file name and nothing more. It is
deliberately short: a wrong-but-confident label is worse than `unclassified`, which is published,
never dropped.

### Scope table

Each indexed file is in exactly one closed scope, by path only, first match wins:

| Order | Scope | Rule (ASCII lower-cased segments) |
|---|---|---|
| 1 | `review-evidence` | path is under `evidence/` (accepted intake / build-discovery outputs the index also holds) |
| 2 | `vendored` | any directory segment in `3rdparty bower_components extern external node_modules third-party third_party thirdparty vendor vendored` |
| 3 | `generated` | any directory segment in `.generated __generated__ autogen generated`; or file name in the lockfile list (`package-lock.json yarn.lock pnpm-lock.yaml Cargo.lock go.sum poetry.lock Pipfile.lock composer.lock Gemfile.lock`); or suffix in `.pb.go .pb.cc .pb.h _pb2.py _pb2_grpc.py .g.cs .designer.cs .generated.cs .min.js .min.css` |
| 4 | `first-party` | everything else |

Scope is a label. Nothing is dropped because of it: totals are published per scope and overall,
and tests prove sum-over-scopes = sum-over-languages = overall, and file count = number of indexed
files. `first-party` means only "no vendored/generated rule matched".

### Paths

One spelling per file: an indexed path must start with `source/` or `evidence/` and have no empty,
`.` or `..` segment, else the attempt fails with a fixed message that does not quote the path. A
path measured twice is refused.

## Bindings and verification

`evidence_store.check_metrics(attempt, rederive)` — both arguments required, `rederive` must be a
`bool`. In order:

1. `metrics_sha256` equals the sha256 of the member's canonical bytes (before anything in it is used);
2. the member satisfies the schema; `descriptive_only` is the literal `true`;
3. `snapshot.source_fingerprint` = `manifest.source_fingerprint`;
4. `excluded_files` = `len(manifest.excluded)`;
5. groups unique and sorted; counts non-negative integers; `lines`/`blank_lines` null exactly for
   non-text; `blank_lines <= lines`; no empty group;
6. `overall`, `by_scope`, `by_language` equal the projections of `groups`;
7. `snapshot.files` = `overall.files` = `manifest.files`;
8. `snapshot.files` and `snapshot.file_set_sha256` equal the row count and digest of the
   `files` table of `index.sqlite` (sorted `(path, sha256, bytes)`);
9. with `rederive=True`: every object is re-read, checked against its indexed sha256 and size,
   re-measured, and the recomputed canonical bytes must equal the published ones.

Error messages are fixed strings; no value read from the attempt is echoed. The function returns a
freshly parsed copy on every call: a cache for the caller, not an authority.

Where it runs: `run()` calls `check_metrics(attempt, False)` in the post phase, before the pointer
is built, so a bad or missing metrics member is a `FAILED` attempt and never accepted. After
acceptance, the pre-existing verifier (`validate`: accepted pointer tree hashes) binds every byte
of `manifest.json`, so any later edit is `index artifact integrity mismatch` for every query.
`validate`, `query` and `evidence_mcp.py` are unchanged. Step 9 is not run by the worker (it is a
second read of the snapshot); `qualify_evidence_index.py` runs it, and any consumer that relies on
the numbers should. Stated limit: without step 9, a forger who rewrites `groups`, all three
projections and `metrics_sha256` consistently passes steps 1–8 — but cannot do so on an accepted
attempt without failing the tree-hash check.

## Identity change

`inputs()` already fingerprints `worker_sha256 = sha256(evidence_store.py)` and the full registry
composition (which includes the contract record). Both changed, so the input fingerprint of every
run changes. Consequences, each proven by a test in
`tests/test_evidence_index_metrics.py::IdentityChangeTests`:

- a pointer accepted under the prior identity still verifies and can be read with `fresh=False`
  (`validate(fresh=False)`, `query(..., fresh=False)`): integrity-readable;
- with freshness (the default, and what MCP/CLI use) it is `index is stale; rerun evidence_index`;
- `run()` does not reuse it: a new attempt is allocated, no reuse receipt is written, the old
  attempt's bytes are untouched; the new attempt is then reused normally;
- a prior attempt has no `metrics` member and `check_metrics` says so rather than inventing one.

## Differences from `cloc` / `scc` (read before comparing numbers)

- No comment/code separation and no complexity. Only `lines` and `blank_lines` are published; a
  comment count that is exactly deterministic and honest across ~80 syntaxes (strings, nesting,
  heredocs) was not achievable in this slice, so none is published. `lines` corresponds to
  `blank + comment + code` of `cloc` for LF/CRLF files.
- Labels come from the file name only: no shebang or content detection, no disambiguation of
  `.h` (C vs C++), `.m` (Objective-C vs MATLAB), `.ts` (TypeScript vs Qt Linguist), `.v`, `.pl`, `.r`.
- `cloc` skips duplicate files and unknown types; here every indexed file is counted once,
  duplicates included, unknown types as `unclassified`.
- A lone `CR` ends a line here; `cloc` would see one long line.
- The population is the index, not the tree: files excluded by accepted intake scope and files over
  the 8 MiB per-file limit are not indexed and so not measured (`excluded_files` counts them;
  `manifest.excluded[]` names them). The index's own `evidence/` inputs are included, under
  `review-evidence`.
- Scope is path-only: no `linguist-generated`, no "DO NOT EDIT" header sniffing, no submodule
  detection.

## Build time

Host: Linux 6.9.3 (Pop!_OS kernel), AMD Ryzen 7 7735U, 16 threads, ext4 on local NVMe, CPython
3.12.3, SQLite from that Python; scratch on the same ext4 NVMe volume. **Not** the pinned runtime: `libfuzzy.so.2` is absent on this host, so
the benchmark used a trivial non-ssdeep stand-in library built outside the repository. Real ssdeep
is slower, so absolute times below are lower than production and the *relative* cost of metrics is
over-stated. Input: `git archive` of `origin/main` at `c797943`, indexed through the real
`collect()` of `origin/main` ("before") and of this branch ("after"), alternating order, fresh
attempt directory each run.

| Input | Runs | before min / median / max (s) | after min / median / max (s) |
|---|---|---|---|
| 1 085 files, 14.3 MB, 253 631 lines | 7 each | 7.52 / 9.07 / 11.32 | 7.63 / 7.66 / 11.62 |
| same tree copied 8× (8 666 indexed files, 114.1 MB, 2 029 006 lines; identical objects are stored once) | 5 each | 12.74 / 13.55 / 16.51 | 13.32 / 17.19 / 17.75 |

Collect time is dominated by one `fsync` per stored object and is bimodal on this host (the same
code lands at either ~13 s or ~17 s on the 8× input), which is far more than the effect being
measured: on the small input the medians come out in the "wrong" order, on the 8× input the
"after" median looks 27 % worse. Neither is the metrics cost. To separate it, one process ran the
branch's `collect()` six times on the 8× input, alternating the real `MetricsTally.add` with a
no-op and timing the seconds spent inside `add`: real 13.35 / 16.20 / 13.39 s total with
0.495 / 0.491 / 0.488 s inside `add`; no-op 15.60 / 12.80 / 12.81 s total. So the slow mode
appears with and without metrics, and the metrics path costs a steady ≈0.49 s per 114 MB
(≈3.8 % of the fastest 8× collect; min-to-min +4.5 % and +1.4 % in the table). Measured in isolation on the same bytes already in memory (9 runs), the whole metrics path
(classification, UTF-8 check, line count, document) takes 0.053 s median / 0.055 s max for the
14.3 MB input, about 258 MiB/s, i.e. ≈0.7 % of the fastest observed collect. The post-phase
`check_metrics(attempt, False)` costs 0.004 s (0.027 s on 8×); the optional `rederive=True` costs
0.10 s (0.75 s on 8×): a second read, hash and measure of every object.

**Recorded bound.** On the same input and host, the metrics path adds at most
`max(0.5 s, 5 %)` to `collect`; in isolation it must sustain at least 100 MiB/s, which caps its
cost at about 5 s for the 512 MiB snapshot budget against a 600 s job timeout. A change that
breaks either number is a regression to investigate. Metrics read no file a second time: they use
the buffer already read, hashed and stored by `collect`.

## Requalification record

**Requalified on Linux, 2026-09-20: `PASS`.** Windows is still outstanding (last paragraph).

| Field | Value |
|---|---|
| Date | 2026-09-20 |
| Command | `python3 -B appsec-review-process/qualify_evidence_index.py --run-id 20260920T220000Z-v15requal`, resumed with `--engagement-run-id 20260920T215639Z-94abfb` after the two host blockers below |
| Result | **`PASS`** — checks: live Dagster success, immutable reuse, separate streams, FTS citations, snapshot read, ssdeep similarity query, MCP initialize/tools/list/tools/call, metrics re-derived from index.sqlite and objects |
| Report path | `appsec-review-process/runs/20260920T220000Z-v15requal/data/qualification/evidence-99e9c424/report.json` (under the ignored `runs/` root; never tracked) |
| Report sha256 | `db324444f12bacc878292ba78ee5f5cf615de70438e0124d7aebb8815289feb8` |
| Engagement run id | `20260920T215639Z-94abfb` |
| Dagster run ids | `76a604cd-7afe-4809-b985-f4e0edee62ab` (first), `3fcdd4b7-32f6-46a5-a287-1de6c063945b` (reuse) |
| Attempt id | `08020154848b4aeb9a7ba49ccfddc345` |
| `metrics_sha256` | `06f5517972808ea01c5dd671512b2882f1f2af631dcc375ad57b14801509a361` |
| Worker | `evidence_store.py` sha256 prefix `ce3fdbb35fe0d222`, identical on the host and inside the container |
| Image | `appsec-review-dagster:local`, id `sha256:722e3187531cd7fed354eb2b3711abbc3c0f74d75be04d1ae769d6b485fa99b7`, built from `orchestrator/dagster/Dockerfile` on this branch; Python 3.12.14, dagster 1.13.21, libfuzzy2 `2.14.1+git20180629.57fcfff-3+b2` (real ssdeep) |
| Target | Freeciv21 `https://github.com/longturn/freeciv21` at `0ce1c60acf1140d6c5c5a5cd6bef2507bd072319`, the revision `docs/phase-1-acceptance.md` records |
| Host | Ubuntu 24.04, Docker 29.1.3, Compose 2.40.3, native Linux (not Docker Desktop) |

What the run measured on Freeciv21: 6 101 files, 252 312 338 bytes (equal to `snapshot_bytes`),
3 017 text files with 3 510 686 lines of which 501 597 blank, 112 excluded, 23 languages, 27 groups.
The text-file count equals the index's own `indexed` + `line length limit` + `text byte limit`
(2 964 + 42 + 11), and binary + not-UTF-8 (3 081 + 3) is the remainder. Scopes present:
`first-party` 6 098 and `review-evidence` 3. **No file was labelled `vendored`**, although
Freeciv21 bundles third-party code under `dependencies/`: that directory name is not in rules
version 1's vendored table. It is a known labelling limit, not a counting error; adding the name is
a rules change (`METRICS_RULES_VERSION` bump) and therefore another identity change.

Time, with real ssdeep: the qualifying `collect` took 47.6 s for the 252 MB snapshot against the
600 s timeout; `check_metrics(attempt, False)` took 0.021 s and `check_metrics(attempt, True)`
0.94 s on that attempt. The share of the 47.6 s spent in the metrics path was not measured in this
run; at the 0.49 s per 114 MB measured above it would be about 1.1 s (roughly 2 %), inside the
recorded bound.

Focused suites inside the Linux code-server (same image, real libfuzzy): `test_evidence_index_metrics`
33 OK, including `GOLDEN_SHA256`; `test_evidence_store` OK. The first attempt found that
`test_evidence_index_metrics` could not be imported there: it built paths from
`<repo>/appsec-review-process`, and the container mounts the tree as `/opt/process` beside
`/opt/schemas`. It now locates the schema and the contract the way the worker does
(`schema_validate.SCHEMAS_DIR`, `evidence_store.ROOT`). Only the test module changed after the
qualifying run; `evidence_store.py` and the registry, which are the worker's identity, did not.

Two host blockers were met before the pass. Both come from the stack's containers running as root
on a native Linux host, neither involves the worker, and both are shared-surface follow-ups:

1. Everything a container creates under the bind-mounted `runs/` is owned by root, so the host-side
   `launch_job.py` (uid 1000) could not create `data/orchestration/launches`. Worked around with
   `chown -R` of that one run directory from inside the container, then the qualifier's documented
   resume.
2. git inside the container refused the uid-1000-owned `/targets/freeciv21` ("dubious ownership");
   `00-intake` correctly went `BLOCKED` instead of guessing a source identity. Worked around with
   `git config --system --add safe.directory /targets/freeciv21` inside the running containers
   (container-local; lost when they are recreated).

An earlier run on the same host, before the stack existed, is superseded: run id
`20260920T000000Z-v15host`, `FAILED` at `create` (`docker compose` absent), report sha256
`d228cdb3ed5a4dc19797173ab654ca26da708b98570077f998c62ae17406cbe2`.

`qualify_evidence_index.py` gained additive checks so that a rerun stays meaningful for the new
identity: after the first launch it re-derives the metrics with `check_metrics(attempt, True)`,
asserts they cover `manifest.files` and `manifest.snapshot_bytes` and that both projections sum to
the file count, records `metrics_sha256` in the report, and re-derives again after the reuse
launch. Those lines ran for the first time in this qualification.

**Still outstanding before V14 may proceed:** the focused suites on Windows, confirming
`GOLDEN_SHA256` there. It has now been computed on the Linux host and in the Linux code-server,
never on Windows.
