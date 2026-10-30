# Scanner launch reduction: design

Status: design, not implemented. See [section 5](#5-implementation-chunks-and-file-ownership) for
the planned chunks.

Branch: `william-sollers-xbox-scanner-launch-reduction-design`, based on local `main` `6d7ecfe9`.
The implementation rebases or merges onto whatever local `main` is when it starts. In particular,
it must include the "Blint for production npm binaries" work (section 2) before it changes the
shared count test.

Line references are to `6d7ecfe9`. Paths without a prefix are under `src/appsec_review/`.

## 1. Problem

In live run `2026-10-29-0004`, `artifact_security_analysis` `analyze.syft` ran for 2.5 hours. It
runs serially and launches one container per artifact (`ContainerScannerRunner`,
`syft file:/target/<name>`), about 3 seconds each. 2,921 launches completed, and only 24 of them
returned any package. About 7,580 rows were eligible for syft, and 7,208 of those sit under
`node_modules`. That run predates the
[dependency output filtering](dependency-output-filtering-design.md) merge.

After that merge, a verified npm package's files are summarized and get no rows. Each verified
package still reaches the scanners as one anchor row: its installed `package.json`, with
`package_metadata.role` `installed-dependency-package`, scope role `runtime_dependency` or
`build_dependency`, the supply_chain lane, and `delivery_evidence`
`{"kind": "npm-installed-record", "workspace_path": "<prefix>/node_modules/.package-lock.json",
"sha256": ..., "entry": "<key>"}` (`job_language_build/node.py:341-345,517-534`). The record itself
is a `resolved-dependency-metadata` row with `dependency_metadata.role`
`installed-dependency-record` (`node.py:482-485`).

Each anchor and the record still cost one syft launch that finds nothing:

1. With a `file:` source, syft 1.52.0 runs only catalogers tagged for directories or files.
   `javascript-package-cataloger`, which parses `package.json`, is tagged for installed, image
   and language sources, so it does not run on an anchor.
2. The npm lock cataloger matches `**/package-lock.json` (and `yarn.lock`, `pnpm-lock.yaml`,
   `bun.lock`, `deno.lock`) by file name. `.package-lock.json` does not match.
3. `parse_package_lock.go` also returns nothing when the lock file's path contains a
   `node_modules` directory. Renaming the file in place would therefore not help. The file has to
   be presented outside any `node_modules` path.
4. grype 0.119.0 catalogs a `file:` source with its embedded syft, using
   `syft.DefaultCreateSBOMConfig()`. It inherits the same cataloger selection, so each anchor and
   the record cost one grype launch that finds nothing too.
5. osv-scanner 1.9.2 `--lockfile` picks its parser by file name. `package.json` and
   `.package-lock.json` are not lockfile names (`tool_inputs.py:74-91`), so osv has no npm coverage
   of the installed tree at all.

The regression test
`tests/test_node_dependency_output_filtering.py::test_scanner_inputs_are_bounded_to_package_anchors_with_exact_counts`
(lines 342-373) pins the effect on its fixture: 69 rows, 68 syft launches (38 of them anchors),
0 osv launches.

The user's direction: **skip syft and grype per package, and scan each install folder once using
its lock record.** The record has the same `lockfileVersion` 3 format as `package-lock.json`. When
staged under that name, one syft launch, one grype launch and one osv launch each cover every
package in the prefix.

## 2. Related efforts and file ownership

| Effort | State | Overlap |
|---|---|---|
| **Blint for production npm binaries** (session `6d386b1c`) | in progress; merges into local `main` before this implementation starts | Adds a narrow `jobs/delivery_scope.py` lane exception so blint scans native-binary rows in `runtime_dependency` packages. Changes the blint expectation in the shared count test from 0 to 1. This design assumes that state and does not touch blint or `delivery_scope.py`. |
| Dependency output filtering (merged, `3cf6b142`, docs `b91da4e4`) | done | Produces the anchor and record rows this design consumes. No change to `node.py` or `node_installed.py` is needed. |

Shared hotspots: `jobs/delivery_scope.py` (not edited here) and the count test in
`tests/test_node_dependency_output_filtering.py` (edited here, after the blint change lands).

## 3. Numbered decisions

### D1. Scope

| Item | Decision |
|---|---|
| npm installer records (`node_modules/.package-lock.json`) | **In scope.** This is the only installer-record classifier that exists (`node_installed.py`). |
| Anchor rows of verified packages | syft and grype are skipped (D2). inventory and osv are unchanged: osv already skips `package.json` with `INPUT_FORMAT_UNSUPPORTED`. |
| The record row | Staged as `package-lock.json` and scanned once per capability by syft, grype and osv (D3). |
| Retained native addons, archives and symbol files under a verified package | **Unchanged.** They are their own rows and are scanned as today. (Blint is handled by the other session; see section 2.) |
| Accepted `npm pack` members | **Unchanged.** |
| Unverified packages (mismatched, missing manifest and so on), per-file rows under an unavailable record, and every target-lane row | **Unchanged.** They stay per-file in the target lane and are scanned as today, including their `package.json`. Nothing from the record scan is attributed to them (D5). |
| Root and workspace `package.json` files, and project lockfiles | **Unchanged.** |
| Other ecosystems (pnpm, Yarn, Go `vendor/modules.txt`, Composer, Cargo, NuGet, Python) | Deferred. No installer record is parsed for them. The rule in D2 is keyed on `delivery_evidence.kind` `npm-installed-record`, so a later classifier adds its own kind and presentation. |
| Scanner parallelism, checkpoint reuse | Out of scope (section 6). |

### D2. Which rows are skipped, and the reason code

Before its per-artifact loop, the `analyze.syft` and `analyze.grype` handler
(`job_artifact_security_analysis/job.py:465-525`) builds a coverage map of **covering records**.
A row is a covering record for the capability when all of these hold:

- `dependency_metadata.role == "installed-dependency-record"` and
  `dependency_metadata.format == ".package-lock.json"`;
- `analysis_scope(row, capability)` allows it;
- `partition_artifacts` for the capability does not mark it not applicable, using the presented
  name from D3.

The key is `(build_unit_id, workspace_path, sha256)` of the record row.

In the loop, after the lane gate and the format partition, an **anchor** row is `SKIPPED_NA` for
syft and grype when all of these hold:

- `package_metadata.role == "installed-dependency-package"`;
- `delivery_evidence.kind == "npm-installed-record"`;
- `(row["build_unit_id"], delivery_evidence.workspace_path, delivery_evidence.sha256)` is a
  covering record's key.

If no covering record matches, the anchor is scanned as today. This covers a record rejected by
the lane gate, a deduplicated record, or a hand-built row. Fail-open keeps coverage.

New reason code: `ReasonCode.INSTALLER_RECORD_COVERED = "INSTALLER_RECORD_COVERED"`
(`applicability.py:62-83`). Add it after `TOOL_REPORTED_UNSUPPORTED_INPUT`, with a comment that an
input whose packages are covered by one scan of its installer record is not launched separately.
`InputDecision.__post_init__` (`tool_inputs.py:159-163`) accepts it. Update the error message to
"requires an input-support or installer-record reason code".

The skipped anchor is recorded like a format skip:

- an `InputDecision(artifact_id, "artifact:<tool_id>", INSTALLER_RECORD_COVERED, reason)` goes into
  `skipped`, and from there into `not_applicable_inputs`;
- `scope_dispositions[-1]` gets `input_disposition` `SKIPPED_NA`, `input_reason_code`
  `INSTALLER_RECORD_COVERED`, `input_reason` set to the reason, `input_covered_by` set to the
  record's `artifact_id`, and `input_evidence_ref` `<record workspace_path>#<entry>`.

The reason text is per record, not per entry, so `not_applicable_inputs.by_reason` groups by record:

`<capability> covers this package through one scan of installer record <record workspace_path> (sha256 <first 12 hex>)`

`<capability>` is `syft` or `grype`. Skipped anchors never call `_scan_one`, never produce an
observation, and are never a gap.

### D3. Staging the record (scanner input presentation)

Add one helper in `job_artifact_security_analysis/scanners.py`. Both `job.py` and the runner use
it, so the partition decision and the launch agree:

```python
INSTALLER_RECORD_PRESENTATION = "appsec-review/npm-installed-record-as-package-lock/1"
INSTALLER_RECORD_ENVIRONMENT = {"syft": {"SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"}}

def scanner_input(artifact: Mapping[str, Any], capability: str | None = None) -> Mapping[str, Any] | None:
    """The presented name and environment for a staged installer record, else None."""
```

It returns `{"name": "package-lock.json", "presentation": INSTALLER_RECORD_PRESENTATION,
"environment": INSTALLER_RECORD_ENVIRONMENT.get(capability, {})}` exactly when
`dependency_metadata` is `{"format": ".package-lock.json", "manager": "npm",
"role": "installed-dependency-record"}`. Otherwise it returns `None`.

Three call sites use it:

- `job.py` `_artifact_name` (lines 157-161) returns `scanner_input(artifact)["name"]` when the
  helper applies, before the existing target-intake and path branches. osv's path partition then
  selects the record (`package-lock.json` is an npm lockfile), and `classify` gets the presented
  name. Classification is unchanged, because `classify` consults the name only for media
  suffixes.
- `ContainerScannerRunner.__call__` (`scanners.py:208-263`) stages the record exactly like target
  intake (lines 218-226). It sets `input_name = "package-lock.json"` and
  `target_root = scratch_root / "installer-records" / token`, touches the placeholder, and adds
  `Mount(path, "/target/package-lock.json", read_only=True)`. The placeholder sits outside every
  `node_modules` path, which syft's lock parser requires. The original file is mounted read-only
  and is never copied or rewritten.
- The runner merges `scanner_input(...)["environment"]` into `environment` for the launch. Only
  syft gets `SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true` (D6). grype and osv need no
  environment.

`argv` is unchanged: it already uses `/target/<input_name>`.

### D4. How each scanner consumes the staged record

| Scanner | Launch | Covers |
|---|---|---|
| syft | `syft file:/target/package-lock.json --output json=...` with the D3 environment | Every non-`link` entry with a name, including `dev` entries (user decision, section 6). `devOptional` entries are already kept. |
| grype | `grype file:/target/package-lock.json --output json ...` (unchanged argv) | Every non-`dev` entry that has a version. grype 0.119.0 builds its own syft config with dev dependencies excluded and missing versions dropped, and it exposes no switch for a `file:` source. The dev shortfall is a named gap (D6). |
| osv | `osv-scanner scan --experimental-offline ... --lockfile /target/package-lock.json`, with only the npm offline database mounted (existing `osv_ecosystem` path) | Every entry in the record, dev included. A snapshot without npm gives the existing `osv_missing_ecosystem_gap`. |
| inventory | unchanged (built-in, reads the row as itself) | unchanged |

Exactly one launch per covering record per capability. The installer-record prefix bound (32 per
build unit) and dedup by `(sha256, path)` in `_accepted_artifacts` cap the launch count.

### D5. Attributing results to anchor rows

Attribution happens in `index` (`job.py:527-600`), from `loaded["artifacts"]`. Scanner checkpoints
are not affected.

1. Build `record_packages: dict[record canonical_identity, dict[(name, version), list[anchor]]]`.
   It covers every covering-record row (any capability) and its anchors, matched with the D2 key.
   Each anchor descriptor is:

   ```json
   {"canonical_identity": "...", "artifact_id": "...", "workspace_path": "<install_path>/package.json",
    "install_path": "...", "evidence_ref": "<record workspace_path>#<entry>", "dev": false,
    "dev_optional": false, "scope_role": "runtime_dependency"}
   ```

   `(name, version)` comes from `package_metadata`. Syft, grype and osv name an entry as
   `node_installed._entry` does: the entry's `name`, else the name derived from its path. So the
   pair is an exact join key.
2. For each grype or osv **finding** record whose scan `artifact.canonical_identity` is a key of
   `record_packages`, look up `(fields.package_name, fields.package_version)`:
   - On a match, the payload gets `installed_package_attribution: "verified-anchor"` and
     `installed_packages`, the matching descriptors sorted by `canonical_identity`, at most 64.
     More than 64 adds `installed_packages_truncated: <count>`. The index adds one
     `OBSERVED_AT` relation from the finding observation to each matched anchor's artifact
     entity, confidence 1.0, in addition to the existing relation to the record entity. It adds
     the anchor entity first if it is absent, in the same `EntityRecord` shape as
     `index` uses for scanned artifacts, with text `produced artifact package-metadata`.
   - With no match, the payload gets `installed_package_attribution: "unverified-record-entry"`
     and no extra relation. This happens for a record entry whose installed package failed
     verification (such as the fixture's `mismatch`), a link entry, or a name the scanner
     normalized differently. The finding stays observed at the record row.
   - Nothing is ever attributed to per-file rows of unverified packages.
3. Finding `identity_key`s are unchanged, so observation identities are stable.
4. Summary records are not given anchor relations.

Payload fields are added in `index`, not in `findings.scan_records`. `scan_records` keeps a single
argument and stays scanner-only. Because the payload changes, `FINDING_NORMALIZER` is bumped (D7).

### D6. Gaps and coverage text (exact)

These gaps are produced in the `analyze.<capability>` handler after the covering record's
`_scan_one` returns. They go into the capability's `gaps`, prefixed with the record's `artifact_id`
like other scan gaps. `<record>` is the record's `workspace_path`. Counts are of anchors matched to
that record (D2).

1. grype dev shortfall. One gap per covering record, when at least one matched anchor has
   `package_metadata.dev == true`:
   `grype: <N> dev-only packages recorded by <record> are not vulnerability-matched by the pinned grype (npm dev entries excluded); osv-scanner scans the same record`.
   This is a gap because grype does not match those entries. osv covers them.
2. Record scan did not complete (syft, grype or osv). If `scan_outcome(result)` is
   `not_completed` (no parsed observation), add
   `<capability>: installer record scan of <record> did not complete; <M> verified packages recorded there have no <capability> coverage`,
   where `<M>` counts all anchors matched to the record. The scan's own gaps (timeout, exit
   code, missing ecosystem) are kept as today.
3. syft shortfall. After a completed syft record scan, compare the anchors' `(name, version)`
   pairs with the reported `artifacts[].name`/`version`. If `K > 0` anchors are not reported, add
   `syft: <K> of <A> verified packages recorded by <record> were not reported by the installer record scan`.

The handler output gets a new key, `installer_records`: a list sorted by `artifact_id`, one entry per
covering record the capability saw. Each entry is:

```json
{"artifact_id": "...", "workspace_path": "...", "sha256": "...", "presentation": "appsec-review/npm-installed-record-as-package-lock/1",
 "anchors_covered": 38, "dev_anchors": 30, "scan_outcome": "completed", "anchors_reported": 38}
```

`anchors_reported` is present for syft only, and `anchors_covered` is 0 for osv because osv skips
no anchors. `publish` adds `installer_records` to each capability's summary next to
`not_applicable_inputs` (`job.py:603-606`). The coverage key `produced-artifact-security` and its
partial/complete rule are unchanged.

### D7. Identity and version changes

| Constant / material | From | To | Effect |
|---|---|---|---|
| `findings.py` `FINDING_NORMALIZER` | `artifact-security-findings/2` | `artifact-security-findings/3` | Rebuilds the observations index shard (`INDEX_NORMALIZER_IDENTITY`). Scan checkpoints stay reusable, as the comment at `findings.py:32-33` intends. |
| `_scan_one` fingerprint material (`job.py:228-237`) | — | adds `"scanner_input": scanner_input(artifact, capability)` **only when it is not None** | Only record-row checkpoints for syft, grype and osv change. Every other checkpoint fingerprint stays byte-identical. |
| `ADAPTERS[...].identity`, `PARSER_IDENTITY`, `NORMALIZER_IDENTITY`, `OBSERVATION_SCHEMA`, `RECORD_SCHEMA`, `SCHEMA` | unchanged | unchanged | Parsing is unchanged. Every new field is additive and optional. |
| `node.py` `CAPTURE_IDENTITY`, `tool_inputs.SCHEMA` | unchanged | unchanged | Language-build rows are unchanged. `InputDecision.as_dict` keeps its shape. |

### D8. Per-file rows of unverified packages

They are unchanged. They keep the target lane, the default role, and their gaps from the
language-build catalog. syft, grype and inventory scan them per file as today, and osv selects any
of them that are lockfiles. Their record entry is still in the staged record, so syft, grype and
osv may report it. Such results are labelled `unverified-record-entry` and observed at the record
only (D5). They never count as coverage of the per-file rows.

## 4. Test plan

Unit tests are run by the implementer in the focused loop. Integration and acceptance tests are
**written but not run**. They run only at the user's request.

### Unit tests (run)

| File | What it pins |
|---|---|
| `tests/test_node_dependency_output_filtering.py` (update) | The count test, below. |
| `tests/test_artifact_security_analysis.py` (extend) | (a) D2 skip: an anchor whose record row is present is `SKIPPED_NA`/`INSTALLER_RECORD_COVERED` for syft and grype, with `input_covered_by` and `input_evidence_ref` in `scope_dispositions` and the D2 reason text in `not_applicable_inputs.by_reason`. (b) No skip when the record row is absent, when its sha256 differs from `delivery_evidence.sha256`, or when its `build_unit_id` differs. (c) Retained `native-addon` rows with `npm-installed-record` evidence are not skipped. (d) osv selects the record and records the format skip for anchors as before. (e) `_artifact_name` returns `package-lock.json` for the record and the path name otherwise. (f) The `_scan_one` fingerprint for a non-record row equals the value computed without the `scanner_input` key. For a record row, it differs between syft and grype (environment). (g) D6 gaps 1-3 with exact text, using a stubbed runner that returns syft, grype and osv JSON. (h) `installer_records` in the handler output and in the published capability summary. |
| `tests/test_artifact_security_analysis.py` (extend) | Staging: monkeypatch `ContainerExecutor.execute` as in `tests/test_target_artifact_intake.py:185-218`, then run `ContainerScannerRunner` for syft, grype and osv on a record row. Assert the read-only mount `/target/package-lock.json`, a placeholder under `installer-records/<token>`, `file:/target/package-lock.json` or `--lockfile /target/package-lock.json` in argv, and `SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true` for syft only. |
| `tests/test_artifact_security_analysis.py` (extend) | D5 attribution: build the job, stub `_scan_one` or the runner to return fixed grype and osv JSON for the record (one match for a verified anchor, one for `mismatch@1.0.0`, one for a name that two anchors share at different install paths). Run `index`. Assert `installed_packages` and `installed_package_attribution` on the finding payloads, `OBSERVED_AT` relations to both anchor entities, no extra relation for the unverified entry, and unchanged finding identity keys. |
| `tests/test_tool_input_support.py` (extend) | `InputDecision` accepts `INSTALLER_RECORD_COVERED` and still rejects other codes such as `POLICY_DISABLED`. |
| `tests/test_scanner_normalization.py` (no change) | Its `RECORD_SCHEMA == /2` assertion stays true. No test asserts `FINDING_NORMALIZER` (checked at `6d7ecfe9`). |

**Count test.** `test_scanner_inputs_are_bounded_to_package_anchors_with_exact_counts`:

- Set `SCANNERS = ("syft", "grype", "inventory", "osv", "blint")`. The fixture's
  `SimpleNamespace(disable_grype=False)` already lets grype run.
- With the record: `len(rows) == 69`, and

  ```python
  {"syft": 30, "grype": 30, "inventory": 69, "osv": 1, "blint": 1}
  ```

  syft and grype get 68 − 38 anchors: the root `package.json`, `frontend/dist/app.js`,
  `frontend/dist/index.html`, the record, the `prod-00` addon, and the 25 `mismatch` rows. osv
  gets the record. blint gets the addon, after the blint session's change.
- Replace the syft/inventory dependency assertion:
  - for `syft` and `grype`, the `node_modules` launches are `{record, addon} | unverified`, and no
    anchor is launched;
  - for `inventory`, `anchors | {record, addon} | unverified`, as today;
  - `selected["osv"] == [record]`.
- Capture the handler outputs and assert 38 `INSTALLER_RECORD_COVERED` decisions each for syft and
  grype, all with the single D2 reason for `node_modules/.package-lock.json`.
- Without the record (unchanged mechanism):

  ```python
  {"syft": 978, "grype": 978, "inventory": 979, "osv": 0, "blint": 1}
  ```

  with no `INSTALLER_RECORD_COVERED` decision.
- The `< 2` second timing assertion stays.

### Integration tests (write, do not run)

New `tests/integration/test_installer_record_scans.py`, which implicit collection already excludes
(`tests/conftest.py:71`). It skips with a named reason unless Docker, the pinned images
`appsec-review/tool-syft:1.52.0`, `tool-grype:0.119.0` and `tool-osv-scanner:1.9.2`, and the
verified grype and osv feed snapshots are present. It reuses the fixture builder from
`tests/test_node_dependency_output_filtering.py` and runs real `ContainerScannerRunner` launches on
the record row:

- syft reports all 38 verified `(name, version)` pairs, dev included.
- grype completes and produces the D6 dev gap with `N == 30`.
- osv parses the record as npm and lists packages from it.
- Root-cause pin: syft on the same bytes mounted as `node_modules/.package-lock.json` (unstaged)
  reports 0 packages. If a future syft changes this, the test fails and the staging can be
  revisited.

### Acceptance tests (write, do not run)

Extend `tests/acceptance/test_dependency_output_bounds.py`. It reads
`load_accepted_artifact_security_analysis(run_root)` alongside the language-build receipts:

- No syft or grype observation exists for an `installed-dependency-package` row whose record row
  is in the same receipt. Each such anchor appears in `scope_dispositions` with
  `INSTALLER_RECORD_COVERED`.
- Each installer record has at most one observation per syft, grype and osv, and a matching
  `installer_records` entry.
- Every grype or osv finding observed at a record row carries `installed_package_attribution`.
- `syft` launches are bounded by (rows not covered by a record) + (records).

## 5. Implementation chunks and file ownership

The core change is one chunk. `job.py` holds the skip rule, the fingerprint material, the handler
output, the gaps and the index attribution. Splitting it would put two owners on one file. The
reason-code contract is too small to justify its own chunk. The integration and acceptance tests
only depend on the field names fixed above, so they can be written in parallel.

| Chunk | Files (exclusive owner) | Depends on |
|---|---|---|
| **I. Implementation and unit tests** | `applicability.py`, `tool_inputs.py`, `jobs/job_artifact_security_analysis/job.py`, `jobs/job_artifact_security_analysis/scanners.py`, `jobs/job_artifact_security_analysis/findings.py` (constant only), `tests/test_artifact_security_analysis.py`, `tests/test_tool_input_support.py`, `tests/test_node_dependency_output_filtering.py` | local `main` with the blint session merged. Rebase first, because that test is shared. |
| **T. Integration and acceptance tests** (optional parallel chunk) | new `tests/integration/test_installer_record_scans.py`, `tests/acceptance/test_dependency_output_bounds.py` | this design's contracts. Merge after I. Not run. |
| **E. Docs** (docs agent) | the pages in section 7 | I (and T for the testing notes) |

`jobs/delivery_scope.py`, `job_language_build/node.py` and `node_installed.py` are **not** edited.
`delivery_scope.py` keeps its CRLF line endings untouched.

## 6. Resolved decisions and open questions

Resolved (user decisions):

1. **Direction.** Skip syft and grype per package (option A) and scan each install folder once
   using its lock record (option B). Rejected: adding `--select-catalogers
   +javascript-package-cataloger`, because it keeps one launch per package.
2. **Dev-only packages.** The user chose the recommended option. syft includes dev entries
   (`SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true` on record launches). osv covers every entry.
   grype matches runtime entries only, with a named gap that counts the dev packages it skipped
   (D6.1). Before this change, a dev package's anchor got a grype launch that found nothing, so
   the gap reports a shortfall that already existed.
3. **Blint for native binaries in production npm packages** is handled by the "Blint for production
   npm binaries" session (`6d386b1c`), not here. This design assumes its count (blint 1).

Open questions (out of scope; recorded for follow-up, not blocking):

1. Every scan logs `CHECKPOINT_MISSED reason=missing_release_identity`, so retries do not reuse
   completed scans. That costs more than the launches this design removes on a retry.
2. Root, workspace and unverified-package `package.json` rows still get one syft and one grype
   launch each, which find nothing for the same cataloger reason. They are few per unit.
3. Whether target-intake `package-lock.json` inputs should also get
   `SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true`. This design limits it to installer records.
4. Feeding grype a syft SBOM (`sbom:`) instead of a `file:` source would match dev entries too and
   save grype's own cataloging. This was not chosen now.
5. Installer records for the other ecosystems (D1). Go `vendor/modules.txt` is next.
6. Running scanner launches in parallel.

## 7. Documentation pages for the docs agent

| Page | Change |
|---|---|
| `docs/operations/artifact-security-analysis.md` | The record staging (D3), the per-scanner coverage (D4), the skip and reason code (D2), the attribution fields (D5), the gaps (D6), `installer_records` in the receipt, and the `FINDING_NORMALIZER` `/3` bump (near lines 110-113). |
| `docs/operations/language-build.md` | In the installer-record section (about lines 385-400), state that the record row is what supply-chain scanners scan, and that anchors are covered through it. |
| `docs/operations/artifact-indexing.md` | Finding observations at a record row also have `OBSERVED_AT` relations to anchor entities (D5). |
| `docs/architecture/jobs-and-runtime.md` | Add `INSTALLER_RECORD_COVERED` where the reason codes and `SKIPPED_NA` inputs are described. |
| `docs/operations/performance-assurance.md` | Supply-chain scanner launches are now one per installer record, not one per package. |
| `docs/reviews/dependency-output-filtering-design.md` | A pointer from its status or D8 note to this design. |
| `docs/TODO.md` | Open questions 1-6 that are not already tracked. |
| This file | The status line and an implementation-status section, as in the filtering design. |
