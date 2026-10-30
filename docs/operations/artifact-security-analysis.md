# Produced-artifact security analysis

`job_artifact_security_analysis` consumes the accepted `job_language_build` publication and the
accepted, hash-verified `job_artifact_indexing` handoff derived from it. The two handoffs must bind
the same language-build identity and target snapshot. It never walks the target tree to find
outputs. Every analyzed object must have an accepted run-relative path, SHA-256, byte count and
producer identity. Build outputs additionally bind a build unit; prebuilt target artifacts instead
bind their target-intake catalog handoff and exact target-relative path, without claiming a build
occurred. Unknown delivery status remains a coverage gap, not exclusion from conservative analysis.
Before any payload access, each capability applies the artifact's
[delivery scope lane](performance-assurance.md#delivery-scope-roles) and records a per-artifact
scope disposition. Target-lane rows reach every capability. Supply-chain rows, including installed
npm packages with role `runtime_dependency` or `build_dependency`, reach only `inventory`,
`packages`, `syft`, `grype` and `osv`, with one exception: a `runtime_dependency` row of kind
`executable`, `shared-library`, `native-addon` or `native-extension` also reaches `blint`. That is
production dependency machine code, such as a retained npm `.node` addon or a shared library a
target executable names in `DT_NEEDED`, which runs with the target. `build_dependency` binaries,
including addons of dev-only npm packages, stay out of `blint`, and the builtin `native` capability
still refuses every supply-chain row. blint's declared format gate then decides tool support as
for any other row. Evidence-lane rows reach only `inventory`.
A changed path, file, handoff, or index manifest is a framework-integrity
failure and stops publication.

Prebuilt objects retain content-addressed storage, but scanner invocation mounts only the selected
object read-only under its original basename in an otherwise empty target directory. This preserves
filename-sensitive tool behavior without copying payloads or mounting the whole shared object store.

The job classifies files from bounded magic bytes plus accepted producer metadata. A filename or
extension never classifies executable, object, or archive content. Supported families include ELF
and native objects/libraries, PE/COFF and managed assemblies, JVM class and archive outputs,
Node/Python/PHP packages and generated bundles, WebAssembly modules, and bounded archives. Media and
asset files are classified into family `media-asset` with a category-prefixed format (`image-png`,
`audio-ogg`, `font-truetype`, `model-fbx`, `texture-dds`, ...) from the typed declarations in
`appsec_review.media_assets`: by content first, and by suffix only when the bytes matched no other
format and the suffix names a media format and nothing else. Ambiguous suffixes (`.obj`, `.mod`,
`.ts`, `.pak`, `.bin`, ...) are never a fallback; a Wavefront `.obj` is recognized only from its
geometry directives, so an ELF or COFF `.obj` stays a native object. Archive inspection reads directory
metadata without extracting or executing members. Traversal, absolute paths, links, excessive
member count or size, expansion ratios, corrupt containers, and unsupported formats become precise
coverage gaps.

Pinned scanners run only on the inputs `appsec_review.tool_inputs` declares for them: BLint on
ELF, PE/.NET, COFF, Mach-O, and Android packages; SpotBugs on JVM classes and on archives that
contain `.class` members; osv-scanner on lockfiles and manifests it extracts offline (by file name,
`OSV_LOCKFILE_ECOSYSTEMS`); Syft and Grype on any produced artifact except media and asset files
(images, audio, video, fonts, 3D models, textures, game data), in which a package cataloger finds
nothing. That exclusion is a denylist of positively recognized formats rather than an allowlist,
because Syft also catalogs by file name and embedded content that classify as `unknown`. An artifact
outside a scanner's support is never launched and is counted per capability in
`not_applicable_inputs` as `SKIPPED_NA`, not as a gap; its row in that capability's
`scope_dispositions` also carries `format`, `input_disposition: SKIPPED_NA`,
`input_reason_code: INPUT_FORMAT_UNSUPPORTED`, and `input_reason`. A skipped artifact is never
evidence that it is clean. Syft and Grype also skip a verified installed npm package whose installer
record they scan, with reason code `INSTALLER_RECORD_COVERED` (see
[installed npm packages](#installed-npm-packages-one-scan-per-installer-record)).
Classification reads bounded member names: a jar holding only
`classes.dex` is `dex-archive` and a jar with no `.class` member is `jvm-resource-archive`, so
neither reaches SpotBugs (which would exit 1 with "No files to analyze could be opened"). Unix `ar`
archives (`.a` static libraries, Rust `.rlib`) are `ar-archive`: their members are listed from GNU,
BSD, and thin headers without extraction instead of being reported as corrupt.

BLint 3.4.0 has no JSON stdout: with `--reports /scratch` it writes `findings.json` (only when there
are findings), `reviews.json`, and one `<name>-metadata.json` per binary it analyzed.
`appsec_review.blint_report` assembles those into `blint-report.json`; a supported binary with no
metadata report is a gap ("blint produced no per-binary analysis report"), never a clean result.

osv-scanner 1.9.2 is invoked as `scan --experimental-offline --lockfile /target/<name>`: it selects
an extractor by file name and has no extractor for jars, wheels, Go/Rust binaries, objects, or
package metadata such as `PKG-INFO` or `composer.json` when handed the file. Only the lockfile's own
ecosystem from the verified OSV snapshot is bind-mounted read-only at
`/database/osv-scanner/<ecosystem>/all.zip`, because offline mode loads every mounted database
whole, and the container runs under `jobs.job_artifact_security_analysis.settings.osv_memory`
(default `3g`) instead of the uniform 1g scanner limit (npm's database alone is 368 MB of JSON). A
lockfile whose ecosystem the snapshot lacks is not launched and records the gap "offline OSV
snapshot lacks ecosystem <X>"; the same text replaces osv-scanner's exit-127 "could not find local
databases" report. Its exit-128 "No package sources found" report (an empty lockfile) is accepted as
`SKIPPED_NA`; any other non-zero exit is a gap carrying the last bounded stderr line, as are
timeouts and truncation.

## Installed npm packages: one scan per installer record

A verified installed npm package reaches this job as one supply-chain anchor row, its installed
`package.json` (see [installed npm dependencies](language-build.md)). Syft and Grype find nothing
in such an anchor: with a `file:` source Syft runs only its directory and file catalogers, and its
npm lock cataloger accepts only lockfile names such as `package-lock.json` outside every
`node_modules` directory. The install's own record, `<prefix>/node_modules/.package-lock.json`, has
the `package-lock.json` v3 format. Syft, Grype and osv-scanner therefore scan each record once
instead of each package it records (design:
[scanner launch reduction](../reviews/scanner-launch-reduction-design.md)).

**Staging.** A row whose `dependency_metadata` is exactly
`{"format": ".package-lock.json", "manager": "npm", "role": "installed-dependency-record"}` is
presented to Syft, Grype and osv-scanner as `package-lock.json` (`scanner_input` in
`jobs/job_artifact_security_analysis/scanners.py`, presentation
`appsec-review/npm-installed-record-as-package-lock/1`). The runner mounts the original record
read-only at `/target/package-lock.json` over an empty placeholder in the unit's
`installer-records/<token>/` scratch directory, outside every `node_modules` path. The record is
never copied or rewritten, and the scanner argv is unchanged. Only the Syft launch adds the
environment `SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true`. The presented name also drives the
declared format partition, so osv-scanner selects the record as an npm lockfile.

| Scanner | Launch per record | Expected coverage |
| --- | --- | --- |
| Syft | `file:/target/package-lock.json`, with dev dependencies included | Every non-`link` entry with a name, dev entries included. |
| Grype | `file:/target/package-lock.json` | Non-dev entries with a version. Grype 0.119.0 catalogs with its embedded Syft defaults, which drop npm dev entries, and has no switch for a `file:` source. The shortfall is a named gap (below). |
| osv-scanner | `--lockfile /target/package-lock.json`, only the npm offline database mounted | Every entry, dev included. A snapshot without npm gives the usual missing-ecosystem gap. |
| inventory | unchanged | Each anchor and the record, as rows. |

The expected coverage follows the pinned scanners' behavior. The integration test that launches
them on a staged record has been written but not yet run (see [tests](#installer-record-tests)).

**Skipped anchors.** Before its per-artifact loop, each Syft, Grype and osv-scanner unit collects
the covering records: record rows that the capability's lane admits and its declared format
partition supports, keyed by `(build_unit_id, workspace_path, sha256)`. In the Syft and Grype units,
after the lane gate and the format partition,
an anchor (`package_metadata.role` `installed-dependency-package` and `delivery_evidence.kind`
`npm-installed-record`) whose `build_unit_id` and `delivery_evidence` `workspace_path` and `sha256`
match a covering record is not launched. It is counted in `not_applicable_inputs` as `SKIPPED_NA`
with reason code `INSTALLER_RECORD_COVERED` and one reason per record:

`<capability> covers this package through one scan of installer record <record workspace_path> (sha256 <first 12 hex>)`

Its `scope_dispositions` row carries `format`, `input_disposition: SKIPPED_NA`,
`input_reason_code: INSTALLER_RECORD_COVERED`, `input_reason`, `input_covered_by` (the record's
`artifact_id`) and `input_evidence_ref` (`<record workspace_path>#<entry>`). A skipped anchor is
neither an observation nor a gap. An anchor with no covering record (record absent, outside the
lane, a different digest or build unit) is scanned as before. osv-scanner still skips anchors with
`INPUT_FORMAT_UNSUPPORTED`, and inventory still reads every anchor. Everything else is scanned per
file as before: retained native addons, shared libraries, symbol files and package archives under
a verified package, accepted `npm pack` members, root and workspace `package.json` files, project
lockfiles, and every per-file row of an unverified package or an unavailable record. pnpm, Yarn and
other ecosystems have no parsed installer record.

**Gaps.** After a covering record's scan, the unit adds these gaps, prefixed with the record's
`artifact_id` like other scan gaps. `<record>` is the record's `workspace_path`; counts are of the
anchors matched to it:

- Grype, when at least one matched anchor has `dev: true`:
  `grype: <N> dev-only packages recorded by <record> are not vulnerability-matched by the pinned grype (npm dev entries excluded); osv-scanner scans the same record`.
- Syft, Grype or osv-scanner, when the scan has gaps and no parsed result (`scan_outcome`
  `not_completed`):
  `<capability>: installer record scan of <record> did not complete; <M> verified packages recorded there have no <capability> coverage`.
  The scan's own timeout, exit-status or missing-ecosystem gap is kept as well.
- Syft, when a parsed scan does not report `K` of the `A` anchors' `(name, version)` pairs in its
  `artifacts`:
  `syft: <K> of <A> verified packages recorded by <record> were not reported by the installer record scan`.

**Installer-record summary.** Each `analyze.<capability>` output, and each capability's summary in
the published `accepted-analysis.json` next to `not_applicable_inputs`, has `installer_records`: one
entry per covering record the unit scanned, sorted by `artifact_id`.

```json
{"artifact_id": "...", "workspace_path": "node_modules/.package-lock.json", "sha256": "...",
 "presentation": "appsec-review/npm-installed-record-as-package-lock/1",
 "anchors_covered": 38, "dev_anchors": 30, "scan_outcome": "completed", "anchors_reported": 38}
```

`anchors_covered` counts the anchors skipped with `INSTALLER_RECORD_COVERED`, so it is 0 for
osv-scanner. `dev_anchors` counts matched anchors with `dev: true`. `scan_outcome` is `completed`,
`completed_with_gaps` or `not_completed`. `anchors_reported` is present for Syft only. The list is
empty for the other capabilities, and the key is null for a Grype unit disabled by
`tools.disable_grype`. The coverage key `produced-artifact-security` and its partial/complete rule
are unchanged.

**Finding attribution.** In `index.observations`, a Grype or osv-scanner finding whose scanned
artifact is an installer record is matched by `(package_name, package_version)` against that
record's verified anchors.

- On a match, the finding payload gets `installed_package_attribution: "verified-anchor"` and
  `installed_packages`: at most 64 descriptors sorted by `canonical_identity`, each with
  `canonical_identity`, `artifact_id`, `workspace_path`, `install_path`, `evidence_ref`, `dev`,
  `dev_optional` and `scope_role`. Above 64, `installed_packages_truncated` holds the total number
  of matches. The observation also gets one `OBSERVED_AT` relation (confidence 1.0) to every
  matched anchor's artifact entity, besides its relation to the record. An anchor entity missing
  from the shard is added with text `produced artifact package-metadata`.
- Otherwise the payload gets `installed_package_attribution: "unverified-record-entry"` and no
  extra relation. This covers an entry whose installed package failed verification, a `link`
  entry, or a name the scanner normalized differently. The finding stays observed at the record.

Nothing is attributed to per-file rows of unverified packages, and a record result never counts as
their coverage. Syft scan summaries and other summary records get no anchor relations, and finding
identity keys are unchanged.

**Launch counts.** For each covering record, Syft and Grype launch once instead of once per
matched anchor, and osv-scanner launches once on a record it previously could not read. In the
unit regression fixture (69 rows, 38 verified anchors, one record and one production addon), Syft
and Grype each launch 30 times instead of 68, inventory 69, osv-scanner 1 instead of 0, and blint 1.
Without the record the same tree costs 978 Syft and 978 Grype launches.

### Installer-record tests

The unit tests are in `tests/test_artifact_security_analysis.py`,
`tests/test_node_dependency_output_filtering.py` (the launch-count regression) and
`tests/test_tool_input_support.py`. The integration and acceptance tests are manual and run only at
the user's request:

- `tests/integration/test_installer_record_scans.py` launches the pinned Syft, Grype and
  osv-scanner images on the staged record of the dependency fixture. It also checks that Syft
  reports nothing for the unstaged `node_modules/.package-lock.json`. It skips, naming what is
  missing, without Docker, the cataloged `tool-syft`, `tool-grype` and `tool-osv-scanner` images,
  or verified grype and osv feed snapshots with npm data:

  ```bash
  python -m pytest -p no:cacheprovider tests/integration/test_installer_record_scans.py \
      --basetemp=test/tmp/installer-record-scans
  ```

- `tests/acceptance/test_dependency_output_bounds.py` reads a completed run. Its installer-record
  checks skip a run whose artifact-security publication predates `installer_records`:

  ```bash
  APPSEC_ACCEPTANCE_RUN_ROOT=runs/<run-id> python -m pytest \
      tests/acceptance/test_dependency_output_bounds.py --basetemp=test/tmp/dof-acceptance
  ```

## Units, recovery, and invalidation

Dagster exposes independent inventory, native, JVM, package, WebAssembly, SpotBugs, BLint, Syft,
Grype, and OSV capability units. Below that graph, each artifact/capability pair has a content-addressed shard
fingerprinted by:

- accepted artifact hash and detected format;
- producer/build identity and accepted language-build handoff;
- scanner, image, rules, parser, normalizer, and schema identities;
- for a Syft, Grype or osv-scanner scan of an installer record only, the `scanner_input`
  presentation (presented name, presentation identity and environment), so every other
  fingerprint is unchanged;
- the required upstream build-index manifest; and
- analysis limits from central configuration.

The repository default sets `[tools].disable_grype = true`. In that state the Grype unit does not
resolve an image, database, or runner and publishes `NOT_APPLICABLE` with a
`CONFIGURED_DISABLED` coverage gap. Set the typed Boolean to `false` to restore the ordinary
hash-verified scanner contract; this does not affect successful sibling evidence.

An interrupted attempt can reuse only shards whose fingerprints and raw artifact hashes still
match. Changing one artifact or scanner identity invalidates its dependent shards without forcing
unrelated siblings to rerun. Scanner failure is isolated to that artifact/capability pair; successful
siblings remain publishable with the failure represented as a gap. Upstream identity changes are not
recoverable scanner failures and stop the job.

Use `appsec-review plan-resume --run-id <id> --target <path>` before a consequential resume. Do not
delete locks, edit pointers, or modify accepted files to force reuse.

## Evidence and retrieval

For every attempted scan, stdout and stderr are retained under the immutable application attempt
with SHA-256, source byte count, capture limit, truncation state, optional tail identity, exit status,
timeout, duration, artifact identity, tool/image/rule identity, and attempt identity. Retrieval stores
only bounded sanitized observation records. The accepted observations manifest verifies the new
SQLite shard and the upstream artifact-index manifest, and retains the upstream index entries alongside
its observations. Standalone retrieval therefore keeps the artifact inventory, including distinct
target paths with identical bytes, available after security analysis. Observations resolve back to
exact run-owned raw artifacts without inventing source-line locations for binary inputs.

The [interchange upgrade](../architecture/job-interchange.md) adds common observation metadata
and native-result references to this scanner lane. The implementation keeps
`appsec-review/artifact-security-record/2` and `appsec-review/artifact-security-observation/1`,
with additive common/provenance metadata. Finding normalization is
`appsec-review/artifact-security-findings/3` (bumped for the installer-record attribution fields,
which rebuilds the observations shard but keeps scan checkpoints reusable), parser identity is
`appsec-review/artifact-security-parsers/3+<policy-identity>`, and normalization is
`appsec-review/artifact-security-normalizer/2` for retained parser-input semantics.
Keep original scanner result identity, parser, retained byte count/hash, selector, and completeness
alongside domain-specific artifact/package fields. A synthesized BLint report or partitioned result
must not replace the original report/invocation provenance. Distinct selectors/invocations remain
visible even when identical references coalesce or file bytes are stored once.
Only safe metadata enters indexes; retained scanner bodies remain protected run artifacts.
Missing provenance or bounded/truncated capture is a named gap, not a clean artifact verdict.

`SKIPPED_NA` scans retain their result/native/execution artifact closure even though they emit no
finding observations. Missing verified execution evidence is an explicit provenance gap.
Normalized Syft and BLint scan summaries retain counts rather than embedding full artifact/review
lists; Grype finding payloads keep compact package/advisory fields and a native match selector.
These bounded projections do not discard the retained native report or replace its provenance.
SpotBugs preserves native priority in common severity metadata, and bytecode findings remain
`source_sast` observations rather than inventory or confirmed findings.

Parser-input retention is separate from diagnostic head/tail capture. The typed setting
`jobs.job_artifact_security_analysis.settings.parser_input_limit_bytes` defaults to 67,108,864
bytes and must be positive. Retain the full native input within that bound so the parser and result
selector refer to the same bytes; `stream_limit_bytes` bounds diagnostic streams instead.
Exceeding the parser-input bound requires explicit partial coverage/truncation rather than parsing
an unrecorded complete report while citing a truncated diagnostic copy.
Diagnostic stdout/stderr truncation is independently reported as a coverage gap even when a
separate parser-input report is complete. Empty scanner JSON fails parsing rather than becoming
an empty successful observation.

Built-in parsers provide bounded inventory and structural metadata. Tool-dependent coverage is
explicit: unavailable BLint, Syft, Grype, OSV, native-symbol/hardening, JVM bytecode, or full WASM
policy tooling is recorded as a gap, never as a clean result. Tool output is evidence only and is not
an adjudicated finding.

For live acceptance, follow `deploy/dagster/README.md`, build the pinned scanner images, start a fresh
Dagster run against an applicable target, and retain its new verification receipt. Historical,
canceled, partial, fake-executor, or stale runs do not establish acceptance.
