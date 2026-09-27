# Operator guide: qualified happy path to a draft report

This guide runs the implemented path to a hash-bound `DRAFT_EVIDENCE_BACKED` report. It does not
authorize a final assessment. The companion diagrams are [Mermaid](happy-path-flow.mmd) and
[BPMN 2.0](happy-path-flow.bpmn).

## 1. Prerequisites and configuration

Required: Linux/WSL, Python 3.11+, Docker, the Dagster code-location environment, sufficient disk
for pinned images and offline vulnerability snapshots, and an authorized target checkout. Validate
the repository before starting:

```bash
python3 appsec-review-process/validate_design_parity.py --check-generated-views
python3 docs/processes/job_catalog.py --check
python3 -B images/tool_pins.py check
```

Define explicit, absolute run paths. Never reuse an accepted attempt directory.

```bash
export REPO=/home/wsollers/projects/appsec-review
export APPSEC_RUNS_ROOT="$REPO/appsec-review-process/runs"
export RUN_ID=<engagement-run-id>
export RUN_ROOT="$APPSEC_RUNS_ROOT/$RUN_ID"
export JOBS_ROOT="$RUN_ROOT/data/jobs"
```

Create and stage the run before starting Dagster. `run_process.py` owns the run directory and
`stage_artifacts.py` owns the engagement definition; do not create either by hand. This Hello
example grants the minimum run-local permissions required by the automatic evidence workers. It
does not grant live-network access or unrestricted target execution.

```bash
cd "$REPO"
python3 -B appsec-review-process/run_process.py --run-id "$RUN_ID" --start
python3 -B appsec-review-process/stage_artifacts.py \
  --run-id "$RUN_ID" \
  --project hello-autotools \
  --target /home/wsollers/projects/appsec-review/fixtures/targets/hello-autotools \
  --business-goal "Complete evidence-qualified application security review of hello-autotools with final PDF and HTML publication." \
  --platform Linux \
  --budget full \
  --permission read-source \
  --permission read-run-data \
  --permission write-run-data \
  --permission read-offline-snapshots \
  --execution-environment dagster-read-only-linux
python3 -B appsec-review-process/build_resolution.py stage-control "$RUN_ID"
python3 -B appsec-review-process/build_configure.py stage-control "$RUN_ID"
python3 -B appsec-review-process/offline_evidence_control.py stage-control "$RUN_ID" \
  --snapshot-registry "$REPO/appsec-review-process/offline/dependency-snapshots" \
  --max-database-age-seconds 1209600 \
  --reference-table "$REPO/data/reference/dependency-lifecycle-reference.json" \
  --max-reference-age-days 30
```

The build control commands retain the engagement owner's run- and source-bound authorization for
package resolution and no-network replay of the accepted configure/build lock. They do not grant
arbitrary commands: the workers still enforce the closed command profiles, pinned images, target
path, expiry, and exact permission decision. The offline-evidence command performs no download: it
fails closed unless both immutable database generations and the lifecycle table already resolve,
rehash, and satisfy the explicit age ceilings. The engagement ceiling for the Grype and OSV
databases is 1,209,600 seconds (14 days; William, 2026-09-27, ADR-0010 M4). The registry directory
`appsec-review-process/offline/` is host-local and ignored by Git. Snapshot synchronization remains a separate,
permissioned maintenance operation. Test execution requires a separate explicit control
after the accepted native-build unit and the target's real test command are known; do not invent a
test command or result path during initial staging.

The dependency snapshot publisher retains OSV ecosystem archives at the scanner's fixed cache
path. For Grype v6 `tar.zst` releases it performs `grype db import` and `grype db status` with the
pinned Grype image, network disabled, before immutable registration; a raw `vulnerability.db`
archive is not a usable cache and must not be registered as though it were one.

For the Hello Autotools workflow, if an earlier `full_review` attempt has retained the accepted
single native-build unit but stopped at the explicit test gate, stage the closed `make check`
authorization and resume the same run:

```bash
python3 -B appsec-review-process/test_evidence.py stage-control "$RUN_ID"
python3 appsec-review-process/launch_job.py --run-id "$RUN_ID" --job full_review --wait
```

The generated control deliberately declares unsupported result format and no coverage artifact;
the execution therefore remains evidence-backed `OK_WITH_GAPS` unless the target later publishes
JUnit/LCOV output. A successful command is never relabeled as coverage evidence.

Offline vulnerability and standards snapshots are configured outside the engagement and then
hash-bound when consumed. Confirm the configured snapshot registries are current before launch;
do not replace a missing or stale snapshot with a live network lookup.

Configuration sources are the staged engagement definition and permission grant, registry job
templates and output contracts, pinned tool images, model registry/ceilings, and offline reference
snapshot registry. Target content is evidence data and may not alter those controls.

## 2. Start and inspect the orchestrator

```bash
docker compose -p appsec-review -f orchestrator/dagster/compose.yaml up -d
orchestrator/dagster/code-location.sh check
orchestrator/dagster/code-location.sh reload
python3 appsec-review-process/launch_job.py --run-id "$RUN_ID" --job full_review --wait
```

If `check` fails, run `orchestrator/dagster/code-location.sh start` in a dedicated service session,
wait for `Started`, then run `reload` and the launch command above from the operator terminal.
`start` remains in the foreground. If `check` succeeds, do not start a duplicate server: reload the
existing code location. The bounded standalone jobs are diagnostics and qualifications only; they do not
replace the authoritative `full_review` engagement. A Dagster success is necessary but not
sufficient: verify the accepted pointer, result envelope, artifact hashes, permission receipt,
lineage and reported coverage.

## 3. Prepare source, build and searchable evidence

Intake fixes target identity, source commit, scope and permissions. Discovery partitions the
repository into independently buildable projects and operational surfaces. The isolated build lane
runs with no network and imports only allowlisted artifacts. Analysis then publishes:

- source SAST, including Go, Java and PHP;
- secrets, IaC, image, SBOM, offline SCA, licence and dependency-lifecycle evidence;
- native SAST, LLVM IR, Joern AST/CPG, test and ELF hardening evidence;
- literal/full-text and LanceDB semantic search projections; and
- cross-references between components, files, symbols, build units, binaries and dependencies.

For SCA, seed Grype/OSV snapshots through the maintenance sync outside the engagement flow. The
engagement binds exact snapshot bytes and accepts only the configured age window. Do not enable
network access to make a stale scan pass.

## 4. Characterize components and assemble review requests

`01-component-characterization` derives stable components, ownership, languages, trust boundaries,
data flows and evidence coverage. `02-full-review-input-assembly` revalidates the accepted component
map, staged target, source generation and available prerequisites; deterministically derives the
closed plan; records absent input classes as `SKIPPED_NA`; and automatically dispatches every
applicable first-wave request.

The dependency branch is intentionally wave-based. Reinvoke the assembler after accepted SBOM,
licence and SCA prerequisites appear. It revalidates their pointers, envelopes, artifact hashes and
source generation before dispatching newly applicable licence, SCA, lifecycle and reachability work.
Do not hand-edit the plan or convert a prerequisite wait into `SKIPPED_NA`.

## 5. Run threat and standards branches

Run these branches separately and retain separate accepted attempts:

1. L6A produces the initial DFD and STRIDE candidates; L6B reconciles them with accepted evidence,
   retaining conflicts and model coverage.
2. OWASP T03-T14 routes controls by component, validates ASVS/MASVS work, and publishes deterministic
   pages plus the control matrix, coverage gaps and candidate routes. Automatic derivation of trusted
   OWASP dispatch facts is still an explicit operator gate.
3. STIG/SRG produces a platform-tailored validation worklist.
4. Deployment hardening consumes the STIG/SRG worklist and deployment evidence. It does not replace
   either standards process and does not issue a compliance certificate.

## 6. Run claim review rendezvous

Candidate admission creates ledger entries, not findings. The red-team pool proposes adversarial
hypotheses. The blue-team pool tries to refute or narrow each hypothesis. Independent verification
alone may verify a claim. Deterministic merge waits for all expected terminal results, retains
dissent, validates citations and ordering, and applies evidence/diversity quorum. Lane 12 scores only
independently verified claims.

If a member is missing, timed out, canceled or blocked, retain that state as a coverage gap. Never
reduce the expected-member manifest after dispatch to force a rendezvous.

## 7. Generate and review the report

The `full_review` lifecycle invokes `synthesis_report` with exact accepted inputs and publishes `report.json`,
`report.md`, coverage appendix, trace index, publication manifest, LaTeX presentation input,
HTML, PDF and render manifests. Its publication status must remain
`DRAFT_EVIDENCE_BACKED`, with `final=false` and `human_signoff=false`, until the final gate is
human-authorized.

Inspect all findings against cited evidence, all unresolved items, tool and control denominators,
snapshot age, source/build identity, threat conflicts and the two claim-ledger heads. A clean-looking
report with incomplete coverage is not a clean assessment.

## 8. Current stop conditions

Stop short of final publication whenever final preparation fails, or whenever its retained control
evidence identifies anything beyond the expected `human_signoff_missing` blocker. In particular,
incomplete completeness obligations, nonterminal resynthesis, a rescope plan that still
requires another iteration, an uncovered final-publication node, an orphan remediation retest, an
authorized proposal without exactly one same-environment retest, or a non-fixed retest are real
evidence/control blockers. They must be corrected or retained as unresolved evidence; human
approval cannot override them.

Quorum decisions that retain conflicting evidence or insufficient diversity are not erased and do
not suppress the draft. They remain unresolved report dispositions, with their counts and exact
evidence bindings retained by publication preparation for human review.

When those controls are satisfied, `full_review` retains the evidence-backed HTML/LaTeX/PDF draft and a
`PENDING_HUMAN_APPROVAL` preparation result. This is a successful draft outcome, not final
publication. A named human must approve the exact draft report hash through the authorized
append-only signoff workflow before `final_publication.py` may create the immutable final package.

For presentation review, compare the retained
[happy-path demo PDF](../report-examples/appsec-review-happy-path-demo.pdf) and
[HTML](../report-examples/appsec-review-happy-path-demo.html). The pair is marked DEMO and is not a
production assessment. The report HTML currently references external fonts and KaTeX scripts; the
operator and design-document HTML publications are self-contained, but this demo report HTML is not.

## 9. Troubleshooting

| Symptom | Action |
|---|---|
| Offline vulnerability DB missing or stale | Run the snapshot maintenance sync; retain the age/error. Do not use live lookup. |
| ELF hardening result absent | Confirm native-build output and build identity reached `binary_hardening`; do not scan an unrelated host binary. |
| Joern or IR result has no cited source | Reject the producer; require bounded records with source location and build identity. |
| OWASP join rejects output | Check dispatch-fact identity, control denominators, page manifest hashes and deterministic page order. |
| Rendezvous never closes | Inspect expected members and durable terminal states; preserve blocked/missing members. |
| Synthesis reports `OK_WITH_GAPS` | Read the limitations and coverage appendix; this is an honest accepted draft state. |
| Dagster shows old definitions | Run `orchestrator/dagster/code-location.sh reload`. |
