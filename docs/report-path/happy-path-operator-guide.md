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
export REPO=/absolute/path/to/appsec-review
export APPSEC_RUNS_ROOT=/absolute/path/to/appsec-runs
export RUN_ID=<engagement-run-id>
export RUN_ROOT="$APPSEC_RUNS_ROOT/$RUN_ID"
export JOBS_ROOT="$RUN_ROOT/data/jobs"
```

Configuration sources are the staged engagement definition and permission grant, registry job
templates and output contracts, pinned tool images, model registry/ceilings, and offline reference
snapshot registry. Target content is evidence data and may not alter those controls.

## 2. Start and inspect the orchestrator

```bash
docker compose -p appsec-review up -d
orchestrator/dagster/code-location.sh start
python3 appsec-review-process/launch_job.py --run-id "$RUN_ID" --job full_review --wait
```

The launcher can also run bounded standalone jobs such as `full_review_input_assembly`,
`owasp_join_report`, and `synthesis_report`. Use the job catalog for exact inputs and outputs. A
Dagster success is necessary but not sufficient: verify the accepted pointer, result envelope,
artifact hashes, permission receipt, lineage and reported coverage.

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
data flows and evidence coverage. `02-full-review-input-assembly` revalidates a supplied closed
launch plan and emits bounded requests for analysis families.

Current operator gate: automatic derivation of that complete launch plan and automatic dispatch of
all emitted requests are not yet integrated. Supply the reviewed plan explicitly; do not invent or
silently omit components.

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

The lifecycle `synthesis_report` job consumes exact accepted inputs and publishes `report.json`,
`report.md`, coverage appendix, trace index, publication manifest, LaTeX presentation input,
HTML and render manifests. Its publication status must remain
`DRAFT_EVIDENCE_BACKED`, with `final=false` and `human_signoff=false`, until the final gate is
human-authorized.

```bash
python3 appsec-review-process/launch_job.py \
  --run-id "$RUN_ID" --job synthesis_report --wait
```

Inspect all findings against cited evidence, all unresolved items, tool and control denominators,
snapshot age, source/build identity, threat conflicts and the two claim-ledger heads. A clean-looking
report with incomplete coverage is not a clean assessment.

## 8. Current stop conditions

The nominal workers and retained fixture qualifications exist. Stop short of final publication if
any of these remain true:

- the full-review plan or request dispatch was not automatically derived and explicitly reviewed;
- OWASP dispatch facts were supplied but not automatically derived from trusted inputs;
- the report was not produced by one retained real accepted upstream chain; or
- a human has not authorized final publication.

Those are the current four known integration gates. They must appear in the draft limitations.

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
