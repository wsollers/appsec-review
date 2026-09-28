# Scale audit: static limits we would exceed on an Unreal Engine-sized target

Status: **audit, 2026-09-28.** Written while freeciv21 and doom3-bfg were running (William: "do a
pass that looks for static limits that we'd exceed if we built Unreal Engine"). Nothing here is
fixed yet except where noted. It is the backlog for making the pipeline work at engine scale; fix
items as real targets reach them (ADR-0013), in the order of the priorities at the end.

## Planning envelope

Measured so far:

| Target | Files | Joern raw output | Joern records | CPG as one JSON |
|---|---|---|---|---|
| hello-autotools | 24 | small | ~thousands | 5 MB |
| freeciv21 | 6,100 (299 MB) | 169 MB | 668K (593K kept) | 580 MB |
| doom3-bfg | not yet counted | 271 MB | 1.08M (1.02M kept) | ~1 GB |

For Unreal Engine we plan against an envelope, not a measurement: **~100K source files, ~20M
lines of C++, a 50 GB checkout once dependencies are fetched, ~10M+ CPG records (~10 GB), builds
that need tens of GB of RAM and hours of CPU.** That is roughly 15-20x freeciv21. When a real
engine-sized target runs, `orchestrator/size-report.py` replaces these guesses with numbers.

## Principle: index-first

Anything that grows with the target is stored as records (JSONL or SQLite), indexed into the
evidence index with partition and component ids, and reached by query. Nothing that grows with the
target is loaded whole into memory, copied per consumer, or pasted into a prompt.

- **Models** work index-first: `evidence_search`, `evidence_derived` and `input_jq` to locate,
  then `input_read` for the exact lines. Tool descriptions and the lookup-mode prompt say so as of
  this audit, and `retrieval-report.py` shows whether jobs comply.
- **Producers** publish a small summary plus a records file with its hash and count, as the CPG does
  now (`code-property-graph.records.jsonl`, on branch `cow-install`).
- **Consumers** stream records, never `read_json` a whole large artifact.

## Where it breaks

Verdict key: **breaks** = stops the run today; **degrades** = runs but slow, truncated or memory
heavy; **ok** = already scales or already logs. "EE" = expected at engine scale.

### A. Whole-checkout reads (architectural; fix first)

| Limit | Where | Value | EE | Verdict | Direction |
|---|---|---|---|---|---|
| Source fingerprint total | `intake.py` | 4 GiB, raises | 50 GB checkout | **breaks** | Scope excludes for binary content and fetched dependencies; log the size; the streaming hash already scales |
| Evidence index files | `evidence_store.LIMITS.max_files` | 20,000, raises | ~100K text files | **breaks** | Log, not cap; shard the index per partition if one SQLite file gets slow |
| Evidence index bytes | `evidence_store.LIMITS.max_total_bytes` | 512 MB, raises | several GB | **breaks** | Same |
| Model readable inputs | `persona_invocation` resolve / `ReadableInput.data` | every file read into memory and hashed per call | GBs per model call | **breaks** (memory) | Pin by the intake snapshot's per-file hashes; serve bytes lazily from the checkout and verify the hash on read |
| Lookup staging | `claude_cli_invoker._stage_inputs_for_mcp` | copies every pinned byte to /tmp per call | GBs per call | **breaks** (disk/time) | Same lazy serving; no copy |
| `input_grep` | `input_mcp.py` | Python scan of all files per call | minutes per call | **degrades** | Route whole-repo searches to the FTS index; `input_grep` only with a prefix (tool text now says so) |

### B. Single-document results (split into records + index)

| Limit | Where | Value | EE | Verdict | Direction |
|---|---|---|---|---|---|
| Result artifact size | `validate_job_output.MAX_RESULT_BYTES` | 8 MB | native/source SAST, IR facts (1.5 MB on hello-autotools already), binary intelligence, SBOM all exceed | **breaks** | Records-file pattern per producer; the limit protects memory, so keep it for the summary |
| CPG | `joern_cpg` | one JSON | ~10 GB | fixed on branch | JSONL records, streamed into the index |
| Redaction of published trees | `evidence_redaction.DEFAULT_LIMITS` | 2,000 files, 128 MB total, 16 MB per file | SAST/tool output trees | **breaks** (publication refused) | Raise and log; redact records streaming |
| Critical-findings SARIF input | `critical_findings_sarif.MAX_INPUT_BYTES` | 4 MB | large SARIF | **breaks** | Stream SARIF runs/results |
| Job handoff inputs | `create_job_handoff` | 16 MB each, 64 MB total | large upstreams | **breaks** | Hand over references (path + hash), not bytes |
| Pool / OWASP documents | `pool_specification.MAX_DOCUMENT_BYTES`, `owasp_dispatch` | 8 MB | many partitions | **degrades/breaks** | Same |
| Build index | `build_index.MAX_INDEX_BYTES` | 512 KB, validation error | thousands of `*.Build.cs`/`*.Target.cs` | **breaks** | Records file; `MAX_SCAN_BYTES` 2 MB per-file truncation is fine |
| IR size | `ir_b13_toolchain.MAX_IR_BYTES` | 64 MB per module/link | engine modules | **breaks** | Per-module IR only, no whole-program link; log sizes |
| Binary raw output | `binary_evidence_adapter.MAX_RAW_BYTES` | 16 MB | engine binaries | **breaks** | Records file |
| Container stdout/stderr | `container_execution` bound | 16 MB max (build: 1 MB) | build logs | **degrades** | Logs to files; parse the file (the copy-on-write installs read these logs for missing packages) |

### C. Compute envelopes (per job, set in code)

| Limit | Where | Value | EE | Verdict | Direction |
|---|---|---|---|---|---|
| Build trial/replay | `build_resolution`, `build_replay` | 2 GB RAM, 2 CPUs, 1,800 s | tens of GB, many cores, hours | **breaks** | Derive from the host and a per-target size class; UE also needs its own dependency fetch (`Setup.sh`), not just apt |
| Joern | `joern_cpg` | 8 GB, 3,600 s | ~100 GB heap for one CPG | **breaks** | One CPG per partition/module, merged in the index |
| Source SAST / vendor tools | `source_sast`, `vendor_evidence_b13`, `dependency_b13_adapters` | 2-4 GB, 900 s | hours | **breaks** | Size class; shard by partition |
| Native SAST | `native_sast` | 4 GB, 2 CPUs | hours (the clang analyzer especially) | **breaks** | Shard by compile-database entries |
| Persona timeouts | `persona_dispatch` budgets | 900-3,600 s | index-first keeps calls small | **ok** if index-first holds | — |
| Container bounds | `container_execution.LIMIT_BOUNDS` | 64 GB RAM, 64 CPUs, 24 h, 4 GB tmpfs | enough per shard | **ok** | — |

### D. Fan-out counts

| Limit | Where | Value | EE | Verdict | Direction |
|---|---|---|---|---|---|
| Pool instances / groups | `pool_specification` | 64 / 32 | hundreds of engine modules | **breaks** | Batch partitions per instance, or log and raise |
| Attempt tree entries | `persona_invocation.MAX_ATTEMPT_ENTRIES` | 100,000 | only if inputs land in the attempt | **ok** today | Keep inputs out of attempt trees |
| Producers / tools per invocation | `persona_invocation` | 64 / 64 | fine | **ok** | — |
| argv size | `container_execution` | 256 members, 64 KB | file lists on argv | **degrades** | Pass file lists as files |
| Concurrent runs | `resource_pools.OUTER_LIMITS` | 2 | we ran 3 without it stopping anything | **check** | Confirm what enforces it before relying on it |

### E. Already removed or logged (2026-09-27/28)

Model input count (256), static-intelligence files/records (200/1,000), evidence-index producers,
records and links, Joern bytes/records (including the exporter's own 50,000), build-discovery
bytes, CPG schema maxima. All now call `size_log.observe`. The per-call return windows
(`input_read` 400 lines, `input_jq` 64 KB, inline 150 KB, inventory 300 rows) scale because the
model narrows its query; they are not data caps.

## Priorities

1. **Lazy, hash-verified input serving** (A: readable inputs, staging). Without it every model job
   on a large target reads the whole checkout into memory.
2. **Records-file pattern for every producer over a few MB** (B), with streaming consumers and index
   ingestion. The CPG change is the template.
3. **Evidence index without file/byte caps**, sharded if needed (A).
4. **Partitioned heavy tools** (C: Joern, SAST, native analysis) and a per-target size class for
   container resources.
5. **Fan-out limits** (D) when a target first needs more than 64 pool instances.

Sources for the envelope: size measurements from our own runs (`size-report.py`); Unreal Engine
figures are an order-of-magnitude planning assumption, not a measurement.
