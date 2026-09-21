# AppSec Review — Multi-Agent Architecture

**v3 — Static-First, Evidence-Qualified, Secure Build Isolation, Streaming Verification, Cross-Lane Synthesis**

Design document • September 2026. Exported from Google Doc 2026-09-11 (see ADR-0004).

## 1. Executive design summary

Mythos is a static/offline application-security review system designed to evaluate supplied source code, binaries, container images, infrastructure-as-code, build metadata, dependency inventories, configuration, repository history, and related evidence without interacting with live production systems. Local compilation is permitted only to enable higher-fidelity static analysis, especially for native C/C++ code.

The architecture separates four functions that must not collapse into one another for consequential findings:

1. Discoverers aggressively search a bounded security domain.
2. Refuters attempt to disprove, mitigate, or benignly explain discoveries.
3. Verifiers independently reproduce or confirm the underlying evidence.
4. Integrators connect independently verified facts across domains and produce the final security interpretation.

Governing principle: specialize discovery → diversify verification → centralize synthesis.

Mythos is explicitly non-short-circuiting. A Critical finding or NO-GO decision changes the decision state immediately, but it does not terminate the authorized review. Every required lane must still reach a recorded terminal state, every finding must receive a terminal disposition, and every escalation must be accounted for before the report may be marked FINAL.

## 2. Baseline operating boundary

### 2.1 Static/offline by design

- Source code, checked-in configuration, IaC, supplied images/binaries, SBOMs, lockfiles, manifests, build metadata, documentation, and static exports are in scope.
- Live cloud access, production connectivity, authenticated DAST, active endpoint probing, runtime packet capture, live service enumeration, and cloud configuration APIs are outside the baseline review.
- Local build/toolchain execution is permitted solely to recover compiler semantics and enable deeper static analysis.
- Reverse engineering, DAST, active fuzzing, live configuration review, and runtime telemetry are follow-on recommendations only when an evidence-qualified quorum determines they would materially reduce uncertainty.

### 2.2 Hostile build-execution boundary

Permitted:

- Generate compile_commands.json.
- Compile or syntax-check translation units.
- Run clang-tidy, Clang Static Analyzer, CodeChecker, cppcheck, Joern, and related static tooling.
- Build sanitizer-capable or parser harness artifacts only as preparation for analysis; do not exercise network services in the baseline review.

**Build-system execution is treated as potentially hostile arbitrary-code execution even when its sole purpose is to enable static analysis. Build scripts, generators, CMake/Make/FASTBuild hooks, package scripts, and compiler wrappers execute only inside a disposable isolated worker. The worker cannot write canonical evidence, findings, state, or the append-only ledger.**

- Prefer an ephemeral VM or microVM-class isolation boundary where host capability permits; sandboxed runtimes such as gVisor/Kata may be used when they satisfy the required isolation properties.
- No network access, reusable credentials, SSH agent, host home directory, host Docker socket, or cloud credentials are exposed to the build worker.
- Evidence inputs are mounted read-only; build output goes to a disposable writable scratch filesystem.
- Run unprivileged, drop unnecessary capabilities, apply syscall/resource restrictions, and enforce CPU/memory/process/time quotas.
- Destroy the worker after execution. Only explicitly allowlisted artifacts and logs may cross the import boundary.
- The trusted orchestrator validates imported artifacts, hashes them, registers them, and alone may append canonical ledger events.

### 2.2.1 Current implementation (Linux/WSL/Docker host) — added 2026-09-17

`images/audit-native/run.sh` is the host-side wrapper enforcing this boundary today for one
audit-native step at a time (the orchestrator calls it with a static argv; see the non-negotiables
in the architecture doc about static argv arrays vs. shell-string assembly). Its current profile:

- `--network none` — no network access, satisfying the boundary's no-network requirement.
  `--hostname audit-native --add-host audit-native:127.0.0.1` works around log4j treating an
  unresolvable self-hostname as a startup error under `--network none`.
- `--read-only` root filesystem, with three purpose-built tmpfs mounts: `/tmp` (`noexec,nosuid,nodev`,
  4g — a hostile build must not be able to drop and run a binary there), `/tmp/home` (same flags,
  1g, `$HOME`), and `/tmp/jvm` (`exec,nosuid,nodev`, 512m — the one exception: Joern's zstd-jni needs
  to `dlopen` a `.so` it extracts into `java.io.tmpdir`, so only the JVM gets an exec-allowed tmpfs).
- `--cap-drop ALL` and `--security-opt no-new-privileges` — no Linux capabilities, no privilege
  escalation via setuid/setgid binaries.
- `--user "$(id -u):$(id -g)"` — runs as the invoking host user (not root, not the image's built-in
  `worker` uid) so the scratch bind mount is writable without a privileged container.
- `--pids-limit`, `--memory`/`--memory-swap`, and `--cpus` quotas (defaults 2048 / 16g / 8, all
  overridable via env vars) — the CPU/memory/process quotas this section calls for.
- Evidence/workspace mounted read-only (`-v ...:/workspace:ro`), scratch mounted read-write
  (`-v ...:/scratch:rw`) — the read-only-inputs / disposable-writable-scratch split this section
  requires.
- No `--privileged`, no docker socket, no host home directory, no SSH agent or credentials exposed —
  enforced by the script's own header comment ("do not add --privileged, a docker socket, host home,
  or --network anything-other-than-none") as a standing instruction to anyone editing it.

**Not yet implemented:** a custom seccomp profile. Docker's own default seccomp profile applies (it
already blocks a broad set of dangerous syscalls), but no profile scoped to audit-native's actual
tool surface (clang-cl/clang, SVF, CSA/CodeChecker, cppcheck, Joern/JVM) has been written or
validated. Writing one is a moderate-risk task, not a pure doc change: an incorrectly restrictive
profile fails silently or noisily mid-build depending on which syscall it blocks, and validating one
requires running it against a real audit-native container across every tool in the image — something
that needs to happen in an environment that can actually execute Docker builds against this image,
not as a paper exercise. Tracked as a follow-up in the project TODO rather than attempted blind here.

**Not yet implemented: Windows/Hyper-V isolation.** The profile above is the Linux/WSL/Docker path.
The 2026-09-16 status log (git history) and the architecture doc confirm Windows PowerShell + Docker is a
validated, supported host path for the evidence pipeline generally, but no equivalent
snapshot-revert or Hyper-V isolation boundary has been designed or documented for the hostile-build
step specifically when run from that host path. This is a genuine open design gap, not just an
undocumented existing thing — noting it here so it isn't lost, but it needs its own design pass
(likely a Hyper-V checkpoint/revert wrapper analogous to `run.sh`, or accepting Docker Desktop's own
Linux-VM boundary as sufficient and documenting why) rather than a one-line fix.

## 3. Review flow and process

*Figure 1 (in Google Doc): initial threat model before discovery, streaming independent verification, follow-on escalation evidence returning through targeted verification, and synthesis from verified facts only.*

The review begins with a seeded validation gate and deterministic pregather, moves through parallel specialist discovery, then through independent verification and cross-lane synthesis. Temporary RE/DAST panels are instantiated only for evidence-backed escalation candidates; they do not perform the activity in the baseline lab.

## 4. Lane architecture

| Lane | Purpose | Primary outcome |
|---|---|---|
| L0 | Intake / scope / liveness | Enforces evidence sufficiency; produces scope, liveness, limitations, and artifact sufficiency. |
| L1 | SBOM / dependencies | Layered SBOMs, dependency resolution, EOL/abandonware, license inventory, CVE enrichment. |
| L2 | ASVS / MASVS controls | Requirement-by-requirement control assessment with Not-Investigated and N/A as first-class states. |
| L3 | Native build / SAST | Build fidelity, compiler-semantic static analysis, TU coverage, clang/CSA/Joern/cppcheck. |
| L4 | Application-security discovery | Conventional AppSec, server authority, authn/authz, injection, serialization, resource abuse, abuse cases. |
| L5 | Vendor / insider / malfeasance | Undocumented egress, hidden control paths, activation mechanisms, toolchain/build integrity, source/artifact divergence. |
| L4B / L5B | Blue-team refutation | Added 2026-09-17 to formalize existing harness reality (see §4.1): general and known-list refutation, defense/mitigation analysis, and residual-risk disposition, answering L4/L5 hypotheses one claim at a time before independent verification. Previously listed only as a reusable skill in §18 with no dedicated lane slot; the harness has run it as a dedicated lane since before this design revision, so this row documents what is actually built rather than introducing new scope. |
| L6A / L6B | Initial threat model / threat-model reconciliation | L6A defines components, trust boundaries, actors, data classes and initial STRIDE hypotheses before discovery; L6B reconciles the model using verified evidence before synthesis. |
| L7 | Independent verification | Streaming fresh-agent evidence-only verification as findings arrive, plus targeted re-verification of any new follow-on evidence. |
| L8 | Scoring / prioritization | CVSS 4.0 plus exposure, EPSS/KEV where applicable, confidence and trust classification. |
| L9 | Reporting | Deterministic executive/technical report generation, SARIF/JSON, architecture outputs and manifests. |
| L10 | Static protocol, parser & wire-format analysis | Static message/serializer/opcode/parser mapping, trust-assumption analysis, and candidate harness definitions; no live traffic or network fuzzing in baseline. |
| L11 | Remediation packages | Codebase-fitting patch proposals plus isolated syntax/type/build/test validation where feasible; validation status is explicit. |
| L12 | Supply-chain / provenance | Complete external-source inventory, pinning/integrity, provenance, release trust, SLSA/SSDF mapping. |
| L13 | Privacy / data protection | RoPA, legal-basis map, DSR, transfers, minors, on-device static analysis, privacy red/blue. |
| L14 | Cross-lane synthesis | Small integrator team correlates only verified facts into attack/control chains and escalations. |
| L15 | Static deployment hardening | Container/cloud/IaC hardening, declared network exposure, IAM, datastore, crypto, backup/recovery, logging. |

### 4.1 Current harness mapping (00–11 lanes)

The tracked process harness under `appsec-review-process/` currently runs as eleven numbered lanes
(`00`–`11`) rather than the eighteen slots above (`L0`–`L15`, with `L6` split `L6A`/`L6B`). This section
records the mapping as it exists today so the two documents can be reconciled incrementally instead of
silently drifting.

| Harness lane | Design lane(s) | Status |
|---|---|---|
| `00-intake-recovery` | L0 | Matches. |
| `01-component-characterization` | L0A | Matches (see §22). |
| `02-evidence-pregather` | — (infrastructure) | Runs the deterministic pipeline; not itself an L-lane. |
| `03-threat-model-dfd-stride` | L6A | Matches. |
| `04-asvs-masvs` | L2 | Matches. |
| `05-native-memory` | subset of L3 | Narrower than L3: covers native memory-safety only, not the full native-build/SAST scope L3 describes. |
| `06-cve-reachability` | L1 | Broadened 2026-09-17 to full L1 scope: dependency inventory, license inventory (re-surfacing the SBOM's own license field plus the pre-existing `scancode` license/copyright scan), best-effort EOL/abandonware signals (new `dependency-lifecycle` step against a small hand-curated, offline reference table — coverage is partial by design, see `data/eol-reference.json`), and CVE reachability triage. |
| `07-red-team-adversarial` | L4 / L5 | Restructured 2026-09-17: every scenario is now tagged with its design lane (`L4` AppSec discovery or `L5` vendor/insider malfeasance) as a first-class axis alongside the existing general/known-list mode axis, run within one lane folder rather than split into two — matching how the harness already treats mode as a run parameter rather than a folder split. |
| `08-blue-team-refutation` | L4B / L5B | Resolved 2026-09-17: added as a formal §4 row (`L4B`/`L5B`) rather than folded back into `07`, since the harness has run it as a dedicated lane and that was judged the better fit going forward. As of this revision it also carries the `L4`/`L5` design-lane tag through from `07`'s claims, so disposition can be reported per design lane. |
| `09-independent-verification` | L7 | Matches. |
| `10-synthesis-report` | subset of L9 / L14 | Covers report assembly and cross-lane synthesis; no longer scores findings itself (see next row). |
| `12-scoring-prioritization` | L8 | Added 2026-09-17: extracts CVSS 4.0 scoring, EPSS/KEV annotation, and priority ranking out of `10-synthesis-report` into its own step ahead of synthesis, using the §14 deterministic-derivation mapping. Runs after `09`/`11`, before `10` (see `process-manifest.json`'s `process_order`). |
| `11-remediation-proposal` | L11 | Matches. |
| `15-deployment-hardening` | L15 | Matches (added 2026-09-17; reuses `audit-iac`/`audit-container` evidence gathered by the existing pregather step). |
| — (unbuilt) | L6B, L10, L12, L13 | No harness lane exists yet; see the L3/L9 narrowing notes above and the standalone gaps list below. |

Unbuilt as standalone lanes: `L6B` (threat-model reconciliation), `L10`
(static protocol/parser/wire-format analysis), `L12` (supply-chain/provenance beyond SBOM), `L13`
(privacy/data protection). `L15` (static deployment hardening) has a harness lane as of this revision
(see §12 and `appsec-review-process/15-deployment-hardening/`). `L1` (2026-09-17: full scope, not
just CVE reachability), `L4`/`L5` (2026-09-17: explicit design-lane tagging within `07`), and
`L4B`/`L5B` (2026-09-17: `08` formalized as its own row) are now fully covered by existing harness
lanes; see the rows above for what changed.

### 4.2 L12 design note — native/vendored supply-chain inference (added 2026-09-18, design only, not yet implemented)

**Motivating gap, confirmed concretely on the `targets/eastl` run.** The `sbom` step's tool
(`syft dir:/workspace -o cyclonedx-json@1.5=...`) only extracts dependencies from files it
recognizes as package-manager manifests/lockfiles (`package.json`, `go.mod`, `requirements.txt`/
`poetry.lock`, `pom.xml`/`build.gradle`, `*.csproj`, `Cargo.lock`, `conan.lock`, `vcpkg.json`, etc.).
It has no reader for raw `CMakeLists.txt` dependency declarations and no ability to infer vendored
code with no manifest at all. On EASTL — a header-only C++ template library with only a
`CMakeLists.txt` and no lockfile — this produced exactly 4 "components," all GitHub Actions
CI-workflow references (`actions/checkout@v4` etc.), not EASTL's own tree. Once the real ScanCode
scan ran (2026-09-18), it directly disproved the "EASTL has no third-party code" reading of that
result: `3RDPARTYLICENSES.TXT` documents real vendored HP (1994) and LLVM/libc++ (2009–2015)
license/copyright text bundled in the tree, and 689 of 1317 scanned files carry real
license/copyright hits. The SBOM step is silently blind to all of it. This is expected behavior for
syft given its actual ecosystem support, not a bug in this repo's own code — but it means `L1`'s
dependency inventory is incomplete for exactly the kind of target (native C/C++, vendored-not-
packaged) this pipeline exists to review, and the gap will recur on `targets/idsoftware-doom3-bfg`
and the real engagement repo, not just here.

**Two tiers, decided 2026-09-18 with the repo owner:**

**Tier A — static, ScanCode-clustering heuristic (cheap, no build required, closes today's specific
gap).** A new deterministic script clusters ScanCode's existing per-file `license_detections`/
`copyrights` output into candidate "vendored component" entries: files sharing a directory,
license expression, and a copyright holder distinct from the project's own declared license become
one flagged pseudo-component, explicitly marked `confidence: "candidate — no package-manager
manifest, inferred from bundled license/copyright evidence"` (never promoted to a definitive SBOM
entry without a human or a later, stronger signal confirming it). Output feeds
`analyze_dependency_lifecycle.py` as a supplementary, clearly-labeled source alongside the syft-
derived component list, not a replacement for it. This is implementable and testable today against
the eastl evidence already on disk (it would surface `3RDPARTYLICENSES.TXT`'s HP/LLVM cluster as a
candidate component) and needs no pipeline reordering.

**Tier B — dynamic, post-build native-dependency inference (needs compiled/linked output; larger
design scope; placement decided below).** Per the repo owner's explicit direction, this job moves
to run *after* the hostile-build step, not alongside static evidence pregather, because it needs
real compile/link output to work from — not just source text. Two internal passes:

1. **Known/easy pass first**: run every popular native build-tool and package-manager's own
   manifest/lockfile reader across the tree before falling back to heuristics — CMake (via any
   `conan.lock`/`conanfile.txt`/`vcpkg.json`/`vcpkg-configuration.json` it references, not raw
   `CMakeLists.txt` parsing), Ninja, Make, Conan, vcpkg, Maven, Ant, Gradle, NuGet, pip/Poetry,
   Cargo, Go modules, npm/yarn — "whatever popular build and code-vendoring solution exists" per
   the repo owner. This is a broader-coverage superset of what `syft` already does for the
   ecosystems it supports, run explicitly rather than assumed complete.
2. **Heuristic pass for what's left unaccounted for**: only after the known/easy pass runs, inspect
   the actual build/link step's output (object files, static/shared libraries, linker command
   lines and logs, final binaries) for vendored code the manifest pass didn't catch. Heuristics to
   apply, per the repo owner's own list:
   - Semantic-versioning-aware parsing where it applies, with the explicit caveat that some vendored
     deps are old enough that strict semver parsing may not be meaningful — degrade gracefully
     (report a raw version string with low confidence rather than failing to match a semver regex).
   - Version signals hiding in: directory paths (`.../2.2.4/...`), filenames (`libraryA-20.4`),
     config files, header comments/includes, macro/`#define` constants, and version banners embedded
     as string/byte-array constants inside compiled binaries (a `strings`-style scan of build output
     for version-looking text near a product-name match).
   - Focus/prioritize heuristics on conventionally-named directories first — `lib`, `libs`, `sdk`,
     `tools`, `shared`, `libraries`, and their common siblings (`vendor`, `third_party`, `extern`,
     `deps`) — rather than scanning the entire tree with equal weight.

**Isolation and placement (decided 2026-09-18):**

- **New dedicated lane/step, not folded into `05-native-memory`'s evidence gathering** — the repo
  owner's explicit choice, to keep this on the `L12` supply-chain/provenance track (already listed
  as unbuilt in §4.1) as its own thing, rather than overloading native-memory's evidence scope.
  Concretely: a new evidence-gathering step (name/numbering TBD — needs a `process-manifest.json`
  slot, following the same "authoritative manifest order, not assumed numeric sequence" discipline
  bug #11 established) that runs after the hostile-build step, and a new harness lane consuming it
  that maps to `L12` in the §4.1 table (currently the `— (unbuilt)` row).
- **A separate, purpose-built isolated Docker image** for this step's tooling (the repo owner's own
  suggestion) — not merged into `images/audit-native`'s existing hostile-build worker. That worker's
  isolation profile (§2.2.1: `--network none`, `--read-only` root, no-exec tmpfs except the one JVM
  carve-out, `--cap-drop ALL`, tight pid/memory/cpu quotas) is scoped to the specific static-analysis
  tools it already runs (clang-cl/clang, SVF, CSA/CodeChecker, cppcheck, Joern/JVM); adding a wide
  matrix of package-manager CLIs and a binary-strings heuristic scanner to that same image would
  needlessly widen its surface. This new step should consume the hostile-build worker's *exported,
  allowlisted* artifacts (compile_commands.json, build/link logs, and whichever compiled
  binaries/objects the worker already exports across the import boundary per §2.2's "only explicitly
  allowlisted artifacts... may cross the import boundary" rule) rather than re-running or re-entering
  the hostile-build sandbox itself — so it needs standard read-only evidence-consumption isolation,
  not the same hostile-execution boundary as the build step.

**Open items before Tier B can actually be built (not resolved by this design note):**

- **Confirm exactly what the hostile-build worker currently exports across the import boundary.**
  `images/audit-native/run.sh`'s own header only documents the isolation profile, not the specific
  allowlisted artifact set (compile_commands.json is certainly produced per §2.2's "permitted" list;
  whether compiled object files/static or shared libraries/final binaries are also exported, or only
  logs and the compile database, is unconfirmed and needs to be checked against the actual
  native-pregather orchestration before Tier B's heuristic pass can be designed in more detail — a
  binary-strings scan needs the binaries themselves, not just compile_commands.json).
- **Exact step/lane name and its slot in `process-manifest.json`'s authoritative `process_order`** —
  not chosen yet.
- **Whether Tier A should be built now, independent of Tier B's larger design/build timeline** — Tier
  A has no dependency on Tier B or on the hostile-build export question above, and would close the
  concrete gap already flagged for the eastl run today. Not yet confirmed with the repo owner whether
  to build it now or hold both tiers together.

This section records the design decision; neither tier is implemented yet.

### 4.2.1 Tier B progress update (2026-09-18, same-day continuation)

Two scripts now exist in `scripts/` (commit `201d5b7`) implementing the first half of Tier B's
pipeline, both tested against a real clang/ld toolchain (not just written blind):

- **`pipeline/capture_build_commands.py`** — command-line capture. Takes `compile_commands.json`
  (already a standard artifact this pipeline produces) and, per-entry, re-invokes the compile
  command with clang's `-###` flag appended, which prints the real `-cc1` subprocess argv without
  executing it — staying inside the hostile-build boundary's existing "compile or syntax-check"
  permitted list (§2.2). Separately accepts `--link-recipe`, a caller-supplied JSON array of
  driver-level link commands (e.g. `clang++ ... -o app`), which it likewise expands via `-###` to
  the real `ld`/`lld`/`collect2` subprocess argv — this is what actually carries every `-L` search
  path and positional `.a`/`.so`/`.o` the link pulled in. Output: `build-commands.jsonl`, one JSON
  record per real subprocess invocation, tagged `kind` (compile/assemble/link/other) and `stage`
  (driver-level vs. `-###`-expanded).
- **`pipeline/extract_vendor_candidates.py`** — the heuristic pass. Parses `-I`/`-L`/`-l` and
  positional object/library paths out of `build-commands.jsonl`, resolves them to absolute paths,
  classifies in-tree vs. out-of-tree against `--repo-root`, dedupes to distinct candidate
  directories, and runs a bounded walk (`--max-depth`, default 4, *from each candidate directory*,
  not from the repo root) looking for version-carrying files (`version.h`-style filenames,
  `*-config.cmake`/`*.pc`, `CHANGELOG`), `#define ...VERSION...` macros in small header/text files,
  and version-looking path segments — checked both in the candidate directory's own descendants
  *and* a few levels of its ancestors (a flag typically points at `.../foo-1.2.3/include`, not at
  the versioned directory itself — missed in the first draft, caught by testing against a real
  fixture, fixed before commit). Confidence-scores each candidate (`high`/`medium`/`low`) from what
  combination of signals it found. Output: `native-vendor-candidates.json` — evidence records only,
  explicitly never a verdict; product/version disambiguation is left to a later, deliberately small
  inference pass over just this candidate list, not the whole tree.

**A real, non-obvious bug found by testing against the actual toolchain, not just written blind**:
an unfiltered real link command line (`clang++ main.o -L. -lvendor -o app` on a stock Ubuntu 18.1.3
clang host) pulled in over 80 `.pc` files from `/usr/lib/x86_64-linux-gnu` alone — standard
toolchain/OS library search paths that show up on essentially every real link line via the
compiler driver's own default search path, not anything the target vendored. Left unfiltered, this
would have flooded the "small, focused candidate list" the whole design exists to produce.
**Fixed**: `extract_vendor_candidates.py` now excludes standard system library directory prefixes
(`/usr/lib`, `/usr/lib64`, `/usr/local/lib`, `/lib`, `/lib64`, and anything nested under them, e.g.
`/usr/lib/gcc/.../13`) by default, with `--include-system-libdirs` to disable and
`--system-libdir-prefix` to override the list. Re-verified end-to-end after the fix: the same test
fixture went from 7 emitted candidates (4 of them pure system noise) down to 3 real candidates.

**Neither script is wired into `pregather.sh` yet, and two concrete things remain open before that
can happen:**

1. **How `compile_commands.json` is actually produced for a real target (e.g. `targets/eastl`) is
   not yet confirmed from this repo's own scripts.** `pipeline/pregather.sh` accepts an existing
   compile database (`--compile-db`) or converts one via `pipeline/normalize_compile_db.py`, and
   there's a separate MSVC/vcxproj path (`vcxproj_to_compile_commands.py`) for the Windows/MSBuild
   case — but nothing found so far in `pipeline/`/`scripts/` shows a CMake generator invocation
   (`cmake -G Ninja`, `cmake -G "Unix Makefiles"`, or a `bear --`-wrapped build) for the Linux/CMake
   case. This matters directly for the link-recipe question: `ninja -t commands <target>` (or an
   equivalent Make dry-run query) can supply real driver-level link commands cheaply, without
   executing a real build, *only if* Ninja is the actual generator in use. If it isn't — or if
   different targets use different generators — `capture_build_commands.py`'s `--link-recipe` input
   needs a different, possibly per-build-system, producer. **Needs the repo owner to confirm** how
   `compile_commands.json` gets generated today for `targets/eastl` specifically before this gap
   can be closed for real, rather than guessed at further.
2. **Real integration and validation against an actual target's real build, inside the
   `audit-native` container**, is something this session's sandbox cannot do (no Docker, no C++
   target checkout, no compile_commands.json for a real multi-file C++ project available here) —
   the synthetic-fixture testing above validates the scripts' own logic against the real clang/ld
   toolchain, but not against a real project's actual scale, oddities, or build-system quirks.
   Matches this project's established discipline (see `claude/review-cli-harness-2026-09-17.md`'s
   "every real bug found this session was found by actually running the real CLI" lesson) — real
   validation needs to happen on hal5000/WSL against `targets/eastl` or a similarly real tree.

Once (1) and (2) are resolved, the remaining pieces of the full sequence discussed with the repo
owner — the step-1 pregather extension to actually export `build-commands.jsonl` as a first-class
artifact (alongside IR), the scoped LLM disambiguation pass over `native-vendor-candidates.json`,
and the expanded SBOM-merge container/step consuming both Tier A and Tier B output — are still
design-only, not yet built.



## 5. Multi-agent operating model

### 5.1 Role separation

- High/Critical, malfeasance, ship-blocking, and escalation-triggering observations may not be discovered, verified, and finally adjudicated by the same agent.
- Panel members form initial conclusions independently before seeing other votes.
- Prompt diversity matters independently of model diversity.
- Model diversity is consequence-weighted: strongest for malfeasance, NO-GO, and RE/DAST escalation decisions.
- Minimum distinct model families: at least 2 for any WARRANTED-tier vote; at least 3 distinct model families for malfeasance, NO-GO, and RE/DAST escalation votes specifically. A vote that does not meet its tier's minimum is not quorum-eligible regardless of agreement.

### 5.2 Evidence-qualified quorum

Voting is not simple majority voting. A vote counts toward quorum only when reviewers independently agree on the artifact, evidence location, mechanism, prerequisites, and material consequence. Three unsupported opinions do not constitute evidence.

Example quorum: 2/3 WARRANTED + independent agreement on mechanism + artifact + evidence location.

### 5.3 Streaming verification and staged threat modeling

L6 is split into two stages. L6A runs immediately after intake to create the initial DFD/STRIDE model that focuses specialist discovery. Findings stream into L7 as they are produced; they do not wait for all discovery lanes to finish. L6B then reconciles the threat model using verified evidence before L14 synthesis.

`L0 → L6A → parallel specialist discovery → streaming L7 verification → L6B reconciliation → L14 synthesis`

### 5.4 Standards-reference discipline (added 2026-09-19)

A finding may cite a standard identifier (CWE, ASVS control, ATT&CK technique, CAPEC, a DISA STIG
V-number, a NIST 800-53 control, a CIS Benchmark control) but the citation discipline differs by
standard, decided against each standard's actual licensing/versioning status rather than treated
uniformly:

- **CWE / ATT&CK / CAPEC** — published under permissive terms, IDs and short names are stable. A
  lane/persona may cite these from its own knowledge; the schema treats the field as optional and
  nullable so a lane leaves it null rather than guessing when unsure.
- **DISA STIGs/SRGs and NSA technical guidance** (general-release, unclassified only — not
  CAC/PKI-gated CUI compilations) — public-domain US federal works (17 U.S.C. §105), safe to vendor
  and quote directly, unlike CIS. A curated, version-pinned offline reference file (same convention
  as `data/eol-reference.json`) may hold real control text for the specific STIGs a lane actually
  uses, re-pinned when the source STIG revises.
- **CIS Benchmarks** — restricted: the free PDFs carry CIS's own Terms of Use, which additionally
  prohibit derivative works and posting/mirroring beyond the underlying CC BY-NC-SA license. Control
  numbering also is not stable across benchmark versions. **Rule: never vendor CIS text, and never
  let a lane/persona recall a CIS control number from its own training knowledge.** A finding may
  only carry a CIS control ID when it was read directly from a scanner's own output (e.g. a
  checkov/trivy rule that already states its CIS mapping) — relayed evidence, not reconstructed
  knowledge.
- **Coverage is not symmetric across domains, and a lane must say so rather than imply otherwise.**
  DISA/NIST have no resource-level equivalent to CIS's AWS/Azure/GCP Foundations Benchmarks for
  cloud/Terraform configuration (DISA's Cloud Computing SRG is authorization/boundary-level, not a
  per-resource checklist) — a lane covering that ground has no legally-vendorable, versioned document
  to claim completeness against, and must scope its own `HARDENING_BASELINE_ASSESSMENT`-style claim
  as "complete relative to the tool's own ruleset," not "complete relative to a named standard,"
  when no such standard exists at the needed resolution. This is a real, evidence-grounded scoping
  limit, the same category as an ASVS/MASVS-does-not-apply determination (§13), not a gap to elide.

### 5.5 Pool launcher, waiter, and rendezvous (proposed 2026-09-19, under discussion — not yet implemented)

§5.1's panel model ("panel members form initial conclusions independently before seeing other
votes," "prompt diversity matters independently of model diversity") and §5.2's evidence-qualified
quorum have so far been descriptions of a voting *outcome*, not a mechanism that actually launches
N independent reviewers and waits for them. This section proposes that mechanism. It generalizes the
`15-deployment-hardening` IaC persona pool (§12; `claude/TODO.md`'s "session 10" entries) into
something every panel-shaped lane can use — `07-red-team-adversarial`, `08-blue-team-refutation`,
and `09-independent-verification` are the immediate intended consumers, not `15` alone.

**Job config, not CLI flags.** A pool job is declared as a config file, the same convention as
`model-config.json`/`process-manifest.json`, rather than assembled from ad hoc CLI flags — the
whole point is that "3 workers of persona X, 2 of persona Y" is a fact about the job worth keeping
on record alongside the run, not a one-off invocation to retype. Sketch:

```json
{
  "job_id": "07-red-team-adversarial-pool-01",
  "lane": "07-red-team-adversarial",
  "run_id": "20260917T193147Z-2319a6",
  "budget": "standard",
  "workers": [
    { "worker_id": "rt-l4-general", "kind": "persona", "persona_id": "redteam-l4-general", "count": 3 },
    { "worker_id": "rt-l5-malfeasance", "kind": "persona", "persona_id": "redteam-l5-malfeasance", "count": 2 },
    { "worker_id": "gitleaks", "kind": "tool", "step": "secrets" }
  ],
  "rendezvous": { "mode": "wait_all", "timeout_seconds": 3600 }
}
```

**Two worker kinds, one bookkeeping mechanism.** A worker is either:

- `kind: "persona"` — an LLM dispatch: the lane's own `config.md`/`prompt.md` stays the fixed outer
  task framing ("you are red team, find vulnerabilities in this design lane"), and `persona_id`
  selects one `subprompts.md` entry as the inner variation. `count: N` expands to N independent
  worker instances of that exact (lane, persona_id) pair, each its own subprocess/container, no
  shared context between instances — this *is* §5.1's "prompt diversity" panel, materialized: running
  the same persona N times independently produces N independent votes for §5.2's evidence-qualified
  quorum, the same way running different personas produces reviewer diversity.
- `kind: "tool"` — a bare deterministic invocation with no LLM/persona layer at all (the "run
  gitleaks" case). Same job config, same launcher, same rendezvous bookkeeping, but no `claude -p`
  call — this is a deliberate unification, not a special case bolted on: a job that mixes reasoning
  workers and deterministic scanner workers should rendezvous as one wave, not two systems that
  happen to run near each other in time.

**Launcher**: expands each worker spec's `count` into concrete instances, launches each at its own
scoped output path (`outputs/<lane>/pool/<job_id>/<instance_id>/`, generalizing the
`workers/<parallel_review_group>/` shape from the pool-dispatch output-merging design note in
`claude/TODO.md` to be keyed by instance id rather than assuming component-sharding is the only
axis a pool ever splits on), and records each instance's expected output path in a job manifest —
the single source of truth the waiter reads.

**Waiter / rendezvous**: polls (not busy-loops — the same zero-API-cost `time.sleep(N)` pattern as
the existing `acquire_run_lock` mutex) for every instance in the job manifest to reach a terminal
state, then hands off to a deterministic (non-LLM) merge step. Per §7 (non-short-circuit
completion), one worker's failure does not abort the wave — it's recorded as a failed/degraded
instance in the merge, not silently dropped or allowed to block the others indefinitely (bounded by
the job's own `timeout_seconds`, mirroring `acquire_run_lock`'s stale-lock reclaim).

**Decided 2026-09-19 — tool-worker dispatch is deterministic, not a shell-out to the legacy
scripts.** `kind: "tool"` workers are launched natively by the pool launcher itself as pinned-image,
argv-array container invocations — the same discipline ADR-0002 already established for the Python
orchestrator over the old PowerShell prepass (never a shell string assembled at runtime; one step is
one tool invocation). The launcher does not shell out to `Invoke-VendorAuditPrePass.ps1`/`.sh` as an
external subprocess; those scripts' step table is the reference for which tools/images/args exist
today, but a `tool` worker's own dispatch path lives in the pool launcher, moving this project one
step further toward the evidence pipeline and the LLM harness converging under one Python mechanism
rather than staying two systems that happen to run near each other in time. Migrating the *existing*
`Invoke-VendorAuditPrePass.ps1`/`.sh` step table into this format is follow-on work, not implied to
be done at once — the decision here is the shape new tool-worker dispatch takes, not a mandate to
port every existing step immediately.

**Decided 2026-09-19 — rendezvous is `wait_all` only; quorum evaluation waits for every worker to
exit.** No early-exit-on-quorum mode. Evidence-qualified quorum (§5.2) requires independent
agreement on mechanism/evidence, not just a headcount of completions, so evaluating it against a
partial worker set (even one that already has enough same-persona agreement to nominally satisfy a
count) would trade real coverage for wall-clock savings the design doesn't want. This closes the
question raised in the prior revision of this section rather than leaving early-exit as a future
optimization to revisit.

**Still open, genuinely undecided — not to be read as settled by appearing in this doc:**

- Concurrency limits: bounded by Docker daemon capacity for `tool` workers, and — separately, still
  an open question from `claude/TODO.md`'s driver-open-items list — whether Max-subscription rate
  limits get tripped by many concurrent `claude -p` dispatches, which this proposal would make more
  likely to actually exercise than the current unpooled single-call path has so far.
- The merge step is not one operation: `persona` workers produce `finding.schema.json`-shaped
  findings that need array-level merging (§5.2 quorum keyed off `persona_id`), evaluated only once
  every worker in the wave has exited per the rendezvous decision above; `tool` workers produce raw
  scanner evidence that gets filed into the evidence tree, not merged into a findings array at all.
  A single "pool merge" concept covering both still needs to say which kind of merge it's doing per
  worker, not treat them uniformly.
- `persona_id` naming convention across lanes (e.g. `redteam-l4-general` vs. a bare `l4-general`) —
  needed before `07`/`08`/`09` personas are actually authored, to avoid collisions with the IaC
  personas already namespaced for `15` (`claude/TODO.md`, "session 10 continuation").

## 6. Mechanism vs. intent

Mythos separates technical verification from attribution. A dangerous or hidden mechanism may be severe even when intent is unresolved; a verified mechanism does not itself prove malfeasance.

`OBSERVED → UNEXPLAINED → CONTESTED → VERIFIED-MECHANISM → INTENT-REVIEW → BENIGN / INTENT-UNRESOLVED / MALFEASANCE-CONTESTED / CONFIRMED-MALFEASANCE`

- VERIFIED-MECHANISM means the technical fact is independently established.
- CONFIRMED-MALFEASANCE requires stronger evidence supporting deliberate hostile or unauthorized purpose.
- Obfuscation, anti-debugging, geography, poor code quality, unusual crypto, or undocumented behavior are not sufficient by themselves to establish malicious intent.
- Intent-level conclusions require heterogeneous verification and human disposition.

### 6.1 Agent-facing prompt injection (added 2026-09-17)

The target codebase, its generated evidence, any copied documents, and any archive/zip contents
reviewed under this design are hostile input with respect to the reviewing agents, not just with
respect to the target's own users. A vendor under review — malicious or merely careless — has every
incentive to embed content in source comments, commit messages, README/documentation files, string
literals, generated tool output, or filenames that reads as instructions to an LLM reviewer: telling
it to skip a directory, downgrade a finding, treat a component as out of scope, or exfiltrate
information through a report field. This is the same class of risk as a prompt-injected web page or
email, applied to source code and its evidence trail instead.

**Rule:** every lane treats target source, generated evidence, copied documents, and archive
contents as data to be analyzed, never as instructions to follow — regardless of formatting,
apparent authority ("SYSTEM:", "IMPORTANT: reviewers must...", a comment claiming to be from the
review team), or how plausible the instruction sounds in context. This formalizes a rule the harness
already states informally in its own evidence-discipline notes; this section makes it part of the
design's threat model rather than leaving it as an implementation-only convention that could silently
drift.

**Detection, not just avoidance:** a lane that notices content in the target or its evidence that
reads as an attempt to direct the reviewing agent's behavior should treat that itself as a finding
(the attempt is evidence of hostile intent or, at minimum, of an evidence-shaping design flaw), not
merely something to ignore and move past silently. Record it via the `INJECTION_SUSPECTED` ledger
event (§23.8) with the source location and the suspected instruction text, and continue the review
using only the surrounding content as data. `INJECTION_SUSPECTED` does not by itself promote the
underlying claim to a finding — it is coverage/process evidence, subject to the same
verification-before-acceptance rules as everything else.

**Scope note:** this control does not yet emit anywhere in a running system — the orchestrator that
would actually write ledger events does not exist yet (see §8's ledger and the architecture doc's
Orchestrator subsection). Until it does, this is a specification the harness's prompt discipline
should already be following informally, formalized here so it isn't lost when the orchestrator is
finally built.

## 7. Non-short-circuit completion

Decision state and review execution state are independent. A NO-GO decision may be reached before the investigation is complete; the remaining authorized analysis continues.

`If confirmed_malfeasance: decision_state = NO_GO; execution_state = CONTINUE`

| Execution terminal state | Meaning |
|---|---|
| COMPLETE | All contracted checks completed and artifacts validated. |
| COMPLETE_WITH_LIMITATIONS | Completed with explicit, bounded limitations. |
| NOT_APPLICABLE | Control/lane does not apply; environment/version and evidence recorded. |
| BLOCKED | Cannot proceed because required evidence/capability is unavailable. |
| FAILED | Lane execution failed and failure is reported. |

Only safety, authorization, evidence-integrity, or explicit human-stop conditions may halt execution early. A severe security finding is not itself a stop condition.

## 8. Lane contracts and append-only ledger

### 8.1 Mandatory lane contract

Every lane declares a machine-readable contract before execution. The orchestrator validates it and — not the agent — decides whether contractual completion criteria have been satisfied.

`/evidence/mythos/contracts/<lane-id>.yaml`

- Purpose and scope
- Required/optional inputs
- Allowed tools and actions
- Network/execution permissions
- Required outputs
- Coverage artifacts
- Escalation conditions
- Terminal states
- N/A evidence requirements
- Prompt/model/tool provenance

### 8.2 Append-only review event ledger

`/evidence/mythos/ledger/review-events.jsonl`

The ledger is the authoritative chronological record of the review. Agents submit events to the orchestrator; only the orchestrator appends to the canonical ledger and assigns the monotonic sequence and hash chain.

- Records agent/model starts and completion.
- Records interesting signals before they become findings.
- Records hypotheses, refutations, verification, votes, quorum results, remediation, human gates, and decision-state changes.
- Past events are never edited; corrections are appended as EVENT_CORRECTION.
- Each event carries previous_event_hash and event_hash; the final ledger head hash is recorded at completion.

## 9. Canonical evidence and state artifacts

| Artifact | Purpose |
|---|---|
| control-coverage.json | Authoritative answer to what was checked, baseline/version, applicability, result, assurance class, evidence and provenance. |
| artifact-sufficiency.json | What evidence each control family requires, what was supplied, and what remains missing. |
| source-completeness.json | Accounts for generated code, submodules, binaries, vendored source, build fetches and referenced-but-missing code. |
| findings.json | Current canonical normalized findings. |
| escalations.json | RE/DAST/fuzz/live-state/human/legal follow-on recommendations and quorum results. |
| review-events.jsonl | Append-only audit trail. |
| run-state.json | Derived current state regenerated from the ledger. |
| run-manifest.json | Models, prompt hashes, tool versions, input hashes, standards snapshot versions. |
| negative-space.md | Material evidence not supplied, unavailable, blocked or not verifiable. |
| deployment-image-map.json | Static chain from deployment configuration to referenced image/digest and image assessment. |
| network-exposure.json | Declared/static network exposure graph. |
| identity-graph.json | Workload → identity → role → action → resource. |
| crypto-inventory.json | Algorithms, keys, storage, rotation/lifecycle and classification. |
| release-trust-chain.json | Source → build → artifact → signature → distribution/update trust chain. |
| verified-facts.jsonl | Compact normalized verified facts/edges consumed by L14; full evidence remains referenced by ID. |
| build-isolation-manifest.json | Isolation mode, worker identity, input/output hashes, privilege/network settings, resource limits, and allowlisted artifacts imported from each build attempt. |

All evidence passes through a secrets-scrubbing step (`pipeline/scrub_evidence.py`) before it enters any LLM lane
prompt or is written to the append-only ledger. Scrubbing records what was redacted (location, rule matched,
count) as evidence metadata; it never writes the secret value itself to canonical evidence or the ledger.

## 10. Assurance and coverage discipline

| Assurance class | Meaning |
|---|---|
| DIRECT_EVIDENCE | Conclusion is directly established by supplied artifacts. |
| STRONG_INFERENCE | Multiple supplied artifacts strongly support the conclusion, but it has not been observed dynamically. |
| WEAK_INFERENCE | Evidence suggests risk but material context is missing. |
| FOLLOW_ON_REQUIRED | The question cannot be resolved adequately from static evidence. |

Confidence is capped by evidence type. Static IaC cannot claim production configuration verified; source inspection cannot claim runtime exploit reproduced; binary metadata cannot claim implementation behavior proven.

## 11. Control families

| Control family | Coverage |
|---|---|
| Application security | Authn/authz, injection, serialization, session handling, file handling, SSRF/egress, server authority, IAP/economy, abuse cases. |
| Native memory safety | Build-backed clang/CSA/CodeChecker/Joern/cppcheck analysis with explicit TU coverage and build fidelity. |
| Supply chain & provenance | SBOM, origin, pinning, hashes, signatures, typosquat/confusion, SLSA/SSDF, release/update trust. |
| Vendor/insider trust | Undocumented egress, hidden control paths, activation mechanisms, toolchain/build integrity, source/artifact divergence. |
| Container & deployment hardening | Image hardening, non-root, read-only FS, capabilities, privileged modes, host mounts, resource controls. |
| Declared network exposure | Static process/listener → container → service → ingress/LB → firewall/NSG trust-path analysis. |
| IAM & machine identity | Workload identities, roles, wildcard privilege, cross-environment access, static credentials and service tokens. |
| Cloud/IaC configuration | Static Terraform/Bicep/ARM/K8s/Helm review; no live cloud claims. |
| Datastores | Network exposure, authn/authz, TLS, admin interfaces, least privilege, backups, logging, support status. |
| Cryptography | Crypto inventory, algorithm/mode/key length, RNG, password hashing, key storage/rotation, TLS/cert validation, custom crypto. |
| Secrets lifecycle | Creation, distribution, storage, use, rotation, revocation and destruction. |
| Availability / abuse resistance | Resource exhaustion, amplification, unbounded work, quotas, rate limits, replay, economy abuse. |
| Fail-safe behavior | Behavior when identity, authorization, secrets, DNS, certificates, remote config, DB or third parties fail. |
| Isolation | Tenant/user/account/region/environment separation and cross-boundary authorization. |
| Backup & recovery | Coverage, immutability, separation of credentials, restore testing, shared-fate analysis. |
| Observability & forensic readiness | Security event coverage, centralized/tamper-resistant logs, retention, identifiers, response usefulness. |
| Privacy / data protection | RoPA, legal basis, DSRs, transfers, minors, device/static privacy behavior and claim-vs-code review. |
| DNS/certificate namespace | Stale/dangling DNS, subdomain takeover conditions, cert ownership/renewal, registrar/admin controls. |
| Lifecycle/EOL | OS/runtime/framework/toolchain/platform support status and upgrade blockers. |
| Vulnerability lifecycle | Ownership, remediation target, retest, closure, expiring risk acceptance and suppressions. |

## 12. Static deployment hardening specifics

- Verify every image referenced by deployment configuration against the image artifact actually supplied; unresolved references become IMAGE_ARTIFACT_NOT_PROVIDED, not PASS.
- Inspect image user, entrypoint, layers, package/tool residue, exposed ports, secrets, setuid/setgid files, base-image lifecycle, signatures/provenance if supplied.
- Assess Kubernetes/AKS manifests and IaC against applicable CIS/DISA/NIST baselines, but report HARDENING_BASELINE_ASSESSMENT unless every applicable requirement has truly been evaluated.
- Build declared exposure and egress inventories from source and configuration only; clearly label them DECLARED_EXPOSURE rather than OBSERVED_EXPOSURE.
- Model IAM statically as workload → identity → role → action → resource.
- If live state would materially change assurance, emit FOLLOW_ON_EFFECTIVE_STATE_REVIEW_RECOMMENDED instead of performing live access.

## 13. Applicability and N/A discipline

A control that does not apply is still recorded. N/A is an evidence-backed result, not an omission.

Required N/A context: component + detected technology/product + detected version (or version unavailable) + control/baseline + baseline version + reason + evidence references + provenance.

### 13.1 Deterministic applicability engine

Routine applicability decisions should be driven first by deterministic inventory/rule evidence rather than repeatedly asking an LLM to prove negatives. The engine evaluates technology, dependency, AST/configuration, and source-completeness signals and returns APPLICABLE, LIKELY_NOT_APPLICABLE, or UNKNOWN. Ambiguous cases go to an agent or human reviewer.

No single absence signal (for example, "no SQL driver detected") is sufficient by itself. Promotion to NOT_APPLICABLE requires a configurable evidence threshold and adequate source/artifact completeness. Underlying signals, product/version information, baseline version, and rationale remain recorded in control-coverage.json.

## 14. Standards and enrichment backing

- OWASP ASVS 5.0.0 for application controls; MASVS/MASTG for mobile client controls.
- CVSS 4.0 for severity vectors; EPSS and CISA KEV used only where applicable for prioritization context.
- CVSS 4.0 vector components are derived deterministically wherever a verified-fact attribute maps directly to a metric (e.g. trust boundary crossed → Attack Vector, authentication evidence → Privileges Required/User Interaction, blast-radius evidence → the Vulnerable/Subsequent System impact metrics); the LLM is only invoked for the residual metrics that have no direct verified-fact mapping. The derivation mapping and its inputs are recorded so a vector can be regenerated from the same verified facts.
- MITRE CWE; CAPEC/ATT&CK where useful for attack mapping.
- NIST SP 800-53, SP 800-190, and SP 800-218 SSDF mappings.
- Platform-specific CIS benchmarks and applicable DISA STIG/SRG controls for supplied deployment artifacts.
- SEI CERT guidance for native remediation/conformance where applicable.

Standards and enrichment feeds are snapshotted and hash-recorded at run start so reruns can distinguish code changes from feed changes.

### 14.1 Static protocol/parser boundary

Baseline L10 is static only. It may recover wire-format definitions from source, identify serializers/deserializers and parser state machines, enumerate opcodes, map trust assumptions, and prepare candidate harnesses. It does not generate application traffic, capture packets, probe endpoints, or execute network fuzzing.

**Any active fuzzing, runtime protocol exercise, DAST, or reverse engineering is a follow-on recommendation behind the evidence-qualified escalation process.**

## 15. Escalation model

| Escalation | Meaning |
|---|---|
| RE_RECOMMENDED | Binary reverse engineering would materially reduce an unresolved security uncertainty; no RE is performed in baseline. |
| DAST_RECOMMENDED | Authenticated/running-app testing would materially reduce uncertainty; no DAST is performed in baseline. |
| FUZZING_RECOMMENDED | Active fuzzing is justified by static parser/protocol evidence; follow-on only. |
| FOLLOW_ON_EFFECTIVE_STATE_REVIEW_RECOMMENDED | Live cloud/runtime state should be compared against reviewed configuration. |
| RUNTIME_TELEMETRY_RECOMMENDED | Observed runtime egress/behavior would materially answer a static uncertainty. |
| HUMAN_CODE_REVIEW_RECOMMENDED | Human specialist review is warranted for a high-consequence or ambiguous issue. |
| LEGAL_PRIVACY_REVIEW_REQUIRED | Privacy/legal determination exceeds technical evidence and requires counsel/DPO review. |

### 15.1 Post-escalation re-verification

An escalation panel may recommend RE, DAST, fuzzing, live-state review, or another follow-on method. A recommendation itself may be consumed as an escalation status, but any new technical evidence or finding produced by authorized follow-on work must re-enter a targeted L7 verification cycle before it may reach L14 synthesis.

`L7 initial verification → escalation quorum → authorized follow-on (outside baseline) → new evidence package → targeted L7 re-verification → L14`

### 15.2 Verified fact graph for L14 synthesis

L14 consumes compact normalized verified facts and graph edges rather than complete lane transcripts. Full evidence remains dereferenceable by finding/evidence ID. This reduces context dilution while preserving traceability.

`fact_id + component + subject + predicate + object + finding_ids + assurance_class + severity + trust_boundary + data_classes`

Integrators may correlate verified facts into attack/control chains, but may not invent factual predicates absent from the verified fact graph.

## 16. Executive reporting policy

The executive report is intentionally short and decision-oriented. It is not the detailed findings database.

Must Fix Before Shipment = High/Critical + VERIFIED + material security impact + remediation required before ship.

- Include only Critical/High findings that genuinely affect ship posture.
- Include review scope, components/versions, process image, coverage summary, major limitations, must-fix results, remediation state, unresolved escalation items, and go/no-go recommendation.
- Keep Medium/Low findings, full control matrix, raw tool output, complete CVSS vectors and detailed evidence in separate technical/machine-readable artifacts.
- Do not promote a High finding into the executive must-fix list if it is speculative, unreachable, duplicate, or strongly mitigated.

### 16.1 Remediation validation

L11 must distinguish a proposed patch from a validated remediation. Proposed changes are applied only to a disposable copy and may be subjected to syntax/type checks, targeted static analysis, compilation/build, and regression tests where the required toolchain is available and the isolated-build policy permits it.

- PATCH_VALIDATED — applicable checks passed.
- PATCH_PROPOSED_UNVALIDATED — patch is technically reasoned but the project/toolchain could not validate it.

**A non-compiling or otherwise unvalidated patch must never be represented in the executive report as a verified fix.**

## 17. Baseline tools, skills and Docker images

| Image | Primary contents |
|---|---|
| mythos-orchestrator | Python, JSON Schema/Pydantic, jq/yq, SQLite/DuckDB, hashing/signing, ledger writer, state machine, artifact registry. |
| audit-static | Semgrep, gitleaks, syft, osv-scanner, Trivy, cdxgen, bandit, gosec, PHPStan/Psalm, Java/C# analyzers, luacheck, tree-sitter/ast-grep/weggli. |
| audit-native | LLVM/Clang, clang-cl, clang-tidy, CSA/CodeChecker, cppcheck, Joern, CMake/Ninja/FASTBuild, bear/compiledb, symbol tools. Runs only inside the hostile-build isolation boundary and has no direct write access to canonical evidence or the ledger. |
| audit-iac | Terraform/IaC parsers, Checkov, tfsec, Trivy config, OPA/Conftest, Helm/kubectl clients used only for static manifest processing. |
| audit-container | Skopeo/crane/cosign, Syft, Trivy, OCI inspection, image-layer and hardening checks. |
| audit-report | TeX Live, latexmk, Pandoc, Jinja2, mermaid-cli, Graphviz. |

Optional follow-on images such as audit-re, audit-fuzz, audit-live-cloud and audit-dast are not part of the baseline environment and are referenced only by approved escalation recommendations.

## 18. Reusable agent skills

lane-contract · finding-schema · evidence-citation · coverage-accounting · independent-verification · red-team-hypothesis · blue-team-refutation · malfeasance-mechanism · intent-attribution · quorum-adjudication · cross-lane-synthesis · cvss4-scorer · remediation-package · supply-chain-vetting · hardening-baseline · network-exposure-analysis · iam-analysis · crypto-review · release-trust · privacy-assessment · completion-validator · report-executive

## 19. Pipeline validation against ground truth

Before vendor results are trusted, the same pinned pipeline must pass a seeded validation corpus spanning the defect classes it claims to detect. The validation set must include both malicious and benign/ambiguous cases so the system proves it can discriminate, not merely flag suspicious constructs.

- Memory-safety bug in C/C++.
- SQL injection in PHP.
- Client-authority/economy bug.
- Unsafe deserialization.
- Planted covert exfiltration path.
- Planted hidden backdoor.
- Dangerous but accidental mechanism.
- Legitimate anti-cheat/anti-analysis mechanism.
- Ambiguous mechanism that must remain INTENT_UNRESOLVED.
- Deployment hardening defects such as root container, privileged pod, wildcard IAM, mutable image tag, public management rule.
- A second validation target built with a VS2013-era toolchain against a known historical CVE, exercising the ADR-0001 compile-feasibility tiering on an older/less-compliant compiler surface rather than only the primary validation target.

## 20. Finalization gate

1. Validate every lane contract.
2. Validate all required lane terminal states.
3. Validate all finding terminal states.
4. Validate all escalation terminal states.
5. Ensure every expected control family has an explicit status in control-coverage.json.
6. Replay and verify the review-events.jsonl hash chain.
7. Regenerate run-state.json from the ledger and compare it to the current snapshot.
8. Validate required report artifacts.
9. Record RUN_INTEGRITY_VALIDATED.
10. Only then transition report_status to FINAL.

### 20.1 Human gates

The following decisions require an explicit named human sign-off recorded as a ledger event; no lane or
quorum result may substitute for them.

| Gate | Who | Ledger event |
|---|---|---|
| Intent disposition (malicious vs. accidental vs. legitimate) for any INTENT_UNRESOLVED or malfeasance-tier finding | Engagement lead | HUMAN_INTENT_DISPOSITION_RECORDED |
| Approval to modify any protected test asset (ADR-governed fixtures, validation corpus, planted-defect files) | Engagement lead | HUMAN_PROTECTED_TEST_MODIFICATION_APPROVED |
| Sign-off transitioning report_status to FINAL | Engagement lead or designated reviewer | HUMAN_FINAL_SIGNOFF_RECORDED |
| Authorization for any follow-on RE/DAST/fuzz/live-state escalation | Engagement lead, with client sign-off where the target is client-owned | HUMAN_ESCALATION_AUTHORIZED |

## 21. Design conclusion

Mythos is intended to be an evidence-production and adjudication system rather than a collection of scanners. Its assurance comes from bounded specialist discovery, independent challenge and verification, explicit applicability/version accounting, a non-short-circuit completion model, cross-domain synthesis, machine-enforced lane contracts, and a hash-chained append-only event record. The baseline review remains static/offline; whenever the supplied artifacts cannot answer an important question, the system records a follow-on recommendation instead of overstating what was established.

### Architectural correction set — v3

- L10 is static-only in the baseline; dynamic fuzzing, DAST, and RE are follow-on methods.
- L6 is split into L6A initial threat modeling and L6B reconciliation, removing the previous serial bottleneck.
- L7 verification is streaming and must run again for new evidence produced by any follow-on engagement.
- Compilation/build execution is treated as hostile execution and isolated from canonical evidence and ledger state.
- Routine applicability/N/A decisions use deterministic evidence first; LLM or human review is reserved for ambiguity.
- L14 consumes a compact verified fact graph rather than full lane transcripts.
- L11 distinguishes validated remediations from unvalidated patch proposals.

## 22. Code Index and Component/Purpose Mapping

*(Numbered 21 in the Google Doc — duplicate heading number; renumbered here.)*

**Design principle.** The full-text searchable code index and the initial component-and-purpose classification are first-class discovery substrates. They accelerate navigation and scoping, but neither replaces verification against canonical source artifacts.

### 22.1 L0A — Component and Purpose Identification

L0A runs immediately after intake and before L6A threat modeling. Its purpose is to construct a semantic map of the supplied codebase so every downstream lane knows what each major component appears to be, what role it serves, and how confidently that classification is supported.

- Partition the repository into deployable components, libraries, clients, servers, management-plane code, infrastructure, build tooling, tests, samples, generated code, vendored code, and documentation.
- Assign a concise observed purpose to each component using repository evidence: manifests, build files, imports, entry points, directory structure, comments, symbols, configuration, and call relationships.
- Record liveness as confirmed-live, ambiguous, confirmed-dead, sample-oss, generated, vendored, or unknown.
- Record likely trust-boundary role: external-facing, internal service, privileged management, client-side, data-store adapter, build-time only, test-only, or unknown.
- Record languages, frameworks, runtimes, build systems, package managers, and detected versions where available.
- Identify relationships between components: calls, shared data stores, shared libraries, build dependencies, deployment references, protocol relationships, and privilege dependencies.
- Do not infer security conclusions at this stage. L0A is descriptive and classificatory.

Required artifact: `/evidence/mythos/scope/component-purpose-map.json`

Recommended schema:

```yaml
component_id:
paths: []
component_type:
observed_purpose:
purpose_confidence:
liveness:
languages: []
frameworks: []
runtime_versions: []
build_systems: []
entry_points: []
trust_boundary_role:
data_classes: []
dependencies: []
dependents: []
deployment_references: []
evidence_refs: []
classification_notes:
```

### 22.2 Component-purpose map as a routing control

Downstream lanes consume the component-purpose map to constrain their analysis. A lane should not treat every source file as equally relevant. The map is used to select applicable standards, choose language-specific tooling, determine likely trust boundaries, distinguish production code from samples/tests, and avoid attributing findings from dead or vendored code to a live product component.

The component map is provisional. If a later lane discovers contradictory evidence, it emits a COMPONENT_CLASSIFICATION_CHALLENGE event. L0A classification is then amended through an append-only correction/update event rather than silently rewritten.

### 22.3 Full-text searchable code index

The searchable code index is the default navigation and candidate-discovery mechanism for specialist agents. It may be used to locate candidate evidence, identify repeated patterns, find call sites and configuration references, seed hypotheses, and partition large repositories across workers.

- L2: locate authentication, session, token, storage, cryptography, validation, and authorization patterns for ASVS/MASVS assessment.
- L4: locate security-sensitive sources/sinks, serializers, deserializers, SQL construction, file I/O, privilege checks, and trust-boundary crossings.
- L5: search for hardcoded destinations, hidden commands, feature gates, date checks, remote configuration, update paths, administrative functionality, obfuscated strings, and unexplained egress.
- L6A/L6B: recover components, data stores, protocol relationships, trust-boundary crossings, and architectural dependencies.
- L10: locate .proto files, opcode tables, dispatchers, framing code, serialization functions, parser length checks, and session/state-machine logic.
- L12: find fetch URLs, package feeds, build-time downloads, external repositories, update sources, and toolchain references.
- L13: locate PII fields, storage sinks, telemetry, consent checks, deletion paths, logging, and SDK data sharing.
- L15: find listeners, bind addresses, ports, TLS settings, image references, IAM references, deployment configuration, and hardening-related settings.

### 22.4 Index is a locator, not evidence authority

**Hard rule:** No finding may be verified solely from indexed text. A search hit must be dereferenced back to the canonical source file, configuration artifact, image, binary, or other authoritative evidence before the finding can progress through L7.

Finding locations cite canonical file:line, artifact hash, manifest location, or equivalent authoritative evidence. Index record identifiers may be retained as provenance/navigation metadata but never substitute for source evidence.

### 22.5 Index provenance and staleness controls

Required artifact: `/evidence/mythos/index/index-manifest.json`

```yaml
source_tree_hash:
source_commit:
index_version:
indexer:
indexer_version:
index_build_timestamp:
languages_detected: []
files_discovered:
files_indexed:
files_skipped:
skip_reasons: {}
generated_code_policy:
vendored_code_policy:
binary_policy:
submodule_policy:
ignored_file_policy:
max_file_size_policy:
symbol_index_available:
call_reference_index_available:
configuration_index_available:
index_hash:
```

- The index must be built from the exact evidence/source snapshot used by the review.
- The source tree hash and index hash are recorded in run-manifest.json.
- A stale or mismatched index cannot be used for verified findings.
- Skipped files and unsupported languages must be explicitly enumerated or summarized with counts and reasons.
- Generated, vendored, ignored, submodule, and binary-only content must have explicit indexing policies.

### 22.6 Index coverage and confidence

Index coverage is reported separately from review coverage. A 100% searchable-text index does not imply 100% semantic coverage, and failure to index binaries, generated sources, or unsupported languages must lower confidence only for the affected control families.

```yaml
coverage:
  source_files_discovered:
  source_files_indexed:
  percentage:
  unsupported_languages: []
  generated_files_excluded: []
  vendored_files_excluded: []
  binaries_indexed_as_metadata:
  submodules_present:
  submodules_indexed:
  known_gaps: []
```

### 22.7 Symbol-aware enrichment

Full-text indexing is sufficient for broad discovery, but symbol-aware and relationship-aware indexing should be added where practical. Preferred relationships include definitions, references, callers, callees, inheritance, imports, routes, handlers, serialization/deserialization pairs, configuration references, and deployment references.

This permits queries such as: `external input -> parser -> validator -> privileged operation -> datastore`

The relationship index should feed the verified-fact graph only after canonical-source verification.

### 22.8 Workflow placement

```
Validation Gate
-> Pregather
-> L0 Intake / evidence sufficiency
-> L0A Component + Purpose Identification
-> Code Index Build / Validation
-> L6A Initial Threat Model
-> Parallel Specialist Discovery
-> Streaming L7 Verification
-> L6B Threat Model Reconciliation
-> L14 Verified-Fact Synthesis
```

### 22.9 Completion requirements

- Every discovered top-level component has a component_id and classification status.
- Every component classification includes evidence references and a confidence value.
- Every material source area is accounted for as indexed, deliberately excluded, unsupported, missing, or binary-only.
- The index source hash matches the review source snapshot.
- Index gaps are propagated to affected lane coverage statements.
- No verified finding cites only the index.

### 22.10 Ledger events

COMPONENT_DISCOVERED · COMPONENT_CLASSIFIED · COMPONENT_PURPOSE_ASSIGNED · COMPONENT_CLASSIFICATION_CHALLENGE · COMPONENT_CLASSIFICATION_UPDATED · INDEX_BUILD_STARTED · INDEX_BUILD_COMPLETED · INDEX_BUILD_FAILED · INDEX_COVERAGE_RECORDED · INDEX_STALENESS_DETECTED · INDEX_QUERY_USED_FOR_DISCOVERY

### 22.11 Architectural rationale

Component-and-purpose identification reduces one of the largest sources of automated AppSec error: correctly detecting a risky pattern but misunderstanding what code it belongs to, whether it is deployed, or which trust boundary it serves. The code index then gives specialist agents a scalable way to navigate the repository without repeatedly ingesting the entire codebase. Together they form a semantic navigation layer; canonical source remains the evidentiary authority.

## 23. Incremental Verification, Re-Scoping, Synthetic Hypotheses, and Validation Hardening

*(Numbered 22 in the Google Doc; renumbered here.)*

### 23.1 L7 Progressive Verification: VERIFIED_PRIMITIVE

L7 may independently confirm a localized technical mechanism before full-system reachability or end-to-end exploitability is known. Introduce VERIFIED_PRIMITIVE as an intermediate state.

A VERIFIED_PRIMITIVE confirms the cited artifact, location, and local mechanism against canonical evidence, but does not yet assert complete exploitability, reachability, severity, or attack-chain consequence.

`OBSERVATION -> CANDIDATE -> VERIFIED_PRIMITIVE -> CONTEXTUALIZED_FINDING -> VERIFIED_FINDING`

Examples include a missing authorization check, an unchecked parser conversion, a deployment manifest exposing a port, or a workload possessing a particular role.

Each primitive may declare unresolved dependencies such as NETWORK_REACHABILITY, PRIVILEGE_CONTEXT, DATA_CLASS, or DEPLOYMENT_LIVENESS. When matching verified facts arrive from other lanes, the orchestrator schedules targeted reevaluation rather than stalling the whole pipeline.

Required ledger events: VERIFIED_PRIMITIVE_CREATED · VERIFICATION_DEPENDENCY_REGISTERED · VERIFICATION_DEPENDENCY_SATISFIED · PRIMITIVE_PROMOTED_TO_FINDING

### 23.2 L0A Classification Invalidation and Dynamic Re-Scoping

Component classification is provisional. A later discovery that changes a component from test/dead/sample to production/live, or otherwise changes its trust-boundary role, may invalidate earlier pruning decisions.

Whenever COMPONENT_CLASSIFICATION_UPDATED is emitted, the orchestrator identifies every downstream result that depended on the superseded classification.

Any lane that skipped, pruned, marked N/A, reduced liveness, suppressed findings, or excluded the component from threat modeling/index queries is marked RESCOPE_REQUIRED for the affected component/control range.

Re-scoping is targeted. The system reruns only invalidated work rather than restarting the entire engagement.

Re-scoping is bounded: a given component may be automatically re-scoped at most twice. A third
COMPONENT_CLASSIFICATION_UPDATED for the same component forces LANE_RESCOPE_REQUIRED to escalate to human
review (§20.1) instead of triggering another automated re-scope, to prevent classification oscillation from
running the engagement in circles.

Required artifact: `/evidence/mythos/state/classification-dependencies.json` — records which lane decisions depended on each component classification so invalidation can be deterministic.

### 23.3 L14 Synthetic Hypotheses

L14 may identify a plausible missing edge between already verified facts. Such an inferred edge is classified strictly as SYNTHETIC_HYPOTHESIS and is not evidence.

Any attack chain containing a SYNTHETIC_HYPOTHESIS remains CHAIN_HYPOTHESIS until the inferred edge is investigated by an appropriate specialist lane and independently confirmed by L7 against canonical source.

`L14 detects missing edge -> SYNTHETIC_HYPOTHESIS -> targeted specialist investigation -> L7 verification -> VERIFIED_FACT or REFUTED -> L14 resynthesis`

This permits creative cross-domain reasoning without allowing inference to masquerade as established evidence.

Required ledger events: SYNTHETIC_HYPOTHESIS_CREATED · SYNTHETIC_HYPOTHESIS_ASSIGNED · SYNTHETIC_HYPOTHESIS_VERIFIED · SYNTHETIC_HYPOTHESIS_REFUTED

### 23.4 Hostile Build: compile_commands.json and Preprocessor Integrity

Build configuration is untrusted input. A generated compile_commands.json must not be assumed trustworthy because hostile or compromised build scripts can manipulate include paths, forced includes, preprocessor macros, compiler wrappers, generated headers, or plugins so that analyzers inspect a materially different program.

Required artifact: `/evidence/mythos/native/compile-command-audit.json`

Audit security-relevant compiler settings including:

- `-I` / `-isystem` and MSVC `/I` / external include equivalents
- `-include` / `-imacros` and MSVC `/FI`
- `-D` / `-U` and MSVC `/D` / `/U`
- `-std`, target, sysroot, compiler executable, working directory
- `-fplugin` / `-Xclang` or comparable compiler extension hooks
- source-file paths and generated-header provenance

Flag at minimum: UNEXPECTED_INCLUDE_PATH · UNEXPECTED_FORCED_INCLUDE · SECURITY_RELEVANT_MACRO · ANALYSIS_ONLY_MACRO_DIFFERENCE · COMPILER_WRAPPER · EXTERNAL_COMPILER_PLUGIN · GENERATED_HEADER_UNVERIFIED · SOURCE_PATH_MISMATCH

Where release and analysis configurations differ, compare security-relevant preprocessing conditions. For high-value translation units, preprocessed output may be generated and hashed to demonstrate the actual source presented to Clang/CSA/other analyzers.

Compilation database trust states: `VALIDATED | VALIDATED_WITH_DIFFERENCES | SUSPICIOUS | UNTRUSTED`

An UNTRUSTED compilation database may remain as evidence but cannot silently become the sole substrate for native analysis.

### 23.5 L11 Patch Validation Hardening

Patch validation must establish that a remediation fixes the vulnerability without tampering with the test oracle, weakening assertions, or disabling required functionality.

Before L11 begins, create `/evidence/mythos/remediation/<finding-id>/patch-policy.json` containing allowed source paths, protected tests/fixtures, fixture hashes, generated paths, security invariant, functional invariant, build target, and validation tests.

By default, remediation may not modify: existing vulnerability regression-test fixtures · expected outputs · assertion blocks · reproducer inputs · test pass/fail conditions.

Any required modification to protected test material must be separately justified and approved. Otherwise PATCH_TOUCHES_PROTECTED_TEST_MATERIAL causes validation failure.

Patch semantic checks must detect candidate trivial bypasses such as: stubbed implementations · unconditional success or failure returns · premature returns that skip vulnerable logic · commenting out or excluding affected code · disabling tests or removing assertions · weakening authorization or validation requirements · constant-return substitutions · feature-flag changes used only to make a path unreachable.

Every remediation package must state both a security_invariant and a functional_invariant. The validator must confirm the patch preserves both.

`PATCH_PROPOSED -> DIFF_POLICY_CHECK -> AST_SEMANTIC_CHECK -> PROTECTED_TEST_CHECK -> SYNTAX/TYPE_CHECK -> ISOLATED_BUILD -> REGRESSION_TEST -> SECURITY_INVARIANT_CHECK -> FUNCTIONAL_INVARIANT_CHECK -> PATCH_VALIDATED`

Terminal results: PATCH_VALIDATED · PATCH_COMPILES_TEST_UNAVAILABLE · PATCH_PROPOSED_UNVALIDATED · PATCH_REJECTED_TEST_TAMPERING · PATCH_REJECTED_TRIVIAL_BYPASS · PATCH_BUILD_FAILED · PATCH_REGRESSION_FAILED

### 23.6 Verified Fact Graph Extensions

The fact graph supports VERIFIED_PRIMITIVE, VERIFIED_FACT, SYNTHETIC_HYPOTHESIS, VERIFIED_FINDING. Only VERIFIED_PRIMITIVE and VERIFIED_FACT are established evidence. SYNTHETIC_HYPOTHESIS remains explicitly non-evidentiary until canonical-source verification.

### 23.7 Completion Validator Extensions

Before report_status = FINAL, the orchestrator verifies:

- No unresolved RESCOPE_REQUIRED states remain.
- Every decision-relevant SYNTHETIC_HYPOTHESIS is VERIFIED, REFUTED, or UNRESOLVED_AND_REPORTED.
- Every compilation database used by L3 has an explicit trust state.
- No remediation is labeled VALIDATED unless protected-test, semantic, build/type, and invariant checks passed where applicable.

### 23.8 Additional Append-Only Ledger Events

VERIFIED_PRIMITIVE_CREATED · VERIFICATION_DEPENDENCY_REGISTERED · VERIFICATION_DEPENDENCY_SATISFIED · PRIMITIVE_PROMOTED_TO_FINDING · CLASSIFICATION_DEPENDENCY_INVALIDATED · LANE_RESCOPE_REQUIRED · LANE_RESCOPE_STARTED · LANE_RESCOPE_COMPLETED · SYNTHETIC_HYPOTHESIS_CREATED · SYNTHETIC_HYPOTHESIS_ASSIGNED · SYNTHETIC_HYPOTHESIS_VERIFIED · SYNTHETIC_HYPOTHESIS_REFUTED · COMPILE_DATABASE_AUDIT_STARTED · COMPILE_DATABASE_AUDIT_COMPLETED · BUILD_SEMANTIC_DIFFERENCE_FOUND · COMPILE_DATABASE_MARKED_UNTRUSTED · PATCH_POLICY_CREATED · PATCH_PROTECTED_MATERIAL_MODIFIED · PATCH_SEMANTIC_CHECK_FAILED · PATCH_TRIVIAL_BYPASS_DETECTED · PATCH_VALIDATION_COMPLETED · INJECTION_SUSPECTED

### 23.9 Incremental Event-Driven Operation

These controls make Mythos an incremental evidence system rather than a sequence of globally blocking stages. Localized facts can be verified early, later facts can satisfy dependencies, classification changes can invalidate only affected work, and integrators may generate new hypotheses without bypassing source verification.
