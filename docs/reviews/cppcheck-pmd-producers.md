# Cppcheck and PMD producer decision

The production C/C++ source producer is Cppcheck 2.22.0. It reads only cataloged C/C++ paths. When
the target catalog contains an accepted `compile_commands.json`, the application creates a bounded,
run-owned copy containing only cataloged translation units; Cppcheck reads it but never runs a
compiler or target code. Without usable build flags, includes, and macros, it runs a conservative
source mode and publishes that loss of build fidelity as a coverage gap.

The production Java source producer is PMD 7.28.0. PMD was selected over another broad scanner
because the upstream project provides a stable offline binary distribution under a BSD-style
license, a Java AST and type model, deterministic JSON output, and an explicit ruleset interface.
The repository pins a small reviewed security ruleset instead of enabling PMD's general quality
catalog. Missing dependency and classpath context is always a gap.

These producers are intentionally complementary:

- Semgrep remains the cross-language, repository-authored pattern scanner.
- MobSFScan remains a mobile-source scanner built on mobile-specific rule knowledge.
- PMD adds Java-specific AST/type-aware rules but does not claim bytecode or complete classpath
  coverage.
- SpotBugs runs only against accepted `.class`, JAR, WAR, or EAR artifacts. Source-only PMD output
  is never described as SpotBugs or bytecode coverage.
- Cppcheck adds C/C++-specific preprocessing and value-flow analysis. It does not replace later
  compiler-backed analysis, and it never compiles or executes a target.

Both images build without network access from hash-locked upstream assets, run as numeric uid/gid
10001 under the central no-network/read-only policy, and write only to run-owned scratch storage.
Scanner output becomes immutable evidence observations and a producer-owned retrieval shard; it is
not a confirmed security finding.

## Runtime, evidence, and recovery lifecycle

The central configuration owns each producer's resource pool, timeout, retry bound, and
scan-to-normalize-to-index topology. Applicability is derived from the accepted target catalog and
analysis plan before dispatch. A non-applicable producer still publishes an explicit disposition;
it is never interpreted as a clean scan.

Each invocation records the pinned image identity, adapter/parser identity, bounded input identity,
duration, retry count, truncation state, result count, disposition, and named gaps in the central
run telemetry stream. Cppcheck's compile database and PMD's file list are sanitized run-owned
inputs. Parser diagnostics such as missing includes or unparseable Java files become coverage gaps,
not vulnerability observations.

Successful scan checkpoints are keyed by the target snapshot, accepted catalog, selected file
hashes, image, parser, normalizer, configuration, and mounted rule/input hashes. A retry or resumed
attempt reuses only an integrity-valid checkpoint. Every producer creates its own immutable
`observations/<producer>` SQLite shard; producer-shard completion and reuse are centrally recorded.
The fan-in manifest is published only after every producer branch reaches a terminal disposition,
so one failed producer yields a named partial-coverage gap without silently dropping the other
shards. Retrieval pins that accepted manifest and returns both matching observations and the shard's
coverage gaps.

## Reproducible update procedure

For an upstream version change, update the version and exact asset URL, byte size, and SHA-256 in
the tool's `assets.lock.json`; review the upstream license; rebuild with the repository container
builder; and run startup, functional, and security probes. PMD rule changes additionally require a
review of `java-security.xml` and a matching `rules.lock.json` hash. Finish with the focused adapter
and job tests, the full host suite, and a live Dagster acceptance run. Generated run artifacts and
local image identities remain under `runs/` and are not committed.
