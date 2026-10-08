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
