# ADR-0014: Native lane granularity is the clang invocation

Status: **Accepted** (William, 2026-09-28)

## Context

The native lane after build resolution assumed exactly one build: IR capture wanted one image
generation, native SAST only an OK native build, and test execution an operator control staged for
exactly one unit. It broke at zero built units (freeciv21 before the 26.04 base, doom3-bfg, which is
MSBuild-only) and at many (appsec-multi-vuln has 27 native units). Per build unit was the first
proposal. The analysis tools, though, work on translation units, and what a translation unit means
is decided by the flags it is compiled with (`-D`, `-I`, `-std`, target, optimisation). The same
source compiled twice with different flags is two different things to analyse.

## Decision

1. **The unit of native analysis is one clang invocation**: one entry of the unit's
   `compile_commands.json`. Its identity is a hash of the source file's sha256, the normalised argv
   (paths relative to the build root) and the toolchain digest.
2. **Three levels, each job at the level its tool works at:**

   | Level | Keyed by | Jobs |
   |---|---|---|
   | Clang invocation | compile-DB entry | IR capture (one bitcode per invocation), clang-tidy, clang static analyzer, cppcheck with the same flags, per-TU IR facts |
   | Link target | a binary or library and the invocations that feed it | IR link, binary triage, debug-symbol index, binary hardening |
   | Build unit | a project root from the build plan | configure, build (produces the compile DB and link commands), tests |

3. **Zero is a skip, one failure is one gap.** No invocations (nothing built) publishes SKIPPED
   with `not-applicable-no-native-binaries`. A failed invocation, link target or unit is a gap for
   that item only; the rest continue. Test commands and their control come from the plan and lock,
   not operator staging.
4. **Link targets need link commands.** Bear records compiles only. Build replay also records link
   steps (`ninja -t commands` for Ninja; linker interception for Make/autotools). Without them,
   link-target jobs fall back to per-unit and say so as a gap.
5. **Index-first storage** ([scale audit](../scale-audit-unreal-engine.md)). Per-invocation status
   and outputs are records (JSONL) indexed in the evidence index, not a directory per invocation.
   Invocations run in shards; shard size and parallelism are tunables.
6. **Content-addressed reuse.** An invocation whose identity is unchanged reuses its earlier IR and
   SAST results, across runs. At engine scale (~100K invocations) re-runs then redo only what
   changed.
7. **Order of work:** per-invocation loops with zero skips (unblocks freeciv21, doom3-bfg and
   multi-vuln's native lane); link-command capture and the link-target level; plan-driven tests;
   unit `depends_on` ordering in the build plan; parallel shards; the reuse cache.

## Consequences

- Native SAST, IR and facts results carry an invocation key on every record, so findings can be
  traced to the exact flags that produced them.
- The evidence index gains an invocation dimension alongside partition and component.
- hello-autotools already captures IR per translation unit (6 modules), so part of this exists; the
  change is making it the rule and adding the other two levels.
