# Clang static analysis

See [`engineering-security-signals.md`](engineering-security-signals.md) for this producer's place
in the combined engineering-signal data flow and downstream review boundary.

`job_clang_static_analysis` is an independent C/C++ evidence producer. It consumes only immutable,
accepted project scopes from `job_cpp_compiled_analysis`; each scope binds a materialized source
snapshot and its run-owned normalized `compile_commands.json`. It does not scan an arbitrary live
tree and never executes a target-produced binary.

For every applicable scope the job runs two actions from the same pinned offline image:

- Clang-Tidy with centrally configured check families; and
- Clang Static Analyzer (`clang --analyze`) with centrally configured checker families.

The image inherits the hash-locked LLVM 18 closure from `tool-native-cpp` and adds the pinned
`clang-tidy-18` packages plus a bounded repository-owned adapter. Every Static Analyzer diagnostic
is labelled `warning` (normalized to medium reported severity); clang-tidy `error` diagnostics
normalize to high. Runtime networking is disabled, the accepted scope is mounted read-only,
and only run-owned scratch is writable. The actions are independent: failure of one action is a
named gap and does not discard valid observations from the other.

## Evidence and coverage

The adapter emits a small JSON envelope per action. The producer rejects a wrong schema, malformed
fields, an excessive document, too many diagnostics, or an excessive trace. Each accepted
diagnostic must resolve through the accepted project source map; its location therefore retains the
target-relative path, accepted file hash, line/column range, mapping method, and producer location.

Each scope publishes an `observations` retrieval shard containing `tool_observation` entities.
Clang Static Analyzer path pieces remain bounded trace data on the observation. A separate coverage
shard records build scopes that lack compilation context. The accepted summary and job identity use
`appsec-review/clang-static-analysis-handoff/1`.

The following conditions are gaps, never clean results: missing or failed native scope, missing
compile commands, unavailable image/tool, timeout, OOM kill, nonzero action exit, output or stream
truncation, malformed or over-limit output, and a diagnostic path outside the accepted source map.
