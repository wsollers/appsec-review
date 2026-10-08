# Python and retrieval layout

Wave 1 publishes bounded path, symbol, and component JSON indices under the accepted catalog
attempt. `RunIndexBackend` implements the existing transport-independent search contract over
those immutable files. It verifies the accepted artifact hash before serving a bounded page and
never falls back to a recursive target scan. Results retain source hashes, relative paths, line
locations where available, and explicit index coverage gaps.

Python source lives under `src/appsec_review/`; tests mirror it under `tests/`. The package owns
domain behavior. Protocols and deployment mechanisms remain adapters around that behavior.

## Retrieval decision

Retrieval is a core application capability with a thin MCP interface. It is not a skill.

- `appsec_review.retrieval` owns typed queries, index readers, ranking, pagination, source identity,
  and coverage-gap behavior. It has no dependency on MCP.
- `appsec_review.mcp` translates model tool calls into core requests and serializes results. It does
  not scan repositories, build indices, rank results, or validate evidence.
- Index-building jobs create immutable run-scoped indices under
  `runs/<run-id>/data/indices/<index-name>/`. Inference reads those indices; it does not recursively
  grep the target checkout.
- Start with one read-only retrieval gateway. Split it into a top-level deployable service only when
  it needs a separate process, dependency set, security boundary, or release lifecycle.
- A skill may later teach repository agents how to operate or diagnose the gateway. It must not be
  the implementation or the authority that grants review workers access.

## I/O boundary

Do not expose general filesystem or shell access through MCP. Tools accept run ids, logical index
names, typed query fields, bounded limits, and opaque cursors. The trusted service resolves those
values to run-owned paths.

Initial tool families should remain narrow:

- evidence search and cited excerpt reads;
- code symbol, definition, reference, caller, and callee lookup;
- component and dependency lookup;
- artifact metadata and coverage-gap lookup.

Every result carries a stable source identity and resolving path/line or artifact reference. Empty
or incomplete indices return explicit gaps. Model-facing tools are read-only; jobs publish new
evidence through validated job outputs rather than arbitrary MCP writes.

## When to split the service

Keep the MCP adapter in the main package until at least one of these is true:

1. it must run with different privileges from the orchestrator;
2. its native or language-server dependencies conflict with the main environment;
3. it must scale or restart independently;
4. another repository consumes its versioned API.

At that point, move the adapter entry point to `services/retrieval-mcp/` while retaining the domain
contracts in `appsec_review.retrieval`. The transport remains replaceable and the tests continue to
exercise the same core behavior without starting an MCP server.
