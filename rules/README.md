# Analysis rule and query packs

Every pack the review graph may load is registered once in [`registry.toml`](registry.toml). The
registry is the authoritative inventory: nothing outside it is verified, and a pack that is not
verified must not be loaded.

## Why a registry

Packs fail silently. A CodeQL pack whose imports no longer resolve still ships inside a
hash-pinned, smoke-tested image, because the image smoke test checks that `codeql version`
answers — not that our queries compile. The failure then arrives mid-run as a coverage gap among
hundreds, indistinguishable in shape from a tool that was correctly inapplicable.

That is what happened to `graph-export-cpp`. It declared `codeql/cpp-all: "*"`, the image shipped
`cpp-all@12.1.0`, and in that library both the old and the relocated dataflow generations export
`DataFlow::DataFlow`. Every query in the pack failed to compile, for every target, for as long as
the mismatch existed. The run recorded 14 `partial` gap records and carried on.

The registry fixes the two causes:

- **Pinned libraries.** `library` names the analysis library version the pack is written against.
  The verifier asserts it is installed before compiling, so an image that moves fails loudly
  instead of silently rebinding the queries to a library they were not written for.
- **A gate that compiles.** `containers/build.py query-packs` type-checks every registered pack in
  its pinned image, offline. Any failure fails the command. Nothing is recorded as a gap.

## Verifying

```bash
python3 containers/build.py query-packs              # every registered pack
python3 containers/build.py query-packs graph-export-cpp
```

Logs land under `runs/container-builds/<run-id>/logs/<pack-id>.verify.log`, and each failure
prints its log path, the number of compile errors and the first error with its file and line.

CodeQL packs use `codeql query compile --check-only`: it resolves imports and types without
building a query plan, so it needs no database and no built target. That is the whole bug class —
ambiguous or relocated library modules, casts that no longer typecheck — and it is cheap enough to
gate on. Full compilation is roughly twenty times slower (8m28s for one query, against 2m31s to
check-only the whole seven-query pack) and adds nothing for this purpose.

Non-CodeQL packs are validated the way the review actually invokes them. Semgrep is scanned with
each config against an empty tree rather than with `semgrep --validate`, because `--validate`
fetches `p/semgrep-rule-lints` from semgrep.dev and cannot run inside the no-network packaging
boundary.

## Registry fields

| field | meaning |
| --- | --- |
| `id` | stable pack identity, unique in the registry |
| `path` | repository-relative pack root |
| `image_path` | absolute path inside `image`, for packs that ship in the image rather than the repository; replaces `path` |
| `engine` | `codeql`, `semgrep` or `pmd` |
| `language` | source language the pack analyses |
| `suite` | pack-relative suite file, when the pack declares one |
| `image` | catalog image id, or the operator-provided CodeQL source tag, used to verify |
| `library` | analysis library version the pack is written against; asserted present before compiling |
| `verify` | `check-only` (type-check) or `validate` (engine-native) |
| `state` | `enabled` or `deferred`; only `enabled` packs are verified |

## Adding a pack

1. Add the pack under `rules/`, or record its in-image path.
2. Register it in `registry.toml` with a pinned `library`.
3. Run `python3 containers/build.py query-packs <id>` and make it pass.
4. A pack that cannot pass is left `enabled` and failing, with the cause recorded in the registry
   entry. Do not set `deferred` to make the gate green: an unverified pack that the graph still
   loads is the condition this registry exists to prevent.

## Known broken

No registered pack is known broken. `cert-cpp-coding-standards` type-checked clean (117 queries,
about 49 minutes with `--check-only`, hence its 7200 s timeout) in the rebuilt
`audit-codeql:custom-2.27.0`. That proves the queries compile; whether the suite produces findings
on a target still has to be confirmed by a review run, because earlier runs reported
`CodeQL cert-cpp query suite completed with zero observations; this is not a clean classification`.
