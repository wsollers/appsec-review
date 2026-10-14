# Application-security remediation integration

Status: integrated and locally verified on 2026-10-14. Root `AGENTS.md` governs.

## Inputs and ownership

The integration branch started at local `main` commit `d476cd5c`, which already contained the
prerequisite commits `531b0602`, `7ccb4b62`, and `53efaaf8`. Each pull request was open, targeted
`main`, had a successful CodeQL rollup, and matched its expected single task commit before merge:

- PR 108, `edc748d6`: bounded Node review-artifact retention and artifact-index validation;
- PR 109, `9d5be027`: build response-file containment, verification, and provenance summary;
- PR 110, `b367ae40`: Tree-sitter Kotlin, PowerShell, and Shell coverage plus request access; and
- PR 111, `03719ca3`: project-build family routing, bounded legacy Maven layout adaptation, and
  writable Node restore caches.

The changed-file sets were disjoint. Node and project-build behavior overlapped only at the
contract boundary: a recipe that explicitly restores dependencies owns its writable workspace and
scratch caches, while language-build retains only the bounded package metadata and produced review
artifacts. No validator or gap behavior was weakened.

## Merge record

The task commits were merged one at a time with non-fast-forward merges:

1. PR 108 at merge `68e5a226`;
2. PR 109 at merge `586b017f`;
3. PR 110 at merge `c55a9cf5`; and
4. PR 111 at merge `f585d183`.

No textual merge conflicts occurred. The only integration-owned source change is the immutable
`tool-tree-sitter` image pin in `containers/catalog.toml`.

## Reconciliation

The Tree-sitter asset cache was acquired from the v1.12.5 upstream Linux parser release and checked
file by file against `assets.lock.json`, including byte counts and SHA-256 values. The image was
built from the digest-pinned Python base with `--pull=false`, `--network none`, and
`--provenance=false`. Docker resolved the result to
`sha256:b6a2d58ad19f6ddcbe67112b5ad0d6f2966ffa9b7f382c434d782025ceeef618`,
which is now the catalog pin. The image inventory contains exactly the 14 locked grammar libraries.
Catalog validation and the image startup smoke passed.

All four fixes have regressions that fail without their task change: Node metadata/output bounds and
package integrity, response-file scratch containment and tamper rejection, closed Tree-sitter
grammar routing plus live parsing, and Maven/Node project-build preparation and routing.

## Verification

- PR 108 focused suites: 23 passed.
- PR 109: 65 passed and 1 skipped in the full focused run; 11 deep-path cases hit the host's Windows
  path ceiling. The five new capture/verifier regressions passed under pytest, and the response-file
  end-to-end regression passed separately from a compact `test/tmp` path.
- PR 110: 10 passed and 2 skipped before the image rebuild. After the rebuild, every language live
  parse passed, and the parallel query/resume graph passed from a compact `test/tmp` path.
- PR 111 focused suite: 23 passed.
- Combined project-build, Node/JVM language-build, artifact indexing and retrieval, build capture,
  Tree-sitter, container build/catalog, Clang static analysis, engineering-signal integration, and
  retrieval-interface run: 171 passed, 3 skipped, 2 deliberately deselected, and 22 Windows
  path-depth failures. Rerunning all 22 failed JVM and artifact-retrieval cases from compact
  repository-owned paths passed.

## Bounded gaps

- Windows does not preserve POSIX mode bits, so the existing exact `0600` assertion for a private
  tool-input file remains an environment-only failure; the container-readable and tamper checks pass.
- Deep pytest-generated paths can exceed the Windows/Docker Desktop or SQLite path boundary even
  when the pytest base is under `test/tmp`. The identical product cases pass with shorter descendants;
  this is not treated as clean evidence for untested environments.
- No external model-provider or unrelated tool-image acceptance was performed as part of this
  integration.
