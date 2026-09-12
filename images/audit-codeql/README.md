# audit-codeql

CodeQL CLI + bundled query packs, run offline, for **pre-engagement evidence gathering**
(ADR-0006). Not the native memory-safety substrate (that is `audit-native`, ADR-0001).

## License gate — read first

The CodeQL CLI license covers open-source and academic use. Running it against a vendor's
proprietary code in a commercial engagement requires GitHub Advanced Security (the
vendor's, or yours). `run-codeql.sh` refuses to start unless `CODEQL_LICENSE_BASIS` is
set to `oss`, `academic`, or `ghas`, and writes the value into `run-manifest.json`. There
is no default on purpose: the decision is made per engagement and is auditable.

## What it produces

`/scratch/codeql/`: one database per language, `<lang>.sarif` (+ `.csv`), per-step logs,
and `run-manifest.json` (CodeQL version, bundle, license basis, suite, source-tree hash,
per-language extraction mode and finding count, query-pack path). All of that goes into
the orchestrator's run manifest — query packs are versioned with the bundle, so reruns
can distinguish code changes from query changes (design §14).

## Languages and extraction modes

| Language | Mode | Note |
|---|---|---|
| javascript/typescript, python, ruby | interpreted | no build needed |
| go | buildless | |
| java, csharp | `--build-mode none` | no build; lower fidelity than a traced build |
| cpp | `--build-mode none` (default) | no compiler; **no** build-driven macro/template resolution. Use for breadth, not for memory-safety claims. |
| cpp, `--traced-cpp compile_commands.json` | traced clang-cl replay | experimental; CodeQL documents clang-cl support as *preliminary*; needs clang-cl + `/msvc` in the same image |
| php | — | **not supported by CodeQL.** Stays with `audit-static` (Psalm/PHPStan/Semgrep). |

## Run

```
docker build -t audit-codeql:local images/audit-codeql
CODEQL_LICENSE_BASIS=oss AUDIT_NATIVE_IMAGE=audit-codeql:local \
  images/audit-native/run.sh <source-root> - ./scratch-codeql -- \
  env CODEQL_LICENSE_BASIS=oss /opt/scripts/run-codeql.sh --langs cpp,javascript --suite security-extended
```

`run.sh` is reused for the boundary (no network, read-only `/workspace`, write only
`/scratch`); the image override is via `AUDIT_NATIVE_IMAGE`. The bundle is self-contained,
so `--network none` holds — if a run ever needs `codeql pack download`, that is a
configuration error, not a reason to open the network.

Sizing: CodeQL wants RAM; `--ram <MB>` is passed through, default is CodeQL's own
heuristic. `MEM_LIMIT` on `run.sh` must be above it.

## Validation

First target: Notepad++ v8.5.6 with `--langs cpp` in build-mode none, then `--traced-cpp`
against the same `compile_commands.json` audit-native produced (needs a combined image or
a bind-mount of the LLVM tarball — open). Compare the two SARIFs and both against the
CSA/SVF results on the four CVEs; record in `validation/notepad-plus-plus-8.5.6.md`.
