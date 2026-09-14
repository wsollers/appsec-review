# audit-codeql

CodeQL CLI + bundled query packs, run offline, for **pre-engagement evidence gathering**
(ADR-0006). Not the native memory-safety substrate (that is `audit-native`, ADR-0001).

## License basis

`ghas` — GitHub Advanced Security via Microsoft (ZeniMax). Set as the image default and
recorded in `run-manifest.json` on every run; override with `CODEQL_LICENSE_BASIS` if an
engagement is run under a different basis (`oss`, `academic`).

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

Build, then prove the image before touching a target (separate steps on purpose):

```
curl -L -C - -o images/audit-codeql/codeql-bundle-linux64.tar.zst \
  https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.0/codeql-bundle-linux64.tar.zst
docker build -t audit-codeql:local images/audit-codeql     # verifies the bundle sha256
AUDIT_NATIVE_IMAGE=audit-codeql:local images/audit-native/run.sh . - ./scratch -- /opt/scripts/smoke-test.sh
AUDIT_NATIVE_IMAGE=audit-codeql:local \
  images/audit-native/run.sh <source-root> - ./scratch-codeql -- \
  /opt/scripts/run-codeql.sh --langs cpp,javascript --suite security-extended
```

`run.sh` is reused for the boundary (no network, read-only `/workspace`, write only
`/scratch`); the image override is via `AUDIT_NATIVE_IMAGE`. The bundle is self-contained,
so `--network none` holds — if a run ever needs `codeql pack download`, that is a
configuration error, not a reason to open the network.

Sizing: CodeQL wants RAM; `--ram <MB>` is passed through, default is CodeQL's own
heuristic. `MEM_LIMIT` on `run.sh` must be above it.

## Traced clang-cl extraction (`Dockerfile.native`)

`audit-codeql-native` layers the CodeQL bundle on `audit-native:local`, so
`codeql database create --command` can trace the exact `clang-cl` invocations from
`compile_commands.json` with `/msvc` mounted. This is the C/C++ mode that matters for
Windows code; build-mode none is for breadth on other languages.

```
docker build -t audit-codeql-native:local -f images/audit-codeql/Dockerfile.native images/audit-codeql
cp scratch-npp/compile_commands.json scratch-npp/vfs-overlay.yaml scratch-codeql/    # same paths inside the container
AUDIT_NATIVE_IMAGE=audit-codeql-native:local MEM_LIMIT=20g \
  images/audit-native/run.sh <source-root> ./msvc ./scratch-codeql -- \
  /opt/scripts/run-codeql.sh --langs cpp --traced-cpp /scratch/compile_commands.json --ram 12000
```

`replay_compile_commands.py` runs each entry under CodeQL's tracer; TU failures are
counted, not fatal. `run-manifest.json` records `extraction_mode: traced-clang-cl` and the
replay's ok/failed counts belong next to it.

## Validation

First target: Notepad++ v8.5.6 with `--langs cpp` in build-mode none, then `--traced-cpp`
against the same `compile_commands.json` audit-native produced (needs a combined image or
a bind-mount of the LLVM tarball — open). Compare the two SARIFs and both against the
CSA/SVF results on the four CVEs; record in `validation/notepad-plus-plus-8.5.6.md`.
