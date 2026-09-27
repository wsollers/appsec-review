# Go, Java, and PHP source-SAST live qualification — 2026-09-27

Run `source-sast-live-20260927c` completed the accepted `02-source-sast` worker path with all five
declared language adapters. Every scanner ran through the pinned B13 container boundary with
network mode `none`, a read-only target, and bounded scratch output.

The retained run is under
`.artifacts/source-sast-live/runs/source-sast-live-20260927c/`. The accepted worker attempt is
`84689994f02b4b60a1fb14d3d5a7cb33`; `source-sast.json` has
`sha256:c8614f975f3cb20fb6a5261cfbdb990c11fc3160cf2c4e92b08706ec9e75d9d6`, and its accepted
common envelope has
`sha256:1ad4584993d37b4ba4540701c0deaefd9ac7efb8a0ecbfbb1f839ddb256c149d`.

## Executed coverage

| Language | Tool | Version | Image digest | Normalized leads |
|---|---|---:|---|---:|
| Go | gosec | 2.29.0 | `sha256:5da32f46380338fa5d27c1309e981b98ff984c38b2d3f6bed048a0f899073dd2` | 2 |
| Java bytecode | SpotBugs + Find Security Bugs | 4.10.4 | `sha256:2bb38baab33f0ee278e0ce1dcd6af6ce8491f4855f60ad9c067d9dd25f853060` | 2 |
| PHP | PHP_CodeSniffer | 4.0.4 | `sha256:ff07323dab6e05710a8f16f66b08ba4be4716ec1649bf6ab66bbe4a21a9ec3a4` | 1 |
| PHP | PHPStan | 2.2.16 | `sha256:2fe2a59293b7d0c89d492514fcc8ac281b3b113400a9838fb6ee9f21000dc8c0` | 1 |
| PHP | Psalm | 6.18.1 | `sha256:1af80dc9c5dcd2bd630b33b867f718a5ed18b4c35c0c7d8714e40c1fb99bd9a5` | 2 |

The bounded fixture produced eight cited leads: gosec `G204` and `G702`; SpotBugs
`EI_EXPOSE_REP2` and `EI_EXPOSE_REP`; PHP_CodeSniffer
`PSR1.Files.SideEffects.FoundWithSymbols`; PHPStan `return.type`; and Psalm
`InvalidReturnType` plus `InvalidReturnStatement`. Each normalized lead points to the current
source file and line and carries that source file's SHA-256. Raw messages, snippets, and scanner
severity remain in the immutable B13 trials and are not promoted.

The machine-readable qualification record is
`qualification/source-sast-languages-live.json`
(`sha256:b9e8b619023f922d5cd37789d462f3ac26f6dccd18ba2f79268df218f6730c7f`).

## Fixes proven by the run

- Psalm now receives a repository-owned, hash-bound, read-only configuration rather than searching
  the writable scratch working directory for target-provided configuration.
- Psalm normalization uses its canonical absolute `file_path`; its presentation-oriented
  `file_name` can contain `../../workspace` and is not a safe citation locator.
- Finding exit codes remain tool-specific accepted terminal states and do not turn scanner findings
  into container failures.

## Boundaries

- SpotBugs analyzes JVM bytecode. A Java source tree without accepted compiled classes or jars must
  remain a coverage gap; this qualification target contained `Example.class` corresponding to the
  cited `Example.java`.
- The worker remains `OK_WITH_GAPS` because the repository-owned C/C++ Semgrep rules do not cover
  every source-analysis family. No Go, Java, PHP, or unavailable-tool execution gap remains in this
  accepted run.
- These records are static-analysis evidence leads, not verified findings, severities, exploitability,
  or runtime behavior.
