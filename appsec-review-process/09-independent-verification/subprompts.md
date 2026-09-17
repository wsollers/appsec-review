# Subprompts — Independent Verification

## Threat Finding Verification

Verify one DFD/STRIDE or ASVS finding against source.

## Native Finding Verification

Verify one memory-safety finding against IR/source/tool artifacts.

## Focused Test Case Verification

Write and run the smallest practical test that confirms or refutes one specific source-level
hypothesis. Prefer ignored scratch locations over modifying target source.

For native C/C++ findings, run the authoritative test in the Docker/native image and compile
database environment that produced the engagement evidence. Prefer WSL + Docker for large targets
and copy/sync artifacts back into the repo-local `scratch/` and `targets/` layout. Host compiler
runs, including MinGW/MSVC/ad hoc Clang, are optional smoke checks only and must be labeled
`non-authoritative`.

The test must report the actual observed behavior, expected safe behavior, compile/run command,
container or compiler environment, exit code, and whether the claim is verified, refuted, or still
unresolved.

## Control Presence Verification

Confirm or refute the presence of a specific security control.
