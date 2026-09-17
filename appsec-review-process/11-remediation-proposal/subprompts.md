# Subprompts - Remediation Proposal

## Minimal Patch Proposal

Given one verified finding, propose the smallest source/configuration patch that addresses root cause.
Preserve surrounding style and public contracts. Include a unified diff and explain why broader
refactors were avoided.

## Same-Environment Retest

Re-run the independent verification testcase before and after the patch using the same compiler,
container, flags, sanitizer settings, and input data. For native C/C++ findings, this means the
Docker/native image and compile database environment used by the evidence pipeline, preferably from
WSL for large targets with artifacts synced back afterward. If exact parity is blocked, record the
difference as a limitation and do not upgrade confidence based on a weaker environment.

## Regression Test Authoring

Create or propose a regression test that should fail before the patch and pass after it. Keep it
small, deterministic, and close to the affected component. Include compile/run commands and expected
exit codes.

## Compatibility Review

Review callers, API contracts, test fixtures, and documented behavior to identify whether the patch
may break legitimate behavior. Distinguish intentional hardening breakage from accidental
compatibility risk.

## Sanitizer And IR Retest

For native findings, regenerate comparable LLVM IR and run the same sanitizer family used during
verification when available. If sanitizer runtime support is missing, produce sanitizer-instrumented
IR when possible and report runtime sanitizer execution as blocked by environment.
