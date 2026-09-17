# Subprompts — Independent Verification

## Threat Finding Verification

Verify one DFD/STRIDE or ASVS finding against source.

## Native Finding Verification

Verify one memory-safety finding against IR/source/tool artifacts.

## Focused Test Case Verification

Write and run the smallest practical test that confirms or refutes one specific source-level
hypothesis. Prefer ignored scratch locations over modifying target source. The test must report the
actual observed behavior, expected safe behavior, compile/run command, exit code, and whether the
claim is verified, refuted, or still unresolved.

## Control Presence Verification

Confirm or refute the presence of a specific security control.
