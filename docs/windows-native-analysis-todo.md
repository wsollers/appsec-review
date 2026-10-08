# Windows native-analysis TODO

- [ ] Implement the future Windows half of the two-project native calibration corpus only after the
  legal, provenance, isolation, tooling, capacity, mock-test, and live-acceptance gates in
  [`architecture/windows-native-analysis-vm.md`](architecture/windows-native-analysis-vm.md) are
  approved. Keep `analyze_cpp_project` generic, keep target execution disabled for the first
  acceptance, export immutable evidence, and verify teardown.

This scoped TODO exists because `docs/TODO.md` and `docs/agent-reader.md` already had concurrent
uncommitted edits when the design was added. Add the design and this entry to shared documentation
navigation only after those edits are reconciled; do not copy this task wholesale into the shared
TODO.
