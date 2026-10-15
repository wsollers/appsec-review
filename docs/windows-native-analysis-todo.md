# Windows native-analysis TODO

- [ ] Implement the future Windows half of the two-project native calibration corpus only after the
  legal, provenance, isolation, tooling, capacity, mock-test, and live-acceptance gates in
  [`architecture/windows-native-analysis-vm.md`](architecture/windows-native-analysis-vm.md) are
  approved. Keep `analyze_cpp_project` generic, keep target execution disabled for the first
  acceptance, export immutable evidence, and verify teardown.

This scoped TODO was created while `docs/TODO.md` and `docs/agent-reader.md` had concurrent
uncommitted edits. Both the design and this entry are now linked from
[`agent-reader.md`](agent-reader.md) and [`architecture/README.md`](architecture/README.md); the
related Linux-first sequencing lives under "Add Windows and large native-build coverage after the
Linux acceptance gate" in [`TODO.md`](TODO.md). Do not copy this task wholesale into the shared
TODO.
