# Q16 — independent hardening qualification

You are the read-only testing agent. Do not edit or commit files. Re-derive current main, inspect
H14 and H16 when the master supplies commits, and independently inspect component-characterization
commit `ef415950` without merging it.

Build a matrix covering happy path, immutable reuse, corrupt artifact, corrupt pointer, stale
upstream/code/config, newest failure with no fallback, forced recovery, recovered reuse, permission
denial, B13 receipt mismatch, network/read-only boundary, cancellation/timeout where implemented,
and deterministic normalized output. Run the focused unit suites, contract qualification, design
parity, generated-catalog checks, shell/Python syntax, and safe live qualifiers when the existing
stack permits. Never mutate accepted run evidence to manufacture a pass.

Report commands and counts, exact failing test names and causes, host-prerequisite failures
separately from code failures, live run/attempt IDs, and a PASS/BLOCKED/FAIL recommendation for each
candidate commit. Do not approve documentation claims that exceed the evidence.
