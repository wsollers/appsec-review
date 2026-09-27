# Binary hardening live qualification — 2026-09-27

The bounded happy-path qualification compiled a real ELF in the pinned
`audit-buildenv-cpp` image, published it through the accepted `02-native-build` binary projection,
and routed that projection through `02-binary-hardening`. Checksec 2.6.0 ran in the pinned
`audit-binary-analysis` image with container networking disabled. The binary-hardening attempt was
accepted after the common output validator re-read the projected ELF and verified its hash, size,
format, tool output, redaction receipt, and common envelope.

The retained machine-readable receipt is
[`validation/binary-hardening-live.json`](../../validation/binary-hardening-live.json). It binds the
build-image digest, ELF hash and byte count, Checksec image and version, accepted attempt, envelope
hash, normalized checks, and rule hits. The live test is
[`appsec-review-process/tests/test_binary_hardening_live.py`](../../appsec-review-process/tests/test_binary_hardening_live.py).

This qualification also found and closed two implementation defects: binary evidence freshness was
incorrectly checked against the repository checkout instead of the immutable native-binary
projection, and Checksec's `FORTIFY_SOURCE` rule was incorrectly projected into the PE-only
high-entropy-ASLR check.

The qualification proves the bounded native-binary projection to offline Checksec to validated
accepted evidence path. It is not a claim that every project can build or that every binary enables
every hardening property; absent properties remain evidence for later analysis rather than being
silently promoted to findings.
