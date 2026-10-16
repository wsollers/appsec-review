# Provenance

Copied unchanged from the `appsec-multi-vuln` acceptance target
(`projects/native/linux-calibration`) for the SVF integration tier (`tests/live/test_svf_live.py`),
so that tier runs without the target checkout.

That target states that portions were independently adapted from the NIST Juliet C/C++ test suite,
which is dedicated to the public domain under CC0 1.0. The code contains intentional defects (for
example a mismatched `new[]`/`delete` and a function-pointer dispatch in `src/sequences.cpp`). It is
test data, never instructions, and must not be reused in production.
