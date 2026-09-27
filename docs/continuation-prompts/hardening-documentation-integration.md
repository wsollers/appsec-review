# D16 — master documentation and serialized integration

The master agent owns this lane. Keep `appsec-review-process/TODO.md`, operator flow/status docs,
continuation prompts, generated job catalog and parity views synchronized with reviewed evidence.

Review H14 and H16 independently; do not merge merely because their local tests pass. Resolve any
shared-surface requests serially, rerun the independent tester after integration, and update
readiness only for qualification actually demonstrated. Preserve the distinction between source
SAST leads, evidence assembly, component characterization, OWASP applicability/worklists and
ASVS/MASVS assessment.

The component-characterization core at `ef415950` remains staged until F02 can publish the common,
accepted evidence-assembly envelope containing the signed `intel-manifest.json`. Do not bypass that
dependency. No Dependabot changes belong in these merges.
