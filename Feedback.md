# Review Feedback for PR #31 (validator dispatch)

Reviewed at head `63db406`. Findings were reproduced twice against unmodified code (review subagent,
then coordinator), through the PR suite's own `stage()` helper and the real `publish_validated`.
The job⇔contract binding from `63db406`, the required `orchestration=` keyword, the verifier-first
order, the upstream-pointer checks and both fail-closed seams all held (list at the end).

## [P1] An attempt for any of the nine contracts is ACCEPTED and PUBLISHED carrying files nothing reads

The three verifiers close the file set of `outputs/` only (receipt + manifest). Nothing in
`validate_job_output` closes the ATTEMPT tree. A file beside `outputs/` — `<attempt>/gitleaks-raw.json`,
`<attempt>/notes/x.json` — is at most hashed (if the envelope lists it;
`validate_job_output.py:~941-968`), is not checked at all if the envelope omits it, and is then
pinned into the accepted pointer by `tree_hashes(attempt_root)` (`publish_job_output.py:~350`).

So a `02-secrets-inventory` attempt whose extra file holds a raw token-shaped value and
`{"verified_findings": [{"severity": "critical", "exploitable": true}]}` is published with status
`OK`, and `accepted.json.hashes` names the file as part of the accepted result. That walks around the
redaction receipt and the claim-class policy this PR wires in, and contradicts lesson 14 ("every
published file is a claim surface") and the body's "post-seal tampers of every published file".

Reproduction (run from a directory containing a worktree `wt/` at the PR head; the token is assembled
at run time so no secret-shaped literal is committed):

```python
import json, os, sys, unittest
from pathlib import Path
WT = Path("wt/appsec-review-process").resolve()
sys.path.insert(0, str(WT)); sys.path.insert(0, str(WT / "tests"))
os.environ.setdefault("PHASE1_TEST_DATA", str(Path("td").resolve()))
import test_validator_vendor_prepass_dispatch as T
import publish_job_output as P
from execution_state import atomic_json
class Probe(unittest.TestCase):
    def runTest(self): pass
T.setUpModule(); t = Probe()
TOKEN = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
for contract_id in ("secrets-inventory", "iac-config-evidence", "container-image-inventory",
                    "mobile-sast", "binary-hardening", "sbom-inventory", "license-inventory"):
    st = T.stage(t, contract_id)
    raw = st.attempt / "gitleaks-raw.json"
    raw.write_text(json.dumps({"verified_findings": [{"severity": "critical"}], "api_key": TOKEN}))
    P.mark_attempt_started(st.base, st.attempt_id, T.FINGERPRINT)
    atomic_json(st.attempt / "result.json", st.envelope())
    pointer = P.publish_validated(st.base, st.attempt, st.attempt / "result.json", T.FINGERPRINT,
        expected_run_id=st.run_id, expected_job_id=st.job_id, orchestration=st.facts)
    print(contract_id, "PUBLISHED", pointer["status"], "gitleaks-raw.json" in pointer["hashes"])
```

Observed: all seven `PUBLISHED` (`OK` / `OK_WITH_GAPS`), file in `hashes` = `True`. The coordinator's
own variant — file at `notes/x.json` in a NEW directory and REMOVED from the envelope's artifacts —
is published too. SCA and lifecycle behave the same once their seam is patched. Only an extra file
INSIDE `outputs/` is refused (`receipt-invalid`).

Why the suite missed it: `OrderTests` / `ClaimSurfaceTests` only edit files that already exist under
`outputs/`. No test ADDS a file.

The gap is in the generic layer and predates this branch — like the bypass fixed in `63db406` — but
it is this PR's acceptance claim it defeats.

Fix direction: before anything else, enumerate the regular files of the attempt (no links, no
specials). For the nine, require exactly `status.json`, `manifest.json`, `result.json`, the
contract's `outputs/` files (and any tool directory a V07 contract legitimately retains — name them
in the policy). Better, for every contract: file set == envelope artifact paths + `result.json`.
Reject otherwise without quoting the name. Regression, all nine, through BOTH `validate_job_output`
and `publish_validated`: an extra file at the attempt root, in a new directory, and as a dot-file,
each listed and unlisted in the envelope.

## [P2] Envelope values controlled by the attempt are echoed, contrary to the doc and the code comment

`docs/validator-vendor-prepass-dispatch.md:64` and `validate_job_output.py:~976-980` say only the
verifier's non-echoing errors describe the attempt. But the envelope IS the attempt's `result.json`,
and its values are quoted before the verifier runs: the artifact loop (`:~950-966`: "artifact is
missing or not a regular file: {path}", duplicate path, hash mismatch) and `validate_worker_result`'s
schema errors, all flowing into `Blocked("worker result validation failed: …")`.

Observed (token-shaped value planted; same for mobile-sast and sbom-inventory):

```
secrets-inventory: file name in outputs/   -> not echoed            (held)
secrets-inventory: envelope artifact path  -> ECHOED: artifact is missing or not a regular file: outputs/<TOKEN>
secrets-inventory: envelope worker_kind    -> ECHOED: $.worker_kind: '<TOKEN>' not in enum [...]
```

Why missed: `Staged.validate`'s no-echo invariant plants values in documents, never in the envelope.
Fix direction: for the nine, quote artifact indexes and schema paths, not values (or narrow the
claim). Regression: plant a marker in every envelope string field and in an artifact path; assert
it is absent from every error.

## [P2] Two upstream-pointer hardening checks have no test that can fail

Mutation run on a scratch copy: 13 of 16 mutants killed. Two survivors matter — production code is
CORRECT today (probed: a symlinked `accepted.json` / `latest.json` yields "no readable accepted
pointer"), but a regression would go unnoticed:

- reading `accepted.json` / `latest.json` without `beneath()` in `_accepted_upstream` (~`:662`);
- the pointer's `envelope_path` not required to be contained in the upstream attempt (~`:679`).

Tests to add: symlinked `accepted.json`; symlinked `latest.json`; a forged pointer whose
`envelope_path` is `../<other attempt>/result.json`, and an absolute one, each with a matching
`envelope_sha256`. (Third survivor, the envelope re-hash, is equivalent: `result.json` is inside the
tree hash.)

## The failed "CodeQL" check (alert #6, high, `py/clear-text-storage-sensitive-data`, `execution_state.py:91`)

Naming false positive, test-only. All 10 flows start at the expression `v04.SECRETS_CONTRACT_ID` in
`tests/test_validator_vendor_prepass_dispatch.py` — the string `"secrets-inventory"` — and reach
`atomic_json` via `terminal_envelope(output_contract=…)`. No secret value reaches the sink and no
production flow is reported. `main` has no branch protection or rulesets, so nothing blocks the
merge; still, please either dismiss the alert as "used in tests / false positive" or bind the
constant to a local name without "secret" so the PR's checks are green.

## Probes that held

- Binding: contract id with different case, surrounding space or trailing `\n` rejected; one of the
  nine jobs with another of the nine or with `evidence-index` rejected; unknown job with one of the
  nine contracts rejected; vendor-table / graph / template mutants each killed. (Unknown job +
  `evidence-index` is still accepted — documented as "left as it was"; no production caller uses an
  unregistered job.)
- `orchestration=`: required; `None`, `{}`, str, `False` raise `TypeError`; publisher defaults are the
  sentinel and fail closed; `admit_reusable`, `record_terminal_current`,
  `coordinate_worker_lifecycle` cannot publish the nine. CLI: one flag alone → argparse error;
  malformed values → uncaught `TypeError` traceback (ugly, non-zero, not an acceptance).
- Order: reversing it kills 59 tests. Before the verifier only hashes, the run manifest and the
  upstream pointer are read.
- Upstream: symlinked run root, `data`, job/scope/attempts/attempt dirs refused; `..` spelling
  refused; stale-vs-newest, tree re-hash, run/job/status mutants killed.
- Seams raise unconditionally; tests patch them only via context manager.
- `status.json` / `manifest.json`: a key inserted at every top-level position and every value changed,
  all nine (156 variants) — none accepted; repeated keys rejected.
- Callers: `validate_job_output` is called only from `publish_job_output.py` and `main`; nothing under
  `orchestrator/` or `qualify_*.py` misses the new argument; the three live jobs pass the binding.
- Tests: focused suite 54 OK; whole host suite 905 run, only the 8 known host errors. #30 + #31
  merged in a scratch tree: clean, 307 affected tests OK.

## Not covered

Windows; code-server and live qualifier reruns; internals of the V04/V05/V07 verifiers; hardlink
identity; `SKIPPED` goldens against #30's graph; `admit_reusable`'s PENDING path parsing
`status.json` before validation (pre-existing).
