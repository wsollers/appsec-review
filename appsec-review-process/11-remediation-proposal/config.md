# Config - Remediation Proposal

## Required Inputs

- independently verified finding or error
- verifier output and testcase artifacts
- target source paths and exact tested environment
- compile database or build command used by verification
- coverage and retrieval artifacts needed to understand callers/impact

## Required Outputs

- proposed minimal fix with rationale
- unified diff or patch file
- before/after test evidence from the same environment as verification
- regression test recommendation or test patch
- risk assessment for behavior compatibility
- explicit status: proposed, verified-locally, blocked, or not-recommended

## Success Criteria

- the fix addresses the verified behavior, not merely the symptom in the test
- the original focused testcase fails before the fix and passes after the fix, or the lane explains why that is not possible
- the same Docker/native-image compiler/container/sanitizer environment is used as independent verification unless explicitly blocked
- host compiler results are labeled non-authoritative and are not used alone for `verified-locally`
- generated artifacts are written under the run output directory or ignored scratch paths
- target source is not silently changed without a reviewable patch/diff
