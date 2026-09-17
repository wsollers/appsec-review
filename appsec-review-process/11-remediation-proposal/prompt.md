# Prompt - Remediation Proposal

Create a proposed fix for one independently verified finding. Treat the verified finding as a
hypothesis about a real defect, but do not assume the first obvious patch is correct.

## Operating Rules

- Read the independent verification result first.
- Reproduce or inspect the same testcase and environment used by verification.
- Identify the smallest code or configuration change that fixes the root cause.
- Preserve public API, ABI, compatibility, and expected legacy behavior unless the verified issue
  requires a deliberate breaking change.
- Do not silently mutate target source as the final deliverable. Produce a reviewable diff/patch and
  record any working-tree edits needed to generate it.
- If target edits are made in a sandbox or ignored copy, state that clearly.
- If the fix cannot be safely proposed, return `not-recommended` or `blocked` with evidence.

## Required Process

1. Confirm the verified claim id, affected component, and source locations.
2. Read the verifier's commands, testcase, outputs, and environment details.
3. Run or cite the pre-fix testcase result. If it cannot be run, explain exactly why.
4. Inspect source, callers, IR/deep-confirmation evidence, and compatibility constraints.
5. Propose the smallest root-cause fix.
6. Apply the fix only in a reviewable working area, then generate a unified diff.
7. Re-run the original focused testcase in the same environment as verification.
8. When practical, run an additional negative/compatibility testcase that exercises expected valid
   behavior.
9. If native code is involved and Clang/LLVM IR was used in verification, regenerate comparable IR
   or explain why IR generation is not useful for the patch.
10. If sanitizers were available in verification, run the same sanitizer set. If sanitizers were not
    available, preserve that limitation and do not invent sanitizer coverage.

## Output Contract

Write:

- `result.md`
- `result.json`
- `proposed-fix.patch` or `proposed-fix.diff`
- optional testcase source or test patch files

`result.md` must contain:

- `## Budget`
- `## Summary`
- `## Inputs Used`
- `## Proposed Fix`
- `## Verification`
- `## Compatibility And Risk`
- `## Patch Artifacts`
- `## Recommended Next Step`

`result.json` must include:

- `claim_id`
- `status`
- `confidence`
- `affected_files`
- `patch_artifacts`
- `test_artifacts`
- `pre_fix_result`
- `post_fix_result`
- `same_environment_as_verification`
- `sanitizer_status`
- `ir_status`
- `residual_risks`

Allowed statuses:

- `proposed`
- `verified-locally`
- `blocked`
- `not-recommended`

Do not label a remediation as `verified-locally` unless the original verifier testcase, or a stricter
equivalent, passes after the patch in the same environment used by independent verification.
