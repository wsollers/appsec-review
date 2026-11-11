# Job pass 10 - `job_project_build`

This pass advances T-057 using the user's capture-proven native-build direction of
2026-11-11. T-035, T-036 and T-037 remain parked. It supersedes the earlier proposed
native commissioning path for this c094 pass; no image rebuild or capture bypass is authorized.

## Starting evidence and ownership

The run-0003 audit was supplied by the read-only Run audit report session. Its canonical
gap counts come from each hash-pinned `outcomes.json`, not recursive check summaries:
source history 18, build environment 1, planning 52 and project-build 122 (193 total).
Project-build `attempt_0001`, dispatch `16b50491-2f9c-4267-97e7-b02e2ee3322f`,
resolved eleven existing base-image references but compiled nothing. Every probe was not
applicable; no accepted artifact was the c094 binary. The native c094 unit was blocked by
`unenforced_native_target` at `outcomes.json:gaps[27,68,110]`.

The audit's earlier repair-turnaround intervals retain their original uncertainty. This pass
uses the user-supplied **2026-11-11 10:39 America/New_York** finding boundary
(15:39 UTC, minute precision) to the first accepted job-10 result on the fresh scoped run.
That interval is not a fabricated timestamp for an earlier failed check.

The referenced `claude/prompt-prime-run-wsollers1-2026-11-10.md` was not present in mounted
main or the audit checkout; the audit session also had no copy. No missing instructions
from it are assumed. The explicit pass-10 prompt and available standing review-loop
instructions govern this work.

Parent session `83ad90fb-4e0a-4161-aa81-57e1bc0bd04f` owns mounted-main integration and
all live operations. One isolated implementation checkout,
`william-sollers-xbox-redesigned-disco`, is prepared at
`e2bb58e245b0b5096c78778c31b53f056da5289d`, containing main
`d01b9e3a510430b8ef247a884b7d2d401ef5c6ed`. Its own editable environment resolves there.
The old run and all accepted keys/attempts remain evidence, not inputs to rewrite.

## User-authorized target scope

With all 31 old dispatches verified stopped and the target clean, the parent applied cone-mode
sparse checkout for `projects/native/case-094`. Git 2.34.1 requires setting cone mode with
`sparse-checkout init --cone`, then `sparse-checkout set projects/native/case-094`.
The verified sparse list contains only that directory. Root files are retained by cone mode.

Target HEAD remains `bd69bfe83fec49155366303604475512c98c4ce6`, exact tag
`appsec-multi-vuln-c094-v1`; Git status is clean. The scoped raw fingerprint is
`a62432fbcad51e7de705a2a2118ce86b0083f2c749cc872b7fdd80e4f61629b6`.
A new application run is required. Run `2026-11-10-0003` will not be repaired onto this
different target fingerprint, and its corpus keys will not be overwritten.

## Required behavior and acceptance criterion

- Pre-build refusal protects capture trust: dynamic commands, compiler-resolution/environment
  escape, network-required steps, missing/invalid recipes and unknown operations remain blocked.
  The old static target proof may remain an annotation, not permission to execute.
- After execution, derive one source- and image-bound enforcement record for each native unit
  from observed compiler invocations, target flags/triples and translation units. The c094
  record must use `proof_kind: captured_invocation`, `status: proven`, and exactly one axis set
  compatible with selection policy. Recipe declarations and a merely generated compile database
  are not execution proof.
- Unknown compilers, mixed/disallowed targets and empty capture produce scoped
  `producer-gap/1` records, not silent success or a job failure.
- The existing pinned C++ image must compile c094 without deriving or rebuilding an image.
  Publish the actual binary and nonempty captured compile database in accepted artifacts.
  Keep one authoritative build and wire downstream consumption without treating a static
  annotation as mandatory proof or silently rebuilding accepted work.
- `stepwise check` must enforce the c094 binary, exactly one proven capture-derived native
  enforcement record and a nonempty compile database before job-10 acceptance.
- Jobs 1-9 on the new run require individual content checks. Canonical gaps must concern c094
  or explicit tooling limits, not omitted corpus cases.

## Verification and live receipt

Implementation, focused commands/counts/timings, the T-047 differential, coverage, exact ready
commits and live identities will be recorded here as they are established. No passing unit test
is a substitute for the requested c094 build and accepted artifact proof.

Required runner-driven cases cover a successful CMake capture, mixed targets, a compiler outside
the pinned image, empty capture, pre-build dynamic/PATH refusal, and direct-compiler parity.
Each uses real configuration and the real runner, faking only the executor boundary and
finishing under ten seconds. Exact selectors and inspected counts use the guarded test runner;
no directory/full-suite selector or unrequested heavy-tier validation is authorized.

The final receipt will include the new run ID, canonical gap table for jobs 1-10, c094 enforcement
record, accepted binary/compile-database references and finding-to-first-acceptance turnaround.
