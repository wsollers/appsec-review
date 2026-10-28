# Target acquisition

`appsec-review acquire-target` creates a new review target under `targets/` from a pinned source:

| Kind | Source | Pinned identity |
|---|---|---|
| `git` | Git repository (https, ssh) with submodules followed recursively | commit, tree, and every submodule's gitlink commit and tree |
| `perforce` | Perforce depot path, read with `p4 print` (no client workspace) | submitted changelist, effective change, per-file revision, MD5 check, and SHA-256 |
| `review_export` | GitLab merge request, Gerrit change, or Azure DevOps pull request | reviewed head revision plus Gerrit patch set or Azure DevOps iteration; Git checkout of that revision |

The command is user-invoked and only ever creates a checkout. If `targets/<id>` or its record
already exists, the request is `REFUSED`. It never pulls, edits, or replaces an existing checkout.
Delete a target yourself, together with `data/target-acquisitions/<id>/`, before acquiring it again.

Implementation: `src/appsec_review/target_acquisition/`. Configuration:
`src/appsec_review/config/target_acquisition.py`. Tests: `tests/test_target_acquisition.py`. These
use local Git repositories with nested submodules, a fake `p4`, and loopback review-API servers. No
test uses the network.

## Configure

Targets live in the central `[target_acquisition]` table of `appsec-review.toml`. That table holds
the bounds and executables, and every key is validated. Unknown keys are refused.

```toml
[[target_acquisition.targets]]
id = "service"
kind = "git"
url = "https://git.example.com/team/service.git"
commit = "0123456789abcdef0123456789abcdef01234567"
submodules = "recursive"           # or "none": each gitlink is then a named gap
fetch_refs = []                    # extra refs/... to fetch when the commit is not on a branch or tag

[[target_acquisition.targets]]
id = "engine"
kind = "perforce"
port = "ssl:perforce.example.com:1666"
trust_fingerprint = "AB:CD:..."    # required for ssl ports; pinned with `p4 trust -i`
depot_path = "//depot/engine/main/..."
changelist = 123456                # must be a submitted change
user_env = "P4USER"
ticket_env = "P4_TICKET"           # optional; passed only as P4PASSWD in the p4 environment

[[target_acquisition.targets]]
id = "service-mr-42"
kind = "review_export"
provider = "gitlab"                # gitlab | gerrit (patchset) | azure_devops (repository, iteration)
source = "api"                     # or "bundle" with bundle_path and bundle_sha256
api_url = "https://gitlab.example.com"
project = "team/service"
change = 42
revision = "<reviewed head commit>"
clone_url = "https://gitlab.example.com/team/service.git"
token_env = "GITLAB_TOKEN"         # Gerrit also needs username_env (HTTP password auth)
```

Credentials never appear in the configuration, a manifest, a failure record, or a log:

- Git URLs with user information are refused. Use the operator's Git credential helper or ssh
  agent instead.
- Perforce tickets and review-API tokens are read from the environment variables a target names.
  A missing variable is `REFUSED`.
- Every record is checked for each secret value before it is published. Process output is scrubbed.

## Run

```bash
appsec-review acquire-target --target service              # acquire one target
appsec-review acquire-target                               # acquire every configured target
appsec-review acquire-target --target service --verify-only  # re-check a target against its manifest
```

The command prints one JSON result per target. Exit codes:

- `0`: every target is `COMPLETE` (or `VERIFIED` with a complete acquisition).
- `2`: at least one target is `PARTIAL`, and none failed.
- `1`: any target is `REFUSED`, `FAILED`, or `MISMATCH`.

## What is written

`targets/<id>/` holds the materialized source. For `git` and `review_export` targets it keeps the
`.git` directory, which source-history and change-context analysis read.

`data/target-acquisitions/<id>/` (ignored by Git) holds:

| File | Content |
|---|---|
| `manifest.json` | `appsec-review/target-acquisition/1`: credential-free spec, pinned `identity` and `identity_sha256`, the raw tree fingerprint (the same `sha256-bounded-tree-v1` value intake computes), the inspection counts, `status` (`COMPLETE`/`PARTIAL`), `gaps`, artifact hashes, tool versions, and the authority statement |
| `perforce-files.json` | per-file depot path, revision, change, type, size, SHA-256, and whether the server MD5 was verified |
| `review-export-bundle.json` | the exact provider responses, reusable offline as a `source = "bundle"` input |
| `review-records.json` | `appsec-review/review-records/1`, the change-context review export |
| `changed-paths.json`, `change.diff` | base-to-head paths and binary-safe patch for the reviewed revision |

A failed or refused attempt publishes nothing under `targets/`. Its staging directories are
removed, and a credential-free failure record is written to
`data/target-acquisitions/.failed/<id>-<time>.json`.

## Safety

Materialization goes through these checks:

- Content is staged in `targets/.staging-*` and inspected before an atomic rename. Inspection
  refuses symbolic links and special files, and enforces `max_files`, `max_total_bytes`,
  `max_file_bytes`, and `max_path_bytes`.
- Every source path is validated before anything is written for it. Absolute paths, `..`,
  backslashes, drive prefixes, control characters, and `.git` components are refused, and so are
  Perforce paths that collide when case-folded.
- Git runs with these settings:
  - No system configuration, and no repository hooks or templates.
  - `core.symlinks=false`: links are materialized as text, and each one is a
    `symlink_materialized_as_text` gap.
  - fsck on fetch, no LFS smudge, and no terminal prompt.
  - A protocol allow-list of https and ssh only. `ext::`, `fd::`, `git://`, and `http://` are
    refused, as are option-like URLs.
- Submodule URLs come from the pinned commit's `.gitmodules` and are checked again. Each submodule
  must check out exactly its gitlink commit. When one cannot, the result is a named gap rather than
  a failure of the whole target.
- Perforce runs with these settings:
  - No `P4CONFIG` or `P4ENVIRO` file, a temporary trust and ticket file, and no client.
  - Reads only: `info`, `describe`, `changes`, `fstat`, and `print`.
- Review-API requests use https only. Redirects are refused. Responses are size-bounded
  (`max_http_response_bytes`) and the commit list is capped (`max_review_commits`). The reported
  head must equal the pinned revision, and for Gerrit the patch set must too; otherwise the request
  is `REFUSED`.
- Review titles, descriptions, comments, and names are never copied into review records. Only typed
  fields are kept: timestamps, identifiers, and approval facts.

## Gaps

Any gap makes the acquisition `PARTIAL`. Intake carries the gaps forward. A gap is never evidence
that a target is clean.

| Gap | Meaning |
|---|---|
| `symlink_materialized_as_text` | a Git symbolic link was written as a text file |
| `submodule_not_materialized` | `submodules = "none"` |
| `submodule_url_refused`, `submodule_url_missing` | the gitlink's URL is unsafe or absent |
| `submodule_checkout_failed`, `submodule_commit_mismatch` | the gitlink commit could not be checked out |
| `submodule_depth_exceeded` | nesting is deeper than `max_submodule_depth` |
| `git_lfs_object_not_fetched` | an LFS pointer was left in place |
| `perforce_digest_unverified` | keyword-expanded or Unicode file whose printed bytes cannot match the server MD5 |
| `perforce_symlink_skipped`, `perforce_revision_unavailable` | symlink type, or purged/archived revision |
| `review_approvals_unavailable`, `review_approval_times_unavailable` | approvals, or their times, are not reported by the provider |
| `review_commits_truncated`, `review_commit_ids_rejected`, `review_head_not_in_commit_list` | incomplete commit coverage |
| `review_not_merged` | open or abandoned review; merge-time metrics are unavailable |
| `change_base_unavailable`, `change_diff_failed`, `change_diff_too_large` | no reviewed diff |
| `target_changed_since_acquisition` | the tree a run reviewed differs from the acquired tree (added by intake or `--verify-only`) |

## Use in a review

Review the target as usual (`--target targets/<id>` or `APPSEC_REVIEW_TARGET`). In
`job_review_intake`, `fingerprint_target` finds the manifest whose `target_path` is the reviewed
target and copies it into the run as `target-acquisition.json`. It records the acquisition id,
identity hash, manifest hash, and whether the reviewed tree matches the acquired tree. The intake
handoff lists the acquisition gaps.

For a `review_export` target, the result's `change_context` names the review export. Pin it in the
change-context settings:

```toml
[jobs.job_change_context_analysis.settings.review]
source = "export"
export_path = "data/target-acquisitions/service-mr-42/review-records.json"
export_sha256 = "<change_context.export_sha256 from the acquisition result>"
```

## Not covered

- Perforce history analysis, and following submodules as independent history sources, belong to
  source-history analysis (see [`../TODO.md`](../TODO.md)). Acquisition pins both identities so
  history analysis can bind to them later.
- Git LFS objects are not fetched.
- Perforce streams, shelved changes, and unsubmitted changelists are refused, not materialized.
- Adapters were validated against recorded and fake responses, not against live GitLab, Gerrit,
  Azure DevOps, or Perforce servers.
