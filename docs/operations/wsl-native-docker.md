# Native WSL Docker: migration lessons

This runbook records the 2026-10-27 migration of the Dagster deployment from Docker Desktop to
Docker Engine inside Ubuntu-22.04. It supplements the
[deployment lifecycle](../../deploy/dagster/README.md) and
[guarded operator scripts](operator-scripts.md); it is not permission to migrate another host,
change resource limits, or launch a review.

## Evidence and completion boundary

The migration evidence is local, run-owned material under
`runs/metadata/native-wsl-migration-20261027/`, not committed documentation. Preserve its archives,
`SHA256SUMS`, inventory, manifests and verification reports rather than copying bulky hashes or
per-run output into this page. Historical paths, versions and identities below describe this
migration; discover and approve the corresponding values for a future host.

At this documentation checkpoint:

| Gate | Recorded result |
| --- | --- |
| Cold backups | PostgreSQL data, Dagster storage and 52 unique images / 67 references archived; checksums recorded. |
| Engine identity | Native Ubuntu 22.04.5, Docker 29.1.3, systemd cgroup v2, `overlayfs`, Docker root `/var/lib/docker`. |
| Image restoration | `native-image-verification.json`: 67 references / 52 IDs, no mismatches, checked at 21:52:09 UTC. |
| Volume restoration | `postgres-data-restoration-verified.json`: 1465 entries; `dagster-storage-restoration-verified.json`: 10758 entries; no content or metadata differences, checked at 21:53:41 and 21:53:48 UTC. |
| Capacity overlay | `configuration-validation.json`: one review team, unchanged semantic hash, package budget `all`, profile `copilot-prod`. |
| Host limits | `host-resource-verification.json`: all four slices have the approved kernel CPU/RAM/swap/PID values at 21:55:45 UTC; execution owner also verified Docker/containerd engine membership. |
| Commit and launch | Deployment commit completed after approved command-local Git identity recovery. Stack startup, live application/task membership, runtime integrity/authentication gates and a new review are not certified here. |

The original source was `1fd76536649f7cc383ef83d80f77108e141d0936`, the Freeciv target was
`977d2fe209b4742373999443fa9bfed3f1c0157d`, and the retained application image was
`sha256:1b6261d3027e6d898198e114a194f3e27de98c64eba039dca164824af4e6f512`.
These are provenance examples, not permanent required pins. Deployment-only resource changes
were committed as `35f29228e42fed3f71951f78a0e2f66f3350d10f`. Record the subsequent documentation
commit and final source revision separately in the launch evidence.

## Identify the engine, filesystem and owner before changing anything

Running `docker` from a WSL shell does **not** establish that the engine runs in that distribution.
Initially, `docker info` reported `Name: docker-desktop` and `OperatingSystem: Docker Desktop`,
even though the checkout was already on Linux ext4 (`/dev/sdd`). Moving that checkout was not
needed. No I/O improvement was measured; native placement alone is not performance evidence.

Record the selected Docker context/endpoint, server name and operating system, Docker root,
storage driver, cgroup driver/version, and actual checkout filesystem. Systemd in Ubuntu does not
imply that `dockerd`, a Docker service or a native image store is present. The restored native
engine reported `WSOLLERS1`, 48 CPUs and about 31.2 GiB RAM; these are observed capacity, not
permission to change global WSL settings.

Use the authoritative checkout and Compose project. Here they were
`/home/wsollers/projects/appsec-review` on `main` and `appsec-review-dagster-wsl`, not the Windows
checkout or `appsec-review-performance`. Preserve unrelated untracked state such as `data/feeds/`.
Establish one execution owner, read-only observers and explicit documentation ownership. Serialize
staging/commits, finish documentation before the final source freeze, and do not change tracked
files while runtime/source integrity is being captured. Do not fetch, pull, reset, branch, create
another checkout or push when the approved operation excludes those actions.

WSL Git author configuration is independent of the Windows checkout's configuration. The first
authorized deployment commit failed because the Ubuntu identity was unset, leaving the intended
three files staged and `HEAD` unchanged. Check identity before committing, obtain the approved
author identity rather than guessing it, and do not change global Git settings to bypass the
failure. The user approved `git -c user.name=... -c user.email=... commit ...` for deployment and
documentation commits, without changing repository/global configuration. Keep the index under
one owner's control and include the required Copilot coauthor trailer.

## Cross-shell inspection must preserve arguments

PowerShell to WSL to Bash quoting can change a command before Linux sees it. Earlier Docker
format expressions containing pipes were interpreted as pipelines. The following transport was
verified for literal Linux scripts; this example only inspects state:

```powershell
$script = @'
set -euo pipefail
cd /home/wsollers/projects/appsec-review
git branch --show-current
git status --short
docker info --format '{{json .}}'
'@
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script)) |
    wsl.exe -d Ubuntu-22.04 -- python3 -c "import sys,base64,subprocess;sys.exit(subprocess.run(['bash'],input=base64.b64decode(sys.stdin.buffer.read())).returncode)"
```

Base64 is argument transport, not encryption or sanitization. Do not include credentials in
transcripts, print `.env`, or publish expanded Compose configuration containing secrets. For
simple reads, `wsl.exe -d Ubuntu-22.04 --cd <checkout> --exec cat <file>` avoids an extra shell.
For Windows editors, the existing checkout is accessible at
`\\wsl.localhost\Ubuntu-22.04\home\wsollers\projects\appsec-review`.
Windows/WSL tools can disagree about line endings: the existing navigation page uses CRLF, which
Linux Git's default whitespace check flags on new lines. Preserve an existing file's newline
convention rather than reformatting the whole page to silence that check; inspect the content
diff before handing it to the commit owner.

Do not install dependencies merely to inspect the host: `rg` was absent in WSL, so use available
`grep`, `find` or Python reads. An optional `findmnt` query returned 1; distinguish an inspection
failure from proof that storage is absent. Check real paths: the deployment helper is
`deploy/dagster/bin/host.py`, not `deploy/dagster/host.py`. Correct inspection-only command mistakes
without treating them as deployment changes. Mutation, integrity, resource or review-execution
failures remain stop-and-recovery-approval gates. Do not invent failure timestamps not captured.

## Preserve state before switching engines

1. Query authoritative Dagster state before stopping anything. The pre-migration report at
   21:14:39 UTC showed 29 terminal historical runs and no active, queued, stale or orphaned runs.
   Those historical IDs are not a newly launched review.
2. Stop the four services through `scripts/stack-stop.sh`. This uses Compose stop and preserves
   containers and volumes; do not substitute `down -v`, purge or reinitialization.
3. Cold-copy the original PostgreSQL `/var/lib/postgresql/data/.` and Dagster `/var/dagster/.`
   data with ownership-preserving `docker cp -a ... -` archive output. Record file types, bytes,
   modes and numeric UID/GID, including the archive root. Archive immutable image IDs and the
   exact references used by configuration. Verify backups before modifying the engine.
4. Preserve unrelated Docker state. This host had an unrelated stopped
   `manual-semantic-index` container and `appsec-codeql-compile` volume. No global prune or
   `wsl --shutdown` was needed or authorized.
5. Shut down Desktop before starting the native daemon to avoid socket conflicts and two
   authoritative schedulers. `docker desktop stop --timeout 120` returned 1, but shutdown
   completed later: frontend/backend processes were gone and the `docker-desktop` distribution
   was stopped while Ubuntu remained running. Recheck live state before escalating. Force-stop
   was not performed; a timeout alone did not justify killing processes.

The approved install used `docker.io` 29.1.3-0ubuntu3~22.04.2 and `docker-compose-v2`
2.40.3+ds1-0ubuntu1~22.04.1, with their dependencies. Temporary runtime service masks prevented
package installation from starting Docker/containerd prematurely. Expected preset warnings were
not proof of a failed install: package configuration and inactive service state were checked.
Remove only masks owned by the operation. Docker/containerd were explicitly started only after
Desktop stopped and remained boot-disabled; `ubuntu-fan` remained inactive/disabled.

### Image identity and registry references are different checks

`docker image save` / `load` preserved all immutable image IDs and named tags but did not restore
the PostgreSQL `RepoDigest` alias. Resolving the configured `postgres:16@sha256:...` consequently
failed even though its image content was present. A tag match or image-ID match alone was not
sufficient. With separate approval, pulling the **exact pinned digest**, not a substitute tag or
version, restored the missing reference. Verification then matched all 67 references and 52 IDs.
See [image-pin verification](image-pin-verification.md).

### Mounted volume roots need their own metadata verification

An ownership-preserving copy into a mounted volume restored the contents and child metadata but
left the destination mount root unchanged. PostgreSQL's root remained `0:0/0755` rather than the
archived `999:999/0700`; starting PostgreSQL at that point would have bypassed the failed
preservation check.

The approved recovery corrected **only the exact mount root**, nonrecursively, to the archived
numeric owner and mode, then repeated the complete manifest comparison. The PostgreSQL root was
`/var/lib/docker/volumes/appsec-review-dagster-wsl_postgres-data/_data`; Dagster's archived root was
`0:0/1777`. Discover the actual mountpoint and archive metadata rather than assuming these values
on another host. Never recursively chown/chmod preserved data or initialize an empty replacement
database to get past a restore error.

Both final manifests matched every compared entry's bytes/type/mode/UID/GID. The operation's
helper containers remained `Created` (never started a process) and were removed after verification.
Migration acceptance requires these final reports, not the earlier failed comparison or merely a
successful copy exit code.

## Budget the engine and services as well as review actions

The action reservation ledger does not account for every host process. The approved hierarchy
separates actions, application/model services, and Docker/containerd overhead under one root:

| Slice | CPU ceiling | RAM ceiling | PID ceiling |
| --- | --- | --- | --- |
| `appsecreview.slice` | 16 | 20 GiB | 8192 |
| `appsecreview-actions.slice` | 8 | 10 GiB | 2048 |
| `appsecreview-services.slice` | 6 | 8 GiB | 4096 |
| `appsecreview-engine.slice` | 2 | 2 GiB | 2048 |

All slices require zero swap. The daemon default cgroup parent routes tool containers into the
actions slice; service drop-ins put Docker/containerd in the engine slice. Compose explicitly
routes its four services into the services slice, with individual CPU/RAM/PID ceilings:
code location 4 / 5 GiB / 2048, PostgreSQL 1 / 1 GiB / 1024, webserver and daemon each
0.5 / 1 GiB / 512. Container memory-plus-swap equals memory.

Approval and declared settings are not proof of enforcement. Before launch, inspect effective
`cpu.max`, `memory.max`, `memory.swap.max`, `pids.max` and actual daemon/service/task membership.
Check both children and their aggregate parent. The largest configured CodeQL compile reserves
8 threads and 9728 MiB: 8192 MiB tool RAM + 1024 MiB container overhead + 512 MiB staging, which
fits the 10 GiB action budget. SDK worker peak memory remains unmeasured. Hard limits bound
exhaustion; they do not certify performance or establish that a full review will fit.

## Reduce capacity without weakening the review

The approved overlay at `test/acceptance/freeciv-instrumented/capacity-overlay.toml` changes only:

```toml
[jobs.job_inference_security_review.settings.teams]
review_teams = 1
```

`src/appsec_review/config/inference_review.py` classifies this as capacity-only and removes it in
`semantic_settings_view`. Configuration verification retained the semantic hash, all-package
scope, languages, roles, STRICT assurance, models and token/tool budgets. In the approved
configuration, five teams' 15 red-or-review and 20 judge concurrency become 3 and 4 at one team;
this is not permission to remove packages or reduce assurance.

The overlay is a read-only bind mount from `test/acceptance`, so it does not require rebuilding
the application image. Select `copilot-prod` explicitly: this deployment's `.env` default was
`copilot-dev`. Follow the gated start/submission examples in the
[deployment README](../../deploy/dagster/README.md#native-wsl-review-host-limits); neither
`--no-probe` nor a successful container start certifies authentication or runtime integrity.

A deployment-only commit and a retained image have different provenance. Record the final
deployment/source SHA, implementation SHA and immutable image ID separately. Prove the installed
application/configuration/guidance bytes match the required implementation instead of claiming
an old image was built from a new deployment commit. Packaged implementation changes still
require a rebuild. Complete commits before freezing source/target/configuration identities.

## Launch once, stop safely, observe without writing

Use the guarded launcher and the explicit `--stop-on-first-error` policy only after the remaining
deployment gates pass. Its admission intent is durably `UNCERTAIN` before launch; timeout or a
lost response is not permission to submit again. Inspect/reconcile the exact recorded UUID.
First-error mode sets `dagster/max_retries=0`, disables step retries and closes admission for new
tools, model calls and repair attempts after an unexpected failure.

When termination is authorized, `scripts/review-stop-id.sh DAGSTER_UUID --reason ...` uses
`SAFE_TERMINATE`; `--now` only marks cancellation immediately and may leave work alive. Confirm
descendant processes and tracked task containers are gone before releasing reservations.
First-error mode rejects application-run resume. A linked fresh segment needs separate approval
and compatible evidence; do not delete journals/reservations or resubmit blindly.

Native Docker migration does not commission a bounded derived-image builder, egress or Skopeo.
The inspected setup still had `builder=None` and no `APPSEC_NATIVE` activation. A required
dependency-image miss must fail closed, not trigger an improvised build or safety bypass.

Read-only monitoring uses `deploy/dagster/bin/run_report.py` (GraphQL), application `status.json`,
`data/logs/pipeline.jsonl`, existing `data/telemetry/summary.json` and immutable receipts within
the selected run. Do not run a writing metrics CLI as an observer. Count unique `job_id` values,
not operations, model calls or retry attempts; unknown counts are unknown, not zero. Separate
historical runs from the new launch and report gaps rather than claiming completion. No game
launch is part of this migration or application-security review.
