# Multivuln walk 01 - `job_model_connectivity`

This record advances T-057 under the
[walk terms](../walks/multivuln-bd69bfe8.md).

**Result: stopped before launch; the recorded runtime image is absent from native Docker.** No new application
run, Dagster dispatch, attempt or corpus namespace has been allocated.

## Expected duration and criterion

Expected job time: **39.233 seconds**, from the most recent local matching
target/profile/overlay run, `2026-11-12-0002`, `job_model_connectivity`,
`attempt_0001`, Dagster dispatch `c4991d76-020d-417b-8e16-8e55a500e2f5`.
Its handoff records start `2026-11-12T00:16:51.829420+00:00` and completion
`2026-11-12T00:17:31.062091+00:00`; its configuration manifest selects
`copilot-prod` and `/opt/app/test/acceptance/prod-capacity-overlay.toml`.
This is a historical timing reference, not a copied baseline or acceptance of
that run's output. Inspect at the expected mark and investigate at twice the
mark; distinguish startup/dispatch overhead from job time.

The new job must consume no upstream handoffs, resolve the provider/model
settings from its own immutable configuration, and establish availability for
each required distinct provider/model pair. Independently count those settings
from the resolved configuration. Verify the handoff's canonical outcomes by
hash and size; any canonical gap stops this walk. Save a fresh host-local
baseline only after the other checks hold.

## Four checks

- **A. Inputs:** not performed; no new claim exists.
- **B. Independent comparison:** not performed; no new job output exists.
- **C. Gaps:** not evaluated; absence of a run is not zero-gap evidence.
- **D. Baseline:** not saved; job not accepted.

## Preflight observations

- The user corrected the initially inferred Freeciv target to multivuln and
  selected the existing Linux main checkout.
- The checkout's `.venv` imports `appsec_review` from its own `src/` directory.
- `git status --short` in `targets/appsec-multi-vuln-c094` is empty;
  HEAD is `bd69bfe83fec49155366303604475512c98c4ce6`, with existing tag
  `appsec-multi-vuln-c094-v1`.
- Native Docker is installed but inactive. Docker Desktop is stopped and will
  not be substituted for the native daemon.
- Main is at `b21c90b095b7dc12f0c1a3487f1bf904106c5fca`. An integration session's
  pending update initially blocked ownership. The user then ordered the other
  threads and monitors stopped. Its update was rejected without changing either
  checkout, and the coordinator's handoff request was withdrawn. The app now
  reports only this walker running, with no pending questions or other busy
  sessions. This walker owns subsequent Linux-main operations.
- The user approved an initially empty expected-gaps list and selected
  `copilot-prod` with the existing production capacity overlay.
- Walk documentation landed on Linux `main` as `2b06514eb` and `ad6284e50`;
  the runtime source remains the existing `b21c90b0` base. An ignore-rule
  conflict was resolved without importing the unrelated main update.
- `sudo -n systemctl start docker` refused with `sudo: a password is required`.
  The service was not started. The walker stopped at the privilege boundary
  rather than trying another privileged execution route.
- The user then confirmed "Docker started—continue the walk". `docker info`
  verified the native systemd/cgroup-v2 engine at `/var/lib/docker`.
  `ops.py stack-status` found five healthy restored services and zero
  non-terminal Dagster runs, but their target is Barracuda, not this walk.
- The restored containers and `appsec-review-dagster:wsl-copilot` tag use
  `sha256:243e6d1ab40cb1f85bd34cfb0916ec4e24c0bb7bb1e5e79b7e0b427f1bade15e`.
  The checkout's `.env` records
  `sha256:29682648dd80ac803efe7cde0ce362098782312b7f44a1a658873823ac522d2b`,
  which `docker image inspect` reports missing. No image was loaded, built,
  re-tagged or selected in its place. The pending startup-plan command did not
  execute because the preceding image inspection failed.

## Commands and timing

Read-only preflight used `git status`, `git rev-parse`, `git tag --points-at HEAD`,
the checkout-local Python import, `systemctl show`, Docker context/status
inspection, and `stepwise.py init --help` / `ops.py stack-start --help`.
Individual command elapsed times were not captured; no job time is claimed.
The historical duration above is calculated from the retained handoff timestamps.

No tests ran. Replays: zero.

Preflight has exceeded the 39.233-second historical job duration. That time is
not live-job time: it went to correcting the target/checkout, obtaining the
missing walk decisions, stopping legacy coordination, integrating documentation,
and discovering the Docker-start privilege requirement.

## Not verified

Compatibility/signatures of the restored image, mounted source identity,
model availability, all four checks for the new job, and every later job.
Stack health and zero active Dagster dispatches were verified after Docker started;
they are not evidence that the mismatched deployment is ready for this walk.
The findings have not been graded.
