# Walk state: multivuln at `bd69bfe8`

Terms: [multivuln-bd69bfe8](multivuln-bd69bfe8.md). Updated 2026-11-12.

| Item | Value |
| --- | --- |
| Host and checkout | WSOLLERS1, Ubuntu-22.04, `/home/wsollers/projects/appsec-review`, `main` |
| Observed main | `305486982fc947c5cd39ee05861f16080ad7bb23`; runtime base remains `b21c90b095b7dc12f0c1a3487f1bf904106c5fca`; only walk documents and their ignore rule added; unrelated untracked `data/feeds/` preserved |
| Run | Not launched; no application run ID allocated |
| Corpus namespace | Not allocated; must be a fresh ignored `multivuln-bd69bfe8-wsollers1-v*` namespace |
| Target | `targets/appsec-multi-vuln-c094`, clean at `bd69bfe83fec49155366303604475512c98c4ce6`; existing tag `appsec-multi-vuln-c094-v1` |
| Profile and overlay | `copilot-prod`; `prod-capacity-overlay.toml` |
| Accepted | None in this fresh walk |
| Job in hand | 1: `job_model_connectivity`; [record](../tasks/2026-11-12-multivuln-walk-01-model-connectivity.md) |
| Stack | Native Docker is running after the user's intervention; five existing services are healthy, still configured for Barracuda; zero active Dagster dispatches |
| Expected gap causes | None |

## Ownership and startup

The user directed this walker to stop the other threads and monitors and become
the sole active repository owner. Fleet main landing's pending update was
rejected with instructions to keep both checkouts unchanged and stop; its
autopilot mode was changed to interactive. The legacy Appsec system review
coordinator was instructed to stop its work and monitors. The earlier request
for those sessions to integrate the walk documents was withdrawn.

The app's subsequent live status reported one running session (this walker),
zero other busy sessions and zero pending questions. No background task agents
or shell sessions were present; no matching user timers were found. The
remaining Linux-main shell is the user's interactive terminal and was untouched.
Dormant sessions were not contacted.

The walk documents were integrated as `2b06514ebf6e18756729ae8cd047c0ef9b1f34d1`
and `ad6284e503b77a70b7dfa2fa77a198858e75381b`. The `.gitignore` cherry-pick conflict
was resolved by retaining the main file and adding only this walk's baseline
rule. No pending runtime-code update was integrated.

## Waiting on the user

The user confirmed "Docker started—continue the walk". Verified native engine:
`WSOLLERS1`, systemd cgroups v2, `/var/lib/docker`. The restored stack has five
healthy services, no non-terminal Dagster runs, profile `copilot-prod`, the
production capacity overlay, and target `/opt/app/targets/barracuda`. It has not
been reconfigured or used for this walk.

The existing image tag `appsec-review-dagster:wsl-copilot` and the restored
containers resolve to
`sha256:243e6d1ab40cb1f85bd34cfb0916ec4e24c0bb7bb1e5e79b7e0b427f1bade15e`
(created 2026-11-04). The checkout's ignored `.env` instead records
`sha256:29682648dd80ac803efe7cde0ce362098782312b7f44a1a658873823ac522d2b`;
`docker image inspect` reports that image absent from this daemon.

Stop for the operator's image decision. Do not silently replace the recorded
identity with the restored older image, rebuild, re-pin, change a key, or bypass
verification. No stack-start or review-launch command has executed.

## In flight

No job, unit test, integration suite or acceptance suite has been launched.
No target changes, image rebuilds, pushes or baseline copies have been made.
