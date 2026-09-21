# Review Feedback for PR #29

## P1: `verify_container_result` accepts mount requests that `run_container` would reject

`run_container` correctly calls `checked_mount_sources(...)` before building the docker argv, so sensitive/system mounts such as `/etc`, the attempt root, host home ancestors, docker sockets, links, and duplicate directory identities are rejected before any container runs. The verification path does not repeat or prove that check. `verify_container_result(...)` validates only `request_errors(...)`, then `_command_record_errors(...)` rebuilds the argv with `build_docker_argv(...)` from `request["target_mounts"]` directly. That means a forged on-disk attempt can carry a request like:

```json
"target_mounts": [
  {"host_path": "/etc", "container_path": "/workspace"}
]
```

and, if `command.json`/`container-result.json` are self-consistent, `verify_container_result(...)` returns `[]`. I reproduced this locally on the PR branch with a synthesized attempt whose `command.json` mounted `/etc` read-only as `/workspace`; the verifier accepted it even though the actual adapter execution path would reject that request.

This matters because `to_worker_envelope(...)` trusts `load_verified_result(...)`. Any future publisher that accepts a previously materialized adapter attempt through the verifier path can certify a result for an execution state that the adapter boundary forbids and that never could have come from `run_container`.

Relevant code:

- `appsec-review-process/container_execution.py:886`: `verify_container_result(...)` does not take enough runtime/mount context to apply `checked_mount_sources(...)`.
- `appsec-review-process/container_execution.py:980`: the verifier delegates to `_command_record_errors(...)` only after file/hash checks.
- `appsec-review-process/container_execution.py:1013`: `to_worker_envelope(...)` maps the verified result into an envelope.

Please make the verifier fail closed for target mounts that execution would reject. A good fix could either pass the needed runtime context into verification and re-run `checked_mount_sources(...)`, or persist and verify an adapter-produced mount identity/proof that cannot be supplied by the container/request alone. Add a regression that forges a self-consistent result with a sensitive mount such as `/etc` and confirms `verify_container_result(...)` and `to_worker_envelope(...)` reject it.
