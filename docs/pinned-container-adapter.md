# Pinned-container argv adapter

## Status

Backlog batch B13. `appsec-review-process/container_execution.py` implements
`appsec-review/pinned-container-adapter/1.0`, and `worker_adapters.PinnedContainerAdapter` exposes
it through the narrow adapter protocol (`kind = "pinned_container"`). **No lifecycle worker uses it
yet**: nothing in the graph, the manifest, the launcher, Dagster or `build_execution.py` was
changed, and `build_execution.py` still calls its bash wrapper. Migrating a worker is a later,
separately qualified batch (E01, D09, M03 to M05).

The adapter runs one argv array in one registry-pinned image inside a fixed boundary, removes the
container, and writes one terminal result that a read-only verifier re-derives from disk.

## Wrapper identity

TODO B13 says the adapter "uses the maintained wrapper". That phrase is ambiguous in this
repository, and the ambiguity is reported rather than resolved silently:

- `images/audit-native/run.sh` is the wrapper `docs/design-v3.md` section 2.2.1 names as the
  implementation of the hostile-build boundary.
- `images/audit-buildenv-common/run.sh` is the wrapper the only container-running worker
  (`build_execution.py`) actually calls. It differs: `ALLOW_NETWORK=1` switches to
  `--network bridge`, `DEBUG_CAPS=1` adds `SYS_PTRACE` with `seccomp=unconfined`, and its tmpfs
  mounts are `exec`.

Neither script can be the adapter's execution path without breaking a B13 requirement. Both take
the image as a caller string (a tag such as `audit-native:local`), read resource limits from
environment variables with permissive defaults, need `bash` (absent on a Windows host, where a
separate `run.ps1` exists), and use `--rm`, which removes the evidence needed to tell an
out-of-memory kill or an external kill from an ordinary exit.

So the wrapper identity for this adapter is the versioned constant
`container_execution.BOUNDARY_FLAGS`, id `appsec-review/container-boundary/1.0`, built as a list in
Python and executed without a shell. It is equivalent to `images/audit-native/run.sh` (the stricter
of the two), and a test reads that script and asserts that every boundary flag it carries is also
in the built argv. `boundary_sha256()` hashes the flags, the environment allow-list, the scratch
target and the limit bounds; it is written into every result and into the fingerprint material, so
a boundary change invalidates accepted work.

## Boundary 1.0

`build_docker_argv` is a pure function. The list it returns is, in order: `docker run`, `--name`
(run-owned), two `--label`s, the constant flags below, the computed flags, allow-listed `--env`
pairs, read-only `--mount`s, the single writable scratch `--mount`, `--entrypoint=<argv[0]>`, the
image reference, then `argv[1:]`. Docker stops parsing options at the image, so nothing in
`argv[1:]` can be read as a docker option.

| Flag | Why |
|---|---|
| `--pull never` | the adapter never uses the network to obtain an image; an absent digest is `IMAGE_NOT_PROVISIONED` |
| `--log-driver none` | the daemon keeps no unbounded copy of container output; retention is the adapter's bounded logs |
| `--network none` | no network, always (see the permission section) |
| `--hostname`, `--add-host` | a resolvable self-name under `--network none`, as in `run.sh` |
| `--read-only` | read-only root filesystem |
| `--cap-drop ALL` | no Linux capabilities; nothing can add one |
| `--security-opt no-new-privileges` | no setuid escalation |
| `--workdir /scratch`, `--env HOME=/tmp` | fixed; not request properties |
| `--user` | numeric non-root `uid:gid` chosen by the trusted runtime (host uid on POSIX so scratch is writable) |
| `--pids-limit`, `--memory`, `--memory-swap` (equal to memory), `--cpus` | from required request limits |
| `--tmpfs /tmp:rw,noexec,nosuid,nodev,size=<tmpfs_bytes>` | the only other writable place, never executable |

`assert_boundary` re-checks every built list before it is executed: the constant flags appear
verbatim and contiguously, each option appears exactly the allowed number of times, every `--env`
carries a value, every mount is a plain bind, and exactly one mount is writable and targets
`/scratch`. There is no `--privileged`, `--cap-add`, `--device`, `-v`, `--env-file`, docker socket,
host home or `--rm`. Differences from `run.sh`: no exec-allowed JVM tmpfs (Joern needs a boundary
1.1), `--mount` instead of `-v` (a Windows drive colon is unambiguous), `--pull never`,
`--log-driver none`, and explicit removal instead of `--rm`.

## Request

`schemas/pinned-container-request.schema.json` (`appsec-review/pinned-container-request/1.0`) is
closed and every property is required. There is no property for a docker option, a tag, a
capability, a device, a user, a working directory or a writable target.

- `run_id`, `job_id`, `attempt_id` must equal those of the `WorkerRequest` the request arrived in.
- `image`: `{image_id, digest}`; see the registry section.
- `argv`: 1 to 256 strings, each at most 4096 characters, 65536 in total, no NUL, newline or
  carriage return. `argv[0]` is one normalized absolute path inside the container and becomes the
  entrypoint, so an image `ENTRYPOINT` cannot prefix it. A shell string is not an array and is
  rejected; `argv[0]` naming a listed shell (`sh`, `bash`, `pwsh`, ...) is rejected too. That last
  rule is a lint against shell-string assembly, not a boundary: a multiplexer such as busybox is
  not caught, and the container is what contains the process.
- `environment`: `{name, value}` pairs whose names are `LANG`, `LC_ALL`, `NO_COLOR`,
  `SOURCE_DATE_EPOCH`, `TZ` or `XDG_CACHE_HOME`; printable ASCII values up to 256 characters.
  The host environment never passes through. The docker client itself receives only `PATH`, `HOME`
  and the Windows profile variables; host `DOCKER_*` variables are dropped and the endpoint comes
  from the trusted runtime.
- `limits`: `timeout_seconds` (1..86400), `memory_bytes` (16 MiB..64 GiB), `cpu_millis`
  (100..64000), `pids` (1..8192), `tmpfs_bytes` (1 MiB..4 GiB), `stdout_limit_bytes` and
  `stderr_limit_bytes` (1..16 MiB). All required, all integers, no defaults.
- `target_mounts`, `scratch_path`, `log_path`, `network`, `permission`: below.

The trusted side is `ContainerRuntime`, built by the integrator, every field required: docker
executable and endpoint, image registry directory, host flavor, container user, the permission
context (`source_snapshot_sha256`, `registry_ceiling`, `clock`) and the cancellation event.

## Image registry

`appsec-review-process/registry/container-images/<image_id>.json`
(`schemas/container-image.schema.json`, `appsec-review/container-image/1.0`) holds a fully
qualified `repository` and an immutable `sha256:` `digest`. The schema has no tag property and the
repository pattern admits no tag. A request names an `image_id` and repeats the digest it expects;
an unknown id, a digest the registry does not hold for that id, a tag, `latest` or a bare name is
rejected before any process starts. The reference handed to docker is built from the registry
record (`repository@digest`), never from request text, and the record hash is part of the result.

## Mounts and paths

- A target mount is `{host_path, container_path}`. `container_path` is `/workspace` or
  `/inputs/<name>`. Every target mount is `readonly`; a request cannot say otherwise.
- `host_path` is one absolute, normalized spelling: no `.`, `..`, empty or trailing segments, no
  comma, double quote or control character (so nothing can add a `--mount` field), and no `:rw`
  suffix that means anything. It must be an existing directory that is not a link and is not
  reached through a link.
- Identity is device and inode, not the string. A mount may not be, or contain, the attempt root,
  the host home, the docker socket or a filesystem root; it may not be inside the attempt, a
  credential directory (`.ssh`, `.aws`, `.docker`, `.gnupg`, `.kube`, `.config`, ...) or `/proc`,
  `/sys`, `/dev`, `/etc`, `/run`, `/var/run`; and two mounts may not be one directory.
- A link *inside* a target is not followed by the host: the container resolves it in its own mount
  namespace, where the attempt and the host are not visible.
- `scratch_path` and `log_path` are single normalized relative paths
  (`tool_instance_shapes.output_path_errors`) beneath the attempt root (`execution_state.beneath`,
  which rejects links in any ancestor). They must not exist, must not be equal and must not contain
  one another, compared case-insensitively. The adapter creates both; scratch is the only writable
  bind and the log directory is never mounted, so a container cannot edit its own diagnostics.

## Permission gate and network

`request.permission` carries the B11 `requirement`, `grants` and `decision`, so the decision is
part of the request and of its fingerprint. For every request, including network `none`, the
adapter calls `permission_capabilities.require_granted` with a context built from trusted values
(the worker request's run and job, the runtime's source snapshot, registry ceiling and clock). A
persisted decision is never trusted: the grants are re-evaluated at the runtime clock. A denied,
stale, foreign, edited or mismatched decision ends `BLOCKED` with `PERMISSION_DENIED` before
docker is contacted.

Network is default deny. `network.mode` is `none`, or `granted-fixed-destinations` with exact
`{scheme, host, port}` entries. A destination that is not exactly a granted
`fixed-network-destination` capability ends `NETWORK_NOT_GRANTED`. **Boundary 1.0 has no egress
filter**, and `--network bridge` would reach every destination, which is wider than the
capability; so a fully granted network request ends `NETWORK_ENFORCEMENT_UNAVAILABLE` and no
container starts. Every list this adapter builds carries `--network none`. No granted capability
(`debugger-ptrace`, `target-mutation`, `credential-use`, `package-restore`) adds a docker
capability, device, writable target or credential in 1.0.

`fingerprint_material(request, image_record)` is what an integrator folds into a job input
fingerprint: adapter id, `boundary_sha256`, image reference and record hash, the B11 capability
fingerprint, and the hash of the request without its permission block. Re-issuing an identical
approval therefore does not change it; any argv, limit, mount, path, image or capability change
does.

## Execution and outcomes

Order: validate the runtime, the request (closed schema, then bounds), the image, the attempt
paths and the mounts, and build and re-check the docker list. Only then is anything created: the
log directory and `request.json`. Then the permission gate, the network rule, a daemon probe and a
local image probe, then scratch is created and the container runs through
`deterministic_child.execute_child` (the process gate, process-tree teardown, concurrent draining
with per-stream retention limits, timeout and cooperative cancellation are reused, not
re-implemented). Afterwards the container state is read, the container is force-removed by its
run-owned name (`appsec-<32 hex of run, job, attempt>`), removal is proven with `docker ps`, and
`container-result.json` is written last.

| Cause | Status | Meaning |
|---|---|---|
| null | OK | exit 0 |
| `PERMISSION_DENIED`, `NETWORK_NOT_GRANTED`, `NETWORK_ENFORCEMENT_UNAVAILABLE` | BLOCKED | gate closed; docker not contacted |
| `DOCKER_UNAVAILABLE`, `IMAGE_NOT_PROVISIONED` | BLOCKED | no daemon answered, or the digest is not on the host |
| `CONTAINER_START_FAILED` | FAILED | docker could not start the process (for example a missing executable) |
| `CONTAINER_EXIT_NONZERO` | FAILED | non-zero exit |
| `TIMEOUT` | FAILED | required timeout exceeded; container removed |
| `CANCELED` | CANCELED | cancellation event, `KeyboardInterrupt` or `SystemExit` (recorded, then re-raised) |
| `WORKER_LOST` | FAILED | the container or its client ended without the adapter asking: killed or removed from outside, state unreadable, client and container exit codes disagree, or exit 137 |
| `OOM_KILLED` | FAILED | the kernel killed the container at its memory limit |
| `LOG_WRITE_FAILED` | FAILED | retained diagnostics could not be written; never a success |
| `CLEANUP_FAILED` | FAILED | removal could not be proven; overrides every other cause |

A hostile or malformed request raises `ContainerRequestError` and leaves no file. A result that
cannot be persisted raises `ContainerExecutionError`. Messages name positions and rules; no value
from a request, the attempt, docker or the container is echoed, and docker's own stderr is
discarded.

## Result and verification

`schemas/pinned-container-result.schema.json` (`appsec-review/pinned-container-result/1.0`) holds
codes, counts, hashes and adapter-derived identities only. The returned mapping is deeply
immutable. The record is a cache: `verify_container_result(attempt_root, run_id=, job_id=,
attempt_id=, request=, images_dir=, host_flavor=, docker_host=)` takes the *expected* request and re-derives the identity
fields, the request hash, the image reference and record hash, the capability fingerprint, the
container name and the paths; checks status against cause, exit-code and removal rules, canonical
bytes and `result_sha256`; requires the log directory to hold exactly the listed regular files
with their sizes and hashes; requires `request.json` to be the expected request byte for byte; and
ties stream counts to the retained logs and the required limits. It also reads `command.json`, the
child runner's own record of the docker client: the recorded (redacted) docker argv must equal the
argv that the expected request, registry and boundary derive -- only the docker executable, the
container user and the scratch source are host facts taken from the record, each re-validated --
its timeout and retention limits must be the required ones, its stream counts must equal the
result's, and the claimed outcome must be one the recorded client exit allows (an `OK` result needs
client exit 0 with no timeout or cancellation). A result can therefore not be resealed against the
files beside it. `result_sha256` is an integrity check, not an authenticator: a party able to
rewrite every file in the log directory consistently is outside what 1.0 detects. The adapter does not hash scratch: worker outputs are validated by
their output contract.

**Execution and verification apply one mount rule.** `request_mount_sources` is the single
definition of which host directories a request may mount; `run_container` and
`verify_container_result` both call it (so do `load_verified_result` and `to_worker_envelope`, which
go through the verifier). `host_flavor` and `docker_host` are therefore required by all three
verification functions: they are the integrator's host facts, the same two `ContainerRuntime` fields
execution reads. Before this (PR 29 review), the verifier checked the request's shape but not its
mounts, and certified a self-consistent attempt whose request mounted `/etc`, the host home, the
attempt itself or the docker socket — states the adapter can never produce. A persisted "mount
proof" was rejected as a fix: the attempt would be vouching for itself. Consequences, stated: the
rule is evaluated against **this host at verification time** (device+inode identity), so a mount
source that has since been removed, or has become sensitive, fails closed; and verification must
run where the mount sources are visible (the worker host), not from an arbitrary machine.

## Worker-result envelope

`to_worker_envelope` reads and verifies the result from the attempt (never a caller's copy) and
maps it to `worker-result-envelope/1.0` through `worker_result.terminal_envelope` and
`artifact_records`, without changing `worker_result.py`. `worker_kind` is `pinned_container`, the
cause code is the envelope cause, the summary is fixed text, the artifacts are the log files plus
caller-declared output paths (single spellings, regular non-link files beneath the attempt), and
`acceptance_status` is always `NOT_ACCEPTED` because acceptance belongs to publication.

## Windows-host and Linux-worker parity

Path translation and list construction are pure and tested for both flavors on any machine.
POSIX sources are `/a/b`; Windows sources are `C:\a\b`, which Docker Desktop accepts in `--mount`.
UNC and device paths (`\\server\share`, `\\?\`, `\\.\pipe`), drive-relative, forward-slash, MSYS,
reserved-name, trailing-dot and alternate-data-stream spellings are rejected, not normalized. The
two lists differ only in the docker executable, the user and the two host sources. On Windows the
container user is `10001:10001`. Inside the Linux code-server there is deliberately no docker
socket, so the adapter ends `DOCKER_UNAVAILABLE`; the live tests skip there and nowhere else.

## Fixture image

`fixture-harmless` is `docker.io/library/alpine` at index digest
`sha256:f71a5f071694a785e064f05fed657bf8277f1b2113a8ed70c90ad486d6ee54dc` (alpine 3.17, busybox).
It is pulled only by digest and never named by tag; see `images/fixture-harmless/README.md`. The
live tests echo, write into scratch, fail to write the target and the root filesystem, find no
network interface but `lo`, show zero capabilities and `NoNewPrivs`, fail to execute from `/tmp`,
time out, cancel, are killed and removed from outside, lose their log writer, exceed memory, and
prove after every test that no labelled container remains.

## Limitations

- No fixed-destination egress enforcement, so no container ever has a network in 1.0.
- No seccomp profile beyond docker's default, and no VM-class isolation (design-v3 2.2.1 gaps).
- If the adapter process itself is killed with SIGKILL, the process gate kills the docker client
  but the container keeps running until something removes it by its derivable name or label.
- Mount checks and the mount itself are not atomic; the target tree is assumed not to be
  rearranged by another process during the call.
- The image must already be on the host. Provisioning by digest is an operator step.
- An image that declares a `VOLUME` still gets a writable anonymous volume from docker; it is
  removed with the container (`rm --force --volumes`), but registered images should declare none.
- The request is persisted verbatim as `request.json`; 1.0 has no credential channel, so argv and
  environment values must not carry secrets.
- Exit 137 without an out-of-memory flag is reported as `WORKER_LOST` even if the process killed
  itself.
- `LOG_WRITE_FAILED` and interrupt results carry weaker stream-count binding than other causes.
- A host that reaches docker through `DOCKER_HOST` or a context must say so in
  `ContainerRuntime.docker_host`; the host variable is ignored on purpose.
- Windows behavior is covered by pure tests only; no live Windows run was made in this batch.
- Scratch is a host bind mount without a disk quota: `tmpfs_bytes` bounds `/tmp` only, and a
  container can fill the filesystem that holds the attempt until its memory or time limit ends it.
- `attempt_root` must itself be a real directory, but an ancestor may be a link; identity checks
  use device and inode, and the scratch mount source is the resolved spelling.

## Integration follow-ups

1. `qualify_phase1.py contracts()`: schema-check `registry/container-images/` (it is already part
   of the code identity hash).
2. Register real tool images by digest, replacing `*:local` tags, before migrating any worker.
3. `build_execution.py` (E01): replace the bash wrapper call with this adapter, then requalify.
4. `create_job_handoff.py`: fold `fingerprint_material(...)["sha256"]` into the input fingerprint.
5. `publish_job_output.py` coordinator: map `ContainerRequestError` to `FAILED` and BLOCKED results
   to `BLOCKED` envelopes; call `to_worker_envelope` for the terminal record.
6. B15: assign `pinned_container` work to the Docker pool. C01: give each instance its own
   `attempt_root`, `scratch_path` and `log_path`; the container name is already unique per attempt.
7. Boundary 1.1: an egress-filtered network mode and an exec tmpfs carve-out, each versioned.
8. `design-parity-manifest.json` and generated views: record the adapter (integrator step).
