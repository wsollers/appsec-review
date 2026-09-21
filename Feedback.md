# Review Feedback for PR #29 (round 2)

Reviewed at head `8ba7d45`. Every finding below was reproduced twice against the unmodified head
(once by a review subagent, once by the coordinator) with real `docker run`s of the fixture image
(`--pull never`); no container was left behind. The round-1 fix holds: the mount rule is one shared
function, every safety argument of `verify_container_result` / `load_verified_result` /
`to_worker_envelope` is keyword-required, and a wrong `host_flavor` fails closed.

Probe scripts are reproduced inline so they do not depend on the reviewer's scratch directory. All
use the PR's own `tests/container_execution_support.py` (`sup.request`, `sup.run`, `sup.verify`,
`sup.host_facts`, `sup.IDS`) and this reseal helper:

```python
def reseal(log, edit_result=None):
    rp = log / ce.RESULT_FILE
    r = json.loads(rp.read_text())
    r["files"] = [{"path": e["path"], "sha256": ce._bytes_sha((log/e["path"]).read_bytes()),
                   "bytes": len((log/e["path"]).read_bytes())} for e in r["files"]]
    if edit_result: edit_result(r)
    r["result_sha256"] = ce.result_sha256(r)
    rp.write_bytes(ce.canonical_request_bytes(r))
```

## [P1] The verifier accepts a `command.json` whose WRITABLE scratch mount points at any host directory

Same class as the round-1 P1 (verifier certifies a state `run_container` can never produce), this
time for the one writable mount.

`_command_record_errors` (`appsec-review-process/container_execution.py:843-893`) takes three host
facts from the attempt's own `command.json` and feeds them back into `build_docker_argv`, so the
"re-derived" argv agrees with the record by construction:

- **scratch source** (`:858-864`): only checked to END with the segments of `request["scratch_path"]`.
  It is never compared with `attempt_root / scratch_path`, which the verifier can compute itself.
- **docker executable** (`:866`, `recorded[0]`): not validated at all.
- **container user** (`:856`): whatever follows `--user`; `1:0` (group 0) is accepted.

The docstring (`:845-849`) and `docs/pinned-container-adapter.md:196-202` say each of these is
"re-validated" and "A result can therefore not be resealed against the files beside it". Both false.

Reproduction — a real `/bin/true` run, then edit ONLY the last `--mount` of `command.json`, reseal:

```python
req = sup.request(None, ["/bin/true"]); sup.run(sup.runtime(), attempt, req)
log = attempt/"logs"/"container"
c = json.loads((log/"command.json").read_text())
i = max(k for k, v in enumerate(c["argv"]) if v == "--mount")
c["argv"][i+1] = "type=bind,source=/etc/scratch,target=/scratch"
(log/"command.json").write_text(json.dumps(c)); reseal(log)
print(sup.verify(attempt, req)); ce.to_worker_envelope(attempt, ...)
```

Observed:

```
A writable mount source='/etc/scratch': verify errors=[] -> ENVELOPE ISSUED OK
A writable mount source='/home/<user>/.ssh/scratch': verify errors=[] -> ENVELOPE ISSUED OK
A writable mount source='/var/run/docker.sock/scratch': verify errors=[] -> ENVELOPE ISSUED OK
A writable mount source='/scratch': verify errors=[] -> ENVELOPE ISSUED OK
A2 docker executable + user forged ("/tmp/evil/docker", "--user 1:0"): []
```

Why the suite missed it: the "scratch elsewhere" widening in `test_container_execution.py` (~`:1083`)
uses a source that fails the suffix check by accident. No case keeps the suffix and changes the prefix.

Fix direction: derive the expected scratch source in the verifier
(`translate_host_path(str(beneath(attempt_root, scratch_path)), host_flavor)`) and compare for
equality; make the docker executable and container user required caller-supplied host facts like
`host_flavor`/`docker_host` (or validate them, and decide whether gid 0 is ever legal). Regression:
forge each of the five edits above with a consistent reseal; verify, `load_verified_result` and
`to_worker_envelope` must all reject, and no planted value may be echoed.

## [P2] Resealing only `container-result.json` still certifies a forged log, an unread file and a reclassified outcome

The PR body says the forged-`stdout.log` case was fixed and that "the claimed outcome must be one the
recorded client exit allows". Observed on the head:

```
stdout.log same-length forged: verify=[]      (b'finding: none\n' -> b'finding: RCE!\n')
events.jsonl replaced by garbage: verify=[]
events.jsonl emptied: verify=[]
D baseline: FAILED CONTAINER_EXIT_NONZERO 1
D result-only edit -> CANCELED/None: verify=[]
D result-only edit -> WORKER_LOST/0: verify=[]
D result-only edit -> OOM_KILLED/0: verify=[]
D result-only edit -> WORKER_LOST/None: verify=[]
```

- `command.json` records stream byte COUNTS only, so the verifier binds a log's length, not its
  content. The existing test changes the length (4 → 7 bytes).
- `events.jsonl` is hashed but never read (lesson 17: a verifier must read every file it hashes).
- The outcome table (`:885-890`) ends in `.get(cause, True)`: only `None`, `CONTAINER_EXIT_NONZERO`,
  `CONTAINER_START_FAILED` and `TIMEOUT` are constrained. A real exit-1 run rewritten as `CANCELED`
  (without `cancelled: true` in `command.json`), `WORKER_LOST` or `OOM_KILLED` verifies.

Fix direction: give EVERY cause a row (default `False`; `CANCELED` requires `cancelled`,
`OOM_KILLED` requires client exit 137, …) and test the full cause × client-record matrix; record a
per-stream sha256 in the child runner's record (or narrow the doc's claim); parse `events.jsonl` or
stop listing it as verified.

## [P2] Legitimate runs that can never be verified

`redact_argv` rewrites any argument containing `password`/`token`/`secret`/`api_key`. When
`scratch_path` or `attempt_root` contains such a word the scratch mount is recorded as
`type=[REDACTED]`, the prefix check at `:859` raises, and the run is permanently unverifiable. These
are plausible names for this tool (`02-secrets-inventory` is a declared job). Separately, `:857`
collects `--mount` values across the WHOLE recorded argv, including the container's own arguments
after the image.

```
B scratch_path='secret-scan/scratch': run=OK verify=["command.json is not the child runner's record of a boundary docker run"]
B scratch_path='token-audit':         run=OK verify=[same]
B attempt_root under 'secrets-detection': run=OK verify=[same]
C argv = ["/bin/echo", "--mount", "x"]:   run=OK verify=[same]
```

Fix direction: computing the expected scratch source (the P1 fix) removes the need to extract it
from the record; compare the recorded argv with the redacted expected argv as a whole. Regression:
the invariant "every request `run_container` accepts and completes also verifies", over
keyword-bearing paths and argv.

## [P2] The mount rule's "host home" is `$HOME` — an unstated, caller-environment safety input

`request_mount_sources` (`container_execution.py:587`) passes `home=Path.home()`, which reads `$HOME`.
Under a service environment where `HOME` points elsewhere, the account's real home, `~/.ssh` and
`~/.docker` become mountable, in execution and in verification alike (lesson 1).

```
HOME='/home/<user>' mount ~/.ssh: refused
HOME='/nonexistent' mount ~: ACCEPTED
HOME='/nonexistent' mount ~/.ssh: ACCEPTED
HOME='/nonexistent' mount ~/.docker: ACCEPTED
HOME unset          mount ~/.ssh: refused      (falls back to the password database)
```

Pure reproduction, no container: set `os.environ["HOME"]`, call
`ce.request_mount_sources({"target_mounts": [{"host_path": <real ~/.ssh>, "container_path": "/workspace"}]}, attempt_root=..., host_flavor="posix", docker_host=None)`.

Fix direction: make `home` a required runtime fact, or refuse the union of the password-database
home and `$HOME`. Regression: patch `HOME` and assert the account home is still refused.

## Observations (not findings)

- `load_image_registry` follows a symlinked record file and accepts repeated JSON keys (last wins).
  The registry is tracked repository content and the PR claims nothing about it; consider hardening
  before real tool images are registered.
- `test_container_execution.py:~375` fails with `AF_UNIX path too long` under a long `TMPDIR`.

## Probes that held

argv/env cannot inject docker flags (single-token `--entrypoint=`, env-name enum, no `DOCKER_*`
pass-through); registry refuses tag-only, uppercase digests, extra keys, id ≠ file name; request
digest must equal registry digest; `acceptance_status` is always `NOT_ACCEPTED`; any edit without a
reseal is rejected; different-length stream forgeries are rejected; repeated keys in the result are
caught by the canonical-bytes check; containers are removed in `finally`; the 19 live tests pass and
leave nothing behind. Focused suites: 84 run, OK.

## Not covered

Windows flavour beyond reading; concurrency of two adapters on one attempt id; disk-full paths; the
whole suite / parity validator / contracts check were not re-run in this round.

**Stacked PRs #32 and #33 are built on this branch and should not merge before this is resolved.**
