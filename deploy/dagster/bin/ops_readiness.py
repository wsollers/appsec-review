"""`run-readiness`: the one-time preparation of a review host (T-057 Phase 0, steps 1-5).

Runs the steps of ``docs/operations/run-readiness.md`` in order — ``host`` (preconditions), ``key``
(operator key, committed anchor, host trust directory), ``images`` (validate, build, smoke, report),
``pin`` (host re-pin as its own commit), ``sign`` (every pinned image), ``codeql`` (query packs) — each
idempotent, each logged under ``runs/run-readiness/<timestamp>/<step>.log``, and stops at the first step
that fails so the operator reads the log before anything downstream runs. Steps 6-8 (target, stack, gate
run) stay with the runbook: they need the stack scripts and a human reading the gate.

Every external command is printed before it runs. ``--dry-run`` prints them all and changes nothing.
The module shells out to the project's own tools (``containers/build.py``, ``appsec-review``,
``scripts/compile-codeql-queries.sh``); it contains no build logic of its own.
"""
from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
import os
from pathlib import Path
import shutil
import subprocess
import sys

from ops import FAILED, REFUSED, USAGE, OpsError, say

STEPS = ("host", "key", "images", "pin", "sign", "codeql")
DEFAULT_PRIVATE_KEY = Path("~/.config/appsec-review/signing/private/operator.pem")
TRUST_ANCHORS = Path("deploy/dagster/trusted-keys")
REQUIRED_CONTEXT = "default"
EXT4 = "ext4"
MIN_PYTHON = (3, 11)
REPORT_PREFIX = "[run-readiness]"


class Host:
    """Everything the steps do to the machine, behind one seam so tests can fake it."""

    def __init__(self, root: Path, log_dir: Path, *, dry_run: bool) -> None:
        self.root = root
        self.log_dir = log_dir
        self.dry_run = dry_run

    def run(self, argv: Sequence[str], step: str, *, capture: bool = False, check: bool = True,
            cwd: Path | None = None, timeout: float | None = None) -> subprocess.CompletedProcess:
        say(f"{REPORT_PREFIX} $ {' '.join(str(a) for a in argv)}")
        if self.dry_run:
            return subprocess.CompletedProcess(list(argv), 0, stdout="", stderr="")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        log = self.log_dir / f"{step}.log"
        with log.open("a", encoding="utf-8") as handle:
            handle.write(f"$ {' '.join(str(a) for a in argv)}\n")
            handle.flush()
            if capture:
                completed = subprocess.run([str(a) for a in argv], cwd=cwd or self.root, text=True, capture_output=True,
                                           timeout=timeout, check=False)
                handle.write(completed.stdout)
                handle.write(completed.stderr)
            else:
                completed = subprocess.run([str(a) for a in argv], cwd=cwd or self.root, text=True, stdout=handle,
                                           stderr=subprocess.STDOUT, timeout=timeout, check=False)
            handle.write(f"exit {completed.returncode}\n")
        if check and completed.returncode != 0:
            raise OpsError(f"{argv[0]} exited {completed.returncode}; see {log}")
        return completed

    def output(self, argv: Sequence[str], step: str, **kwargs) -> str:
        return self.run(argv, step, capture=True, **kwargs).stdout.strip()

    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def exists(self, path: Path) -> bool:
        return path.exists()


def appsec_review_cli(root: Path) -> list[str]:
    """The checkout's own ``appsec-review`` entry point, through the venv when there is one."""
    venv = root / ".venv" / "bin" / "appsec-review"
    if venv.is_file():
        return [str(venv)]
    return [sys.executable, "-m", "appsec_review.cli"]


# -- steps ----------------------------------------------------------------------------------------
def step_host(host: Host, args: argparse.Namespace) -> None:
    root = host.root
    if host.which("docker") is None:
        raise OpsError("docker is not on PATH", REFUSED)
    context = host.output(["docker", "context", "show"], "host")
    if context != REQUIRED_CONTEXT and not host.dry_run:
        raise OpsError(f"docker context is {context!r}; the review host standard is {REQUIRED_CONTEXT!r} (the in-WSL "
                       "engine). Images built on another daemon are invisible to the stack. `docker context use "
                       f"{REQUIRED_CONTEXT}` and re-run.", REFUSED)
    say(f"{REPORT_PREFIX} docker: {host.output(['docker', 'info', '--format', '{{.ServerVersion}} {{.Driver}}'], 'host')}")
    if host.which("findmnt") is not None:
        fstype = host.output(["findmnt", "-no", "FSTYPE", "-T", str(root)], "host", check=False)
        if fstype and fstype != EXT4 and not host.dry_run:
            raise OpsError(f"checkout {root} is on {fstype!r}, not {EXT4}; the mounted sources must live on WSL ext4, "
                           "never under /mnt/c or /mnt/f (deployment-image-and-source-mount.md)", REFUSED)
        say(f"{REPORT_PREFIX} filesystem: {fstype or 'unknown'}")
    dirty = host.output(["git", "status", "--porcelain"], "host")
    if dirty and not host.dry_run:
        raise OpsError("the checkout has uncommitted changes; readiness makes its own commits (anchor, re-pin) and "
                       "needs a clean tree to tell them apart:\n" + dirty, REFUSED)
    say(f"{REPORT_PREFIX} checkout: {host.output(['git', 'rev-parse', '--short', 'HEAD'], 'host')} clean")
    if sys.version_info < MIN_PYTHON:
        raise OpsError(f"python {sys.version.split()[0]} is older than {'.'.join(map(str, MIN_PYTHON))}", REFUSED)
    if host.which("openssl") is None:
        raise OpsError("openssl is not on PATH (signing needs OpenSSL 3)", REFUSED)
    say(f"{REPORT_PREFIX} {host.output(['openssl', 'version'], 'host')}")
    if not host.exists(root / ".venv" / "bin" / "appsec-review") and not host.dry_run:
        raise OpsError("no .venv with appsec-review installed: `python3 -m venv .venv && . .venv/bin/activate && "
                       "python -m pip install -e \".[test]\"`", REFUSED)


def step_key(host: Host, args: argparse.Namespace) -> None:
    cli = appsec_review_cli(host.root)
    private_key = Path(os.path.expanduser(str(args.private_key)))
    if host.exists(private_key):
        say(f"{REPORT_PREFIX} operator key present: {private_key} (never overwritten)")
    else:
        host.run([*cli, "signing", "keygen", "--private-key", str(private_key)], "key")
    anchors = host.root / TRUST_ANCHORS
    host.run([*cli, "signing", "export-trust-anchor", "--private-key", str(private_key), "--into", str(anchors)], "key")
    status = host.output(["git", "status", "--porcelain", "--", str(TRUST_ANCHORS)], "key")
    if status:
        host.run(["git", "add", "--", str(TRUST_ANCHORS)], "key")
        host.run(["git", "commit", "-q", "-m", f"Trust anchor: {args.host_label} operator public key"], "key")
        say(f"{REPORT_PREFIX} committed the public anchor (push it yourself)")
    else:
        say(f"{REPORT_PREFIX} committed anchor already current")
    installer = [*cli, "signing", "install-trust-anchors"]
    if os.name != "nt" and (host.dry_run or os.geteuid() != 0):
        installer = ["sudo", *installer]
    host.run(installer, "key")


def step_images(host: Host, args: argparse.Namespace) -> None:
    build = [sys.executable, str(host.root / "containers" / "build.py")]
    host.run([*build, "validate"], "images")
    outcome = host.run([*build, "build", "--all", "--jobs", str(args.jobs), "--continue-on-error"], "images",
                       check=False)
    if outcome.returncode != 0 and not host.dry_run:
        host.run([*build, "report"], "images", check=False)
        raise OpsError("one or more images did not build; read the report above and runs/container-builds/<run>/"
                       "<image>/build.log. The runbook's rule: an image failing for a reason unrelated to the run is "
                       "disabled in the catalog and recorded, not fixed now. Re-run `--from images` afterwards.")
    host.run([*build, "smoke", "--all"], "images")
    host.run([*build, "report"], "images")
    say(f"{REPORT_PREFIX} keep runs/container-builds/<run-id>/summary.json: it is the T-058 measurement")


def step_pin(host: Host, args: argparse.Namespace) -> None:
    cli = appsec_review_cli(host.root)
    host.run([*cli, "update-image-pins"], "pin")
    host.run([*cli, "update-image-pins", "--write"], "pin")
    changed = host.output(["git", "status", "--porcelain"], "pin")
    if not changed:
        say(f"{REPORT_PREFIX} pins already match this host; nothing to commit")
        return
    say(f"{REPORT_PREFIX} re-pinned files:\n{changed}")
    host.run(["git", "add", "-A"], "pin")
    date = datetime.now(UTC).strftime("%Y-%m-%d")
    host.run(["git", "commit", "-q", "-m", f"Host re-pin: {args.host_label}, {REQUIRED_CONTEXT} context, {date}\n\n"
              "Image IDs observed on this host after a full build; no code change."], "pin")
    say(f"{REPORT_PREFIX} committed the re-pin as its own commit (push it yourself)")


def step_sign(host: Host, args: argparse.Namespace) -> None:
    cli = appsec_review_cli(host.root)
    private_key = Path(os.path.expanduser(str(args.private_key)))
    host.run([*cli, "signing", "sign-image", "--all-pinned", "--private-key", str(private_key)], "sign")
    say(f"{REPORT_PREFIX} image enforcement stays disabled for the first runs; the signatures are ready for when "
        "[signing] image_enforcement becomes \"required\"")


def step_codeql(host: Host, args: argparse.Namespace) -> None:
    host.run(["bash", str(host.root / "scripts" / "compile-codeql-queries.sh")], "codeql", timeout=None)


HANDLERS: dict[str, Callable[[Host, argparse.Namespace], None]] = {
    "host": step_host, "key": step_key, "images": step_images, "pin": step_pin, "sign": step_sign, "codeql": step_codeql,
}


def selected_steps(args: argparse.Namespace) -> tuple[str, ...]:
    if args.only:
        return (args.only,)
    start = STEPS.index(args.start)
    return STEPS[start:]


def run(args: argparse.Namespace, root: Path, host_factory: Callable[..., Host] = Host) -> int:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    log_dir = root / "runs" / "run-readiness" / stamp
    host = host_factory(root, log_dir, dry_run=args.dry_run)
    steps = selected_steps(args)
    say(f"{REPORT_PREFIX} steps: {' -> '.join(steps)}{' (dry run)' if args.dry_run else ''}; logs: {log_dir}")
    for step in steps:
        say(f"{REPORT_PREFIX} == {step}")
        HANDLERS[step](host, args)
        say(f"{REPORT_PREFIX} == {step}: done")
    say(f"{REPORT_PREFIX} finished steps 1-5 of docs/operations/run-readiness.md; next: step 6 (target), "
        "7 (scripts/stack-rebuild then stack-start) and 8 (the gate run) by hand")
    return 0


def register(commands, add, root: Path) -> None:
    sub = add("run-readiness", lambda args: run(args, root),
              "Prepare this host for review runs: preconditions, key and anchor, build/smoke/report every image, "
              "re-pin, sign, compile CodeQL packs (run-readiness.md steps 1-5).", dry_run=True, url=False)
    sub.add_argument("--from", dest="start", choices=STEPS, default=STEPS[0], metavar="STEP",
                     help=f"start at this step and run the rest in order: {', '.join(STEPS)} (default: host)")
    sub.add_argument("--only", choices=STEPS, metavar="STEP", help="run just this one step")
    sub.add_argument("--jobs", type=int, default=4, help="parallel image builds (default %(default)s)")
    sub.add_argument("--private-key", type=Path, default=DEFAULT_PRIVATE_KEY,
                     help=f"operator signing key (default: {DEFAULT_PRIVATE_KEY}); created by the key step if absent")
    sub.add_argument("--host-label", default=os.uname().nodename if hasattr(os, "uname") else "host",
                     help="name used in the anchor and re-pin commit messages (default: this host's name)")
