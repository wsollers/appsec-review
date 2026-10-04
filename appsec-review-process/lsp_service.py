#!/usr/bin/env python3
"""On-demand language-server broker for pipeline jobs and model query tools (``runs/<run>/data/lsp/``).

The languages present (an accepted ``02-language-census``'s ``languages_needing_server`` when there is one, else
the accepted code index's file languages) are mapped by ``SERVER_PLAN`` to one pinned
server and buildenv image each (``tooling/buildenv-catalog.json``). A server is **ready** once its build
input exists: C/C++ the accepted ``02-native-build`` unit's ``compile_commands.json`` (one build variant per
unit), Java a ``pom.xml``/Gradle file, Go ``go.mod``, Rust ``Cargo.toml``, TS/JS ``tsconfig.json``/
``jsconfig.json``/``package.json``, Python and PHP nothing. A missing input is a gap
(``lsp-not-ready: no compile_commands``); a present language without a server is ``lsp-no-server``.

**Start on first query, never twice.** ``Broker.query`` answers from the recording first. Otherwise the
first caller for (run, server, variant) creates ``locks/<server>-<variant>.lock`` with ``mkdir`` (atomic) and
spawns a daemon (``serve``) that starts the server in its image through the B13 boundary
(``container_execution.build_docker_argv``: network none, the checkout and build inputs mounted read-only,
one run-owned scratch dir) plus ``--interactive`` for the stdio pipe, initializes it and writes
``owner.json`` (pid, container id, start time, a loopback port and a token). Every other caller waits for
``ready`` and talks to that daemon; concurrent first queries therefore start exactly one container. A lock
whose owner pid or container is gone is taken over: it is renamed aside atomically (one winner) with a
recovery record. The daemon stays up until ``idle_seconds`` pass without a query or ``teardown`` (run end),
then shuts the server down, removes the container and releases the lock. A server that fails to start or
initialize is recorded in ``failures/``; it is retried once, then every query is an ``lsp-server-failed`` gap.

**No project code runs.** The presets switch off what would execute or fetch: rust-analyzer build scripts,
proc macros and check-on-save; gopls with ``GOFLAGS=-mod=readonly GOPROXY=off GOTOOLCHAIN=local``; jdtls
with Maven/Gradle import and autobuild disabled (so no plugin runs; dependencies on the classpath are then
unresolved, recorded as ``lsp-limit``); clangd with ``--compile-commands-dir`` and no background index, no
``--query-driver`` (no compiler is executed), no clang-tidy; typescript-language-server without automatic
type acquisition. csharp-ls loads projects through MSBuild, which runs project targets: no C# server.

**Record and replay.** Every live answer is written once to ``recordings/<key>.json``: the method and
params, the response, server name and version, image id and digest, build variant and build-input hash,
source snapshot and time, sealed by ``record_sha256``. ``key`` hashes the query and the server identity
(image digest, argv, options, build input, snapshot), so the same query on the same inputs replays the
same answer; a recording that fails its hash is a gap, never overwritten. Server output is untrusted data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Callable

ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

import lsp_driver  # noqa: E402

RECORDING_SCHEMA = "appsec-review/lsp-recording/1"
OWNER_SCHEMA = "appsec-review/lsp-lock-owner/1"
CONTAINER_ROOT = "/workspace"
COMPILE_DB_MOUNT = "/inputs/compile-db"
HEADERS_MOUNT = "/inputs/generated-headers"     # native_sast.HEADERS_MOUNT: where adapted -I entries point
MAX_START_ATTEMPTS = 2                          # one retry, then gap
DEFAULTS = {"idle_seconds": 900.0, "start_seconds": 180.0, "request_seconds": 30.0, "poll_seconds": 0.05}
_ENV = "/usr/bin/env"

# server_key -> plan. ``markers``: build-input file names (``*.ext`` = any file with that suffix).
SERVER_PLAN: dict[str, dict[str, Any]] = {
    "cpp": {"languages": ("c", "cpp"), "server": "clangd", "image_id": "audit-buildenv-cpp",
            "readiness": "compile_commands",
            "argv": [_ENV, "clangd", "--background-index=false", "--log=error", "--pch-storage=memory",
                     "--clang-tidy=false", "--header-insertion=never", "--compile-commands-dir=" + COMPILE_DB_MOUNT]},
    "java": {"languages": ("java",), "server": "jdtls", "image_id": "audit-buildenv-java", "readiness": "markers",
             "markers": ("pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"),
             "argv": [_ENV, "JAVA_TOOL_OPTIONS=-Duser.home=/scratch/home -Djava.io.tmpdir=/scratch", "jdtls",
                      "-data", "/scratch/jdtls-workspace"], "settle_seconds": 10.0,
             "initialization_options": {"settings": {"java": {
                 "import": {"maven": {"enabled": False}, "gradle": {"enabled": False, "wrapper": {"enabled": False}},
                            "exclusions": ["**/node_modules/**"]},
                 "autobuild": {"enabled": False}, "maven": {"downloadSources": False},
                 "configuration": {"updateBuildConfiguration": "disabled"}}}},
             "limit": "jdtls-build-import-disabled: Maven/Gradle import is off so no build plugin runs; library "
                      "types from dependencies are unresolved and cross-references stop at the project's own code"},
    "go": {"languages": ("go",), "server": "gopls", "image_id": "audit-buildenv-go", "readiness": "markers",
           "markers": ("go.mod", "go.work"),
           "argv": [_ENV, "GOFLAGS=-mod=readonly", "GOPROXY=off", "GOTOOLCHAIN=local", "GOSUMDB=off",
                    "GOPATH=/scratch/go", "GOCACHE=/scratch/go-cache", "gopls", "serve"],
           "limit": "gopls-offline: GOPROXY=off; packages missing from the module cache are unresolved"},
    "rust": {"languages": ("rust",), "server": "rust-analyzer", "image_id": "audit-buildenv-rust",
             "readiness": "markers", "markers": ("Cargo.toml",),
             "argv": [_ENV, "CARGO_NET_OFFLINE=true", "CARGO_HOME=/scratch/cargo", "rust-analyzer"],
             "settle_seconds": 5.0,
             "initialization_options": {"cargo": {"buildScripts": {"enable": False}}, "procMacro": {"enable": False},
                                        "checkOnSave": False, "check": {"command": "none"}},
             "limit": "rust-analyzer-no-build-scripts: build scripts and proc macros are off; generated items are "
                      "unresolved"},
    "typescript": {"languages": ("javascript", "typescript", "tsx"), "server": "typescript-language-server",
                   "image_id": "audit-buildenv-typescript", "readiness": "markers",
                   "markers": ("tsconfig.json", "jsconfig.json", "package.json"),
                   "argv": [_ENV, "typescript-language-server", "--stdio"],
                   "initialization_options": {"tsserver": {"path": "/opt/node-lsp/node_modules/typescript/lib"},
                                              "disableAutomaticTypingAcquisition": True}},
    "python": {"languages": ("python",), "server": "pylsp", "image_id": "audit-buildenv-python", "readiness": "none",
               "argv": [_ENV, "pylsp"]},
    "php": {"languages": ("php",), "server": "phpactor", "image_id": "audit-buildenv-php", "readiness": "none",
            "argv": [_ENV, "phpactor", "language-server"], "settle_seconds": 3.0,
            "initialization_options": {"indexer.enabled_watchers": [], "language_server.diagnostics_on_update": False}},
}
# Languages a pinned server exists for but that is not started, with the reason (never silently dropped).
WITHHELD = {"c_sharp": "csharp-ls loads projects through MSBuild, which runs project targets (project code)"}
LANGUAGE_SERVER = {language: key for key, plan in SERVER_PLAN.items() for language in plan["languages"]}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _file_sha(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            value.update(chunk)
    return "sha256:" + value.hexdigest()


def _utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _marker(name: str, markers: tuple[str, ...]) -> bool:
    return any(name == marker or (marker.startswith("*") and name.endswith(marker[1:])) for marker in markers)


def build_inputs(target: Path, excluded: Callable[[str], Any] | None = None) -> list[str]:
    """Every server's marker files in the checkout (sorted; ``.git`` and symlinks skipped, ``excluded`` paths out)."""
    markers = {marker for plan in SERVER_PLAN.values() for marker in plan.get("markers", ())}
    found = []
    for directory, subdirs, files in os.walk(target, followlinks=False):
        subdirs[:] = sorted(name for name in subdirs if name != ".git" and not (Path(directory) / name).is_symlink())
        for name in files:
            if _marker(name, tuple(markers)):
                relative = (Path(directory) / name).relative_to(target).as_posix()
                if not (excluded and excluded(relative)):
                    found.append(relative)
    return sorted(found)


def server_plan(languages: dict[str, int], inputs: list[str]) -> list[dict[str, Any]]:
    """Per server: the present languages it serves ({language: files}), its image and its build-input files."""
    counts: dict[str, dict[str, int]] = {}
    for language, files in languages.items():
        key = LANGUAGE_SERVER.get(language)
        if key:
            counts.setdefault(key, {})[language] = files
    out = []
    for key in sorted(counts):
        plan = SERVER_PLAN[key]
        markers = plan.get("markers", ())
        out.append({"server_key": key, "server": plan["server"], "image_id": plan["image_id"],
                    "languages": sorted(counts[key]), "files": sum(counts[key].values()),
                    "readiness": plan["readiness"],
                    "build_inputs": [path for path in inputs if markers and _marker(PurePosixPath(path).name, markers)]})
    return out


def lock_name(server_key: str, variant: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", variant)[:48]
    return f"{server_key}-{slug}" + ("" if slug == variant else "-" + hashlib.sha256(variant.encode()).hexdigest()[:8])


def readiness(plan: list[dict[str, Any]], *, target: Path, native_units: list[dict[str, Any]] | None,
              native_gap: str | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(ready servers [{server_key, variant, build_input}], gaps). ``native_units`` are
    ``native_sast.load_native_build`` units (None: no accepted native build)."""
    ready, gaps = [], []
    for entry in plan:
        key, kind = entry["server_key"], entry["readiness"]
        if kind == "compile_commands":
            units = [unit for unit in native_units or [] if unit.get("adapted")]
            if not units:
                gaps.append({"kind": "lsp-not-ready", "server_key": key,
                             "detail": "lsp-not-ready: no compile_commands" + (f" ({native_gap})" if native_gap else "")})
            for unit in sorted(units, key=lambda u: u["build_variant"]["variant_id"]):
                ready.append({"server_key": key, "variant": unit["build_variant"]["variant_id"],
                              "build_input": {"kind": "compile_commands", "unit_id": unit["unit_id"],
                                              "sha256": unit["compile_database"]["adapted_sha256"]}})
        elif kind == "markers":
            found = []
            for relative in entry["build_inputs"]:
                path = target.joinpath(*PurePosixPath(relative).parts)
                if path.is_file() and not path.is_symlink():
                    found.append({"path": relative, "sha256": _file_sha(path)})
            if not found:
                gaps.append({"kind": "lsp-not-ready", "server_key": key, "detail":
                             f"lsp-not-ready: no {' / '.join(SERVER_PLAN[key]['markers'])} for {entry['server']}"})
                continue
            ready.append({"server_key": key, "variant": "default",
                          "build_input": {"kind": "build_file", "files": found, "sha256": _sha(found)}})
        else:
            ready.append({"server_key": key, "variant": "default", "build_input": {"kind": "none", "sha256": None}})
    return ready, gaps


def spec(ready: dict[str, Any], *, image: dict[str, Any] | None, source_snapshot_sha256: str, target: Path,
         limits: dict[str, Any], container_limits: dict[str, int]) -> dict[str, Any]:
    """Everything a daemon needs to start one server, and its ``identity`` (what recordings are keyed by)."""
    plan = SERVER_PLAN[ready["server_key"]]
    identity = {"server_key": ready["server_key"], "variant": ready["variant"], "server": plan["server"],
                "image_id": plan["image_id"], "image_digest": (image or {}).get("digest"), "argv": plan["argv"],
                "initialization_options": plan.get("initialization_options"),
                "build_input_sha256": ready["build_input"]["sha256"], "source_snapshot_sha256": source_snapshot_sha256}
    return {"identity": identity, "identity_sha256": _sha(identity), "build_input": ready["build_input"],
            "target_path": str(target), "limits": {**limits, "settle_seconds": plan.get("settle_seconds", 0.0)},
            "container_limits": container_limits, "limit": plan.get("limit")}


# ---- recordings -------------------------------------------------------------------------------------------

def normalize(query: dict[str, Any]) -> dict[str, Any]:
    keys = ("method", "path", "line", "character", "include_declaration", "query")
    return {key: query[key] for key in keys if key in query}


def recording_key(identity_sha256: str, query: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical({"identity": identity_sha256, "query": normalize(query)})).hexdigest()


def seal(record: dict[str, Any]) -> dict[str, Any]:
    body = {key: value for key, value in record.items() if key != "record_sha256"}
    return {**body, "record_sha256": _sha(body)}


def sealed(record: Any) -> bool:
    return isinstance(record, dict) and seal(record).get("record_sha256") == record.get("record_sha256")


class Recordings:
    """``recordings/<k[:2]>/<k>.json``: written once (first writer wins), verified on every read."""

    def __init__(self, base: Path):
        self.root = base / "recordings"

    def path(self, key: str) -> Path:
        return self.root / key[:2] / f"{key}.json"

    def load(self, key: str) -> tuple[dict[str, Any] | None, str | None]:
        path = self.path(key)
        if not path.is_file():
            return None, None
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None, "lsp-recording-invalid: unreadable"
        if not sealed(record) or record.get("key") != key or path.is_symlink():
            return None, "lsp-recording-invalid: record_sha256 or key mismatch"
        return record, None

    def store(self, record: dict[str, Any]) -> dict[str, Any]:
        record = seal(record)
        path = self.path(record["key"])
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.{secrets.token_hex(4)}")
        temp.write_bytes(json.dumps(record, indent=2, sort_keys=True).encode("utf-8") + b"\n")
        try:
            os.link(temp, path)
        except FileExistsError:
            pass
        finally:
            temp.unlink(missing_ok=True)
        stored, problem = self.load(record["key"])
        return stored if stored is not None else {**record, "problem": problem}


# ---- containers -------------------------------------------------------------------------------------------

class ContainerLauncher:
    """Starts a server image through the B13 boundary with stdin attached (``docker run --interactive``)."""

    def __init__(self, run_id: str, base: Path):
        import container_execution as ce
        self.ce, self.run_id, self.base = ce, run_id, base
        defaults = ce.host_defaults()
        self.runtime = None if defaults["docker_executable"] is None else ce.ContainerRuntime(
            docker_executable=defaults["docker_executable"], docker_host=None, images_dir=ce.IMAGES_DIR,
            host_flavor=defaults["host_flavor"], container_user=defaults["container_user"],
            source_snapshot_sha256="sha256:" + "0" * 64, registry_ceiling=[], clock=_utc, cancel=threading.Event())

    def argv(self, server: dict[str, Any], name: str, scratch: Path, mounts: list[tuple[str, str]]) -> tuple[str, ...]:
        ce = self.ce
        if self.runtime is None:
            raise RuntimeError("Docker is unavailable")
        record = ce.load_image_registry(ce.IMAGES_DIR).get(server["identity"]["image_id"])
        if record is None or record["digest"] != server["identity"]["image_digest"]:
            raise RuntimeError(f"{server['identity']['image_id']} has no current B16 record with the bound digest")
        flavor = self.runtime.host_flavor
        command = ce.build_docker_argv(
            docker_executable=str(self.runtime.docker_executable), name=name, user=self.runtime.container_user,
            image_ref=ce.image_reference(record), limits=server["container_limits"],
            environment=[{"name": "LANG", "value": "C.UTF-8"}, {"name": "LC_ALL", "value": "C.UTF-8"}],
            mounts=[(ce.translate_host_path(host, flavor), target) for host, target in mounts],
            scratch_source=ce.translate_host_path(str(scratch), flavor), argv=server["identity"]["argv"],
            network_mode="none")
        return command[:2] + ("--interactive",) + command[2:]

    def start(self, server: dict[str, Any], name: str, scratch: Path, mounts: list[tuple[str, str]]) -> tuple[Any, str]:
        command = self.argv(server, name, scratch, mounts)
        env = self.ce.docker_client_environment(os.environ, self.runtime.docker_host)
        process = subprocess.Popen(list(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env, cwd=str(scratch))
        return process, name

    def alive(self, container_id: str) -> bool:
        if self.runtime is None:
            return False
        state = self.ce.container_state(self.runtime, container_id)
        return state is not None and not state["exited"]

    def stop(self, container_id: str) -> bool:
        return self.runtime is not None and self.ce.remove_container(self.runtime, container_id)


def stage_inputs(base: Path, name: str, server: dict[str, Any], native_units: list[dict[str, Any]] | None
                 ) -> list[tuple[str, str]]:
    """Read-only mounts: the checkout, and for clangd the adapted compile database and generated headers."""
    mounts = [(server["target_path"], CONTAINER_ROOT)]
    build = server["build_input"]
    if build["kind"] == "compile_commands":
        unit = next((u for u in native_units or [] if u["unit_id"] == build["unit_id"]), None)
        if unit is None:
            raise RuntimeError("the accepted native-build unit is no longer available")
        import native_sast_adapters as adapters
        if adapters.canonical_sha(unit["adapted"]) != build["sha256"]:
            raise RuntimeError("adapted compile database differs from the bound build input")
        folder = base / "inputs" / name
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "compile_commands.json").write_text(json.dumps(unit["adapted"], indent=1), encoding="utf-8")
        mounts.append((str(folder.resolve()), COMPILE_DB_MOUNT))
        headers = unit.get("generated_headers") or {}
        if headers.get("host_path"):
            mounts.append((headers["host_path"], HEADERS_MOUNT))
    return mounts


# ---- lock directory ---------------------------------------------------------------------------------------

def _pid_alive(pid: Any) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _atomic(path: Path, value: dict[str, Any]) -> None:
    temp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temp, path)


def _read(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _record_failure(base: Path, name: str, error: str) -> None:
    path = base / "failures" / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = _read(path) or {}
    _atomic(path, {"schema": "appsec-review/lsp-start-failure/1", "lock": name,
                   "attempts": int(previous.get("attempts", 0)) + 1, "at": _utc(), "error": lsp_driver.clean(error, 500)})


def serve(run_id: str, base: Path, server: dict[str, Any], lock: Path, *, launcher: Any,
          native_units: list[dict[str, Any]] | None = None, idle_seconds: float = DEFAULTS["idle_seconds"],
          stop: threading.Event | None = None) -> None:
    """The broker daemon for one (server, variant): owns ``lock`` until idle, teardown or failure."""
    name = lock.name[:-len(".lock")]
    owner_path = lock / "owner.json"
    owner = {"schema": OWNER_SCHEMA, "pid": os.getpid(), "host": socket.gethostname(), "state": "starting",
             "started_at": _utc(), "container_id": None, "server_key": server["identity"]["server_key"],
             "variant": server["identity"]["variant"], "identity_sha256": server["identity_sha256"]}
    _atomic(owner_path, owner)
    live, container = None, None
    try:
        import container_execution as ce
        container = ce.container_name(run_id, "02-lsp-xref", re.sub(r"[^A-Za-z0-9_-]", "-", name)[:80] + "-"
                                      + secrets.token_hex(4))
        owner["container_id"] = container
        _atomic(owner_path, owner)
        scratch = base / "scratch" / name
        scratch.mkdir(parents=True, exist_ok=True)
        mounts = stage_inputs(base, name, server, native_units)
        process, container = launcher.start(server, container, scratch, mounts)
        owner["container_id"] = container
        live = lsp_driver.LiveServer(server["identity"]["argv"], Path(server["target_path"]), limits=server["limits"],
                                     initialization_options=server["identity"]["initialization_options"],
                                     uri_root=CONTAINER_ROOT, process=process)
        if not live.start():
            raise RuntimeError("; ".join(gap["kind"] + ": " + gap["detail"] for gap in live.driver.gaps) or "start failed")
    except Exception as exc:  # noqa: BLE001 - a server that cannot start is a recorded failure, never a crash loop
        _record_failure(base, name, f"{type(exc).__name__}: {exc}")
        if live is not None:
            live.stop()
        if container is not None:
            launcher.stop(container)
        _atomic(owner_path, {**owner, "state": "failed", "ended_at": _utc()})
        _release(base, lock, "failed")
        return
    token = secrets.token_hex(16)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    listener.settimeout(0.2)
    _atomic(owner_path, {**owner, "state": "ready", "ready_at": _utc(), "port": listener.getsockname()[1],
                         "token": token, "server_info": live.info})
    last = time.monotonic()
    reason = "idle"
    try:
        while True:
            if stop is not None and stop.is_set():
                reason = "stopped"
                break
            if time.monotonic() - last > idle_seconds:
                break
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(server["limits"].get("request_seconds", 30.0) * 4)
                try:
                    request = json.loads(_recv_line(connection))
                except (OSError, ValueError):
                    continue
                if not isinstance(request, dict) or not secrets.compare_digest(str(request.get("token")), token):
                    continue
                last = time.monotonic()
                if request.get("op") == "shutdown":
                    connection.sendall(_canonical({"ok": True}) + b"\n")
                    reason = "teardown"
                    break
                if request.get("op") == "ping":
                    reply: dict[str, Any] = {"ok": live.alive}
                else:
                    reply = live.ask(request.get("query"))
                    reply = {**reply, "server_info": live.info, "alive": live.alive}
                try:
                    connection.sendall(_canonical(reply) + b"\n")
                except OSError:
                    pass
                if not live.alive:   # the server died mid-run: counts as a failed start (one retry, then gap)
                    _record_failure(base, name, "the server exited or broke the protocol")
                    reason = "server-died"
                    break
    finally:
        listener.close()
        live.stop()
        launcher.stop(container)
        _atomic(owner_path, {**_read(owner_path), "state": "stopped", "ended_at": _utc(), "reason": reason})
        _release(base, lock, reason)


def _recv_line(connection: socket.socket, limit: int = 64 * 1024 * 1024) -> bytes:
    data = b""
    while not data.endswith(b"\n"):
        chunk = connection.recv(65536)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise ValueError("message over limit")
    return data


def _release(base: Path, lock: Path, reason: str) -> None:
    """Move the lock aside (keeping owner.json as the record), so the next first query may start again."""
    released = base / "locks" / "released"
    released.mkdir(parents=True, exist_ok=True)
    try:
        os.rename(lock, released / f"{lock.name}.{reason}.{int(time.time() * 1000)}.{secrets.token_hex(3)}")
    except OSError:
        shutil.rmtree(lock, ignore_errors=True)


def _spawn_process(run_id: str, base: Path, server: dict[str, Any], lock: Path, idle_seconds: float) -> None:
    folder = base / "specs"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{lock.name}.json"
    _atomic(path, server)
    log = (base / "logs").joinpath(lock.name + ".log")
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("ab") as handle:
        subprocess.Popen([sys.executable, "-B", str(ROOT_DIR / "lsp_service.py"), "serve", "--run-id", run_id,
                          "--spec", str(path), "--lock", str(lock), "--idle-seconds", str(idle_seconds)],
                         stdin=subprocess.DEVNULL, stdout=handle, stderr=handle, start_new_session=True)


# ---- the broker client ------------------------------------------------------------------------------------

class Broker:
    """Answers LSP queries for one run: recording first, then the (lazily started, shared) live server.

    ``servers`` maps (server_key, variant) to its ``spec``. ``launcher`` checks/stops containers (and starts
    them in an in-process ``spawn``); ``spawn(run_id, base, server, lock, idle_seconds)`` starts the daemon
    (default: a detached ``lsp_service.py serve`` process). ``replay_only`` answers from recordings only."""

    def __init__(self, run_id: str, base: Path, servers: list[dict[str, Any]], *, launcher: Any = None,
                 spawn: Callable[..., None] | None = None, replay_only: bool = False,
                 config: dict[str, float] | None = None, clock: Callable[[], str] = _utc):
        self.run_id, self.base = run_id, Path(base)
        self.servers = {(row["identity"]["server_key"], row["identity"]["variant"]): row for row in servers}
        self.launcher = launcher if launcher is not None or replay_only else ContainerLauncher(run_id, self.base)
        self.spawn = spawn or _spawn_process
        self.replay_only, self.clock = replay_only, clock
        self.config = {**DEFAULTS, **(config or {})}
        self.recordings = Recordings(self.base)
        self.stats = {"replayed": 0, "live": 0, "gaps": 0, "starts": 0, "recoveries": 0}

    def _gap(self, kind: str, detail: str, server: dict[str, Any] | None = None) -> dict[str, Any]:
        self.stats["gaps"] += 1
        return {"status": "GAP", "results": [], "truncated": False, "dropped_outside_root": 0,
                "gaps": [{"kind": kind, "detail": detail}], "unresolved_includes": 0, "recording": None,
                "replayed": False, "server": (server or {}).get("identity", {}).get("server")}

    def query(self, server_key: str, variant: str, query: dict[str, Any]) -> dict[str, Any]:
        server = self.servers.get((server_key, variant))
        if server is None:
            return self._gap("lsp-not-ready", f"no ready {server_key} server for build variant {variant}")
        key = recording_key(server["identity_sha256"], query)
        record, problem = self.recordings.load(key)
        if problem:
            return self._gap("lsp-recording-invalid", problem, server)
        if record is not None:
            self.stats["replayed"] += 1
            return {**record["response"], "recording": key, "replayed": True, "server": record["server"]}
        if self.replay_only:
            return self._gap("lsp-not-recorded", "replay-only: no recording for this query on these inputs", server)
        reply, failure = None, None
        for _ in range(2):   # a dead owner found on the first send is recovered once
            endpoint = self.ensure(server)
            if "gap" in endpoint:
                failure = endpoint["gap"]
                break
            reply = send(endpoint, {"op": "query", "query": normalize(query)}, self.config["request_seconds"] * 4)
            if reply is not None:
                break
            reason = self._stale(endpoint, self.lock_path(server), containers=True)
            if reason is None:
                break
            self._recover(self.lock_path(server), endpoint, reason)
        if reply is None:
            # A server that failed is a recorded answer too: retries see the same gap (one retry, then gap).
            kind, detail = failure or ("lsp-server-failed", "the live server did not answer")
            self.stats["gaps"] += 1
            reply = {"entry": {"status": "GAP"}, "gaps": [{"kind": kind, "detail": detail}]}
        entry = reply["entry"]
        response = {"status": entry.get("status", "GAP"), "results": entry.get("results", []),
                    "truncated": bool(entry.get("truncated")), "dropped_outside_root": entry.get("dropped_outside_root", 0),
                    "gaps": [{"kind": gap["kind"], "detail": re.sub(r"^query \d+: ", "", gap["detail"])}
                             for gap in reply.get("gaps", [])],
                    "unresolved_includes": int(reply.get("unresolved_includes") or 0)}
        info = reply.get("server_info") or {}
        stored = self.recordings.store({
            "schema": RECORDING_SCHEMA, "key": key, "method": query.get("method"), "params": normalize(query),
            "response": response, "server": {"name": server["identity"]["server"], "info_name": info.get("name"),
                                             "version": info.get("version")},
            "image": {"image_id": server["identity"]["image_id"], "digest": server["identity"]["image_digest"]},
            "build_variant": variant, "build_input_sha256": server["identity"]["build_input_sha256"],
            "source_snapshot_sha256": server["identity"]["source_snapshot_sha256"],
            "identity_sha256": server["identity_sha256"], "recorded_at": self.clock()})
        self.stats["live"] += 1
        return {**stored["response"], "recording": key, "replayed": False, "server": stored["server"]}

    # -- lifecycle --
    def lock_path(self, server: dict[str, Any]) -> Path:
        return self.base / "locks" / (lock_name(server["identity"]["server_key"], server["identity"]["variant"]) + ".lock")

    def _failures(self, lock: Path) -> int:
        return int((_read(self.base / "failures" / f"{lock.name[:-5]}.json") or {}).get("attempts", 0))

    def _stale(self, owner: dict[str, Any] | None, lock: Path, containers: bool = False) -> str | None:
        if owner is None:
            try:
                age = time.time() - lock.stat().st_mtime
            except OSError:
                return None
            return "owner record missing" if age > self.config["start_seconds"] else None
        same_host = owner.get("host") in (None, socket.gethostname())
        if same_host and not _pid_alive(owner.get("pid")):
            return f"owner pid {owner.get('pid')} is gone"
        if containers and owner.get("state") == "ready" and owner.get("container_id") and self.launcher is not None \
                and not self.launcher.alive(owner["container_id"]):
            return f"container {owner['container_id']} is gone"
        return None

    def _recover(self, lock: Path, owner: dict[str, Any] | None, reason: str) -> None:
        aside = self.base / "locks" / "stale" / f"{lock.name}.{int(time.time() * 1000)}.{secrets.token_hex(3)}"
        aside.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.rename(lock, aside)          # exactly one recoverer wins the rename
        except OSError:
            return
        if owner and owner.get("container_id") and self.launcher is not None:
            self.launcher.stop(owner["container_id"])
        self.stats["recoveries"] += 1
        folder = self.base / "recoveries"
        folder.mkdir(parents=True, exist_ok=True)
        _atomic(folder / f"{aside.name}.json", {"schema": "appsec-review/lsp-lock-recovery/1", "lock": lock.name,
                                                "moved_to": str(aside.relative_to(self.base)), "reason": reason,
                                                "previous_owner": owner, "recovered_by_pid": os.getpid(),
                                                "at": _utc()})

    def ensure(self, server: dict[str, Any]) -> dict[str, Any]:
        """The ready owner record of this server's daemon (starting it when nobody has), or {"gap": ...}."""
        lock = self.lock_path(server)
        lock.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.config["start_seconds"]
        while time.monotonic() < deadline:
            if self._failures(lock) >= MAX_START_ATTEMPTS:
                failure = _read(self.base / "failures" / f"{lock.name[:-5]}.json") or {}
                return {"gap": ("lsp-server-failed", f"{server['identity']['server']} failed to start or initialize "
                                f"{failure.get('attempts')} time(s): {failure.get('error')}")}
            try:
                os.mkdir(lock)
            except FileExistsError:
                owner = _read(lock / "owner.json")
                if owner and owner.get("state") == "ready" and owner.get("identity_sha256") == server["identity_sha256"]:
                    reason = self._stale(owner, lock)
                    if reason is None:
                        return owner
                    self._recover(lock, owner, reason)
                    continue
                reason = self._stale(owner, lock)
                if reason is not None:
                    self._recover(lock, owner, reason)
                    continue
                time.sleep(self.config["poll_seconds"])
                continue
            _atomic(lock / "owner.json", {"schema": OWNER_SCHEMA, "pid": os.getpid(), "host": socket.gethostname(),
                                          "state": "spawning", "started_at": _utc(), "container_id": None,
                                          "identity_sha256": server["identity_sha256"]})
            self.stats["starts"] += 1
            self.spawn(self.run_id, self.base, server, lock, self.config["idle_seconds"])
        return {"gap": ("lsp-server-failed", f"{server['identity']['server']} was not ready within "
                        f"{self.config['start_seconds']}s")}


def send(owner: dict[str, Any], request: dict[str, Any], timeout: float = 120.0) -> dict[str, Any] | None:
    """One request to a daemon over loopback, authenticated by the owner record's token; None on failure."""
    try:
        with socket.create_connection(("127.0.0.1", int(owner["port"])), timeout=timeout) as connection:
            connection.sendall(_canonical({**request, "token": owner["token"]}) + b"\n")
            reply = json.loads(_recv_line(connection))
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return reply if isinstance(reply, dict) else None


def teardown(base: Path, *, launcher: Any = None, wait_seconds: float = 10.0) -> list[dict[str, Any]]:
    """Run end: ask every live daemon to stop; anything still holding a lock is stopped and moved aside."""
    rows = []
    locks = base / "locks"
    for lock in sorted(locks.glob("*.lock")) if locks.is_dir() else []:
        owner = _read(lock / "owner.json") or {}
        if owner.get("state") == "ready":
            send(owner, {"op": "shutdown"}, wait_seconds)
        deadline = time.monotonic() + wait_seconds
        while lock.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        forced = lock.exists()
        if forced:
            if owner.get("container_id") and launcher is not None:
                launcher.stop(owner["container_id"])
            _release(base, lock, "teardown-forced")
        rows.append({"lock": lock.name, "forced": forced})
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    daemon = sub.add_parser("serve", help="(internal) the daemon one first query spawns")
    daemon.add_argument("--run-id", required=True); daemon.add_argument("--spec", required=True, type=Path)
    daemon.add_argument("--lock", required=True, type=Path)
    daemon.add_argument("--idle-seconds", type=float, default=DEFAULTS["idle_seconds"])
    down = sub.add_parser("teardown", help="stop every language server of a run (run end)")
    down.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    from execution_state import data_path
    base = data_path(args.run_id, "lsp")
    if args.command == "teardown":
        print(json.dumps(teardown(base, launcher=ContainerLauncher(args.run_id, base)), indent=2))
        return 0
    server = json.loads(args.spec.read_text(encoding="utf-8"))
    units = None
    if server["build_input"]["kind"] == "compile_commands":
        import lsp_xref_job
        units = lsp_xref_job.native_units(args.run_id)[0]
    serve(args.run_id, base, server, args.lock, launcher=ContainerLauncher(args.run_id, base), native_units=units,
          idle_seconds=args.idle_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
