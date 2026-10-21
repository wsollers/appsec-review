"""Fakes for the operator scripts: a PATH-injected docker, a lifecycle stand-in and a Dagster GraphQL server.

Nothing here touches the real stack. ``Sandbox`` copies the scripts and ``deploy/dagster/bin`` into a
temporary repository, replaces ``lifecycle.py`` with a recorder, and runs the scripts with a fake
``docker`` first on PATH and ``APPSEC_DAGSTER_URL`` pointing at a local fake server.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

REPOSITORY = Path(__file__).resolve().parents[1]
BIN = REPOSITORY / "deploy" / "dagster" / "bin"
sys.path.insert(0, str(BIN))
import ops  # noqa: E402

PROJECT = "appsec-review-dagster-test"
WEBSERVER_ID = hashlib.sha1(b"webserver").hexdigest()[:12]
CODE_ID = hashlib.sha1(b"code-location").hexdigest()[:12]

FAKE_DOCKER = '''#!{python}
import json, os, sys
state = json.load(open(os.environ["FAKE_DOCKER_STATE"]))
argv = sys.argv[1:]
with open(os.environ["FAKE_DOCKER_LOG"], "a") as log:
    log.write(json.dumps(argv) + "\\n")
joined = " ".join(argv)
def out(text="", rc=0, err=""):
    sys.stdout.write(text)
    sys.stderr.write(err)
    sys.exit(rc)
if argv[:1] == ["ps"] and "-q" in argv:
    out("".join(c["Id"][:12] + "\\n" for c in state["containers"]))
if argv[:1] == ["ps"]:
    out("".join(line + "\\n" for line in state.get("ps_names", [])))
if argv[:1] == ["inspect"]:
    wanted = argv[1:]
    out(json.dumps([c for c in state["containers"] if any(c["Id"].startswith(w) for w in wanted)]))
if argv[:2] == ["image", "inspect"]:
    image = state.get("images", {}).get(argv[2])
    if image is None:
        out(rc=1, err="Error: No such image")
    out(image["created"] if "Created" in joined else image["id"])
if argv[:2] == ["volume", "ls"]:
    out("".join(v + "\\n" for v in state.get("volumes", [])))
if argv[:1] == ["logs"]:
    out("log line from " + argv[-1] + "\\n")
if argv[:1] == ["exec"]:
    for rule in state.get("exec", []):
        if rule["match"] in joined:
            out(rule.get("stdout", ""), rule.get("rc", 0), rule.get("stderr", ""))
sys.exit(0)
'''

FAKE_LIFECYCLE = '''import json, os, sys
with open(os.environ["LIFECYCLE_LOG"], "a") as log:
    log.write(json.dumps({"argv": sys.argv[1:], "env": {k: v for k, v in os.environ.items() if k.startswith("APPSEC_REVIEW_")}}) + "\\n")
sys.exit(int(os.environ.get("FAKE_LIFECYCLE_RC", "0")))
'''

FAKE_PYTHON = '''#!{python}
import os, sys
args = sys.argv[1:]
if args[:2] == ["-m", "pytest"]:
    with open(os.environ["FAKE_PYTEST_LOG"], "a") as log:
        log.write(" ".join(args) + "\\n")
    sys.stdout.write(open(os.environ["FAKE_PYTEST_OUTPUT"]).read())
    sys.exit(int(os.environ.get("FAKE_PYTEST_RC", "0")))
if args[:1] == ["-c"] and "xdist" in args[1]:
    sys.exit(1)
os.execv({python!r}, [{python!r}] + args)
'''

TOML = """[jobs.job_project_build.settings.profiles.p1]
tag = "img:p1"
image_id = "sha256:aaa"
"""


def container(service: str, deploy: Path, *, state: str = "running", health: str = "healthy",
              files: list[str] | None = None, settings: dict[str, str] | None = None) -> dict[str, Any]:
    environment = [f"{key}={value}" for key, value in (settings or {}).items()] + ["DAGSTER_POSTGRES_PASSWORD=hunter2-secret"]
    files = files if files is not None else [str(deploy / "compose.yaml"), str(deploy / ops.overlay_name())]
    return {"Id": hashlib.sha1(service.encode()).hexdigest() + "0" * 24, "Name": f"/{PROJECT}-{service}-1",
            "State": {"Status": state, "Health": {"Status": health}},
            "Config": {"Image": ops.image_tag(), "Env": environment, "Labels": {
                "com.docker.compose.service": service, "com.docker.compose.project": PROJECT,
                "com.docker.compose.project.config_files": ",".join(files)}}}


def step(key: str, status: str, start: float, end: float | None = None) -> dict[str, Any]:
    return {"stepKey": key, "status": status, "startTime": start, "endTime": end}


def run(run_id: str, status: str, *, job: str = "wave1_review", app: str | None = None, start: float = 1_700_000_000.0,
        end: float | None = None, steps: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    tags = [{"key": "appsec/application_run_id", "value": app}] if app else []
    return {"runId": run_id, "status": status, "pipelineName": job, "startTime": start, "endTime": end,
            "tags": tags, "stepStats": steps or []}


def runs_data(*runs: dict[str, Any]) -> dict[str, Any]:
    return {"runsOrError": {"__typename": "Runs", "results": list(runs)}}


def run_data(item: dict[str, Any]) -> dict[str, Any]:
    return {"runOrError": {"__typename": "Run", **item}}


def plan_data(*jobs: str) -> dict[str, Any]:
    return {"runOrError": {"__typename": "Run", "executionPlan": {"steps": [{"key": f"{job}__begin"} for job in jobs]}}}


class FakeDagster:
    """A localhost GraphQL server answering by operation name from scripted response lists."""

    def __init__(self) -> None:
        self.routes: dict[str, list[dict[str, Any]]] = {}
        self.requests: list[tuple[str, dict[str, Any]]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                match = re.search(r"(?:query|mutation)\s+(\w+)", body["query"])
                name = match.group(1) if match else "?"
                outer.requests.append((name, body.get("variables") or {}))
                queue = outer.routes.get(name)
                if not queue:
                    payload: dict[str, Any] = {"errors": [{"message": f"no scripted response for {name}"}]}
                else:
                    payload = {"data": queue.pop(0) if len(queue) > 1 else queue[0]}
                data = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_args: object) -> None:
                return

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/graphql"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def script(self, name: str, *responses: dict[str, Any]) -> None:
        self.routes[name] = list(responses)

    def runs(self, *items: dict[str, Any]) -> None:
        self.script("OpsRuns", runs_data(*items))
        self.script("RecoveryRuns", runs_data(*items))

    def calls(self, name: str) -> list[dict[str, Any]]:
        return [variables for call, variables in self.requests if call == name]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class Sandbox:
    """A throwaway repository copy plus the fakes; every script runs against it, never the real stack."""

    def __init__(self, base: Path, dagster: FakeDagster) -> None:
        self.base = base
        self.repo = base / "repo"
        self.bin = base / "fakebin"
        self.dagster = dagster
        self.deploy = self.repo / "deploy" / "dagster"
        shutil.copytree(REPOSITORY / "scripts", self.repo / "scripts")
        shutil.copytree(BIN, self.deploy / "bin", ignore=shutil.ignore_patterns("__pycache__"))
        (self.deploy / "bin" / "lifecycle.py").write_text(FAKE_LIFECYCLE, encoding="utf-8")
        (self.deploy / ".env").write_text(f"APPSEC_COMPOSE_PROJECT={PROJECT}\n", encoding="utf-8")
        (self.repo / "appsec-review.toml").write_text(TOML, encoding="utf-8")
        for name in ("runs", "data", "targets/demo", "test/acceptance", "test/tmp"):
            (self.repo / name).mkdir(parents=True)
        self.bin.mkdir()
        self.docker_log = base / "docker.jsonl"
        self.lifecycle_log = base / "lifecycle.jsonl"
        self.state_file = base / "docker-state.json"
        self.pytest_log = base / "pytest.log"
        self.pytest_output = base / "pytest.out"
        docker = self.bin / "docker"
        docker.write_text(FAKE_DOCKER.replace("{python}", sys.executable), encoding="utf-8")
        docker.chmod(0o755)
        self.state: dict[str, Any] = {}
        self.stack()

    def stack(self, *, running: bool = True, files: list[str] | None = None, settings: dict[str, str] | None = None,
              probe: dict[str, Any] | None = None, volumes: list[str] | None = None) -> None:
        state = "running" if running else "exited"
        self.state = {
            "containers": [container(name, self.deploy, state=state, health="healthy" if running else "none",
                                     files=files, settings=settings if name == "code-location" else None)
                           for name in ops.SERVICES],
            "images": {ops.image_tag(): {"id": "sha256:img", "created": "2026-10-20T00:00:00.000000000Z"},
                       "img:p1": {"id": "sha256:aaa", "created": "x"}},
            "volumes": volumes if volumes is not None else [f"{PROJECT}_postgres-data", f"{PROJECT}_dagster-storage"],
            "exec": [probe or {"match": "claude -p", "stdout": "ok\n"}, {"match": "dagster job launch", "stdout": "launched"}],
        }
        self.save()

    def save(self) -> None:
        self.state_file.write_text(json.dumps(self.state), encoding="utf-8")

    def environment(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        return {**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}", "APPSEC_PYTHON": sys.executable,
                "FAKE_DOCKER_STATE": str(self.state_file), "FAKE_DOCKER_LOG": str(self.docker_log),
                "LIFECYCLE_LOG": str(self.lifecycle_log), "APPSEC_DAGSTER_URL": self.dagster.url,
                "FAKE_PYTEST_LOG": str(self.pytest_log), "FAKE_PYTEST_OUTPUT": str(self.pytest_output),
                **(extra or {})}

    def run(self, script: str, *arguments: str, extra: dict[str, str] | None = None,
            cwd: Path | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(self.repo / "scripts" / f"{script}.sh"), *arguments], text=True,
                              capture_output=True, env=self.environment(extra), cwd=cwd or self.base, timeout=120,
                              check=False)

    def install_fake_python(self) -> str:
        fake = self.bin / "fakepython"
        fake.write_text(FAKE_PYTHON.replace("{python!r}", repr(sys.executable)).replace("{python}", sys.executable),
                        encoding="utf-8")
        fake.chmod(0o755)
        return str(fake)

    def docker_calls(self) -> list[list[str]]:
        if not self.docker_log.exists():
            return []
        return [json.loads(line) for line in self.docker_log.read_text(encoding="utf-8").splitlines()]

    def lifecycle_calls(self) -> list[dict[str, Any]]:
        if not self.lifecycle_log.exists():
            return []
        return [json.loads(line) for line in self.lifecycle_log.read_text(encoding="utf-8").splitlines()]
