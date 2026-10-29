"""Live acceptance of ``job_codeql_analysis`` in a ``wave1_review`` run of appsec-multi-vuln.

Run 2026-10-29-0002 aborted ``job_codeql_analysis`` because 41 of 55 scopes ran in build images with
no preinstalled CodeQL declaration ("requires one exact environment/user declaration"). Under the
shipped ``preinstalled_undeclared = "derive"`` policy every scope must instead resolve a runtime
(declared preinstalled, or derived on its build image) and end with a database or a named coverage
gap, never a job abort. Database replays run networked, with an executable ``/tmp`` exactly when the
replay runs Gradle, and Go ``-mod=mod`` replays read the image module cache before the network.

Operator-run, skipped unless ``APPSEC_REVIEW_CODEQL_ACCEPTANCE`` is set. Starting a run needs the
Dagster stack from ``deploy/dagster`` running on the pinned images with its code location reviewing
``targets/appsec-multi-vuln``, the Docker daemon, network egress for dependency restores, and the
model backend for the jobs before CodeQL:

    APPSEC_REVIEW_CODEQL_ACCEPTANCE=1 \\
        python -m pytest tests/live/test_codeql_analysis_wave1_live.py --basetemp=test/tmp/codeql-acceptance

Set ``APPSEC_REVIEW_CODEQL_RUN`` to an application run id to evaluate a finished run under ``runs/``
instead of starting one. The Dagster run need not succeed overall: only ``job_codeql_analysis`` and
the evidence it recorded are judged.
"""

from __future__ import annotations

from collections import Counter
import importlib.util
import json
import os
from pathlib import Path
import sys
import tomllib
from typing import Any
from uuid import uuid4

import pytest

from appsec_review.acceptance.diff import failing
from appsec_review.acceptance.normalize import locate_attempt
from appsec_review.acceptance.system import run_problems
from appsec_review.codeql import runtime
from appsec_review.codeql.runtime import IMAGE_SCHEMA, PREINSTALLED_IMAGE_SCHEMA

ROOT = Path(__file__).parents[2]
JOB = "job_codeql_analysis"
TARGET = "appsec-multi-vuln"
DAGSTER_URL = "http://127.0.0.1:3000/graphql"
DECLARATION_ERROR = "requires one exact environment/user declaration"
PREFLIGHT_ERROR = "CodeQL runtime preflight rejected"
IMAGE_GO_PROXY = "file:///opt/project-deps/go/cache/download"

pytestmark = [
    pytest.mark.skipif(not os.environ.get("APPSEC_REVIEW_CODEQL_ACCEPTANCE"),
                       reason="set APPSEC_REVIEW_CODEQL_ACCEPTANCE=1 to run the live CodeQL analysis acceptance"),
]


def _stepwise():
    bin_dir = ROOT / "deploy" / "dagster" / "bin"
    sys.path.insert(0, str(bin_dir))
    spec = importlib.util.spec_from_file_location("stepwise_codeql_acceptance", bin_dir / "stepwise.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _artifact(run_root: Path, reference: dict | None) -> Any:
    return None if not reference else _json(run_root / reference["path"])


@pytest.fixture(scope="module")
def review() -> dict[str, Any]:
    stepwise = _stepwise()
    app_run_id = os.environ.get("APPSEC_REVIEW_CODEQL_RUN")
    if not app_run_id:
        configured = stepwise.compose("exec", "-T", "code-location", "printenv", "APPSEC_REVIEW_TARGET").strip()
        assert configured.rstrip("/").endswith(f"/{TARGET}"), f"the code location reviews {configured}, not {TARGET}"
        dagster_run_id = str(uuid4())
        stepwise.review_run.submit(dagster_run_id)
        run = stepwise.wait(DAGSTER_URL, dagster_run_id, 30)
        app_run_id = run["tag_map"].get("appsec/application_run_id")
        assert app_run_id, "\n".join(stepwise.failure_messages(DAGSTER_URL, dagster_run_id))[-4000:]
    run_root = ROOT / "runs" / app_run_id
    assert run_root.is_dir(), f"no run tree at runs/{app_run_id}"
    attempt = locate_attempt(run_root, JOB)
    assert attempt is not None, f"{JOB} never started in runs/{app_run_id}"
    result_path = attempt / "result.json"
    result = _json(result_path) if result_path.is_file() else {}
    return {"stepwise": stepwise, "run_id": app_run_id, "run_root": run_root, "attempt": attempt,
            "claim": _json(attempt / "claim.json"), "status": _json(attempt / "status.json"),
            "outputs": dict(result.get("outputs") or {})}


@pytest.fixture(scope="module")
def databases(review) -> list[dict[str, Any]]:
    execution = review["outputs"].get("execution.scopes")
    assert execution is not None, f"{JOB} did not complete its execution step: {review['status']}"
    return list(execution["databases"])


@pytest.fixture(scope="module")
def settings(review) -> dict[str, Any]:
    document = tomllib.loads((review["run_root"] / "data" / "configuration" / "appsec-review.toml")
                             .read_text(encoding="utf-8"))
    return document["jobs"][JOB]["settings"]


def _replay(review, scope_id: str) -> tuple[Path, dict | None]:
    scope_root = review["run_root"] / "data" / "codeql" / "scopes" / scope_id
    path = scope_root / "protected-replay.json"
    return scope_root, (_json(path) if path.is_file() else None)


def _launches_gradle(replay: dict | None) -> bool:
    return any(Path(str(command["argv"][0])).name in {"gradle", "gradlew"}
               for command in (replay or {}).get("commands", ()) if command.get("argv"))


def test_codeql_analysis_completes_without_a_runtime_declaration_abort(review) -> None:
    run_root, status = review["run_root"], review["status"]
    events = run_root / "data" / "logs" / "pipeline.jsonl"
    log = events.read_text(encoding="utf-8", errors="replace") if events.is_file() else ""
    for text in (json.dumps(status), log):
        assert DECLARATION_ERROR not in text and PREFLIGHT_ERROR not in text
    target = review["stepwise"].host_path(review["claim"]["target_root"])
    assert target.name == TARGET, target
    problems = failing(run_problems(run_root, review["run_id"], [JOB], target))
    assert not problems, "\n".join(f"{item.path}: {item.expected} -> {item.actual}" for item in problems)


def test_the_run_resolved_the_shipped_derive_policy(settings) -> None:
    assert settings["preinstalled_undeclared"] == "derive"


def test_every_planned_scope_has_a_database_or_a_named_gap(review, databases) -> None:
    plan = _json(review["attempt"] / "artifacts" / "codeql" / "plan.json")
    planned = [scope["scope_id"] for scope in plan["scopes"]]
    executed = [item["scope"]["scope_id"] for item in databases]
    assert planned and len(set(planned)) == len(planned)
    assert sorted(executed) == sorted(planned), "every planned scope reaches exactly one database outcome"
    outcomes = Counter(item.get("terminal_status") for item in databases)
    assert set(outcomes) <= {"SUCCEEDED", "FAILED"}, outcomes
    assert outcomes["SUCCEEDED"] > 0, outcomes
    for item in databases:
        scope_id = item["scope"]["scope_id"]
        if item["terminal_status"] == "SUCCEEDED":
            assert item.get("database_manifest") and not item["gaps"], scope_id
        else:
            assert item["gaps"] and all(str(gap).strip() for gap in item["gaps"]), scope_id
            assert not any(DECLARATION_ERROR in str(gap) for gap in item["gaps"]), (scope_id, item["gaps"])


def test_only_declared_environments_use_preinstalled_runtimes(review, databases, settings) -> None:
    declared = {item["build_image_id"] for item in settings.get("preinstalled_runtimes", ())}
    derived = 0
    for item in databases:
        image = _artifact(review["run_root"], item.get("image"))
        if image is None:
            continue  # An operational failure before resolution is a named gap, judged above.
        scope_id = item["scope"]["scope_id"]
        if image["build_image_id"] in declared:
            assert image["preinstalled"] and image["schema"] == PREINSTALLED_IMAGE_SCHEMA, scope_id
        else:
            derived += 1
            assert not image["preinstalled"] and image["schema"] == IMAGE_SCHEMA, scope_id
            assert image["image_tag"].startswith("appsec-review-codeql:"), (scope_id, image["image_tag"])
    assert derived > 0, "appsec-multi-vuln has build images without a preinstalled declaration"


def test_database_containers_are_networked_with_tmp_exec_only_for_gradle(review, databases) -> None:
    checked = 0
    for item in databases:
        receipt = _artifact(review["run_root"], item.get("database_execution"))
        if receipt is None or item.get("database_reused"):
            continue
        scope_id = item["scope"]["scope_id"]
        scope_root, replay = _replay(review, scope_id)
        arguments = ("--replay", "protected-replay.json") if replay is not None else ()
        assert receipt["limits"]["network"] == "bridge", scope_id
        assert receipt["limits"]["tmp_executable"] is runtime.replay_needs_executable_tmp(scope_root, arguments), scope_id
        checked += 1
        for command in (replay or {}).get("commands", ()):
            environment = dict(command.get("environment") or {})
            if "-mod=mod" in environment.get("GOFLAGS", "").split() and "GOPROXY" in environment:
                proxies = environment["GOPROXY"].split(",")
                assert environment["GOMODCACHE"] == "/tmp/appsec-go-mod", scope_id
                assert proxies[0] == IMAGE_GO_PROXY and "off" not in proxies, (scope_id, proxies)
            if "GRADLE_USER_HOME" in environment:
                assert environment["GRADLE_USER_HOME"].startswith("/tmp/"), scope_id
                assert receipt["limits"]["tmp_executable"] is True, scope_id
    assert checked > 0


def test_gradle_replays_including_android_build_their_databases(review, databases) -> None:
    gradle = {}
    for item in databases:
        scope_id = item["scope"]["scope_id"]
        _scope_root, replay = _replay(review, scope_id)
        if _launches_gradle(replay):
            gradle[scope_id] = item
    assert gradle, "appsec-multi-vuln has Gradle projects (projects/android/case-092) that CodeQL replays"
    failed = {scope_id: item["gaps"] for scope_id, item in gradle.items() if item["terminal_status"] != "SUCCEEDED"}
    assert not failed, failed
