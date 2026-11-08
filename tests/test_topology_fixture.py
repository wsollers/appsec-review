"""The build-topology fixture monorepo against its target contract (fast: no Docker, no model).

``test/topology/monorepo`` is run through the real catalog/discovery/topology/plan code in process
(``appsec_review.acceptance.topology``) and compared with ``test/topology/monorepo.expectations.json``.
Hard failures are what the current code must already satisfy: the fixture matches its manifest,
the expectations validate against their schema, every marker is discovered and every unit accounted
for exactly once, the plan is deterministic, nothing unexpected appears, and the tree stays blind.
Every expectation the current runtime does not meet is a strict expected failure carrying the reason
code the expectations declare, so it flips to a hard failure the moment the behaviour lands and the
expectations must then be updated.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess

import pytest

from appsec_review.acceptance import topology
from appsec_review.jobs.build_discovery import _MARKERS, _SUFFIX_MARKERS, DISCOVERED_BUILD_SYSTEMS
from appsec_review.jobs.build_topology import DISPOSITIONS, validate_build_topology
from tests.test_blind_target_isolation import ANSWER_MARKER, TEXT_SUFFIXES

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = topology.FIXTURE_ROOT
TASK_DOC = ROOT / "docs" / "tasks" / "2026-11-07-topology-fixture-monorepo.md"
_EXPECTATIONS = topology.load_expectations()
_PLAN = topology.plan_fixture(FIXTURE)
_CHECKS = topology.compare(_PLAN, _EXPECTATIONS)
_CASES = [pytest.param(check, id=check.case_id,
                       marks=(pytest.mark.xfail(strict=True, reason=check.reason_code),) if check.reason_code else ())
          for check in _CHECKS]


@pytest.fixture(scope="module")
def plan() -> dict:
    return _PLAN


@pytest.fixture(scope="module")
def expectations() -> dict:
    return _EXPECTATIONS


# --------------------------------------------------------------------------------- the fixture

def test_manifest_matches_fixture_bytes() -> None:
    assert topology.manifest_drift(FIXTURE) == []
    manifest = topology.load_manifest(FIXTURE)
    assert manifest["file_count"] == len(topology.fixture_files(FIXTURE)) >= 40


def test_fixture_is_small_text_only_and_blind() -> None:
    failures = []
    for path in topology.fixture_files(FIXTURE):
        relative = path.relative_to(FIXTURE).as_posix()
        data = path.read_bytes()
        if path.stat().st_size > 16 * 1024:
            failures.append(f"too large: {relative}")
        if b"\0" in data:
            failures.append(f"binary: {relative}")
        if b"\r\n" in data:
            failures.append(f"crlf: {relative}")
        if ANSWER_MARKER.search(relative):
            failures.append(f"path: {relative}")
        if (path.suffix.lower() in TEXT_SUFFIXES or path.name in {"CMakeLists.txt", "Makefile"}
                or path.suffix.lower() in {".cs", ".swift", ".kt", ".gradle", ".php", ".js", ".rs", ".go", ".mod", ".work", ".pbxproj"}):
            if ANSWER_MARKER.search(data.decode("utf-8", errors="replace")):
                failures.append(f"content: {relative}")
    assert not failures, failures
    assert all(not path.is_symlink() for path in FIXTURE.rglob("*"))


def test_expectations_validate_against_their_schema(expectations: dict) -> None:
    assert expectations["schema"] == topology.EXPECTATIONS_SCHEMA
    assert expectations["fixture"]["root"] == FIXTURE.relative_to(ROOT).as_posix()
    shape_ids = [shape["id"] for shape in expectations["shapes"]]
    assert shape_ids == sorted(shape_ids) and len(set(shape_ids)) == len(shape_ids)
    # Every declared reason code is used by at least one gap, so the list stays an honest gap report.
    used = {code for shape in expectations["shapes"] for group in ("units", "components", "relationships")
            for item in shape[group] for code in item.get("gaps", {}).values()}
    assert used == set(expectations["reason_codes"])


def test_schema_rejects_an_unknown_gap_field_and_an_undeclared_reason_code(tmp_path: Path, expectations: dict) -> None:
    broken = copy.deepcopy(expectations)
    broken["shapes"][0]["units"][0]["gaps"] = {"colour": "ownership-vendored"}
    path = tmp_path / "broken.json"
    path.write_text(json.dumps(broken), encoding="utf-8")
    with pytest.raises(topology.TopologyFixtureError, match="colour"):
        topology.load_expectations(path)
    undeclared = copy.deepcopy(expectations)
    undeclared["shapes"][0]["units"][0]["gaps"] = {"ownership": "not-a-declared-code"}
    path.write_text(json.dumps(undeclared), encoding="utf-8")
    with pytest.raises(topology.TopologyFixtureError, match="undeclared reason codes"):
        topology.load_expectations(path)


# ------------------------------------------------------------------------ discovery accounting

def _marker_files() -> list[str]:
    values = []
    for path in topology.fixture_files(FIXTURE):
        relative = PurePosixPath(path.relative_to(FIXTURE).as_posix())
        engine = (relative.parent.name == "ProjectSettings" and relative.name == "ProjectVersion.txt"
                  or relative.parent.name == "Packages" and relative.name == "manifest.json")
        if engine or relative.name in _MARKERS or relative.suffix.lower() in _SUFFIX_MARKERS:
            values.append(relative.as_posix())
    return sorted(values)


def test_every_marker_file_is_claimed_by_exactly_one_unit_or_deliberately_absorbed(plan: dict, expectations: dict) -> None:
    claimed: dict[str, list[str]] = {}
    for action in plan["build_topology"]["build_actions"]:
        for marker in action["markers"]:
            claimed.setdefault(marker["path"], []).append(action["build_unit_id"])
    absorbed = {item["path"] for shape in expectations["shapes"] for item in shape.get("absorbed_markers", ())}
    markers = _marker_files()
    assert len(markers) >= 18
    unclaimed = [path for path in markers if path not in claimed and path not in absorbed]
    twice = sorted(path for path, owners in claimed.items() if len(owners) != 1)
    assert unclaimed == [], unclaimed
    assert twice == [], twice
    assert absorbed <= set(markers) and not absorbed & set(claimed)


def test_every_unit_is_accounted_for_exactly_once_in_a_valid_graph(plan: dict) -> None:
    graph = plan["build_topology"]["executable_graph"]
    validate_build_topology(graph)
    actions = plan["build_topology"]["build_actions"]
    assert sorted(node["build_unit_id"] for node in graph["nodes"]) == sorted(action["build_unit_id"] for action in actions)
    assert len({action["build_unit_id"] for action in actions}) == len(actions)
    assert all(node["disposition"] in DISPOSITIONS for node in graph["nodes"])
    assert {action["build_system"] for action in actions} <= DISCOVERED_BUILD_SYSTEMS
    for node in graph["nodes"]:
        if node["disposition"] == "contained":
            owner = next(item for item in graph["nodes"] if item["build_unit_id"] == node["owner_build_unit_id"])
            assert owner["disposition"] == "independent" and owner["build_unit_id"] != node["build_unit_id"]


def test_plan_is_deterministic_across_compilations() -> None:
    again = topology.plan_fixture(FIXTURE)
    graph, other = _PLAN["build_topology"]["executable_graph"], again["build_topology"]["executable_graph"]
    assert graph["topology_id"] == other["topology_id"]
    assert graph["bundle_identity"] == other["bundle_identity"]
    assert _PLAN["source_fingerprint"] == again["source_fingerprint"]


def test_no_unit_outside_the_expectations(plan: dict, expectations: dict) -> None:
    assert topology.unexpected_units(plan, expectations) == []


def test_unity_client_is_an_engine_project_not_a_linux_build(plan: dict) -> None:
    unity = [action for action in plan["build_topology"]["build_actions"] if action["root"] == "client-unity"]
    assert len(unity) == 1 and unity[0]["build_system"] == "unity" and unity[0]["family"] == "dotnet"
    assert unity[0]["required_image_profile"] == "unity" and unity[0]["project_type"] == "unity"
    assert unity[0]["engine"]["declared_version"] == "2022.3.20f1"
    assert unity[0]["requires_inference"] is False


def test_php_public_tree_is_a_source_only_scope_without_a_unit(plan: dict) -> None:
    scopes = {(item["root"], item["language"]) for item in plan["build_topology"]["source_only_scopes"]}
    assert scopes == {("website/public", "php")}
    assert not any(action["root"].startswith("website/public") for action in plan["build_topology"]["build_actions"])
    composer = [action for action in plan["build_topology"]["build_actions"] if action["root"] == "website/lib"]
    assert len(composer) == 1 and composer[0]["required_image_profile"] == "php"


def test_ios_project_has_no_build_unit_bound_to_a_linux_image(plan: dict) -> None:
    assert not any(action["root"] == "client-ios" or action["root"].startswith("client-ios/")
                   for action in plan["build_topology"]["build_actions"])


def test_npm_workspace_inventory_names_the_root_and_both_members(plan: dict) -> None:
    web = next(action for action in plan["build_topology"]["build_actions"] if action["root"] == "web")
    workspace = web["descriptor_package"]["workspace"]
    assert workspace["root"] == "web" and workspace["role"] == "root" and workspace["manager"] == "npm"
    assert workspace["members"] == ["web/packages/api", "web/packages/ui"]
    assert workspace["lockfile"] == "web/package-lock.json"


# -------------------------------------------------------------------------------- the contract

@pytest.mark.parametrize("check", _CASES)
def test_contract(check: topology.Check) -> None:
    assert check.ok, (f"{check.case_id}: expected {json.dumps(check.expected, sort_keys=True)} "
                      f"observed {json.dumps(check.observed, sort_keys=True)}")


def test_declared_gaps_are_the_only_mismatches_and_all_are_documented(expectations: dict) -> None:
    undeclared = [check.case_id for check in _CHECKS if not check.ok and check.reason_code is None]
    flipped = [check.case_id for check in _CHECKS if check.ok and check.reason_code is not None]
    assert undeclared == [] and flipped == [], {"undeclared": undeclared, "flipped": flipped}
    text = TASK_DOC.read_text(encoding="utf-8")
    missing = [code for code in sorted(expectations["reason_codes"]) if f"`{code}`" not in text]
    assert missing == [], missing
    assert topology.verdict(_CHECKS) == 0


# ------------------------------------------------------------------- materialization (toolchain)

def _materialize(source: Path, destination: Path, roots: tuple[str, ...]) -> None:
    for root in roots:
        target = destination / root if root != "." else destination
        shutil.copytree(source / root if root != "." else source, target, dirs_exist_ok=True)


@pytest.mark.parametrize("unit, minimum", [
    ("server/third_party/tinylib/test", "server/third_party/tinylib"),
    ("tools/packer", "."),
])
def test_sibling_referencing_makefile_needs_more_than_its_own_root(tmp_path: Path, unit: str, minimum: str) -> None:
    if shutil.which("make") is None or shutil.which("gcc") is None:
        pytest.skip("make and gcc are required to prove the materialization boundary")
    alone = tmp_path / "alone"
    _materialize(FIXTURE, alone, (unit,))
    result = subprocess.run(["make", "-C", str(alone / unit)], capture_output=True, text=True, timeout=60)
    assert result.returncode != 0 and "No rule to make target" in result.stderr
    enough = tmp_path / "enough"
    _materialize(FIXTURE, enough, (minimum,))
    result = subprocess.run(["make", "-C", str(enough / unit)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr


# ----------------------------------------------------------------------------------------- CLI

def test_prepare_copies_the_fixture_and_refuses_a_populated_directory(tmp_path: Path) -> None:
    into = tmp_path / "targets" / "topology-monorepo"
    assert topology.prepare(into) == into
    assert topology.manifest_drift(into) == []
    assert (into / "server" / "CMakeLists.txt").read_bytes() == (FIXTURE / "server" / "CMakeLists.txt").read_bytes()
    with pytest.raises(topology.TopologyFixtureError, match="new or empty"):
        topology.prepare(into)


def test_cli_evaluate_reports_and_exits_zero_and_score_never_raises(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert topology.main(["evaluate", "--target", str(FIXTURE)]) == 0
    out = capsys.readouterr().out
    assert "topology summary checks=" in out and "undeclared_failures=0" in out and "declared_gaps_now_met=0" in out
    assert topology.main(["manifest"]) == 0
    capsys.readouterr()
    assert topology.main(["score", "--run", str(tmp_path / "absent-run")]) == 2
    assert "no run tree" in capsys.readouterr().err
    run = tmp_path / "run"
    (run / "data").mkdir(parents=True)
    assert topology.main(["score", "--run", str(run)]) == 2
    assert capsys.readouterr().err.startswith("topology: ")


def test_score_reads_a_real_accepted_plan_handoff(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The fixture plan published as a genuine accepted job_target_analysis_plan handoff scores identically."""
    from appsec_review.config import load_config
    from appsec_review.runtime import Job, JobRunner, Unit
    from appsec_review.storage import atomic_json
    from appsec_review.storage.shared import reference
    from tests.test_job_runtime import write_config

    config_path = write_config(tmp_path)
    with config_path.open("a", encoding="utf-8") as stream:
        stream.write('\n[jobs.job_target_analysis_plan]\nname = "synthetic accepted source producer"\n')
    config = load_config(config_path)

    def publish(context):
        path = context.job.attempt_root / "target-analysis-plan.json"
        atomic_json(path, _PLAN)
        return {"artifact": reference(context.job.run_root, path), "terminal_status": "SUCCEEDED"}

    job = Job("job_target_analysis_plan", "synthetic accepted source producer", lambda _: {},
              units=(Unit("plan_acceptance.publish_handoff", publish),))
    outcome = JobRunner(config).run(job, source_fingerprint=_PLAN["source_fingerprint"])
    run_root = config.runtime.runs_dir / outcome["status"]["run_id"]
    assert topology.main(["score", "--run", str(run_root)]) == 0
    out = capsys.readouterr().out
    assert f"topology summary checks={len(_CHECKS)} met=" in out and "undeclared_failures=0" in out
    assert topology.main(["score", "--run", str(run_root), "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert [item["case_id"] for item in document["checks"]] == [check.case_id for check in _CHECKS]
    assert [item["ok"] for item in document["checks"]] == [check.ok for check in _CHECKS]


def test_cli_json_output_lists_every_check(capsys: pytest.CaptureFixture[str]) -> None:
    assert topology.main(["evaluate", "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert len(document["checks"]) == len(_CHECKS) and document["unexpected_units"] == []
    assert {item["reason_code"] for item in document["checks"] if not item["ok"]} == set(_EXPECTATIONS["reason_codes"])
