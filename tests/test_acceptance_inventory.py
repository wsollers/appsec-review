from __future__ import annotations

import ast
import json
from pathlib import Path
import tomllib

from appsec_review.inference import MODEL_CHECKS, PROVIDERS
from appsec_review.acceptance.staging import StageDeclaration, StageKind
from appsec_review.mcp.schema import TOOLS


ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "tests" / "acceptance_inventory.json"


def duplicate_test_definitions(root: Path) -> dict[str, list[int]]:
    duplicates = {}

    def visit(path: Path, body: list, prefix: str = "") -> None:
        names: dict[str, list[int]] = {}
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                names.setdefault(node.name, []).append(node.lineno)
            elif isinstance(node, ast.ClassDef):
                visit(path, node.body, prefix + node.name + "::")
        for name, lines in names.items():
            if len(lines) > 1:
                duplicates[f"{path.relative_to(root).as_posix()}::{prefix}{name}"] = lines

    for path in sorted((root / "tests").rglob("test_*.py")):
        visit(path, ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path)).body)
    return duplicates


def test_inventory_matches_active_catalogs() -> None:
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    configuration = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    catalogs = inventory["catalogs"]
    assert catalogs["jobs"] == sorted(configuration["jobs"])
    assert catalogs["mcp_tools"] == sorted(tool["name"] for tool in TOOLS)
    assert catalogs["provider_families"] == sorted(MODEL_CHECKS)
    assert catalogs["provider_transports"] == sorted(PROVIDERS)
    assert "openai" not in catalogs["provider_transports"]


def test_inventory_selections_and_dispositions() -> None:
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    assert inventory["schema"] == "appsec-review/acceptance-inventory/1"
    obligations = inventory["obligations"]
    ids = {item["id"] for item in obligations}
    assert len(ids) == len(obligations)
    for item in [*obligations, *inventory["deferred_features"]]:
        for field in ("boundary", "gap_ids", "variants", "substitutions", "prerequisites", "deferrals", "nodes"):
            assert field in item, (item["id"], field)
        assert item["gap_ids"] and item["boundary"]
        assert item["nodes"] or item["deferrals"]
        for node in item["nodes"]:
            file, separator, symbol = node.partition("::")
            assert separator and symbol and file.startswith("tests/") and ".." not in Path(file).parts
            assert (ROOT / file).is_file()
            tree = ast.parse((ROOT / file).read_text(encoding="utf-8-sig"))
            assert symbol.split("[", 1)[0].split("::")[-1] in {
                entry.name for entry in ast.walk(tree) if isinstance(entry, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for name, profile in inventory["profiles"].items():
        assert set(profile["obligations"]) <= ids
        assert profile["obligations"] or profile["deferral"]
        assert profile["case_deadline_seconds"] <= profile["deadline_seconds"]
        for item in obligations:
            if item["id"] in profile["obligations"]:
                cap = item.get("case_deadline_seconds", 60)
                assert type(cap) is int and 3 < cap <= profile["case_deadline_seconds"]
    quick = [item for item in obligations if item["id"] in inventory["profiles"]["quick"]["obligations"]]
    assert quick
    assert not any("/live/" in node or "test_live_" in node for item in quick for node in item["nodes"])


def test_no_untracked_duplicate_test_definitions() -> None:
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    actual = duplicate_test_definitions(ROOT)
    known = {entry["node"] for entry in inventory["known_duplicate_definitions"]}
    assert set(actual) == known, (
        "Untracked duplicate definitions, or repaired gaps requiring inventory reconciliation", actual, known)
    assert all(entry["status"] == "unverified" and entry["gap_id"] and entry["reason"]
               for entry in inventory["known_duplicate_definitions"])


def test_staged_review_inventory_has_explicit_complete_compatible_prerequisites() -> None:
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    obligations = {item["id"]: item for item in inventory["obligations"]}
    stages = {name: StageDeclaration.from_mapping(item["stage"])
              for name, item in obligations.items() if "stage" in item}
    producer_nodes = []
    for name, stage in stages.items():
        if stage.kind is StageKind.PRODUCER:
            nodes = obligations[name]["nodes"]
            assert len(nodes) == 1 and nodes[0].endswith(f"[{stage.variant}]")
            producer_nodes.extend(nodes)
            assert obligations[name].get("case_deadline_seconds", 60) == (
                60 if name.endswith("-prepare") else 120)
        for predecessor in stage.depends_on:
            assert predecessor in stages
            parent = stages[predecessor]
            assert parent.kind is StageKind.PRODUCER and parent.variant == stage.variant
            assert parent.seals is (stage.kind is StageKind.CONSUMER)
    assert len(producer_nodes) == len(set(producer_nodes))
    for profile in inventory["profiles"].values():
        selected = set(profile["obligations"])

        def visit(name, ancestors=()):
            assert name not in ancestors
            for parent in stages[name].depends_on:
                assert parent in selected, (name, parent)
                visit(parent, (*ancestors, name))

        for name in selected & stages.keys():
            visit(name)


def test_review_quick_representatives_and_exhaustive_variants_keep_strict_caps() -> None:
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    profiles = inventory["profiles"]
    assert profiles["quick"]["deadline_seconds"] == 720
    for name in ("review", "review-report-integrity", "review-outcomes", "review-exhaustive"):
        assert profiles[name]["deadline_seconds"] == 600
        assert profiles[name]["case_deadline_seconds"] == 120
    quick = set(profiles["quick"]["obligations"])
    exhaustive = set(profiles["review-exhaustive"]["obligations"])
    assert {"review-candidate", "current-report-oracle"} <= quick
    assert "current-report-integrity" not in quick
    assert {"review-empty", "review-corrupt", "review-benign", "review-blocked",
            "current-report-integrity"} <= exhaustive
    for name, profile in profiles.items():
        if name not in ("review-exhaustive", "review-outcomes"):
            assert not any(item.startswith(("ci-benign-", "ci-blocked-"))
                           for item in profile["obligations"])
    obligations = {item["id"]: item for item in inventory["obligations"]}
    assert set(obligations["current-report-integrity"]["variants"]) == {
        "identity-state-bucket", "missing-current", "orphan-hit", "report-tamper", "manifest-tamper",
        "finding-tamper", "handoff-tamper", "same-length-report-tamper"}
    assert not any("stage" in obligations[name] for name in profiles["consumers"]["obligations"])


def test_exhaustive_series_conserves_vectors_nodes_and_dependencies() -> None:
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    profiles = inventory["profiles"]
    obligations = {item["id"]: item for item in inventory["obligations"]}
    integrity = obligations["current-report-integrity"]
    vectors = [
        "identity-state-bucket", "missing-current", "orphan-hit", "report-tamper",
        "manifest-tamper", "finding-tamper", "handoff-tamper", "same-length-report-tamper",
    ]
    assert integrity["variants"] == vectors
    assert integrity["nodes"] == [
        f"tests/integration/test_current_report_integrity_cases.py::test_current_report_integrity_vector[{vector}]"
        for vector in vectors
    ]
    assert integrity["case_deadline_seconds"] == 60
    assert integrity["stage"] == {
        "kind": "consumer", "variant": "ci-positive", "depends_on": ["ci-positive-report"],
    }
    positive = ["ci-positive-prepare", "ci-positive-review", "ci-positive-gate", "ci-positive-report"]
    assert profiles["review-report-integrity"]["obligations"] == [*positive, "current-report-integrity"]
    outcomes = [
        "ci-benign-prepare", "ci-benign-review", "ci-benign-gate", "ci-benign-report", "review-benign",
        "ci-blocked-prepare", "ci-blocked-review", "ci-blocked-gate", "ci-blocked-report", "review-blocked",
    ]
    assert profiles["review-outcomes"]["obligations"] == outcomes

    def selected_nodes(profile: str) -> set[str]:
        return {node for name in profiles[profile]["obligations"] for node in obligations[name]["nodes"]}

    members = ("review", "review-report-integrity", "review-outcomes")
    assert [len(selected_nodes(name)) for name in members] == [13, 12, 10]
    assert set().union(*(selected_nodes(name) for name in members)) == selected_nodes("review-exhaustive")
    assert len(selected_nodes("review-exhaustive")) == 31
    assert selected_nodes("review") & selected_nodes("review-report-integrity") == {
        node for name in positive for node in obligations[name]["nodes"]
    }
    assert selected_nodes("review-outcomes").isdisjoint(
        selected_nodes("review") | selected_nodes("review-report-integrity"))
    assert "unqualified" in profiles["review-exhaustive"]["deferral"].lower()


def test_exhaustive_split_preserves_calibrated_representative_selections() -> None:
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    profiles = inventory["profiles"]
    positive = ["ci-positive-prepare", "ci-positive-review", "ci-positive-gate", "ci-positive-report"]
    native = ["native-positive-prepare", "native-positive-review", "native-positive-poc", "review-candidate"]
    assert profiles["quick"]["obligations"] == [
        "harness-contract", "harness-isolation", "harness-owned-fixtures", "inventory-drift",
        "signal-lifecycle", "dependency-lifecycle", "mcp-error-recovery", "graph-consumer", "helper-cli",
        "process-configuration", "worker-recovery", "submission-recovery", "mcp-accepted-run",
        "control-source-evidence", "feed-tls", *native, *positive, "current-report-oracle",
    ]
    assert profiles["review"]["obligations"] == [
        *native, "review-corrupt", "native-empty-prepare", "native-empty-review", "review-empty",
        *positive, "current-report-oracle",
    ]
    assert profiles["quick"]["case_deadline_seconds"] == 120
    assert profiles["quick"]["deadline_seconds"] == 720


def test_duplicate_detector_preserves_class_and_async_scope(tmp_path: Path) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_example.py").write_text(
        "def test_a(): pass\nasync def test_a(): pass\n"
        "class TestX:\n    def test_b(self): pass\n    def test_b(self): pass\n"
        "class TestY:\n    def test_b(self): pass\n", encoding="utf-8")
    assert duplicate_test_definitions(tmp_path) == {
        "tests/test_example.py::test_a": [1, 2], "tests/test_example.py::TestX::test_b": [4, 5]}
