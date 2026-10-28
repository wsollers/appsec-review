from __future__ import annotations

import ast
import json
from pathlib import Path
import tomllib

from appsec_review.inference import MODEL_CHECKS, PROVIDERS
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


def test_duplicate_detector_preserves_class_and_async_scope(tmp_path: Path) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_example.py").write_text(
        "def test_a(): pass\nasync def test_a(): pass\n"
        "class TestX:\n    def test_b(self): pass\n    def test_b(self): pass\n"
        "class TestY:\n    def test_b(self): pass\n", encoding="utf-8")
    assert duplicate_test_definitions(tmp_path) == {
        "tests/test_example.py::test_a": [1, 2], "tests/test_example.py::TestX::test_b": [4, 5]}
