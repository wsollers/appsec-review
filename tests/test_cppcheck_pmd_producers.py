from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.container_runtime import load_catalog
from appsec_review.jobs.cataloging import inventory, source_fingerprint
from appsec_review.jobs.job_evidence_collection.adapters import (
    Applicability,
    ScanCatalog,
    adapter_registry,
)


ROOT = Path(__file__).parents[1]


def _catalog(*paths: str, root: Path | None = None,
             compile_commands: tuple[dict[str, object], ...] = ()) -> ScanCatalog:
    files = tuple({"path": path, "sha256": hashlib.sha256(path.encode()).hexdigest()}
                  for path in paths)
    return ScanCatalog("f" * 64, "h" * 64, files, (), (), root, compile_commands)


def test_cppcheck_source_mode_is_bounded_and_truthfully_gapped() -> None:
    adapter = adapter_registry()["tool-cppcheck"]
    selection = adapter.applicability(_catalog("src/main.cpp", "include/main.hpp", "notes.txt"))
    assert selection.applicable
    assert selection.files == ("include/main.hpp", "src/main.cpp")
    assert selection.coverage_kind == "cpp_source_without_build_context"
    assert any("build flags" in gap for gap in selection.gaps)
    argv = adapter.argv("/opt/cppcheck/bin/cppcheck", selection)
    assert "--project=/scratch/compile_commands.json" not in argv
    assert "/target/src/main.cpp" in argv and "/target/notes.txt" not in argv


def test_cppcheck_accepts_one_cataloged_compile_database_without_executing_it(tmp_path: Path) -> None:
    database = [{"directory": str(tmp_path), "file": "src/main.cpp",
                 "arguments": ["c++", "-DREVIEW=1", "src/main.cpp"]}]
    (tmp_path / "compile_commands.json").write_text(json.dumps(database), encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    catalog = _catalog("compile_commands.json", "src/main.cpp", root=tmp_path,
                       compile_commands=({"path": "compile_commands.json"},))
    selection = adapter_registry()["tool-cppcheck"].applicability(catalog)
    assert selection.coverage_kind == "cpp_compile_database"
    assert selection.families["compile_database"] == ("compile_commands.json",)
    argv = adapter_registry()["tool-cppcheck"].argv("/opt/cppcheck/bin/cppcheck", selection)
    assert "--project=/scratch/compile_commands.json" in argv
    assert not any(value.endswith("src/main.cpp") for value in argv)


def test_cppcheck_and_pmd_argv_reject_uncataloged_parent_paths() -> None:
    cppcheck = adapter_registry()["tool-cppcheck"]
    unsafe = Applicability(True, "fixture", ("../outside.cpp",), "cpp_source_without_build_context")
    with pytest.raises(ValueError, match="catalog path is unsafe"):
        cppcheck.argv("/opt/cppcheck/bin/cppcheck", unsafe)


def test_cppcheck_parser_preserves_native_location_and_separates_coverage_diagnostics() -> None:
    payload = b"""<?xml version='1.0'?><results><errors>
      <error id='arrayIndexOutOfBounds' severity='error' msg='index out of bounds'>
        <location file='/target/src/main.cpp' line='7'/>
      </error>
      <error id='missingIncludeSystem' severity='information' msg='include not found'>
        <location file='/target/src/main.cpp' line='1'/>
      </error>
    </errors></results>"""
    records = adapter_registry()["tool-cppcheck"].parse(payload)
    assert records[0]["rule_id"] == "arrayIndexOutOfBounds"
    assert records[0]["path"] == "/target/src/main.cpp" and records[0]["start_line"] == "7"
    assert records[1]["gap_only"] is True and "missingIncludeSystem" in records[1]["coverage_gap"]


def test_pmd_scope_parser_and_configuration_error_contract() -> None:
    adapter = adapter_registry()["tool-pmd"]
    selection = adapter.applicability(_catalog("src/Main.java", "src/main.cpp"))
    assert selection.files == ("src/Main.java",)
    assert any("classpath" in gap for gap in selection.gaps)
    assert any("bytecode" in gap for gap in selection.gaps)
    assert adapter.argv("/opt/pmd/bin/pmd", selection)[-2:] == ("--file-list", "/scratch/pmd-files.txt")
    payload = json.dumps({"files": [{"filename": "/target/src/Main.java", "violations": [{
        "rule": "RuntimeCommandExecution", "description": "review command execution",
        "priority": 2, "beginline": 4, "endline": 4,
    }]}], "configurationErrors": []}).encode()
    records = adapter.parse(payload)
    assert records[0]["rule_id"] == "RuntimeCommandExecution"
    assert records[0]["path"] == "/target/src/Main.java" and records[0]["start_line"] == 4
    with pytest.raises(ValueError, match="tool-pmd output parser failed"):
        adapter.parse(json.dumps({"files": [], "configurationErrors": [{"msg": "bad rules"}]}).encode())


def test_negative_applicability_is_language_specific() -> None:
    catalog = _catalog("README.md", "main.py")
    assert not adapter_registry()["tool-cppcheck"].applicability(catalog).applicable
    assert not adapter_registry()["tool-pmd"].applicability(catalog).applicable


def test_real_target_has_bounded_cpp_and_java_applicability() -> None:
    target = ROOT / "targets" / "appsec-multi-vuln"
    snapshot = inventory(target)
    catalog = ScanCatalog(source_fingerprint(target), "a" * 64, tuple(snapshot["files"]), (), (), target)
    cpp = adapter_registry()["tool-cppcheck"].applicability(catalog)
    java = adapter_registry()["tool-pmd"].applicability(catalog)
    assert cpp.applicable and all(Path(path).suffix.lower() in {".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"}
                                  for path in cpp.files)
    assert java.applicable and all(path.endswith(".java") for path in java.files)


def test_container_manifests_and_pmd_rules_are_hash_locked_to_runtime_policy() -> None:
    catalog = load_catalog(ROOT)
    assert {"tool-cppcheck", "tool-pmd"} <= set(catalog.tools)
    for tool_id in ("tool-cppcheck", "tool-pmd"):
        tool = catalog.tool(tool_id)
        assert tool.user == "10001:10001" and tool.network == "none"
        assert tool.expected_image_id is None
    lock = json.loads((ROOT / "rules" / "pmd" / "rules.lock.json").read_text(encoding="utf-8"))
    actual = hashlib.sha256((ROOT / "rules" / "pmd" / "java-security.xml").read_bytes()).hexdigest()
    assert lock["sha256"] == actual
