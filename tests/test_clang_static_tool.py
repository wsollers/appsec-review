from __future__ import annotations

import importlib.util
from pathlib import Path
import plistlib


ROOT = Path(__file__).parents[1]


def _driver():
    path = ROOT / "containers" / "tools" / "clang-static-analysis" / "clang-static.py"
    spec = importlib.util.spec_from_file_location("clang_static_driver", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_clang_tidy_text_diagnostic_is_normalized() -> None:
    driver = _driver()
    records = driver._text_diagnostics(
        "/target/source/main.cpp:7:9: warning: unchecked return [bugprone-unused-return-value]\n",
        engine="clang-tidy", default_rule="driver",
    )
    assert records == [{
        "rule_id": "bugprone-unused-return-value", "message": "unchecked return",
        "severity": "warning", "path": "/target/source/main.cpp", "line": 7,
        "column": 9, "notes": [],
    }]


def test_static_analyzer_plist_retains_path_notes(tmp_path: Path) -> None:
    driver = _driver()
    report = tmp_path / "result.plist"
    report.write_bytes(plistlib.dumps({
        "files": ["/target/source/main.cpp"],
        "diagnostics": [{
            "check_name": "core.NullDereference", "description": "Dereference of null pointer",
            "location": {"file": 0, "line": 4, "col": 3},
            "path": [{"location": {"line": 3, "col": 5}, "message": "Null assigned here"}],
        }],
    }))
    records = driver._plist_diagnostics(report)
    assert records[0]["rule_id"] == "core.NullDereference"
    assert records[0]["path"] == "/target/source/main.cpp"
    assert records[0]["notes"] == [{"message": "Null assigned here", "line": 3, "column": 5}]
