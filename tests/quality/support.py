from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[2]


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "user.name=Quality fixture", "-c", "user.email=quality@example.invalid",
         "-c", f"core.hooksPath={root / '.git' / 'no-fixture-hooks'}", "-c", "commit.gpgsign=false", *args],
        cwd=root, check=True, capture_output=True, text=True, timeout=10,
    )
    return result.stdout.strip()


def write(root: Path, path: str, source: str) -> Path:
    result = root / path
    result.parent.mkdir(parents=True, exist_ok=True)
    result.write_text(source, encoding="utf-8")
    return result


def repository(root: Path, *, copy_tools: bool = False) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    quality = dict(project["tool"]["appsec-quality"])
    quality.update(
        unit_tests=["tests/test_fixture.py"], contract_tests=["tests/test_contract.py"],
        bootstrap_modules=["appsec_review.signing.bootstrap", "appsec_review.signing.core",
                           "appsec_review.signing.modules"],
        public_contracts=["appsec_review.runtime.contract"],
    )
    text = (
        '[project]\nname = "quality-fixture"\nversion = "0.0.0"\n'
        '[project.optional-dependencies]\nquality = '
        + json.dumps(project["project"]["optional-dependencies"]["quality"])
        + '\n[tool.ruff.lint]\nselect = ["E9", "F811", "F821", "F822", "F823"]\n'
        '[tool.mypy]\npython_version = "3.11"\nstrict = true\nfollow_imports = "silent"\n'
        'files = ["src/appsec_review/runtime/contract.py"]\n'
        'cache_dir = "test/tmp/.mypy_cache"\n'
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n'
        'addopts = "--basetemp=test/tmp"\ncache_dir = "test/tmp/.pytest_cache"\n'
        '[tool.appsec-quality]\n'
        + "\n".join(f"{key} = {json.dumps(value)}" for key, value in quality.items()) + "\n"
    )
    write(root, "pyproject.toml", text)
    for path in ("src/appsec_review/__init__.py", "src/appsec_review/runtime/__init__.py",
                 "src/appsec_review/signing/__init__.py"):
        write(root, path, "")
    write(root, "src/appsec_review/runtime/contract.py", "def contract(value: int) -> int:\n    return value\n")
    write(root, "src/appsec_review/signing/bootstrap.py", "import sys\n")
    write(root, "src/appsec_review/signing/core.py", "import hashlib\n")
    write(root, "src/appsec_review/signing/modules.py", "if __package__:\n    from . import core\n")
    write(root, "tests/test_fixture.py", "def test_fixture():\n    assert 1 + 1 == 2\n")
    write(root, "tests/test_contract.py", "def test_contract():\n    assert True\n")
    write(root, "quality/baseline.json", '{"version": 1, "reason": "Clean fixture", "findings": []}\n')
    if copy_tools:
        shutil.copytree(ROOT / "tools" / "quality", root / "tools" / "quality",
                        ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copyfile(ROOT / "tools" / "__init__.py", root / "tools" / "__init__.py")
    else:
        write(root, "tools/quality/__init__.py", "")
    git(root, "init", "--quiet")
    git(root, "add", ".")
    git(root, "commit", "--quiet", "-m", "Clean fixture")
    return root
