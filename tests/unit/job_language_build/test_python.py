from __future__ import annotations

from pathlib import Path

from appsec_review.jobs.job_language_build import python as python_adapter


def test_python_recipe_validation_is_package_only_and_allows_dependency_download(tmp_path: Path) -> None:
    setup = tmp_path / "setup.py"
    setup.write_text("from setuptools import setup\nsetup(name='sample')\n", encoding="utf-8")
    base = {"family": "python", "recipe": {"dependency_files": ["setup.py"],
        "network_required": False, "configure_commands": [],
        "build_commands": [["python", "setup.py", "sdist", "bdist_wheel"]]}}
    assert python_adapter.validate_dispatch(base, tmp_path) == []
    unsafe = {"family": "python", "recipe": {**base["recipe"],
        "build_commands": [["python", "-m", "pytest"]]}}
    assert any("allowlist" in gap for gap in python_adapter.validate_dispatch(unsafe, tmp_path))
    unlocked = {"family": "python", "recipe": {**base["recipe"], "network_required": True}}
    assert python_adapter.validate_dispatch(unlocked, tmp_path) == []
