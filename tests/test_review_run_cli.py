from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "review_run", ROOT / "deploy" / "dagster" / "bin" / "review_run.py")
assert SPEC is not None and SPEC.loader is not None
review_run = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review_run)


def _document() -> dict:
    return {"jobs": {"job_project_build": {"settings": {"profiles": {
        "android": {"tag": "audit-buildenv-android:local", "image_id": "sha256:expected"},
        "java": {"tag": "audit-buildenv-java:local", "image_id": "sha256:java"},
    }}}}}


def test_submit_preflight_accepts_only_exact_configured_image_identities() -> None:
    resolved = {
        "audit-buildenv-android:local": "sha256:expected",
        "audit-buildenv-java:local": "sha256:java",
    }

    def runner(argv, **_kwargs):
        return SimpleNamespace(returncode=0, stdout=resolved[argv[3]] + "\n", stderr="")

    review_run.verify_build_profile_images(_document(), runner=runner)
    resolved["audit-buildenv-android:local"] = "sha256:replacement"
    with pytest.raises(RuntimeError, match=(
            "android: expected sha256:expected, resolved sha256:replacement")):
        review_run.verify_build_profile_images(_document(), runner=runner)


def test_submit_preflight_reports_missing_profile_image() -> None:
    def runner(argv, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="missing")

    with pytest.raises(RuntimeError, match="resolved unavailable"):
        review_run.verify_build_profile_images(_document(), runner=runner)
