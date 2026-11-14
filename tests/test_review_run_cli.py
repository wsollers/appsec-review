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


def test_native_marker_prevents_ambient_image_inspection(monkeypatch) -> None:
    monkeypatch.setenv("APPSEC_NATIVE_ENGINE_CONTRACT", "")

    def forbidden(*_args, **_kwargs):
        pytest.fail("prepared native configuration reached ambient Docker")

    with pytest.raises(RuntimeError, match="ambient engine fallback is prohibited"):
        review_run.verify_build_profile_images(_document(), runner=forbidden)


SOURCE_ID, CPP_ID = "sha256:" + "a" * 64, "sha256:" + "b" * 64
SOURCE_RUNTIME, CPP_RUNTIME = "sha256:" + "c" * 64, "sha256:" + "d" * 64


def _codeql_document(declarations: list[dict], *, builder: bool = False, enabled: bool = True) -> dict:
    from appsec_review.container_runtime.identity import application_runtime_user
    user = application_runtime_user("10001:10001")
    for item in declarations:
        item.setdefault("runtime_user", user)
    return {"review_policy": ({"image_builder": {"endpoint": "/run/x.sock"}} if builder else {}),
            "jobs": {"job_codeql_analysis": {"settings": {
                "enabled": enabled, "runtime_user": "10001:10001", "source_image_tag": "audit-codeql:custom-2.27.0",
                "source_image_id": SOURCE_ID, "preinstalled_runtimes": declarations}},
                "job_project_build": {"settings": {"profiles": {
                    "native": {"tag": "audit-buildenv-cpp:local", "image_id": CPP_ID},
                    "python": {"tag": "audit-buildenv-python:local", "image_id": "sha256:" + "e" * 64}}}}}}


def _present(*image_ids: str):
    def runner(argv, **_kwargs):
        return SimpleNamespace(returncode=0 if argv[3] in image_ids else 1, stdout=argv[3] + "\n", stderr="")
    return runner


def test_codeql_preflight_refuses_an_undeclared_inventory_runtime_without_a_builder() -> None:
    """Regression for smoke-cpp runs 2026-11-13-0001 to 2026-11-14-0003: an empty preinstalled_runtimes
    list on a host with no bounded image builder left CodeQL reporting no extractor for every language."""
    with pytest.raises(RuntimeError, match="inventory image audit-codeql:custom-2.27.0: no preinstalled runtime "
                                           "declaration for sha256:a.*host-pins.toml"):
        review_run.verify_codeql_runtimes(_codeql_document([]), runner=_present())
    assert review_run.verify_codeql_runtimes(_codeql_document([], builder=True), runner=_present()) == []
    assert review_run.verify_codeql_runtimes(_codeql_document([], enabled=False), runner=_present()) == []


def test_codeql_preflight_warns_for_each_undeclared_compiled_build_profile() -> None:
    source = {"build_image_id": SOURCE_ID, "runtime_image_id": SOURCE_RUNTIME}
    warnings = review_run.verify_codeql_runtimes(_codeql_document([dict(source)]),
                                                 runner=_present(SOURCE_RUNTIME))
    assert len(warnings) == 1 and "native build profile audit-buildenv-cpp:local" in warnings[0]
    assert "TOOLCHAIN_UNAVAILABLE" in warnings[0] and "python" not in warnings[0]
    cpp = {"build_image_id": CPP_ID, "runtime_image_id": CPP_RUNTIME}
    assert review_run.verify_codeql_runtimes(_codeql_document([dict(source), dict(cpp)]),
                                             runner=_present(SOURCE_RUNTIME, CPP_RUNTIME)) == []


def test_codeql_preflight_requires_the_declared_runtime_image_to_exist_locally() -> None:
    source = {"build_image_id": SOURCE_ID, "runtime_image_id": SOURCE_RUNTIME}
    with pytest.raises(RuntimeError, match="declared runtime image sha256:c.* resolved unavailable"):
        review_run.verify_codeql_runtimes(_codeql_document([dict(source)]), runner=_present())
    other_user = {"build_image_id": SOURCE_ID, "runtime_image_id": SOURCE_RUNTIME, "runtime_user": "7:7"}
    with pytest.raises(RuntimeError, match="no preinstalled runtime declaration"):
        review_run.verify_codeql_runtimes(_codeql_document([other_user]), runner=_present(SOURCE_RUNTIME))
