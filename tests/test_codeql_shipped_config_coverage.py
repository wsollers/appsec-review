"""The shipped CodeQL runtime configuration covers every environment the review can hand it.

Run 2026-10-29-0002 aborted because the shipped ``preinstalled_runtimes`` declared only the source
and native images, so every other build profile and every per-run customized project image raised
``ValueError`` during runtime resolution. These checks load the real shipped configuration and
resolve declared identities with the real resolver; Docker is never consulted.
"""
from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path

import pytest

from appsec_review.codeql import CodeQLImageResolver
from appsec_review.config import load_config
from appsec_review.container_runtime import profiles_from_settings


ROOT = Path(__file__).resolve().parents[1]
JOB = "job_codeql_analysis"
CUSTOMIZED_IMAGE_ID = "sha256:" + "c" * 64
# The deployed review host profile (deploy/dagster/native/deployment.example.toml).
HOST_PROFILE = "copilot-prod"


def _refuse_docker(command, timeout):  # pragma: no cover - reaching it is the failure
    raise AssertionError(f"declared identity must not invoke the container engine: {command!r}")


@pytest.fixture(scope="module")
def shipped():
    config = load_config(ROOT / "appsec-review.toml", profile=HOST_PROFILE, overlay="")
    settings = config.job(JOB).typed_settings
    profiles = profiles_from_settings(config.job("job_project_build").settings["profiles"])
    return config, settings, profiles


@pytest.fixture(autouse=True)
def host_process(monkeypatch, shipped):
    """Run as the review host's application user named by the shipped declarations."""
    _config, settings, _profiles = shipped
    users = {item.runtime_user for item in settings.preinstalled_runtimes}
    assert len(users) == 1
    uid, gid = (int(part) for part in next(iter(users)).split(":"))
    monkeypatch.setattr(os, "geteuid", lambda: uid, raising=False)
    monkeypatch.setattr(os, "getegid", lambda: gid, raising=False)
    for name in [name for name in os.environ if name.startswith("APPSEC_NATIVE_")]:
        monkeypatch.delenv(name)


def _resolver(config, settings) -> CodeQLImageResolver:
    return CodeQLImageResolver(
        repository_root=ROOT, metadata_root=ROOT / "test" / "tmp" / "unused-metadata", settings=settings,
        runner=_refuse_docker, releases=config.review_policy.releases)


def _requests(settings, profiles):
    """Every (environment image, nominal user) pair the job passes to runtime resolution."""
    pairs = {(settings.source_image_id, settings.runtime_user)}
    for profile in profiles.values():
        pairs.add((profile.image_id, profile.user))
        pairs.add((CUSTOMIZED_IMAGE_ID, profile.user))
    return sorted(pairs)


def test_shipped_policy_derives_wholly_undeclared_environments(shipped):
    _config, settings, profiles = shipped
    assert settings.preinstalled_undeclared == "derive"
    declared = {item.build_image_id for item in settings.preinstalled_runtimes}
    assert settings.source_image_id in declared
    assert profiles["native"].image_id in declared
    assert any(profile.image_id not in declared for profile in profiles.values())


def test_shipped_settings_resolve_every_build_profile_and_customized_image(shipped):
    config, settings, profiles = shipped
    resolver = _resolver(config, settings)
    derived_only = _resolver(config, replace(settings, preinstalled_runtimes=()))
    declared = {item.build_image_id for item in settings.preinstalled_runtimes}
    for image_id, user in _requests(settings, profiles):
        identity = resolver.declared_identity(build_image_id=image_id, runtime_user=user)
        derived = derived_only.declared_identity(build_image_id=image_id, runtime_user=user)
        if image_id in declared:
            assert identity != derived, image_id
        else:
            assert identity == derived, image_id


def test_fail_policy_on_shipped_settings_reproduces_the_undeclared_fault(shipped):
    config, settings, profiles = shipped
    resolver = _resolver(config, replace(settings, preinstalled_undeclared="fail"))
    declared = {item.build_image_id for item in settings.preinstalled_runtimes}
    refused = []
    for image_id, user in _requests(settings, profiles):
        if image_id in declared:
            resolver.declared_identity(build_image_id=image_id, runtime_user=user)
            continue
        with pytest.raises(ValueError, match="requires one exact environment/user declaration"):
            resolver.declared_identity(build_image_id=image_id, runtime_user=user)
        refused.append(image_id)
    assert CUSTOMIZED_IMAGE_ID in refused
    assert {profiles[name].image_id for name in ("go", "java", "dotnet", "node")} <= set(refused)
