"""First unit test: the session must not inherit production sizing or configuration.

``tests/conftest.py`` moves this module to the front of every session that collects it. The guard
asserts the outcome the inherited environment produces; it never repairs the environment itself.
Expected values are derived from ``appsec-review.toml`` and ``profiles/*.toml``, never hard-coded.
"""

from __future__ import annotations

import os
from pathlib import Path
import json
import tomllib
from typing import Any, Mapping

from appsec_review.config.assurance import parse_review_policy
from appsec_review.config.loader import (
    DEFAULT_PROFILE,
    OVERLAY_ENVIRONMENT,
    PROFILE_DIRECTORY,
    PROFILE_ENVIRONMENT,
    PROFILES,
    load_config,
    profile_override_keys,
    resolve_profile_name,
)
from appsec_review.orchestration.dagster.native import CONFIG_ENV as NATIVE_DEPLOYMENT_CONFIG_ENV

ROOT = Path(__file__).resolve().parents[1]
DEV_CONFIG = ROOT / "appsec-review.toml"
CONFIG_ENVIRONMENT = "APPSEC_REVIEW_CONFIG"
# Every APPSEC_NATIVE_* variable switches code onto the native production lifecycle
# (appsec_review.config.native_dagster.native_execution_requested).
NATIVE_PREFIX = "APPSEC_NATIVE_"
# conftest.acceptance_workspace binds job fixtures to this supervisor workspace and its runs_dir.
ACCEPTANCE_BINDINGS = ("APPSEC_ACCEPTANCE_ROOT", "APPSEC_ACCEPTANCE_RUNS_DIR")
_SECRET_MARKERS = ("PASSWORD", "TOKEN", "SECRET", "KEY")


def _shown(name: str, value: str) -> str:
    return "<redacted>" if any(marker in name for marker in _SECRET_MARKERS) else repr(value)


def offending_environment(environ: Mapping[str, str], *, root: Path = ROOT) -> list[str]:
    """Each inherited variable that would select non-dev configuration, sizing or instances."""
    offences: list[str] = []
    profile = environ.get(PROFILE_ENVIRONMENT)
    if profile and profile != DEFAULT_PROFILE:
        offences.append(f"{PROFILE_ENVIRONMENT}={profile!r} merges {PROFILE_DIRECTORY}/{profile}.toml "
                        f"over the dev configuration (expected unset or {DEFAULT_PROFILE!r})")
    overlay = environ.get(OVERLAY_ENVIRONMENT)
    if overlay:
        offences.append(f"{OVERLAY_ENVIRONMENT}={overlay!r} applies a capacity overlay "
                        "(teams, Dagster pools, review_policy.resources)")
    configured = environ.get(CONFIG_ENVIRONMENT)
    if configured and Path(configured).resolve() != (root / "appsec-review.toml").resolve():
        offences.append(f"{CONFIG_ENVIRONMENT}={configured!r} selects a configuration other than "
                        f"{root / 'appsec-review.toml'} (application_paths, signing policy, Dagster adapter)")
    for name in sorted(environ):
        if name.startswith(NATIVE_PREFIX):
            detail = (" names the native production deployment configuration"
                      if name == NATIVE_DEPLOYMENT_CONFIG_ENV else " requests native production execution")
            offences.append(f"{name}={_shown(name, environ[name])}{detail}")
    dagster_home = environ.get("DAGSTER_HOME")
    if dagster_home:
        offences.append(f"DAGSTER_HOME={dagster_home!r} selects a persistent Dagster instance; "
                        "unit tests must use ephemeral or per-test instances")
    for name in ACCEPTANCE_BINDINGS:
        if environ.get(name):
            offences.append(f"{name}={environ[name]!r} binds unit fixtures to an acceptance workspace")
    return offences


def _lookup(document: Mapping[str, Any], dotted: str) -> tuple[bool, Any]:
    node: Any = document
    for part in dotted.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return False, None
        node = node[part]
    return True, node


def _profile_sizing_keys() -> dict[str, tuple[str, ...]]:
    """Dotted keys each non-dev profile file overrides, as the loader's own allowlist reports them."""
    keys: dict[str, tuple[str, ...]] = {}
    for name in PROFILES:
        if name == DEFAULT_PROFILE:
            continue
        document = tomllib.loads((ROOT / PROFILE_DIRECTORY / f"{name}.toml").read_text(encoding="utf-8"))
        keys[name] = profile_override_keys(document)
    return keys


def test_unit_session_does_not_inherit_production_sizing() -> None:
    offences = offending_environment(os.environ)

    if Path.cwd().resolve() != ROOT:
        offences.append(f"working directory {Path.cwd().resolve()} is not the checkout {ROOT}; "
                        "load_config() resolves the relative default 'appsec-review.toml' from it")
    try:
        selected = resolve_profile_name()
    except ValueError as error:
        selected = None
        offences.append(f"resolve_profile_name() failed: {error}")
    if selected is not None and selected != DEFAULT_PROFILE:
        offences.append(f"resolve_profile_name() selects {selected!r}, not {DEFAULT_PROFILE!r}")

    # The two forms unit tests use: the explicit checkout path and the cwd-relative default.
    ambient = load_config(DEV_CONFIG)
    explicit_dev = load_config(DEV_CONFIG, profile=DEFAULT_PROFILE, overlay="")
    for label, config in (("load_config(ROOT / 'appsec-review.toml')", ambient),
                          ("load_config()", load_config() if Path.cwd().resolve() == ROOT else None)):
        if config is None:
            continue
        if config.source_path != DEV_CONFIG:
            offences.append(f"{label} reads {config.source_path}, not {DEV_CONFIG}")
        if config.profile != DEFAULT_PROFILE or config.profile_path is not None:
            offences.append(f"{label} resolves profile {config.profile!r} from {config.profile_path}")
        if config.overlay_path is not None:
            offences.append(f"{label} applies overlay {config.overlay_path}")

    base = tomllib.loads(DEV_CONFIG.read_text(encoding="utf-8"))
    resolved = json.loads(ambient.resolved_json)
    profile_keys = _profile_sizing_keys()
    discriminating: list[str] = []
    for profile_name, keys in profile_keys.items():
        profile_document = tomllib.loads(
            (ROOT / PROFILE_DIRECTORY / f"{profile_name}.toml").read_text(encoding="utf-8"))
        for key in keys:
            in_base, base_value = _lookup(base, key)
            in_resolved, resolved_value = _lookup(resolved, key)
            _, profile_value = _lookup(profile_document, key)
            if (in_resolved, resolved_value) != (in_base, base_value):
                found = (f"profiles/{profile_name}.toml value {profile_value!r}"
                         if resolved_value == profile_value else repr(resolved_value))
                expected = repr(base_value) if in_base else "no value"
                offences.append(f"{key} resolves to {found}; appsec-review.toml has {expected}")
            if not in_base or base_value != profile_value:
                discriminating.append(f"{profile_name}:{key}")

    base_dagster = base.get("orchestration", {}).get("dagster", {})
    if dict(ambient.dagster.pool_limits) != base_dagster.get("pools", {}):
        offences.append(f"orchestration.dagster.pools resolves to {dict(ambient.dagster.pool_limits)}; "
                        f"appsec-review.toml has {base_dagster.get('pools', {})}")
    if "max_concurrent" in base_dagster and ambient.dagster.max_concurrent != base_dagster["max_concurrent"]:
        offences.append(f"orchestration.dagster.max_concurrent resolves to {ambient.dagster.max_concurrent}; "
                        f"appsec-review.toml has {base_dagster['max_concurrent']}")
    base_policy = parse_review_policy(base.get("review_policy", {})).view()
    if ambient.review_policy.view() != base_policy:
        offences.append(f"review_policy resolves to {ambient.review_policy.view()}; "
                        f"appsec-review.toml has {base_policy}")
    if ambient.resolved_sha256 != explicit_dev.resolved_sha256:
        offences.append("the resolved configuration differs from load_config(profile='dev', overlay=''): "
                        f"{ambient.resolved_sha256} != {explicit_dev.resolved_sha256}")

    assert not offences, (
        "unit tests would run with non-dev (production) sizing or configuration:\n  - "
        + "\n  - ".join(offences))
    # The comparison above must be able to fail: some profile file really differs from dev.
    assert discriminating, f"no profile in {PROFILE_DIRECTORY}/ differs from appsec-review.toml; the guard is vacuous"


def test_guard_names_each_production_variable() -> None:
    """The detector flags every production selector and leaves a clean dev environment alone."""
    clean = {"PATH": "/usr/bin", PROFILE_ENVIRONMENT: DEFAULT_PROFILE, OVERLAY_ENVIRONMENT: "",
             CONFIG_ENVIRONMENT: str(DEV_CONFIG)}
    assert offending_environment(clean) == []

    production = {
        PROFILE_ENVIRONMENT: "prod",
        OVERLAY_ENVIRONMENT: "/opt/app/test/acceptance/prod-capacity-overlay.toml",
        CONFIG_ENVIRONMENT: "/opt/app/appsec-review.toml",
        NATIVE_DEPLOYMENT_CONFIG_ENV: "/var/lib/appsec-review-native/deployment.toml",
        "APPSEC_NATIVE_DEPLOYMENT_ID": "prod",
        "DAGSTER_HOME": "/var/lib/appsec-review-dagster",
        "APPSEC_ACCEPTANCE_ROOT": "/opt/appsec-review/acceptance",
    }
    offences = offending_environment(production)
    assert len(offences) == len(production)
    for name, value in production.items():
        assert any(offence.startswith(f"{name}={value!r}") for offence in offences), name
