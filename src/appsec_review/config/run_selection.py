"""Per-run runtime profile, capacity overlay and compiler target selection from launch tags.

The code location loads one base configuration from its environment (``APPSEC_REVIEW_PROFILE`` and
``APPSEC_REVIEW_CONFIG_OVERLAY``). A run launched with ``appsec/profile`` and/or ``appsec/overlay`` tags
resolves its own configuration from the same base file instead. ``appsec/compiler_target`` chooses
the native debug-symbol lane independently; a run without selection tags keeps the base.

What a per-run selection may not change, and is therefore refused rather than ignored:

- the provider family (``dev``/``prod`` use the Claude image, ``copilot-*`` the Copilot image and login);
- anything under native execution, whose operator contract pins one configuration and resource budget;
- the overlay location: it must be a file under ``<repository>/test/acceptance``.

The profile allowlist and the overlay capacity-key allowlist are enforced by ``load_config`` itself.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import threading
from typing import Any, Mapping

from .loader import AppConfig, PROFILES, load_config
from .compiler_target import COMPILER_TARGET_TAG, compiler_target

PROFILE_TAG = "appsec/profile"
OVERLAY_TAG = "appsec/overlay"
NO_OVERLAY = "none"
SELECTION_SOURCE = "run_tags"
ACCEPTANCE_DIRECTORY = ("test", "acceptance")
_CACHE_LIMIT = 8


def provider_family(profile: str) -> str:
    """``copilot`` for the Copilot SDK profiles, ``claude`` otherwise; fixed per container image."""
    return "copilot" if profile.startswith("copilot-") else "claude"


def _overlay_path(base: AppConfig, value: str) -> Path | None:
    if value == NO_OVERLAY:
        return None
    acceptance = base.runtime.repository_root.joinpath(*ACCEPTANCE_DIRECTORY).resolve()
    candidate = Path(value)
    if not candidate.is_absolute():
        raise ValueError(f"{OVERLAY_TAG} must be an absolute path under {acceptance} or {NO_OVERLAY!r}: {value!r}")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"{OVERLAY_TAG} names no readable file: {value!r}") from error
    if not resolved.is_file() or not resolved.is_relative_to(acceptance):
        raise ValueError(f"{OVERLAY_TAG} must be a file under {acceptance}: {value!r}")
    return resolved


def _base_overlay(base: AppConfig) -> Path | None:
    return base.overlay_path.resolve() if base.overlay_path is not None else None


def requested_selection(base: AppConfig, tags: Mapping[str, str]) -> tuple[str, Path | None] | None:
    """The (profile, overlay) a run's tags select, validated; None when they select the base configuration."""
    if PROFILE_TAG not in tags and OVERLAY_TAG not in tags:
        return None
    profile = tags.get(PROFILE_TAG, base.profile)
    if profile not in PROFILES:
        raise ValueError(f"{PROFILE_TAG}={profile!r} is not a runtime profile; expected one of: {', '.join(PROFILES)}")
    if provider_family(profile) != provider_family(base.profile):
        raise ValueError(f"{PROFILE_TAG}={profile} needs the {provider_family(profile)} provider, but this code "
                         f"location runs {base.profile} ({provider_family(base.profile)}); the provider is fixed "
                         "when the container is created (scripts/stack-restart --profile)")
    overlay = _overlay_path(base, tags[OVERLAY_TAG]) if OVERLAY_TAG in tags else _base_overlay(base)
    if profile == base.profile and overlay == _base_overlay(base):
        return None
    from .native_dagster import native_execution_requested
    if native_execution_requested():
        raise ValueError("native execution pins one configuration and resource budget per operator contract; "
                         "a per-run profile or overlay is refused")
    return profile, overlay


class RunConfigurations:
    """The base configuration plus the per-run configurations that launch tags select (cached)."""

    def __init__(self, base: AppConfig):
        self.base = base
        self._cache: dict[tuple[str, str, str], AppConfig] = {}
        self._lock = threading.Lock()

    def for_tags(self, tags: Mapping[str, str]) -> AppConfig:
        target = compiler_target(tags.get(COMPILER_TARGET_TAG, self.base.compiler_target.value))
        selection = requested_selection(self.base, tags)
        if selection is None and target == self.base.compiler_target:
            return self.base
        profile, overlay = selection or (self.base.profile, _base_overlay(self.base))
        key = (profile, str(overlay) if overlay is not None else "", target.value)
        with self._lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached
        resolved = replace(load_config(self.base.source_path, profile=profile, overlay=key[1],
                                       compiler_target=target.value),
                           selection_source=SELECTION_SOURCE)
        with self._lock:
            if len(self._cache) >= _CACHE_LIMIT:
                self._cache.pop(next(iter(self._cache)))
            self._cache[key] = resolved
        return resolved

    def for_run(self, run: Any) -> AppConfig:
        return self.for_tags(dict(getattr(run, "tags", None) or {}))


def configurations(config: AppConfig | RunConfigurations) -> RunConfigurations:
    return config if isinstance(config, RunConfigurations) else RunConfigurations(config)


def reject_run_selection(config: AppConfig, tags: Mapping[str, str], job_name: str) -> None:
    """For jobs whose executor is fixed at definition time: refuse a tag selecting another configuration."""
    target = compiler_target(tags.get(COMPILER_TARGET_TAG, config.compiler_target.value))
    if requested_selection(config, tags) is not None or target != config.compiler_target:
        raise ValueError(f"{job_name} uses the code location's configuration ({config.profile}); "
                         f"launch it without {PROFILE_TAG}/{OVERLAY_TAG}/{COMPILER_TARGET_TAG} tags that select another")
