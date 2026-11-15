"""T-5018: the typed cppcheck scan profile, from TOML to argv to receipt."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import MappingProxyType

import pytest

from appsec_review.config import CppcheckProfile, load_config, parse_cppcheck_profile
from appsec_review.config.cppcheck import ENABLE_CLASSES, EXTRA_ARG_VALUES, PREFIX
from appsec_review.container_runtime.executor import CommandOutcome, ContainerExecutor, ExecutionRequest
from appsec_review.jobs.job_evidence_collection.adapters import (
    CPPCHECK_FIXED_ARGS, Applicability, ScanCatalog, adapter_registry,
)
from tests.test_container_runtime import DIGEST, catalog as executor_catalog


ROOT = Path(__file__).parents[1]
TABLE = "[jobs.job_evidence_collection.steps.source_sast.tasks.cppcheck_scan.settings]"
EXECUTABLE = "/opt/cppcheck/bin/cppcheck"


def _selection(*paths: str) -> Applicability:
    files = tuple({"path": path, "sha256": hashlib.sha256(path.encode()).hexdigest()} for path in paths)
    return adapter_registry()["tool-cppcheck"].applicability(ScanCatalog("f" * 64, "h" * 64, files, ()))


def _variant(tmp_path: Path, *replacements: tuple[str, str], suffix: str = ""):
    source = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    for old, new in replacements:
        assert source.count(old) == 1, old
        source = source.replace(old, new)
    path = tmp_path / "appsec-review.toml"
    path.write_text(source + suffix, encoding="utf-8")
    return load_config(path)


def _task_settings(config):
    return config.job("job_evidence_collection").step("source_sast").task("cppcheck_scan").settings


# ---------------------------------------------------------------- the typed profile


def test_default_profile_enables_warning_only() -> None:
    profile = parse_cppcheck_profile({})
    assert profile == CppcheckProfile()
    assert profile.enable == ("warning",)
    assert profile.suppressions == () and profile.extra_args == ()
    assert profile.argv_fragment == ("--enable=warning",)
    assert parse_cppcheck_profile(None) == profile
    assert {"style", "performance", "portability", "information"} <= ENABLE_CLASSES
    assert "all" not in ENABLE_CLASSES
    assert "--project" not in EXTRA_ARG_VALUES and "--output-file" not in EXTRA_ARG_VALUES


def test_widened_profile_keeps_configuration_order_and_is_frozen() -> None:
    profile = parse_cppcheck_profile({
        "enable": ["warning", "style", "missingInclude"], "suppressions": ["unusedStructMember", "variableScope"],
        "extra_args": ["--std=c++17", "--check-level=exhaustive", "--inconclusive"]})
    assert profile.argv_fragment == (
        "--enable=warning,style,missingInclude", "--suppress=unusedStructMember", "--suppress=variableScope",
        "--std=c++17", "--check-level=exhaustive", "--inconclusive")
    assert profile.view() == {"enable": ["warning", "style", "missingInclude"],
                              "suppressions": ["unusedStructMember", "variableScope"],
                              "extra_args": ["--std=c++17", "--check-level=exhaustive", "--inconclusive"]}
    with pytest.raises(AttributeError):
        profile.enable = ("style",)  # type: ignore[misc]


@pytest.mark.parametrize(("settings", "key", "fragment"), [
    ({"enable": ["warning", "lint"]}, "enable", "unknown cppcheck check class 'lint'"),
    ({"enable": ["warning", "all"]}, "enable", "unknown cppcheck check class 'all'"),
    ({"enable": []}, "enable", "at least one"),
    ({"enable": ["warning", "warning"]}, "enable", "repeats"),
    ({"enable": "warning"}, "enable", "must be a list"),
    ({"suppressions": ["unused member"]}, "suppressions", "invalid cppcheck message id: 'unused member'"),
    ({"suppressions": ["nullPointer:src/main.cpp"]}, "suppressions", "invalid cppcheck message id"),
    ({"suppressions": [7]}, "suppressions", "invalid cppcheck message id"),
    ({"extra_args": ["--project=/etc/passwd"]}, "extra_args", "outside the allow-list: '--project=/etc/passwd'"),
    ({"extra_args": ["--output-file=/tmp/x"]}, "extra_args", "outside the allow-list"),
    ({"extra_args": ["-DDEBUG=1"]}, "extra_args", "outside the allow-list"),
    ({"extra_args": ["--std=rust"]}, "extra_args", "flag --std has an unsupported value"),
    ({"extra_args": ["--check-level"]}, "extra_args", "flag --check-level has an unsupported value"),
    ({"extra_args": ["--inconclusive=yes"]}, "extra_args", "flag --inconclusive takes no value"),
    ({"extra_args": ["--std=c11", "--std=c17"]}, "extra_args", "repeats flag --std"),
    ({"extra_args": "--inconclusive"}, "extra_args", "must be a list"),
], ids=lambda value: value if isinstance(value, str) and " " not in value else None)
def test_invalid_profiles_are_refused_by_key(settings, key: str, fragment: str) -> None:
    with pytest.raises(ValueError) as refusal:
        parse_cppcheck_profile(settings)
    assert str(refusal.value).startswith(f"{PREFIX}.{key}")
    assert fragment in str(refusal.value)


def test_unknown_profile_keys_are_refused_by_table() -> None:
    with pytest.raises(ValueError, match=rf"{PREFIX} has unknown settings: addons, enabled"):
        parse_cppcheck_profile({"enabled": ["warning"], "addons": ["misra"]})


# ---------------------------------------------------------------- the adapter argv


def test_adapter_argv_follows_the_default_profile_and_keeps_the_fixed_tail() -> None:
    adapter = adapter_registry()["tool-cppcheck"]
    selection = _selection("src/main.cpp", "include/main.hpp")
    assert adapter.argv(EXECUTABLE, selection) == (
        EXECUTABLE, "--enable=warning", *CPPCHECK_FIXED_ARGS, "/target/include/main.hpp", "/target/src/main.cpp")
    assert adapter.argv(EXECUTABLE, selection, {}) == adapter.argv(EXECUTABLE, selection)
    assert CPPCHECK_FIXED_ARGS == ("--inline-suppr", "--xml", "--xml-version=2", "--output-file=/scratch/output.xml")
    assert not any(item.startswith("--enable=") and "style" in item for item in adapter.argv(EXECUTABLE, selection))


def test_adapter_argv_follows_a_widened_profile_without_moving_the_fixed_tail() -> None:
    adapter = adapter_registry()["tool-cppcheck"]
    selection = _selection("src/main.cpp")
    settings = MappingProxyType({"enable": ["warning", "style", "performance"], "suppressions": ["unusedStructMember"],
                                 "extra_args": ["--check-level=exhaustive", "--std=c++20"]})
    argv = adapter.argv(EXECUTABLE, selection, settings)
    assert argv == (EXECUTABLE, "--enable=warning,style,performance", "--suppress=unusedStructMember",
                    "--check-level=exhaustive", "--std=c++20", *CPPCHECK_FIXED_ARGS, "/target/src/main.cpp")
    assert argv.count("--output-file=/scratch/output.xml") == 1
    with pytest.raises(ValueError, match=rf"{PREFIX}\.extra_args"):
        adapter.argv(EXECUTABLE, selection, {"extra_args": ["--output-file=/target/x.xml"]})


# ---------------------------------------------------------------- the configuration layer


def test_repository_recipe_freezes_the_profile_in_the_resolved_configuration() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    settings = _task_settings(config)
    assert isinstance(settings, MappingProxyType)
    assert dict(settings) == {"enable": ["warning"], "suppressions": [], "extra_args": ["--check-level=normal"]}
    resolved = json.loads(config.resolved_json)
    assert resolved["jobs"]["job_evidence_collection"]["steps"]["source_sast"]["tasks"]["cppcheck_scan"][
        "settings"] == dict(settings)
    with pytest.raises(TypeError):
        settings["enable"] = ["style"]  # type: ignore[index]
    assert parse_cppcheck_profile(settings).argv_fragment == ("--enable=warning", "--check-level=normal")


def test_omitted_profile_table_resolves_to_the_default_profile(tmp_path: Path) -> None:
    config = _variant(tmp_path, (f"{TABLE}\nenable = [\"warning\"]\nsuppressions = []\n"
                                 "extra_args = [\"--check-level=normal\"]\n", ""))
    assert dict(_task_settings(config)) == {"enable": ["warning"], "suppressions": [], "extra_args": []}


def test_recipe_can_widen_the_profile(tmp_path: Path) -> None:
    config = _variant(tmp_path, ('enable = ["warning"]\nsuppressions = []\n',
                                 'enable = ["warning", "portability"]\nsuppressions = ["unusedStructMember"]\n'))
    settings = _task_settings(config)
    assert settings["enable"] == ["warning", "portability"] and settings["suppressions"] == ["unusedStructMember"]
    argv = adapter_registry()["tool-cppcheck"].argv(EXECUTABLE, _selection("a.c"), settings)
    assert argv[1:4] == ("--enable=warning,portability", "--suppress=unusedStructMember", "--check-level=normal")


@pytest.mark.parametrize(("old", "new", "message"), [
    ('enable = ["warning"]\nsuppressions', 'enable = ["warning", "lint"]\nsuppressions',
     rf"{PREFIX}\.enable names an unknown cppcheck check class 'lint'"),
    ("suppressions = []\n", 'suppressions = ["bad id"]\n', rf"{PREFIX}\.suppressions contains an invalid"),
    ('extra_args = ["--check-level=normal"]', 'extra_args = ["--check-level=normal", "--project=/etc/passwd"]',
     rf"{PREFIX}\.extra_args contains a flag outside the allow-list"),
    ("suppressions = []\n", 'suppressions = []\naddons = ["misra"]\n', rf"{PREFIX} has unknown settings: addons"),
], ids=["unknown-class", "malformed-id", "disallowed-flag", "unknown-key"])
def test_recipe_refuses_an_invalid_profile_at_load(tmp_path: Path, old: str, new: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _variant(tmp_path, (old, new))


# ---------------------------------------------------------------- the receipt


def test_execution_receipt_records_the_effective_argv(tmp_path: Path) -> None:
    def runner(argv, timeout):
        if tuple(argv[:3]) == ("docker", "image", "inspect"):
            return CommandOutcome(0, (DIGEST + "\n").encode(), b"")
        return CommandOutcome(0, b"", b"")

    target = tmp_path / "target"
    target.mkdir()
    scratch = tmp_path / "run" / "scratch"
    argv = ("/bin/fixture", "--enable=warning", "--suppress=unusedStructMember", *CPPCHECK_FIXED_ARGS, "/target/a.c")
    result = ContainerExecutor(executor_catalog(tmp_path), tmp_path / "run", runner=runner).execute(
        ExecutionRequest("tool-fixture", argv, target, scratch))
    receipt = json.loads((scratch / "execution.json").read_text(encoding="utf-8"))
    assert tuple(receipt["argv"]) == argv == result.argv
    assert receipt["argv_identity"] == hashlib.sha256(json.dumps(list(argv), separators=(",", ":")).encode()).hexdigest()
