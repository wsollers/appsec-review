from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.config.remediation import RemediationPlanningSettings, RemediationValidationSettings
from appsec_review.jobs.job_remediation_planning.contracts import PlanAnswer
from appsec_review.jobs.job_remediation_planning.patches import (
    PatchError, apply_exact, parse_patch, patched_bytes, relative_path, unsafe_build_changes,
)
from appsec_review.review.models import IntegrityError
from tests import remediation_support as support


@pytest.mark.parametrize("name", ["../x.c", "/tmp/x.c", "C:\\x.c", "x\\y.c", "a/../x.c", "a//b.c",
                                    "./x.c", "file:stream", "con", "aux.h", "a./x.c", "x.c/"])
def test_paths_refuse_cross_platform_escapes(name):
    with pytest.raises(PatchError):
        relative_path(name)


def test_exact_bytes_and_new_file_absence_are_checked_before_any_write(tmp_path):
    text = "void p(char *s) { char b[8]; strcpy(b, s); }\n"
    original = tmp_path / "source.c"
    original.write_text(text, encoding="utf-8")
    digest = hashlib.sha256(original.read_bytes()).hexdigest()
    value = support.patch("source.c", digest, start=text.index("strcpy"))
    value["files"].extend(support.patch("new.h", None, old="", new="#pragma once\n")["files"])
    parsed = parse_patch(value, support.bounds())
    apply_exact(parsed, tmp_path, {"source.c": digest}, support.bounds())
    assert "if (strlen(s) < sizeof b)" in original.read_text()
    assert (tmp_path / "new.h").read_text() == "#pragma once\n"
    with pytest.raises(PatchError, match="absence"):
        patched_bytes(parse_patch(support.patch("new.h", None, old="", new="bad"), support.bounds()),
                      tmp_path, {}, support.bounds())


@pytest.mark.parametrize("mutate", [
    lambda p: p["files"][0].update(before_sha256="b" * 64),
    lambda p: p["files"][0]["edits"][0].update(old="not matching"),
    lambda p: p["files"][0]["edits"][0].update(start=True),
    lambda p: p["files"][0]["edits"][0].update(end=999999),
    lambda p: p["files"].append(deepcopy(p["files"][0])),
    lambda p: p["files"][0].update(absence_proof=True),
    lambda p: p["files"][0]["edits"].append(deepcopy(p["files"][0]["edits"][0])),
    lambda p: p["files"][0]["edits"][0].update(new="strcpy(b, s);"),
    lambda p: p.update(command="patch -p1"),
])
def test_malformed_fuzzy_and_undeclared_edits_fail(tmp_path, mutate):
    original = b"strcpy(b, s);"
    (tmp_path / "source.c").write_bytes(original)
    digest = hashlib.sha256(original).hexdigest()
    value = support.patch("source.c", digest)
    mutate(value)
    with pytest.raises(PatchError):
        parsed = parse_patch(value, support.bounds())
        patched_bytes(parsed, tmp_path, {"source.c": digest}, support.bounds())
    assert (tmp_path / "source.c").read_bytes() == original


def test_modified_accepted_baseline_is_an_integrity_failure(tmp_path):
    (tmp_path / "source.c").write_bytes(b"tampered")
    digest = hashlib.sha256(b"strcpy(b, s);").hexdigest()
    with pytest.raises(IntegrityError, match="baseline changed"):
        patched_bytes(parse_patch(support.patch("source.c", digest), support.bounds()),
                      tmp_path, {"source.c": digest}, support.bounds())


def test_symlink_parent_is_rejected_without_following_it(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "source.c").write_bytes(b"strcpy(b, s);")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    try:
        (workspace / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("host cannot create symlinks")
    digest = hashlib.sha256(b"strcpy(b, s);").hexdigest()
    parsed = parse_patch(support.patch("link/source.c", digest), support.bounds())
    with pytest.raises(IntegrityError, match="symlink"):
        patched_bytes(parsed, workspace, {"link/source.c": digest}, support.bounds())


def test_parent_symlink_policy_is_exercised_even_on_hosts_without_symlink_privilege(tmp_path, monkeypatch):
    (tmp_path / "linked").mkdir()
    (tmp_path / "linked" / "source.c").write_bytes(b"strcpy(b, s);")
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path.name == "linked" or original(path))
    digest = hashlib.sha256(b"strcpy(b, s);").hexdigest()
    parsed = parse_patch(support.patch("linked/source.c", digest), support.bounds())
    with pytest.raises(IntegrityError, match="symlink"):
        patched_bytes(parsed, tmp_path, {"linked/source.c": digest}, support.bounds())


def test_supported_poc_documentation_never_promotes_a_finding_to_remediation_intake():
    from appsec_review.jobs.job_remediation_planning.inputs import confirmed_findings
    confirmed = {"finding_package_id": "finding-confirmed", "claim_id": "claim-confirmed", "state": "confirmed"}
    supported = {"finding_package_id": "finding-supported", "claim_id": "claim-supported", "state": "supported",
                 "poc": {"status": "compile_verified", "runtime_verified": False}}
    review = {"partition": {"confirmed": ["finding-confirmed"], "supported": ["finding-supported"]},
              "packages": [supported, confirmed]}
    assert confirmed_findings(review) == [confirmed]
    with pytest.raises(IntegrityError, match="confirmed partition"):
        confirmed_findings({**review, "partition": {"confirmed": ["finding-supported"], "supported": []}})


@pytest.mark.parametrize("name", ["CMakeLists.txt", "cmake/options.cmake", "build.rs", "setup.py",
                                    ".clangd", "tool.cfg", ".github/build.yml", "x.ps1", "plugin.so"])
def test_executable_build_and_tool_loading_changes_require_manual_validation(name):
    parsed = parse_patch(support.patch(name, "a" * 64), support.bounds())
    assert unsafe_build_changes(parsed) == [name]


def test_writer_output_is_typed_bounded_and_never_promotes_supported():
    value = support.answer(["evrel-1"], support.patch("source.c", "a" * 64))
    assert PlanAnswer.from_mapping(value, support.bounds(), evidence_ids={"evrel-1"}).patch is not None
    for bad in ({"commands": ["make"]}, {**value, "evidence_ids": ["unknown"]},
                {**value, "status": "fixed"}, {**value, "regression_spec": {}},
                {**value, "status": "manual_design_required"}, {**value, "patch": None}):
        with pytest.raises(ValueError):
            PlanAnswer.from_mapping(bad, support.bounds(), evidence_ids={"evrel-1"})


def test_closed_central_settings_and_schema_contracts():
    assert RemediationPlanningSettings.from_mapping(support.planning_settings()).settings_sha256()
    assert RemediationValidationSettings.from_mapping(support.validation_settings()).adapters == ("native_syntax",)
    for table in (support.planning_settings(extra_budget=3), {**support.planning_settings(), "commands": []}):
        with pytest.raises(ValueError):
            RemediationPlanningSettings.from_mapping(table)
    with pytest.raises(ValueError):
        RemediationValidationSettings.from_mapping(support.validation_settings(adapters=["shell"]))
    import jsonschema
    schemas = support.ROOT / "docs" / "schemas" / "remediation"
    for path in schemas.glob("*.schema.json"):
        jsonschema.Draft202012Validator.check_schema(json.loads(path.read_text()))
