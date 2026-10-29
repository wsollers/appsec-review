"""CodeQL runtime derivation for javascript/TypeScript and python scopes.

These unit tests load the real shipped configuration, plan real javascript/python scopes, and
drive the real job image selection and resolver without Docker: every container-engine boundary
is a fake that fails the test unless it answers a read-only ``docker image inspect``.
"""
from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace

import pytest

from appsec_review.codeql import runtime
from appsec_review.codeql.runtime import (
    IMAGE_SCHEMA, PREINSTALLED_IMAGE_SCHEMA, CodeQLImage, CodeQLImageResolver,
)
from appsec_review.config import load_config
from appsec_review.jobs.job_codeql_analysis import job as codeql_job
from appsec_review.jobs.job_codeql_analysis.planning import build_codeql_plan
from appsec_review.storage import canonical_json


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "appsec-review.toml"
NOMINAL_USER = "10001:10001"
HOST_USER = "1000:1000"
NUMERIC_NON_ROOT = re.compile(r"[1-9][0-9]*:[1-9][0-9]*")
# Synthetic per-run customized node/python images (job_project_build image repair).
CUSTOMIZED = {"node": "sha256:" + "c" * 64, "python": "sha256:" + "d" * 64}
CUSTOMIZED_TAGS = {"node": "appsec-review-project-node:" + "e" * 24,
                   "python": "appsec-review-project-python:" + "f" * 24}


@pytest.fixture(autouse=True)
def _no_processes(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("CodeQL derivation unit tests must not start processes")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(runtime, "native_execution_requested", lambda: False)


def _forbidden_runner(*_args, **_kwargs):
    raise AssertionError("the identity contract must not call the container engine")


@pytest.fixture(scope="module")
def shipped():
    config = load_config(CONFIG, overlay="")
    settings = config.job("job_codeql_analysis").typed_settings
    profiles = config.job("job_project_build").settings["profiles"]
    return SimpleNamespace(config=config, settings=settings, releases=config.review_policy.releases,
                           profiles={name: dict(profiles[name]) for name in ("node", "python")})


def _settings(shipped, policy: str):
    return replace(shipped.settings, preinstalled_undeclared=policy)


def _resolver(shipped, tmp_path, policy: str, runner=_forbidden_runner) -> CodeQLImageResolver:
    return CodeQLImageResolver(repository_root=ROOT, metadata_root=tmp_path / "metadata",
                               settings=_settings(shipped, policy), runner=runner,
                               releases=shipped.releases)


def _derived_identity(shipped, build_image_id: str, user: str) -> str:
    return hashlib.sha256(canonical_json({
        "schema": IMAGE_SCHEMA, "source_image_id": shipped.settings.source_image_id,
        "build_image_id": build_image_id, "runtime_user": user,
        "component_release_id": shipped.releases.values["codeql"],
        "runner_release_id": shipped.releases.values["codeql_runner"],
    })).hexdigest()


def _profile_images(shipped) -> dict[str, tuple[str, str, str]]:
    """Build image id, tag, and receipt user a javascript/python scope would hand the resolver."""
    images = {f"profile-{name}": (value["image_id"], value["tag"], value["user"])
              for name, value in shipped.profiles.items()}
    images.update({f"customized-{name}": (CUSTOMIZED[name], CUSTOMIZED_TAGS[name],
                                          shipped.profiles[name]["user"]) for name in CUSTOMIZED})
    return images


IMAGE_KINDS = ("profile-node", "profile-python", "customized-node", "customized-python")


# --- Shipped configuration facts the derivation relies on ---------------------------------

def test_shipped_config_declares_only_codeql_images_and_numeric_users(shipped):
    settings = shipped.settings
    assert NUMERIC_NON_ROOT.fullmatch(settings.runtime_user)
    declared = {item.build_image_id for item in settings.preinstalled_runtimes}
    assert settings.source_image_id in declared
    for name, profile in shipped.profiles.items():
        assert NUMERIC_NON_ROOT.fullmatch(profile["user"]), name
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", profile["image_id"]), name
        # The fault: node/python environment images carry no preinstalled declaration.
        assert profile["image_id"] not in declared, name
    for image_id in CUSTOMIZED.values():
        assert image_id not in declared
    assert shipped.releases.require("codeql", "codeql_runner") == (True, None)


# --- Derive policy: node/python profile and customized images derive ----------------------

@pytest.mark.parametrize("effective", [HOST_USER, NOMINAL_USER])
@pytest.mark.parametrize("kind", IMAGE_KINDS)
def test_derive_policy_derives_node_and_python_images(shipped, tmp_path, monkeypatch, kind, effective):
    monkeypatch.setattr(runtime, "application_runtime_user", lambda _user: effective)
    image_id, _tag, user = _profile_images(shipped)[kind]
    resolver = _resolver(shipped, tmp_path, "derive")

    assert resolver._preinstalled(build_image_id=image_id, runtime_user=user) is None
    identity = resolver.declared_identity(build_image_id=image_id, runtime_user=user)

    # Derived identity is keyed by the nominal receipt user, never by the host's effective user.
    assert identity == _derived_identity(shipped, image_id, NOMINAL_USER)
    assert identity != _derived_identity(shipped, image_id, HOST_USER)


def test_derived_identities_are_distinct_per_environment_image(shipped, tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "application_runtime_user", lambda _user: HOST_USER)
    resolver = _resolver(shipped, tmp_path, "derive")
    identities = {resolver.declared_identity(build_image_id=image_id, runtime_user=user)
                  for image_id, _tag, user in _profile_images(shipped).values()}
    assert len(identities) == len(IMAGE_KINDS)


# --- Declared source runtime stays preinstalled under both policies ------------------------

@pytest.mark.parametrize("policy", ["fail", "derive"])
def test_source_image_keeps_declared_preinstalled_runtime(shipped, tmp_path, monkeypatch, policy):
    monkeypatch.setattr(runtime, "application_runtime_user", lambda _user: HOST_USER)
    settings = shipped.settings
    resolver = _resolver(shipped, tmp_path, policy)

    selected = resolver._preinstalled(build_image_id=settings.source_image_id,
                                      runtime_user=settings.runtime_user)
    assert selected is not None and selected.build_image_id == settings.source_image_id
    expected = hashlib.sha256(canonical_json({
        "schema": PREINSTALLED_IMAGE_SCHEMA, "source_image_id": settings.source_image_id,
        "build_image_id": settings.source_image_id, "runtime_user": selected.runtime_user,
        "component_release_id": shipped.releases.values["codeql"],
        "runner_release_id": shipped.releases.values["codeql_runner"],
        "preinstalled": asdict(selected),
    })).hexdigest()
    assert resolver.declared_identity(build_image_id=settings.source_image_id,
                                      runtime_user=settings.runtime_user) == expected


@pytest.mark.parametrize("policy", ["fail", "derive"])
def test_declared_source_image_with_other_effective_user_fails_closed(shipped, tmp_path, monkeypatch,
                                                                      policy):
    monkeypatch.setattr(runtime, "application_runtime_user", lambda _user: NOMINAL_USER)
    settings = shipped.settings
    with pytest.raises(ValueError, match=re.escape(
            f"build_image_id={settings.source_image_id}, effective_user={NOMINAL_USER}")):
        _resolver(shipped, tmp_path, policy).declared_identity(
            build_image_id=settings.source_image_id, runtime_user=settings.runtime_user)


# --- Fail policy: undeclared node/python images name image and user ------------------------

@pytest.mark.parametrize("kind", IMAGE_KINDS)
def test_fail_policy_rejects_undeclared_node_and_python_images(shipped, tmp_path, monkeypatch, kind):
    monkeypatch.setattr(runtime, "application_runtime_user", lambda _user: HOST_USER)
    image_id, _tag, user = _profile_images(shipped)[kind]
    assert shipped.settings.preinstalled_undeclared == "fail"
    with pytest.raises(ValueError, match="requires one exact environment/user declaration") as caught:
        _resolver(shipped, tmp_path, "fail").declared_identity(build_image_id=image_id, runtime_user=user)
    assert f"build_image_id={image_id}" in str(caught.value)
    assert f"effective_user={HOST_USER}" in str(caught.value)


# --- Real planning: which image each javascript/python scope uses -------------------------

def _file(path: str) -> dict[str, object]:
    return {"path": path, "sha256": hashlib.sha256(path.encode()).hexdigest(), "size_bytes": 10}


def _receipt(family: str, unit: str, root: str, image_id: str, tag: str, user: str) -> dict[str, object]:
    return {"build_unit_id": unit, "family": family, "root": root, "fingerprint": "f" * 64,
            "terminal_status": "SUCCEEDED", "workspace": {"path": f"data/build/{unit}"},
            "commands": [], "recipe_identity": "r" * 64,
            "image": {"image_tag": tag, "image_id": image_id, "user": user}}


def _plan(shipped, receipts):
    files = [_file("web/src/app.ts"), _file("web/src/util.js"), _file("svc/main.py"),
             _file("tools/loose.js"), _file("scripts/loose.py")]
    return build_codeql_plan(source_fingerprint="s" * 64, files=files, receipts=receipts,
                             supported_extractors=("javascript", "python", "cpp"),
                             source_image_id=shipped.settings.source_image_id)


@pytest.mark.parametrize("variant", ["profile", "customized"])
def test_job_selects_receipt_image_for_none_mode_scopes_and_source_image_otherwise(
        shipped, tmp_path, monkeypatch, variant):
    images = _profile_images(shipped)
    node = images[f"{variant}-node"]
    python = images[f"{variant}-python"]
    receipts = [_receipt("node", "unit-web", "web", *node), _receipt("python", "unit-svc", "svc", *python)]
    plan = _plan(shipped, receipts)
    by_root = {(scope.language, scope.root): scope for scope in plan.scopes}

    web = by_root[("javascript", "web")]
    svc = by_root[("python", "svc")]
    loose_js = by_root[("javascript", "tools")]
    loose_py = by_root[("python", "scripts")]
    assert (web.mode, web.build_unit_id, web.commands_permitted) == ("none", "unit-web", False)
    assert (svc.mode, svc.build_unit_id, svc.commands_permitted) == ("none", "unit-svc", False)
    assert loose_js.build_unit_id is None and loose_py.build_unit_id is None

    calls: list[dict[str, str]] = []

    class Stop(Exception):
        pass

    def capture(_unit, **kwargs):
        calls.append(kwargs)
        raise Stop

    monkeypatch.setattr(codeql_job, "_resolve_image", capture)
    unit = SimpleNamespace(unit_id="unit", job=SimpleNamespace(
        config=SimpleNamespace(typed_settings=_settings(shipped, "derive")),
        review_policy=shipped.config.review_policy, run_root=tmp_path / "run"))
    by_unit = {str(receipt["build_unit_id"]): receipt for receipt in receipts}
    for scope in (web, svc, loose_js, loose_py):
        with pytest.raises(Stop):
            codeql_job._database_one(unit, scope, by_unit)

    settings = shipped.settings
    assert [(call["build_image_id"], call["build_image_tag"], call["runtime_user"]) for call in calls] == [
        (node[0], node[1], node[2]), (python[0], python[1], python[2]),
        (settings.source_image_id, settings.source_image_tag, settings.runtime_user),
        (settings.source_image_id, settings.source_image_tag, settings.runtime_user),
    ]


# --- Real job resolution: derived reuse for node/python, preinstalled for source ----------

class _Events:
    def __init__(self):
        self.records: list[tuple[str, dict]] = []

    def write(self, event_type, **fields):
        self.records.append((event_type, fields))


def _inspect_runner(known: dict[str, str]):
    def run(argv, _timeout):
        argv = tuple(argv)
        if argv[:3] != ("docker", "image", "inspect") or argv[4:] != ("--format", "{{.Id}}"):
            raise AssertionError(f"unexpected container-engine call: {argv}")
        value = known.get(argv[3])
        return (0, value.encode() + b"\n", b"", False) if value else (1, b"", b"missing", False)
    return run


def _unit(shipped, tmp_path, settings, events):
    return SimpleNamespace(unit_id="unit", job=SimpleNamespace(
        config=SimpleNamespace(typed_settings=settings), review_policy=shipped.config.review_policy,
        repository_root=ROOT, metadata_root=tmp_path / "metadata", events=events))


@pytest.mark.parametrize("kind", IMAGE_KINDS)
def test_real_job_resolution_reuses_derived_node_and_python_image(shipped, tmp_path, monkeypatch, kind):
    monkeypatch.setattr(runtime, "application_runtime_user", lambda _user: HOST_USER)
    settings = _settings(shipped, "derive")
    image_id, tag, user = _profile_images(shipped)[kind]
    identity = _derived_identity(shipped, image_id, user)
    derived_tag = f"appsec-review-codeql:{identity[:24]}"
    derived_id = "sha256:" + hashlib.sha256(identity.encode()).hexdigest()
    manifest = tmp_path / "metadata" / "codeql-images" / identity / "manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps(asdict(CodeQLImage(
        IMAGE_SCHEMA, identity, settings.source_image_id, image_id, tag, derived_id, derived_tag, user,
        shipped.releases.values["codeql"], shipped.releases.values["codeql_runner"], False,
        manifest.relative_to(tmp_path / "metadata").as_posix(), image_build_performed=True))))
    monkeypatch.setattr(runtime, "_run", _inspect_runner({
        settings.source_image_tag: settings.source_image_id, tag: image_id, derived_tag: derived_id}))
    events = _Events()

    image, _stdout, _stderr = codeql_job._resolve_image(
        _unit(shipped, tmp_path, settings, events), build_image_tag=tag, build_image_id=image_id,
        runtime_user=user, scope_id="codeql-unit-" + "a" * 24)

    assert (image.preinstalled, image.reused, image.image_build_performed) == (False, True, False)
    assert (image.image_id, image.build_image_id, image.runtime_user) == (derived_id, image_id, NOMINAL_USER)
    assert image.runner_source == "image"
    resolved = [fields for name, fields in events.records if name == "CODEQL_RUNTIME_RESOLVED"]
    assert len(resolved) == 1
    assert resolved[0]["preparation_kind"] == "derived"
    assert resolved[0]["build_image_id"] == image_id
    assert resolved[0]["requested_runtime_user"] == NOMINAL_USER


def test_real_job_resolution_keeps_preinstalled_source_runtime_under_derive(shipped, tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "application_runtime_user", lambda _user: HOST_USER)
    settings = _settings(shipped, "derive")
    declared = next(item for item in settings.preinstalled_runtimes
                    if item.build_image_id == settings.source_image_id)
    monkeypatch.setattr(runtime, "_run", _inspect_runner({
        settings.source_image_tag: settings.source_image_id,
        declared.runtime_image_id: declared.runtime_image_id}))
    events = _Events()

    image, _stdout, _stderr = codeql_job._resolve_image(
        _unit(shipped, tmp_path, settings, events), build_image_tag=settings.source_image_tag,
        build_image_id=settings.source_image_id, runtime_user=settings.runtime_user)

    assert image.preinstalled and image.image_build_performed is False
    assert (image.image_id, image.runtime_user) == (declared.runtime_image_id, declared.runtime_user)
    resolved = [fields for name, fields in events.records if name == "CODEQL_RUNTIME_RESOLVED"]
    assert [fields["preparation_kind"] for fields in resolved] == ["preinstalled"]


def test_real_job_resolution_fail_policy_names_customized_python_image(shipped, tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "application_runtime_user", lambda _user: HOST_USER)
    settings = _settings(shipped, "fail")
    monkeypatch.setattr(runtime, "_run", _forbidden_runner)
    with pytest.raises(ValueError, match=re.escape(
            f"build_image_id={CUSTOMIZED['python']}, effective_user={HOST_USER}")):
        codeql_job._resolve_image(
            _unit(shipped, tmp_path, settings, _Events()), build_image_tag=CUSTOMIZED_TAGS["python"],
            build_image_id=CUSTOMIZED["python"], runtime_user=NOMINAL_USER)


# --- Static compatibility of the derived CodeQL layer with node/python images -------------

def _instructions(path: Path) -> list[tuple[str, str]]:
    text = path.read_text(encoding="utf-8").replace("\\\n", " ")
    values = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            keyword, _, rest = line.partition(" ")
            values.append((keyword.upper(), rest.strip()))
    return values


@pytest.mark.parametrize("name", ["Dockerfile", "Dockerfile.source"])
def test_derived_layer_runs_as_numeric_non_root_in_scratch_and_keeps_base_path(name):
    instructions = _instructions(ROOT / "containers" / "tools" / "codeql" / name)
    keywords = [keyword for keyword, _ in instructions]
    users = [value for keyword, value in instructions if keyword == "USER"]
    assert users == ["0:0", "${RUNTIME_USER}"]
    first_root = keywords.index("USER")
    assert all(keywords.index(keyword) > first_root for keyword in ("COPY", "RUN"))
    assert ("ARG", "RUNTIME_USER=10001:10001") in instructions
    assert ("ENV", "PATH=/opt/codeql:${PATH}") in instructions
    assert instructions[-2:] == [("USER", "${RUNTIME_USER}"), ("WORKDIR", "/scratch")]
    assert "SHELL" not in keywords and "ENTRYPOINT" not in keywords
    run = next(value for keyword, value in instructions if keyword == "RUN")
    # Shell-form RUN needs /bin/sh and coreutils chmod in the base build image.
    assert not run.startswith("[") and run.startswith("chmod ")
    if name == "Dockerfile":
        assert instructions[3] == ("FROM", "${BUILD_IMAGE}")


def _chain(context: str) -> list[list[tuple[str, str]]]:
    tags = {"appsec-review/buildenv-native-toolchain:noble-gcc13.3-clang18.1": "buildenv/native-toolchain",
            "appsec-review/base-ubuntu:24.04": "bases/ubuntu"}
    chain = []
    while True:
        instructions = _instructions(ROOT / "containers" / context / "Dockerfile")
        chain.append(instructions)
        parent = next(value for keyword, value in instructions if keyword == "FROM")
        if parent not in tags:
            return chain + [[("FROM", parent)]]
        context = tags[parent]


@pytest.mark.parametrize("context", ["buildenv/typescript", "buildenv/python"])
def test_node_and_python_build_images_are_glibc_ubuntu_with_numeric_user(context):
    chain = _chain(context)
    upstream = chain[-1][0][1]
    assert re.fullmatch(r"ubuntu:24\.04@sha256:[0-9a-f]{64}", upstream)
    assert "alpine" not in upstream and "musl" not in upstream
    for instructions in chain[:-1]:
        joined = " ".join(value for _, value in instructions).lower()
        assert "alpine" not in joined and "musl" not in joined and "apk " not in joined
        assert [value for keyword, value in instructions if keyword == "USER"][-1] == "10001:10001"
        assert "SHELL" not in [keyword for keyword, _ in instructions]
    native = _instructions(ROOT / "containers" / "buildenv" / "native-toolchain" / "Dockerfile")
    assert any(keyword == "RUN" and "/scratch" in value and "chown 10001:10001" in value
               for keyword, value in native)


def test_native_toolchain_pins_shell_coreutils_and_python3_for_the_runner_entrypoint():
    lock = (ROOT / "containers" / "buildenv" / "native-toolchain" / "packages.lock").read_text(encoding="utf-8")
    pinned = {line.split("=", 1)[0] for line in lock.splitlines() if "=" in line and not line.startswith("#")}
    assert {"bash", "coreutils", "python3"} <= pinned
    runner = (ROOT / "containers" / "tools" / "codeql" / "codeql_runner.py").read_text(encoding="utf-8")
    assert runner.startswith("#!/usr/bin/env python3\n")


def test_node_image_puts_glibc_node_on_an_absolute_path():
    instructions = _instructions(ROOT / "containers" / "buildenv" / "typescript" / "Dockerfile")
    run = " ".join(value for keyword, value in instructions if keyword == "RUN")
    assert "node-v22.23.3-linux-x64.tar.gz" in run and "linux-x64-musl" not in run
    env = " ".join(value for keyword, value in instructions if keyword == "ENV")
    path = re.search(r"PATH=(\S+)", env).group(1)
    # The derived layer prepends /opt/codeql to this PATH, so the TypeScript extractor finds node.
    assert path.split(":")[0] == "/opt/node/bin" and "/usr/bin" in path.split(":")


def test_codeql_source_image_has_no_node_runtime_for_source_only_typescript():
    """Documents a gap: source-only javascript scopes run on the CodeQL source image."""
    tool = ROOT / "containers" / "tools" / "codeql"
    sources = [path for path in tool.iterdir() if path.name.startswith("Dockerfile.")]
    text = " ".join(path.read_text(encoding="utf-8") for path in sources)
    assert "Dockerfile.source" in {path.name for path in sources}
    assert "/opt/node" not in text and "nodejs" not in text
