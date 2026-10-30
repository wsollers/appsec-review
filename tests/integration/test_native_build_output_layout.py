"""Real-image native build-output classification for CMake FetchContent and Meson wraps.

Each case writes a small synthetic native project into a run-owned target and drives the review
pipeline exactly as a run does: intake, catalog, analysis plan, ``job_project_build`` (real probe
container) and ``job_language_build`` (real build container, the CMake file API query and the
``[build_outputs]`` policy shipped in ``appsec-review.toml``). Only recipe inference is replaced,
and only for Meson; CMake recipes are deterministic from the pipeline.

Cases:

- CMake FetchContent from a local source tarball (``URL``), runnable in the pinned native image.
- CMake FetchContent from a local ``file://`` git repository (``GIT_REPOSITORY``). The repository
  lives inside the target because the build container mounts only the workspace. The pinned
  native image (``containers/buildenv/cpp/Dockerfile``) ships no ``git``, so the case skips until
  the image provides it. A container user that does not own the bind-mounted repository may also
  need git's ``safe.directory``; the case reports that as a build failure, not a skip.
- A Meson wrap subproject served from ``subprojects/packagecache`` (``supply_chain``) beside a
  committed in-house subproject that stays ``target``. The pinned native image ships no ``meson``,
  so the case skips until the image provides it.

Gating mirrors ``tests/integration/test_family_project_builds.py``: a missing Docker daemon or
build image skips; a local image id that differs from the pin fails unless
``APPSEC_REVIEW_BUILDENV_PINS=local``.

Run explicitly:

    python -m pytest tests/integration/test_native_build_output_layout.py --basetemp=test/tmp/<name>
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tomllib
from typing import Any

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime import profiles_from_settings
from appsec_review.inference import ModelResult
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_project_build.job import load_accepted_builds
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.runtime import GraphRunner


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "appsec-review/build-output-dispositions/1"
SUMMARIZED = "dependency-content-summarized:"

FMT_CMAKE = """cmake_minimum_required(VERSION 3.20)
project(fmt CXX)
add_library(fmt STATIC src/format.cc)
target_include_directories(fmt PUBLIC include)
"""
FMT_HEADER = "#pragma once\nint fmt_answer();\n"
FMT_SOURCE = '#include "fmt/format.h"\nint fmt_answer() { return 42; }\n'
APP_SOURCE = '#include "fmt/format.h"\nint main() { return fmt_answer() == 42 ? 0 : 1; }\n'
FMT_FILES = {"CMakeLists.txt": FMT_CMAKE, "include/fmt/format.h": FMT_HEADER, "src/format.cc": FMT_SOURCE}


class RecipeModel:
    """The recipe a build engineer writes for the Meson fixture (the inference stand-in)."""

    def __call__(self, request, *, timeout_seconds: int) -> ModelResult:
        recipes = []
        for unit in request.summary["build_units"]:
            if unit.get("family") != "native" or unit.get("build_system") != "meson":
                continue
            root = str(unit["root"])
            build_dir = "builddir" if root == "." else f"{root}/builddir"
            recipes.append({
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": "native", "source_dir": root, "build_dir": build_dir,
                "system_packages": [], "environment": {},
                "dependency_files": sorted(str(item["path"]) for item in unit["markers"]),
                "configure_commands": [["meson", "setup", "builddir"]],
                "build_commands": [["meson", "compile", "-C", "builddir"]],
                "expected_outputs": [build_dir], "network_required": False,
                "reason": "Meson setup and compile; the wrap is served from subprojects/packagecache."})
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [], "build_recipes": recipes})


def _docker_image_id(tag: str) -> str | None:
    try:
        completed = subprocess.run(["docker", "image", "inspect", tag, "--format", "{{.Id}}"],
                                   capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return completed.stdout.strip() if completed.returncode == 0 else None


def _native_profile():
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    profiles = profiles_from_settings(tomllib.loads(text)["jobs"]["job_project_build"]["settings"]["profiles"])
    return text, profiles["native"]


def _config(tmp_path: Path):
    text, profile = _native_profile()
    local = _docker_image_id(profile.tag)
    if local is None:
        pytest.skip(f"live build image is unavailable: {profile.tag}")
    if local != profile.image_id:
        if os.environ.get("APPSEC_REVIEW_BUILDENV_PINS") != "local":
            pytest.fail(f"{profile.tag} is {local}, not the pinned {profile.image_id}; rebuild it "
                        "from containers/buildenv or update the pin (see containers/buildenv/README.md)")
        text = text.replace(f'image_id = "{profile.image_id}"', f'image_id = "{local}"')
    path = tmp_path / "appsec-review.toml"
    path.write_text(text, encoding="utf-8")
    return load_config(path), profile.tag


def _require_tool(tag: str, tool: str) -> None:
    try:
        completed = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "--entrypoint", "sh", tag, "-c", f"command -v {tool}"],
            capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip(f"cannot probe {tag} for {tool}")
    if completed.returncode != 0:
        pytest.skip(f"the pinned native image ships no {tool}")


def _write(root: Path, files: dict[str, str]) -> None:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")


def _tarball(path: Path, top: str, files: dict[str, str]) -> str:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for relative, content in sorted(files.items()):
            data = content.encode("utf-8")
            info = tarfile.TarInfo(f"{top}/{relative}")
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            archive.addfile(info, io.BytesIO(data))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(buffer.getvalue())
    return hashlib.sha256(buffer.getvalue()).hexdigest()


def _git(*args: str, cwd: Path) -> str:
    environment = {**os.environ, "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
                   "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z"}
    completed = subprocess.run(["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
                                "-c", "init.defaultBranch=main", *args],
                               cwd=cwd, env=environment, capture_output=True, text=True, timeout=60, check=True)
    return completed.stdout.strip()


def _fetchcontent_target(tmp_path: Path, transport: str) -> Path:
    target = tmp_path / "target"
    if transport == "url":
        digest = _tarball(target / "deps" / "fmt-1.0.tar.gz", "fmt-1.0", FMT_FILES)
        declare = (f"FetchContent_Declare(fmt\n  URL ${{CMAKE_CURRENT_SOURCE_DIR}}/deps/fmt-1.0.tar.gz\n"
                   f"  URL_HASH SHA256={digest}\n  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)\n")
    else:
        if shutil.which("git") is None:
            pytest.skip("the host has no git to create the file:// fixture repository")
        work = tmp_path / "fmt-work"
        _write(work, FMT_FILES)
        _git("init", "-q", cwd=work)
        _git("add", "-A", cwd=work)
        _git("commit", "-q", "-m", "fmt 1.0", cwd=work)
        commit = _git("rev-parse", "HEAD", cwd=work)
        bare = target / "third_party" / "fmt.git"
        bare.parent.mkdir(parents=True)
        _git("clone", "-q", "--bare", str(work), str(bare), cwd=tmp_path)
        declare = (f"FetchContent_Declare(fmt\n  GIT_REPOSITORY file://${{CMAKE_CURRENT_SOURCE_DIR}}/third_party/fmt.git\n"
                   f"  GIT_TAG {commit})\n")
    _write(target, {
        "CMakeLists.txt": ("cmake_minimum_required(VERSION 3.24)\nproject(app CXX)\ninclude(FetchContent)\n" +
                           declare + "FetchContent_MakeAvailable(fmt)\n"
                           "add_executable(app main.cpp)\ntarget_link_libraries(app PRIVATE fmt)\n"),
        "main.cpp": APP_SOURCE,
    })
    return target


def _meson_target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    digest = _tarball(target / "subprojects" / "packagecache" / "zdep-1.0.tar.gz", "zdep-1.0", {
        "meson.build": ("project('zdep', 'c')\nzdep_lib = static_library('zdep', 'zdep.c')\n"
                        "zdep_dep = declare_dependency(link_with: zdep_lib, include_directories: '.')\n"),
        "zdep.c": "int zdep_answer(void) { return 40; }\n",
        "zdep.h": "int zdep_answer(void);\n",
    })
    _write(target, {
        "meson.build": ("project('app', 'c')\n"
                        "zdep_dep = subproject('zdep').get_variable('zdep_dep')\n"
                        "inhouse_dep = subproject('inhouse').get_variable('inhouse_dep')\n"
                        "executable('app', 'main.c', dependencies: [zdep_dep, inhouse_dep])\n"),
        "main.c": ('#include "zdep.h"\n#include "inhouse.h"\n'
                   "int main(void) { return zdep_answer() + inhouse_answer() == 42 ? 0 : 1; }\n"),
        "subprojects/zdep.wrap": ("[wrap-file]\ndirectory = zdep-1.0\n"
                                  "source_url = https://example.invalid/zdep-1.0.tar.gz\n"
                                  f"source_filename = zdep-1.0.tar.gz\nsource_hash = {digest}\n"),
        "subprojects/inhouse/meson.build": (
            "project('inhouse', 'c')\ninhouse_lib = static_library('inhouse', 'inhouse.c')\n"
            "inhouse_dep = declare_dependency(link_with: inhouse_lib, include_directories: '.')\n"),
        "subprojects/inhouse/inhouse.c": "int inhouse_answer(void) { return 2; }\n",
        "subprojects/inhouse/inhouse.h": "int inhouse_answer(void);\n",
    })
    return target


def _run(config, target: Path) -> tuple[Path, dict[str, Any]]:
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan(infer=RecipeModel())]).run(
        target_root=target, source_fingerprint=fingerprint)
    run_id = upstream["run_id"]
    GraphRunner(config, [build_projects()]).run(target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    run_root = config.runtime.runs_dir / run_id
    probes = [item for item in load_accepted_builds(run_root)["probe_receipts"] if item["root"] == "."]
    assert len(probes) == 1 and probes[0]["terminal_status"] == "SUCCEEDED", probes
    GraphRunner(config, [build_language()]).run(target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    receipts = [item for item in load_accepted_language_build(run_root)["receipts"]
                if item.get("build_unit_id") == probes[0]["build_unit_id"]]
    assert len(receipts) == 1
    assert receipts[0]["terminal_status"] == "SUCCEEDED", _diagnostics(run_root, receipts[0])
    return run_root, receipts[0]


def _diagnostics(run_root: Path, receipt: dict[str, Any]) -> str:
    lines = [f"status={receipt.get('terminal_status')} gaps={receipt.get('gaps')}"]
    for command in receipt.get("commands", ()):
        for stream in ("stdout", "stderr"):
            identity = command.get(stream)
            if isinstance(identity, dict) and identity.get("path") and (run_root / identity["path"]).is_file():
                lines.append(f"--- command {command.get('ordinal')} {stream}\n" +
                             (run_root / identity["path"]).read_bytes()[-4000:].decode("utf-8", "replace"))
    return "\n".join(lines)


def _manifest(run_root: Path, receipt: dict[str, Any]) -> set[str]:
    document = json.loads((run_root / receipt["workspace_manifest"]["path"]).read_text(encoding="utf-8"))
    return set(document["files"])


def _classified(run_root: Path) -> list[dict[str, Any]]:
    records = [json.loads(line) for line in (run_root / "data" / "logs" / "pipeline.jsonl").read_text(
        encoding="utf-8").splitlines()]
    return [record.get("details", record) for record in records if record["event_type"] == "BUILD_OUTPUT_CLASSIFIED"]


@pytest.mark.parametrize("transport", ["url", "git"])
def test_real_cmake_fetchcontent_dependency_is_supply_chain(tmp_path: Path, transport: str) -> None:
    config, tag = _config(tmp_path)
    if transport == "git":
        _require_tool(tag, "git")
    target = _fetchcontent_target(tmp_path, transport)
    run_root, receipt = _run(config, target)
    detail = _diagnostics(run_root, receipt)

    rows = {row["workspace_path"]: row for row in receipt["artifacts"]}
    assert {path for path, row in rows.items()
            if row["kind"] in {"object", "executable"} and row["analysis_lane"] != "supply_chain"} == {
        "build/CMakeFiles/app.dir/main.cpp.o", "build/app"}, detail
    library = rows["build/_deps/fmt-build/libfmt.a"]
    assert library["analysis_lane"] == "supply_chain" and library["build_output_root"] == "build/_deps/fmt-build"
    assert not any(path.startswith(("build/_deps/fmt-src/", "build/_deps/fmt-subbuild/")) for path in rows)

    document = receipt["build_output_dispositions"]
    assert document["schema"] == SCHEMA
    roots = {root["root"]: root for root in document["roots"]}
    assert {path: root["disposition"] for path, root in roots.items()} == {
        "build/_deps/fmt-build": "supply_chain", "build/_deps/fmt-src": "supply_chain"}, document
    assert roots["build/_deps/fmt-src"]["kept"] == []
    assert "build/_deps/fmt-build/libfmt.a" in roots["build/_deps/fmt-build"]["kept"]
    (excluded,) = document["configured_exclusions"]
    assert excluded["path"] == "build/_deps/fmt-subbuild" and excluded["name"] == "cmake-fetchcontent-subbuild"
    assert excluded["scope"] == "build_outputs" and excluded["files"] > 0
    kinds = {source["kind"] for source in document["layout_sources"]}
    assert {"cmake-cache", "cmake-file-api-codemodel"} <= kinds, document["layout_sources"]

    gaps = receipt["gaps"]
    assert sum(gap.startswith(SUMMARIZED) for gap in gaps) == 1, gaps
    assert not any("fmt-subbuild" in gap or gap.startswith("cmake-file-api-reply-missing:") for gap in gaps), gaps

    manifest = _manifest(run_root, receipt)
    assert {"build/_deps/fmt-src/src/format.cc", "build/_deps/fmt-subbuild/CMakeLists.txt",
            "build/_deps/fmt-build/libfmt.a", "build/app"} <= manifest
    (classified,) = _classified(run_root)
    assert classified["supply_chain_trees"] == 2 and classified["target_rows"] == 1


def test_real_meson_wrap_subproject_is_supply_chain_and_committed_subproject_is_target(tmp_path: Path) -> None:
    config, tag = _config(tmp_path)
    _require_tool(tag, "meson")
    target = _meson_target(tmp_path)
    run_root, receipt = _run(config, target)
    detail = _diagnostics(run_root, receipt)

    rows = {row["workspace_path"]: row for row in receipt["artifacts"]}
    assert rows["builddir/app"]["analysis_lane"] == "target", detail
    wrapped = rows["builddir/subprojects/zdep-1.0/libzdep.a"]
    assert wrapped["analysis_lane"] == "supply_chain"
    assert wrapped["build_output_root"] == "builddir/subprojects/zdep-1.0"
    inhouse = rows["builddir/subprojects/inhouse/libinhouse.a"]
    assert inhouse["analysis_lane"] == "target" and "build_output_root" not in inhouse
    assert not any(path.startswith("subprojects/zdep-1.0/") for path in rows)

    document = receipt["build_output_dispositions"]
    assert document["schema"] == SCHEMA
    dispositions = {root["root"]: root["disposition"] for root in document["roots"]}
    assert dispositions["subprojects/zdep-1.0"] == "supply_chain"
    assert dispositions["builddir/subprojects/zdep-1.0"] == "supply_chain"
    assert not any(path.startswith(("subprojects/inhouse", "builddir/subprojects/inhouse")) and
                   value != "per_file" for path, value in dispositions.items()), document
    assert any(source["kind"].startswith("meson-") for source in document["layout_sources"])
    assert sum(gap.startswith(SUMMARIZED) for gap in receipt["gaps"]) == 1, receipt["gaps"]
    assert {"subprojects/zdep-1.0/zdep.c", "builddir/subprojects/zdep-1.0/libzdep.a"} <= _manifest(run_root, receipt)
