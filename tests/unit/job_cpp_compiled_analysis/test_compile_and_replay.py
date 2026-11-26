from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import pytest

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import inventory, source_fingerprint
from appsec_review.jobs.job_cpp_compiled_analysis import PROJECT_TASKS, build_job
from appsec_review.jobs.job_cpp_compiled_analysis.job import (
    _infer_compile_database,
    _load_ast_document,
    _project_key,
    normalize_compile_db,
    normalize_link_commands,
    replay_failures,
)
from appsec_review.runtime import plan_jobs


ROOT = Path(__file__).resolve().parents[3]


def _native_driver(tmp_path):
    spec = importlib.util.spec_from_file_location("native_cpp_outcomes", ROOT / "containers/tools/native-cpp/native.py")
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    driver.ROOT, driver.SOURCE, driver.BUILD, driver.OUT = (
        tmp_path, tmp_path / "source", tmp_path / "build", tmp_path / "analysis")
    driver.SOURCE.mkdir()
    driver.BUILD.mkdir()
    return driver


def test_whole_program_native_ast_is_not_filtered_by_source_display_names(tmp_path, monkeypatch):
    from types import SimpleNamespace
    driver = _native_driver(tmp_path)
    source = driver.SOURCE / "unit.cpp"
    source.write_text("namespace one { int left() { return 1; } }\n"
                      "namespace two { int right() { return 2; } }\nint main() { return 0; }\n")
    (tmp_path / "normalized-compile-commands.json").write_text(json.dumps([
        {"file": str(source), "directory": str(driver.BUILD), "arguments": ["clang++-18", str(source)]}]))
    calls = []

    def execute(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=b'{"kind":"TranslationUnitDecl","inner":[]}', stderr=b"")

    monkeypatch.setattr(driver.subprocess, "run", execute)
    assert driver.replay("ast") == 0
    assert len(calls) == 1
    assert "-ast-dump-filter" not in calls[0][0]
    assert calls[0][1]["cwd"] == driver.BUILD


@pytest.mark.parametrize("exit_code", [0, 1])
def test_native_symbol_subcommand_outcomes_reach_the_real_normalizer(tmp_path, monkeypatch, exit_code):
    from types import SimpleNamespace
    from appsec_review.jobs.job_cpp_compiled_analysis import job
    from tests.unit.job_cpp_compiled_analysis.test_job_pipeline import _make_unit

    unit = _make_unit(tmp_path / "unit", "binary.projects", repository_root=tmp_path / "repo")
    case = job._case_root(unit, "case")
    case.mkdir(parents=True)
    driver = _native_driver(case)
    artifact = driver.BUILD / "unit.o"
    artifact.write_bytes(b"fake object bytes")
    monkeypatch.setattr(driver.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=exit_code, stdout=b"", stderr=b"file format not recognized" if exit_code else b""))
    code = driver.symbols()
    records_path = driver.OUT / "binary/records.json"
    records = json.loads(records_path.read_text())
    catalog = {"mapping": {"project_id": "project", "case_snapshot": "a" * 64},
               "artifact_catalog": job._artifact(unit.job.run_root, artifact),
               "outputs": [{"path": "build/unit.o", "sha256": job.file_sha256(artifact), "kind": "object"}]}
    execution = {"execution": job._artifact(unit.job.run_root, records_path), "image_id": "fake", "exit_code": code}
    result = job._binary_index(unit, "case", catalog, execution)
    assert records[0]["tools"]["nm"]["exit_code"] == exit_code
    assert records[0]["tools"]["readelf"]["exit_code"] == exit_code
    assert result["symbol_count"] == 0
    if exit_code:
        assert code != 0
        assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
        assert any("nm" in gap and "file format" in gap for gap in result["gaps"])
        assert result["checkpointable"] is False
    else:
        assert code == 0
        assert result["terminal_status"] == "SUCCEEDED" and not result["gaps"]


@pytest.mark.parametrize("project", [".", "app"])
def test_normalized_context_uses_exact_recipe_paths_and_command_directory(tmp_path, project):
    from appsec_review.jobs.cpp_index_scopes import container_compile_database
    prefix = "" if project == "." else project + "/"
    build_dir = prefix + "out"
    (tmp_path / "build").mkdir()
    commands = [{"directory": f"/workspace/{build_dir}/sub", "file": "../../src/a.cpp",
                 "arguments": ["g++", "-I../../include", "-I../generated", "-include", "../config.h",
                               "-I/workspace/app-other/inc", "-DNAME=/workspace/app",
                               "-c", "../../src/a.cpp", "-o", "a.o"]}]
    (tmp_path / "build/compile_commands.json").write_text(json.dumps(commands))
    mapping = {"project_key": "p", "project_id": "p", "root": project, "source_dir": project,
               "build_dir": build_dir, "case_snapshot": "a" * 64, "files": [{
                   "scratch_path": "source/src/a.cpp", "target_path": prefix + "src/a.cpp", "sha256": "b" * 64}]}
    rows = normalize_compile_db(tmp_path, mapping)
    assert rows[0]["directory"] == "/scratch/build/sub"
    assert rows[0]["file"] == "/scratch/source/src/a.cpp"
    assert rows[0]["output_path"] == "build/sub/a.o"
    assert "-I/scratch/source/include" in rows[0]["arguments"]
    assert "-I/scratch/build/generated" in rows[0]["arguments"]
    assert "/scratch/build/config.h" in rows[0]["arguments"]
    assert "-DNAME=/workspace/app" in rows[0]["arguments"]
    if project == "app":
        assert "-I/workspace/app-other/inc" in rows[0]["arguments"]
    mounted = container_compile_database(project, rows)[0]
    assert mounted["directory"] == "/target/build/sub"
    assert "-I/target/build/generated" in mounted["arguments"]
    assert mounted["file"] == "/target/source/src/a.cpp"


@pytest.mark.parametrize("directory", ["/unaccepted", "relative-unaccepted"],
                         ids=["foreign-directory", "relative-directory"])
def test_compile_source_with_matching_display_suffix_is_not_admitted(tmp_path, directory):
    (tmp_path / "build").mkdir()
    (tmp_path / "build/compile_commands.json").write_text(json.dumps([{
        "directory": directory, "file": "/unaccepted/main.cpp", "arguments": ["cc", "-c", "main.cpp"]}]))
    mapping = {"project_key": "p", "project_id": "p", "root": "app", "case_snapshot": "a" * 64,
               "files": [{"scratch_path": "source/main.cpp", "target_path": "app/main.cpp", "sha256": "b" * 64}]}
    with pytest.raises(ValueError, match="accepted"):
        normalize_compile_db(tmp_path, mapping)


def _project(target: Path, relative: str, *, library: bool) -> str:
    root = target / Path(*PurePosixPath(relative).parts)
    root.mkdir(parents=True)
    (root / "main.cpp").write_text(
        "extern int helper(); int main() { return helper(); }\n" if library else
        "int main() { return 0; }\n", encoding="utf-8")
    if library:
        (root / "helper.cpp").write_text("int helper() { return 0; }\n", encoding="utf-8")
        body = (
            "add_library(helper STATIC helper.cpp)\n"
            "add_executable(observer main.cpp)\n"
            "target_link_libraries(observer PRIVATE helper)\n"
        )
    else:
        body = "add_executable(observer main.cpp)\n"
    (root / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.20)\nproject(sample LANGUAGES CXX)\n" + body,
        encoding="utf-8")
    return _project_key(PurePosixPath(relative))


def _target(root: Path) -> tuple[Path, tuple[str, str]]:
    target = root / "target"
    first = _project(target, "projects/native/alpha", library=True)
    second = _project(target, "projects/examples/beta", library=False)
    return target, (first, second)


def _fixture(tmp_path: Path):
    shutil.copy2(ROOT / "appsec-review.toml", tmp_path / "appsec-review.toml")
    target, keys = _target(tmp_path)
    return load_config(tmp_path / "appsec-review.toml"), target, keys


def test_compile_database_normalization_preserves_only_reviewed_build_semantics(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / "build").mkdir(parents=True)
    (root / "source").mkdir()
    (root / "source" / "main.cpp").write_text("int main(){}\n", encoding="utf-8")
    (root / "build" / "compile_commands.json").write_text(json.dumps([{
        "directory": str(root / "build"), "file": str(root / "source" / "main.cpp"),
        "command": f"c++ -DVALUE=1 -I{root / 'source'} -std=c++20 -c {root / 'source' / 'main.cpp'} -o x.o",
    }, {
        "directory": str(root / "build"), "file": str(root / "source" / "main.cpp"),
        "arguments": ["clang++-18", "-cc1", "-emit-obj", str(root / "source" / "main.cpp")],
    }]), encoding="utf-8")
    source_sha = hashlib.sha256((root / "source" / "main.cpp").read_bytes()).hexdigest()
    rows = normalize_compile_db(root, {"project_key": "project-a", "project_id": "cpp:projects/native/a",
        "case_snapshot": "a" * 64, "root": "projects/native/a", "files": [{
            "target_path": "projects/native/a/main.cpp", "scratch_path": "source/main.cpp",
            "sha256": source_sha,
        }]})
    assert rows[0]["target_path"] == "projects/native/a/main.cpp"
    assert rows[0]["project_key"] == "project-a"
    assert rows[0]["arguments"][0] == "clang++-18"
    assert "-DVALUE=1" in rows[0]["arguments"] and "-std=c++20" in rows[0]["arguments"]
    assert "-c" not in rows[0]["arguments"] and "-o" not in rows[0]["arguments"]
    assert rows[0]["output_path"] == "build/x.o"
    assert len(rows) == 1


def test_infer_compile_database_uses_stable_read_only_container_paths() -> None:
    value = _infer_compile_database({
        "mapping": {"root": "projects/native/a"},
        "compile_commands": [{
            "target_path": "projects/native/a/main.cpp",
            "arguments": ["clang++-18", "-I/scratch/source/include", "-std=c++20",
                          "/scratch/source/main.cpp"],
        }],
    })
    assert value == [{
        "directory": "/target/source",
        "file": "/target/source/main.cpp",
        "arguments": ["clang++", "-I/target/source/include", "-std=c++20",
                      "/target/source/main.cpp"],
    }]


def test_clang_ast_loader_accepts_bounded_concatenated_declarations(tmp_path: Path) -> None:
    path = tmp_path / "ast.json"
    path.write_text('{"kind":"FunctionDecl","name":"first"}\n'
                    '{"kind":"FunctionDecl","name":"second"}\n', encoding="utf-8")
    document = _load_ast_document(path)
    assert document["kind"] == "TranslationUnitDecl"
    assert [item["name"] for item in document["inner"]] == ["first", "second"]


def test_snapshot_identity_covers_catalog_excluded_bytes(tmp_path: Path) -> None:
    from appsec_review.config.exclusions import ExclusionRule, PathExclusions

    target = tmp_path / "target"
    (target / "vendor").mkdir(parents=True)
    (target / "main.cpp").write_text("int main() {}\n", encoding="utf-8")
    vendored = target / "vendor" / "dependency.cpp"
    vendored.write_text("int dependency() { return 1; }\n", encoding="utf-8")
    before = inventory(target, exclusions=PathExclusions((ExclusionRule("vendor/", "global"),)))
    assert not any(item["path"].startswith("vendor/") for item in before["files"])
    first = source_fingerprint(target)
    vendored.write_text("int dependency() { return 2; }\n", encoding="utf-8")
    assert first != source_fingerprint(target)


def test_native_link_receipts_include_versioned_archiver_without_self_links(tmp_path: Path) -> None:
    source = ROOT / "containers" / "tools" / "native-cpp" / "native.py"
    spec = importlib.util.spec_from_file_location("native_cpp_driver", source)
    assert spec and spec.loader
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    build = tmp_path / "build"
    links = build / "CMakeFiles" / "core.dir"
    links.mkdir(parents=True)
    (links / "link.txt").write_text(
        "/usr/bin/llvm-ar-18 qc libcore.a CMakeFiles/core.dir/unit.o\n", encoding="utf-8")
    driver.ROOT = tmp_path
    driver.BUILD = build
    driver.emit_link_commands()
    receipts = json.loads((build / "link-commands.json").read_text(encoding="utf-8"))
    assert receipts[0]["output_path"] == "build/libcore.a"
    assert receipts[0]["input_paths"] == ["build/CMakeFiles/core.dir/unit.o"]

    (links / "link.txt").write_text(
        "clang++ -shared -Wl,-soname,libcore.so CMakeFiles/core.dir/unit.o -o libcore.so\n",
        encoding="utf-8")
    driver.emit_link_commands()
    receipts = json.loads((build / "link-commands.json").read_text(encoding="utf-8"))
    assert receipts[0]["output_path"] == "build/libcore.so"
    assert receipts[0]["input_paths"] == ["build/CMakeFiles/core.dir/unit.o"]


def test_link_normalization_keeps_only_cataloged_artifact_edges() -> None:
    outputs = [
        {"path": "build/unit.o", "kind": "object"},
        {"path": "build/libcore.so", "kind": "library"},
    ]
    assert normalize_link_commands([{
        "output_path": "build/libcore.so",
        "input_paths": ["build/-Wl,-soname,libcore.so", "build/unit.o", "build/unit.o"],
        "receipt": "CMakeFiles/core.dir/link.txt",
        "command_sha256": "a" * 64,
    }], outputs) == [{
        "output_path": "build/libcore.so",
        "input_paths": ["build/unit.o"],
        "receipt": "CMakeFiles/core.dir/link.txt",
        "command_sha256": "a" * 64,
    }]


def test_cpp_job_graph_is_project_batched_and_repository_independent(tmp_path: Path) -> None:
    config, _, _ = _fixture(tmp_path)
    job = build_job(executor_factory=lambda unit: None)
    plan = plan_jobs((job,), config)
    assert PROJECT_TASKS == ("projects",)
    assert len(job.units) == 9
    assert plan.node("job_cpp_compiled_analysis.ast.projects").dependencies == (
        "job_cpp_compiled_analysis.catalog.projects", "job_cpp_compiled_analysis.ir.projects")
    assert plan.node("job_cpp_compiled_analysis.ir.projects").dependencies == (
        "job_cpp_compiled_analysis.catalog.projects",)
    assert plan.node("job_cpp_compiled_analysis.infer.projects").dependencies == (
        "job_cpp_compiled_analysis.catalog.projects",)
    final = plan.node("job_cpp_compiled_analysis.acceptance.publish_handoff")
    assert len(final.dependencies) == 5
    assert not any("case001" in node.node_id for node in plan.nodes)
    assert not any(node.node_id.endswith(("configure.projects", "compile.projects")) for node in plan.nodes)


def test_infer_failure_is_a_project_scoped_gap() -> None:
    source = (ROOT / "src" / "appsec_review" / "jobs" / "job_cpp_compiled_analysis" / "job.py").read_text()
    assert "load_accepted_language_build" in source
    assert "load_accepted_plan(unit.job.run_root)" not in source


def test_project_failure_is_scoped_and_retry_reuses_other_checkpoints(tmp_path: Path) -> None:
    config, _, _ = _fixture(tmp_path)
    job = build_job(executor_factory=lambda unit: None)
    assert {unit.unit_id for unit in job.units}.isdisjoint({"configure.projects", "compile.projects"})
    assert config.job("job_cpp_compiled_analysis").steps.keys().isdisjoint({"configure", "compile"})


@pytest.mark.parametrize("stage,tool", (("catalog", "tool-native-cpp"), ("branch-infer", "tool-infer")))
@pytest.mark.parametrize("mode", ("strict", "first_party_managed"))
def test_cpp_checkpoint_requires_declared_platform_releases(tmp_path, stage, tool, mode):
    from dataclasses import replace
    from types import SimpleNamespace
    from appsec_review.config.assurance import AssuranceMode, ComponentReleases, ReviewPolicy
    from appsec_review.jobs.job_cpp_compiled_analysis.job import (
        _checkpoint_identity, _load_checkpoint, _save_checkpoint,
    )
    policy = ReviewPolicy(mode=AssuranceMode(mode), project_id="fixture",
                          approved_first_party_projects=("fixture",), target_root=str(tmp_path),
                          custody="application_private_v1")
    events = []
    unit = SimpleNamespace(job=SimpleNamespace(
        run_root=tmp_path, repository_root=tmp_path, attempt_id="attempt_0001", review_policy=policy,
        events=SimpleNamespace(write=lambda event, **details: events.append((event, details)))))
    identity = _checkpoint_identity(unit, "fixture", stage, {}, tool_id=tool)
    _save_checkpoint(unit, "fixture", stage, identity, {"terminal_status": "SUCCEEDED"})
    assert _load_checkpoint(unit, "fixture", stage, identity) is None
    assert events[-1][1]["reason"] == "missing_release_identity"
    unit.job.review_policy = replace(policy, releases=ComponentReleases(
        {"platform": "fixture/1", "validation": "fixture/1", tool: "fixture/1"}))
    declared_identity = _checkpoint_identity(unit, "fixture", stage, {}, tool_id=tool)
    assert declared_identity != identity
    assert _load_checkpoint(unit, "fixture", stage, declared_identity) is None
    _save_checkpoint(unit, "fixture", stage, declared_identity, {"terminal_status": "SUCCEEDED"})
    assert _load_checkpoint(unit, "fixture", stage, declared_identity)["checkpoint_reused"]


PHP_INCLUDES = ["/usr/include/php/20230831", "/usr/include/php/20230831/main",
                "/usr/include/php/20230831/TSRM", "/usr/include/php/20230831/Zend",
                "/usr/include/php/20230831/ext", "/usr/include/php/20230831/ext/date/lib"]
PYTHON_INCLUDES = ["/usr/include/python3.12"]
FAKE_CLANG = r'''
import json, re, sys
from pathlib import Path
SCRATCH, IMAGE = Path(sys.argv[1]), Path(sys.argv[2])
argv = sys.argv[3:]
def host(value):
    if value.startswith("/scratch/"):
        return SCRATCH / value[len("/scratch/"):]
    return IMAGE / value.lstrip("/") if value.startswith("/") else SCRATCH / "source" / value
dirs, output, index = [], None, 0
while index < len(argv):
    value = argv[index]
    if value in {"-I", "-isystem"}:
        dirs.append(host(argv[index + 1])); index += 2; continue
    for flag in ("-isystem", "-I"):
        if value.startswith(flag) and len(value) > len(flag):
            dirs.append(host(value[len(flag):])); break
    if value == "-o":
        output = argv[index + 1]; index += 2; continue
    index += 1
source = [value for value in argv if value.endswith(".c")][-1]
for name in re.findall(r'#include\s*[<"]([^>"]+)[>"]', host(source).read_text()):
    if not any((directory / name).is_file() for directory in [host(source).parent, *dirs]):
        sys.stderr.write(f"{source}:1:10: fatal error: '{name}' file not found\n")
        sys.exit(1)
if output:
    Path(output).write_text("define i32 @ext_entry() {\nentry:\n  ret i32 0\n}\n")
else:
    print(json.dumps({"kind": "TranslationUnitDecl", "inner": [
        {"id": "0x1", "kind": "FunctionDecl", "name": "ext_entry", "loc": {"line": 2, "col": 1}}]}))
'''


def _extension_rows(scratch: Path) -> list[dict]:
    """Normalize one captured phpize compile and one captured setuptools compile."""
    source = scratch / "source"
    (source / "src").mkdir(parents=True)
    (source / "php_sample.c").write_text('#include "php.h"\n#include "ext/standard/info.h"\n'
                                         "int ext_entry(void) { return 0; }\n", encoding="utf-8")
    (source / "src" / "fast.c").write_text("#include <Python.h>\nint ext_entry(void) { return 0; }\n",
                                           encoding="utf-8")
    (scratch / "build").mkdir()
    root = "ext/sample"
    php_argv = ["cc", "-I.", "-I/workspace/ext/sample", "-DPHP_ATOM_INC",
                "-I/workspace/ext/sample/include", "-I/workspace/ext/sample/main",
                *[f"-I{path}" for path in PHP_INCLUDES[:-1]], "-isystem", PHP_INCLUDES[-1],
                "-DHAVE_CONFIG_H", "-g", "-O2", "-c", "/workspace/ext/sample/php_sample.c",
                "-fPIC", "-DPIC", "-o", ".libs/php_sample.o"]
    python_argv = ["x86_64-linux-gnu-gcc", "-fno-strict-overflow", "-DNDEBUG", "-g", "-O2", "-fPIC",
                   f"-I{PYTHON_INCLUDES[0]}", "-c", "/workspace/ext/sample/src/fast.c",
                   "-o", "build/temp.linux-x86_64-cpython-312/src/fast.o"]
    (scratch / "build" / "compile_commands.json").write_text(json.dumps([
        {"directory": "/workspace/ext/sample", "file": "/workspace/ext/sample/php_sample.c",
         "arguments": php_argv},
        {"directory": "/workspace/ext/sample", "file": "/workspace/ext/sample/src/fast.c",
         "arguments": python_argv},
    ]), encoding="utf-8")
    files = [{"target_path": f"{root}/{name}", "scratch_path": f"source/{name}",
              "sha256": hashlib.sha256((source / name).read_bytes()).hexdigest()}
             for name in ("php_sample.c", "src/fast.c")]
    return normalize_compile_db(scratch, {"project_key": "unit-ext", "project_id": f"cpp:{root}",
                                          "case_snapshot": "c" * 64, "root": root, "files": files})


def _image(root: Path, *, php: bool, python: bool) -> Path:
    """A stand-in for the replay image's filesystem with the dev headers it carries."""
    root.mkdir(parents=True, exist_ok=True)
    if php:
        for directory in PHP_INCLUDES:
            (root / directory.lstrip("/")).mkdir(parents=True, exist_ok=True)
        (root / PHP_INCLUDES[1].lstrip("/") / "php.h").write_text("", encoding="utf-8")
        (root / PHP_INCLUDES[0].lstrip("/") / "ext" / "standard").mkdir(parents=True, exist_ok=True)
        (root / PHP_INCLUDES[0].lstrip("/") / "ext" / "standard" / "info.h").write_text("")
    if python:
        (root / PYTHON_INCLUDES[0].lstrip("/")).mkdir(parents=True, exist_ok=True)
        (root / PYTHON_INCLUDES[0].lstrip("/") / "Python.h").write_text("", encoding="utf-8")
    return root


def _replay(tmp_path: Path, scratch: Path, rows: list[dict], image: Path, mode: str) -> int:
    source = ROOT / "containers" / "tools" / "native-cpp" / "native.py"
    spec = importlib.util.spec_from_file_location("native_cpp_replay", source)
    assert spec and spec.loader
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    driver.ROOT, driver.SOURCE, driver.OUT = scratch, scratch / "source", scratch / "analysis"
    clang = tmp_path / "fake-clang.py"
    clang.write_text(FAKE_CLANG, encoding="utf-8")
    wrapper = tmp_path / "fake-clang"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{clang}" "{scratch}" "{image}" "$@"\n',
                       encoding="utf-8")
    wrapper.chmod(0o755)
    replayed = [{**row, "arguments": [str(wrapper), *row["arguments"][1:]],
                 "directory": str(scratch / Path(row["directory"]).relative_to("/scratch"))} for row in rows]
    (scratch / "normalized-compile-commands.json").write_text(json.dumps(replayed), encoding="utf-8")
    return driver.replay(mode)


def test_php_and_python_extension_include_paths_reach_the_replay_unchanged(tmp_path: Path) -> None:
    rows = _extension_rows(tmp_path / "scratch")
    php, python = rows
    assert php["target_path"] == "ext/sample/php_sample.c"
    assert python["target_path"] == "ext/sample/src/fast.c"
    assert php["arguments"][0] == "clang-18" and python["arguments"][0] == "clang-18"
    assert [value for value in php["arguments"] if value.startswith("-I/usr/include/")] == [
        f"-I{path}" for path in PHP_INCLUDES[:-1]]
    assert php["arguments"][php["arguments"].index("-isystem") + 1] == PHP_INCLUDES[-1]
    assert "-I/scratch/source/include" in php["arguments"] and "-I/scratch/source" in php["arguments"]
    assert not any("/workspace/" in value for row in rows for value in row["arguments"])
    assert f"-I{PYTHON_INCLUDES[0]}" in python["arguments"]
    assert python["arguments"][-1] == "/scratch/source/src/fast.c"


def test_joined_system_include_forms_are_retained_for_replay(tmp_path: Path) -> None:
    root = tmp_path / "scratch"
    (root / "source").mkdir(parents=True)
    (root / "build").mkdir()
    (root / "source" / "a.c").write_text("int a;\n", encoding="utf-8")
    (root / "build" / "compile_commands.json").write_text(json.dumps([{
        "directory": "/workspace/lib", "file": "/workspace/lib/a.c",
        "arguments": ["cc", "-isystem/usr/include/python3.12", "-iquote/workspace/lib/inc",
                      "-idirafter/usr/local/include", "-c", "/workspace/lib/a.c"]}]), encoding="utf-8")
    rows = normalize_compile_db(root, {"project_key": "k", "project_id": "cpp:lib",
        "case_snapshot": "d" * 64, "root": "lib", "files": [{
            "target_path": "lib/a.c", "scratch_path": "source/a.c",
            "sha256": hashlib.sha256(b"int a;\n").hexdigest()}]})
    assert rows[0]["arguments"] == ["clang-18", "-isystem/usr/include/python3.12",
                                    "-iquote/scratch/source/inc", "-idirafter/usr/local/include",
                                    "/scratch/source/a.c"]


@pytest.mark.parametrize("mode", ["ast", "ir"])
def test_extension_replay_resolves_php_and_python_headers_in_the_replay_image(
        tmp_path: Path, mode: str) -> None:
    scratch = tmp_path / "scratch"
    rows = _extension_rows(scratch)
    image = _image(tmp_path / "image", php=True, python=True)
    assert _replay(tmp_path, scratch, rows, image, mode) == 0
    assert replay_failures(scratch, mode, rows) == {}


@pytest.mark.parametrize("mode", ["ast", "ir"])
def test_missing_extension_header_is_a_named_replay_gap(tmp_path: Path, mode: str) -> None:
    scratch = tmp_path / "scratch"
    rows = _extension_rows(scratch)
    image = _image(tmp_path / "image", php=False, python=True)
    assert _replay(tmp_path, scratch, rows, image, mode) == 2
    assert replay_failures(scratch, mode, rows) == {0: (
        f"ext/sample/php_sample.c: {mode} replay header not found in tool-native-cpp: php.h "
        "(an include path the build image had is absent from the replay image)")}


def test_replay_receipt_that_does_not_match_the_compile_database_is_unusable(tmp_path: Path) -> None:
    rows = [{"target_path": "a.c"}, {"target_path": "b.c"}]
    destination = tmp_path / "analysis" / "ast"
    destination.mkdir(parents=True)
    assert replay_failures(tmp_path, "ast", rows) is None
    (destination / "receipt.json").write_text(json.dumps([{"index": 0, "exit_code": 0}]))
    assert replay_failures(tmp_path, "ast", rows) is None
    (destination / "receipt.json").write_text(json.dumps([
        {"index": 0, "exit_code": 0},
        {"index": 1, "exit_code": None, "timeout": True},
    ]))
    assert replay_failures(tmp_path, "ast", rows) == {1: "b.c: ast replay timed out"}
    (destination / "receipt.json").write_text(json.dumps([
        {"index": 0, "exit_code": 1,
         "stderr": "a.c:1:10: fatal error: config.h: No such file or directory"},
        {"index": 1, "exit_code": 1, "stderr": "warning: x\nb.c:3:1: error: unknown type name 'zval'"},
    ]))
    failures = replay_failures(tmp_path, "ast", rows)
    assert "a.c: ast replay header not found in tool-native-cpp: config.h" in failures[0]
    assert failures[1] == "b.c: ast replay failed with exit 1: b.c:3:1: error: unknown type name 'zval'"


def _shell_value(text: str, name: str) -> str:
    match = re.search(rf'^{name}="([^"]+)"$', text, re.MULTILINE)
    assert match, name
    return match.group(1)


def test_replay_closure_pins_the_build_environment_dev_header_versions() -> None:
    native = ROOT / "containers" / "tools" / "native-cpp"
    script = (native / "acquire_assets.sh").read_text(encoding="utf-8")
    buildenv = ROOT / "containers" / "buildenv"
    php_dockerfile = (buildenv / "php" / "Dockerfile").read_text(encoding="utf-8")
    python_dockerfile = (buildenv / "python" / "Dockerfile").read_text(encoding="utf-8")
    php_version = _shell_value(script, "php_version")
    python_version = _shell_value(script, "python_version")
    for package in ("php8.3-cli", "php8.3-dev"):
        assert f"{package}={php_version}" in php_dockerfile
        assert f"{package}=$php_version" in script
    assert f"python3-dev={python_version}" in python_dockerfile
    assert "python3-dev=$python_version" in script
    assert re.search(r'^packages="clang-18 cmake bear"$', script, re.MULTILINE)
    dockerfile = (native / "Dockerfile").read_text(encoding="utf-8")
    for header in (f"{PHP_INCLUDES[1]}/php.h", f"{PYTHON_INCLUDES[0]}/Python.h"):
        assert f"test -f {header}" in dockerfile
    assert f"-I{PHP_INCLUDES[0]} -I{PHP_INCLUDES[1]}" in dockerfile
    assert f"python3.12-config --includes | grep -F -- '-I{PYTHON_INCLUDES[0]}'" in dockerfile


def test_compile_database_normalization_maps_a_project_at_the_target_root(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / "build").mkdir(parents=True)
    (root / "source" / "src").mkdir(parents=True)
    (root / "source" / "src" / "add.c").write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    (root / "build" / "compile_commands.json").write_text(json.dumps([{
        "directory": "/workspace/build", "file": str(root / "source" / "src" / "add.c"),
        "arguments": ["cc", "-I/workspace/include", "-c", str(root / "source" / "src" / "add.c"),
                      "-o", "/workspace/build/add.o"],
    }]), encoding="utf-8")
    source_sha = hashlib.sha256((root / "source" / "src" / "add.c").read_bytes()).hexdigest()
    rows = normalize_compile_db(root, {"project_key": "root", "project_id": "cpp:.",
        "case_snapshot": "a" * 64, "root": ".", "files": [{
            "target_path": "src/add.c", "scratch_path": "source/src/add.c", "sha256": source_sha}]})
    assert [row["target_path"] for row in rows] == ["src/add.c"]
    assert rows[0]["file"] == "/scratch/source/src/add.c"
    assert "-I/scratch/source/include" in rows[0]["arguments"]
    assert rows[0]["output_path"] == "build/add.o"
