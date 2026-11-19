"""Offline T-5171/T-5172 regressions over real planning and validation handlers."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound_json
from appsec_review.jobs.job_language_build.native import _row
from appsec_review.jobs.job_poc_generation.buildctx import AcceptedBuilds
from appsec_review.jobs.job_remediation_validation import build_job
from appsec_review.jobs.job_remediation_validation.workspace import (
    WorkspaceLimit, admit_source_context, manifest, materialize,
)
from appsec_review.review.models import IntegrityError
from appsec_review.storage import atomic_json
from tests import remediation_support as support
from tests.unit.job_remediation_validation.test_coverage_edges import _seed_env, _val_ctx

PRIMARY = "native/src/parse.c"
OTHER = "native/src/other.c"
SOURCE = "void p(char *s) {\n  char b[8];\n  strcpy(b, s);\n}\n"


def _builds(root, workspace, manifest, *, cwd=".", foreign=False):
    """Use the native producer's actual row serializer, not a second compile-row format."""
    receipts = []
    groups = [[name] for name in sorted(manifest)] if foreign else [sorted(manifest)]
    for index, names in enumerate(groups):
        rows = []
        for name in names:
            argument = str(Path(name).relative_to(cwd)) if cwd != "." else f"/workspace/{name}"
            standard = ["-std=c++14"] if name.endswith(".cpp") else []
            rows.append(_row("clang", "compiler", ["/usr/bin/clang", *standard, "-c", argument],
                             workspace, cwd, "inert-capture"))
        base = root / "data" / "accepted-build" / str(index)
        database = base / "compile.json"
        manifest_path = base / "manifest.json"
        atomic_json(database, {"schema": "appsec-review/protected-compile-commands/1", "rows": rows})
        atomic_json(manifest_path, {"files": {name: manifest[name] for name in names}})
        receipts.append({
            "build_unit_id": f"native-{index}", "family": "native", "terminal_status": "SUCCEEDED",
            "build_system": "custom", "root": "native", "fingerprint": str(index + 1) * 64,
            "workspace": workspace.relative_to(root).as_posix(),
            "workspace_manifest": artifact_ref(root, manifest_path),
            "protected_compile_commands": artifact_ref(root, database),
            "image": {"image_tag": "native:fixture", "image_id": "sha256:" + "a" * 64,
                      "user": "10001:10001"},
            # Deliberately different: a recipe directory is not the captured process cwd.
            "recipe": {"build_dir": "unrelated-build-directory"}, "artifacts": [],
        })
    return AcceptedBuilds(root, loader=lambda _root: {"receipts": receipts})


def _validate(env, settings=None):
    reviewer, executor = support.Writer(), support.Executor()
    result = build_job(
        infer=reviewer, executor_factory=lambda _u, _p: executor,
        builds_factory=lambda _root: env.builds, repository_root=support.ROOT,
    ).execute(_val_ctx(env.root, settings or support.validation_settings()))
    assert not result["failed_units"], result
    document = read_bound_json(env.root, result["outputs"]["acceptance.publish_handoff"]["artifact"])
    [item] = document["items"]
    record = read_bound_json(env.root, item["validation"])
    assert read_bound_json(env.root, record["cleanup"])["removed"]
    assert record["assurance"]["runtime_verified"] is False
    return record, reviewer, executor


def test_related_translation_unit_does_not_change_selected_patch_build(tmp_path, monkeypatch):
    env = _seed_env(tmp_path, monkeypatch, extra_files={OTHER: "int helper() { return 1; }\n"},
                    extra_entity_path=OTHER, builds_fn=_builds)
    record, reviewer, executor = _validate(env)
    assert record["status"] == "build_checked", record["reason"]
    assert len(reviewer.requests) == 1 and len(executor.calls) == 2
    assert {row["path"] for row in reviewer.requests[0].task_input["task"]["source_files"]} == {PRIMARY, OTHER}
    assert all(call["argv"][-1] == f"/workspace/{PRIMARY}" for call in executor.calls)
    assert env.src_file.read_text() == SOURCE


def test_foreign_build_context_is_not_merged_into_selected_workspace(tmp_path, monkeypatch):
    env = _seed_env(tmp_path, monkeypatch, extra_files={OTHER: "int other;\n"}, extra_entity_path=OTHER,
                    builds_fn=lambda *args: _builds(*args, foreign=True))
    record, reviewer, executor = _validate(env)
    assert record["status"] == "manual_validation_required"
    assert record["reason"] == "multi_build_proposal_requires_manual_validation"
    assert not reviewer.requests and not executor.calls


def test_producer_cwd_reaches_accepted_consumer_and_both_validation_phases(tmp_path, monkeypatch):
    env = _seed_env(tmp_path, monkeypatch, builds_fn=lambda *args: _builds(*args, cwd="native"))
    record, reviewer, executor = _validate(env)
    assert record["status"] == "build_checked", record["reason"]
    assert len(reviewer.requests) == 1 and len(executor.calls) == 2
    assert [call["working_directory"] for call in executor.calls] == ["native", "native"]
    assert all(call["argv"][-1] == f"/workspace/{PRIMARY}" for call in executor.calls)
    assert env.builds.locate(PRIMARY).unit.command.argv[-1] == "src/parse.c"


@pytest.mark.parametrize("field,limit,refused", [
    ("max_source_files", 1, True),
    ("max_source_files", 2, False),
    ("max_source_files", 3, False),
    ("max_source_bytes", len(SOURCE.encode()) + len("// é\r\n".encode()) - 1, True),
    ("max_source_bytes", len(SOURCE.encode()) + len("// é\r\n".encode()), False),
    ("max_source_bytes", len(SOURCE.encode()) + len("// é\r\n".encode()) + 1, False),
    ("max_file_bytes", len(SOURCE.encode()) - 1, True),
])
def test_validation_readmits_context_before_source_copy_or_model(tmp_path, monkeypatch, field, limit, refused):
    env = _seed_env(tmp_path, monkeypatch, extra_files={OTHER: "// é\r\n"}, extra_entity_path=OTHER,
                    builds_fn=_builds)
    before = {name: (env.workspace / name).read_bytes() for name in env.manifest}
    record, reviewer, executor = _validate(env, support.validation_settings(**{field: limit}))
    if refused:
        assert record["status"] == "manual_validation_required", record
        assert record["reason"] == ("source_file_bound_reached" if field == "max_source_files"
                                    else "source_byte_bound_reached")
        assert record["gaps"]
        assert not reviewer.requests and not executor.calls
        assert read_bound_json(env.root, record["cleanup"])["created"] is False
    else:
        assert record["status"] == "build_checked", record["reason"]
        task = reviewer.requests[0].task_input["task"]
        assert {row["path"]: row["text"].encode() for row in task["source_files"]} == before
        assert len(executor.calls) == 2
    assert {name: (env.workspace / name).read_bytes() for name in env.manifest} == before


def test_source_bound_refusal_precedes_workspace_reads_and_model_dispatch(tmp_path, monkeypatch):
    env = _seed_env(tmp_path, monkeypatch, builds_fn=_builds)
    original_open = Path.open

    def bounded_open(path, *args, **kwargs):
        assert env.workspace not in path.parents, "over-budget context must not read workspace source"
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", bounded_open)
    record, reviewer, executor = _validate(env, support.validation_settings(max_source_bytes=1))
    assert record["reason"] == "source_byte_bound_reached"
    assert record["status"] == "manual_validation_required" and record["gaps"]
    assert not reviewer.requests and not executor.calls
    assert read_bound_json(env.root, record["cleanup"])["created"] is False


def test_patch_scope_read_remains_bounded_after_source_admission(tmp_path, monkeypatch):
    env = _seed_env(tmp_path, monkeypatch, builds_fn=_builds)
    original_open = Path.open
    limit = 128
    reads = []
    opened = 0

    class ObservedStream:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, size=-1):
            reads.append(size)
            return self.stream.read(size)

    def growing_open(path, *args, **kwargs):
        nonlocal opened
        mode = args[0] if args else kwargs.get("mode")
        if path == env.src_file and mode == "rb":
            opened += 1
            if opened == 2:
                with original_open(path, "ab") as stream:
                    stream.write(b"x" * (limit + 1 - len(SOURCE.encode())))
            return ObservedStream(original_open(path, *args, **kwargs))
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", growing_open)
    reviewer, executor = support.Writer(), support.Executor()
    result = build_job(
        infer=reviewer, executor_factory=lambda _u, _p: executor,
        builds_factory=lambda _root: env.builds, repository_root=support.ROOT,
    ).execute(_val_ctx(env.root, support.validation_settings(max_file_bytes=limit)))
    assert reads == [limit + 1, limit + 1], "admission and exact patch scope must both bound their reads"
    assert not result["failed_units"], result
    summary = read_bound_json(env.root, result["outputs"]["acceptance.publish_handoff"]["artifact"])
    [item] = summary["items"]
    assert item["status"] == "rejected"
    assert item["reason"] == f"patch_rejected:baseline file bound exceeded: {PRIMARY}"
    record = read_bound_json(env.root, item["validation"])
    assert record["checks"]["patch_applicability"]["status"] == "failed"
    assert read_bound_json(env.root, record["cleanup"])["created"] is False
    assert not reviewer.requests and not executor.calls


@pytest.mark.parametrize("damage", ["text", "hash", "build", "duplicate"])
def test_source_readmission_never_replaces_accepted_text_or_identity(tmp_path, monkeypatch, damage):
    env = _seed_env(tmp_path, monkeypatch, builds_fn=_builds)
    summary = read_bound_json(env.root, env.pub_out["artifact"])
    plan = read_bound_json(env.root, summary["items"][0]["plan"])
    context = read_bound_json(env.root, plan["provenance"]["source_context"])
    [source] = context["files"]
    if damage == "duplicate":
        context["files"].append(dict(source))
    elif damage == "text":
        source["text"] = source["text"].replace("char b[8]", "char b[9]")
    elif damage == "hash":
        source["sha256"] = "0" * 64
    else:
        source["build"] = {**source["build"], "receipt_fingerprint": "0" * 64}
    with pytest.raises(IntegrityError, match="(text differs|hash differs|identity changed|duplicate)"):
        admit_source_context(context["files"], env.builds, support.bounds(), run_root=env.root)


@pytest.mark.parametrize("operation", ["materialize", "manifest"])
def test_workspace_reads_are_bounded_even_if_file_grows_after_stat(tmp_path, monkeypatch, operation):
    env = _seed_env(tmp_path, monkeypatch, builds_fn=_builds)
    unit = env.builds.locate(PRIMARY).unit
    original_open = Path.open
    reads = []
    bound = len(SOURCE.encode())
    settings = replace(support.bounds(), max_workspace_bytes=bound)

    class ObservedStream:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, size=-1):
            reads.append(size)
            assert size == bound + 1
            return self.stream.read(size)

    def growing_open(path, *args, **kwargs):
        if path == env.src_file and args and args[0] == "rb":
            with original_open(path, "ab") as stream:
                stream.write(b"grew")
            return ObservedStream(original_open(path, *args, **kwargs))
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", growing_open)
    with pytest.raises(WorkspaceLimit, match="(workspace_byte|scratch_workspace)_bound_reached"):
        if operation == "materialize":
            materialize(unit, env.root / "scratch-copy", settings, run_root=env.root)
        else:
            manifest(env.workspace, settings)
    assert reads == [bound + 1]


@pytest.mark.parametrize("cwd", [None, "", "../escape", "/elsewhere", "/workspace/../escape", "native\\src"])
def test_historical_or_unresolvable_cwd_never_falls_back_to_recipe(tmp_path, cwd):
    root = tmp_path / "run"
    workspace = root / "data" / "workspace"
    path = workspace / PRIMARY
    path.parent.mkdir(parents=True)
    path.write_text(SOURCE)
    from appsec_review.storage import file_sha256
    builds = _builds(root, workspace, {PRIMARY: file_sha256(path)}, cwd="native")
    receipt = builds.accepted["receipts"][0]
    reference = receipt["protected_compile_commands"]
    database = read_bound_json(root, reference)
    if cwd is None:
        database["rows"][0].pop("working_directory", None)
    else:
        database["rows"][0]["working_directory"] = cwd
    atomic_json(root / reference["path"], database)
    receipt["protected_compile_commands"] = artifact_ref(root, root / reference["path"])
    located = builds.locate(PRIMARY)
    assert located.unit is None
    assert located.code == "no_compile_command"
    assert "working directory" in located.reason


def test_existing_cpp_digit_separator_survives_exact_patch_and_validation(tmp_path, monkeypatch):
    name = "native/src/parse.cpp"
    source = SOURCE.replace("char b[8];", "char b[8];\n  long limit = 1'000;")
    env = _seed_env(tmp_path, monkeypatch, primary_path=name, extra_files={name: source}, builds_fn=_builds)
    record, reviewer, executor = _validate(env)
    assert record["status"] == "build_checked", record["reason"]
    assert record["checks"]["patch_applicability"]["status"] == "passed"
    assert record["checks"]["static_checks"]["status"] == "passed"
    assert len(reviewer.requests) == 1 and len(executor.calls) == 2
    assert env.src_file.read_text() == source
