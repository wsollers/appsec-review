"""Code-level unit tests for ``job_sanitizer_build.job`` handlers and helpers."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.config.build_outputs import parse_build_outputs
from appsec_review.container_runtime import BuildProfile
from appsec_review.indexing.inventory import Claim, FileClaims, runtime_claims, scan_run_tree
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.engineering_contracts import SANITIZER_BUILD_HANDOFF_SCHEMA
from appsec_review.jobs.job_sanitizer_build import JOB_ID, build_job
from appsec_review.jobs.job_sanitizer_build import job as sanitizer_job
from appsec_review.jobs.job_sanitizer_build.datasets import DATASETS
from appsec_review.jobs.job_sanitizer_build.settings import SanitizerBuildSettings
from appsec_review.runtime import UnitContext
from appsec_review.storage import canonical_json, file_sha256
from tests.sanitizer_support import ET_REL, DockerFake, elf_with_symbols, instrumented_elf


ROOT = Path(__file__).resolve().parents[3]
SETTINGS = {
    "enabled": True,
    "workers": 1,
    "sanitizers": ["address", "undefined"],
    "extra_flags": ["-fno-omit-frame-pointer", "-g", "-O1"],
    "required_evidence": ["address"],
    "build_systems": ["cmake", "autotools", "meson", "make"],
    "build_environment": {"ASAN_OPTIONS": "detect_leaks=0"},
    "command_timeout_seconds": 60,
    "output_bytes": 1_000_000,
    "artifact_count_limit": 100,
    "max_units": 4,
}


def _settings(**overrides) -> SanitizerBuildSettings:
    return SanitizerBuildSettings.from_mapping({**deepcopy(SETTINGS), **overrides})


def _synthetic_fixture(base: Path, *, settings_override: dict | None = None):
    config = load_config(ROOT / "appsec-review.toml")
    target = base / "target"
    (target / "native").mkdir(parents=True, exist_ok=True)
    (target / "native" / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    (target / "native" / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.20)\n", encoding="utf-8")
    fingerprint = source_fingerprint(target)

    run_root = base / "run"
    cmd_dir = run_root / "data" / "jobs" / "job_language_build" / "protected"
    cmd_dir.mkdir(parents=True, exist_ok=True)
    image = {
        "image_tag": "appsec-build-native:test",
        "image_id": "sha256:" + "b" * 64,
        "user": "1000:1000",
    }
    raw_cmds = [
        (
            "configure",
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
            ],
        ),
        ("build", ["cmake", "--build", "build", "--parallel", "2"]),
    ]
    commands = []
    for idx, (role, argv) in enumerate(raw_cmds, 1):
        doc = {
            "schema": sanitizer_job.PROTECTED_COMMAND_SCHEMA,
            "argv": argv,
            "working_directory": "native",
            "environment": {},
        }
        cmd_file = cmd_dir / f"{idx:03d}.json"
        cmd_file.write_text(json.dumps(doc), encoding="utf-8")
        commands.append(
            {
                "role": role,
                "working_directory": "native",
                "image_id": image["image_id"],
                "argv_sha256": hashlib.sha256(canonical_json(argv)).hexdigest(),
                "protected_argv": {
                    "path": cmd_file.relative_to(run_root).as_posix(),
                    "sha256": file_sha256(cmd_file),
                },
            }
        )

    base_bin = run_root / "data" / "language_build" / "native" / "units" / "unit-1" / "workspace" / "native" / "build" / "sample"
    base_bin.parent.mkdir(parents=True, exist_ok=True)
    base_bin.write_bytes(elf_with_symbols(undefined=("puts",)))

    receipt = {
        "build_unit_id": "unit-1",
        "family": "native",
        "root": "native",
        "build_system": "cmake",
        "recipe_identity": "recipe-1",
        "fingerprint": "1" * 64,
        "terminal_status": "SUCCEEDED",
        "image": image,
        "recipe": {
            "source_dir": "native",
            "build_dir": "native/build",
            "network_required": False,
            "configure_commands": [raw_cmds[0][1]],
            "build_commands": [raw_cmds[1][1]],
        },
        "commands": commands,
        "artifacts": [
            {
                "workspace_path": "native/build/sample",
                "kind": "executable",
                "path": base_bin.relative_to(run_root).as_posix(),
                "sha256": file_sha256(base_bin),
            }
        ],
    }

    job_cfg = config.job(JOB_ID)
    merged_settings = {**deepcopy(SETTINGS), **(settings_override or {})}
    cfg_ns = SimpleNamespace(
        settings=merged_settings,
        steps=job_cfg.steps,
        step=job_cfg.step,
    )
    events = SimpleNamespace(write=lambda *args, **kwargs: None)
    job_ns = SimpleNamespace(
        run_root=run_root,
        target_root=target,
        source_fingerprint=fingerprint,
        config=cfg_ns,
        app_config=config,
        events=events,
        attempt_id="attempt_0001",
    )
    unit_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / "attempt_0001" / "steps" / "acceptance" / "tasks" / "publish_handoff"
    unit_root.mkdir(parents=True, exist_ok=True)
    ctx = UnitContext(job_ns, "build.units", "build", "units", unit_root, MappingProxyType({}))
    return config, target, fingerprint, run_root, receipt, ctx


def _doctored(run_root: Path, receipt: dict, index: int, change) -> dict:
    receipt = deepcopy(receipt)
    command = receipt["commands"][index]
    path = run_root / command["protected_argv"]["path"]
    document = json.loads(path.read_text(encoding="utf-8"))
    change(document)
    rewritten = path.with_name("doctored-" + path.name)
    rewritten.write_text(json.dumps(document), encoding="utf-8")
    command["protected_argv"] = {
        "path": rewritten.relative_to(run_root).as_posix(),
        "sha256": file_sha256(rewritten),
    }
    command["argv_sha256"] = hashlib.sha256(canonical_json(document["argv"])).hexdigest()
    return receipt


def _never_started(_unit, _profile):
    raise AssertionError("no container may be started for a unit that cannot be instrumented")


def test_artifact_custody_and_bounded_gap_helpers(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    run_root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    with pytest.raises(sanitizer_job.FrameworkIntegrityError, match="escaped the run"):
        sanitizer_job._artifact(run_root, outside)

    gaps = [f"gap-{i}" for i in range(25)] + ["gap-0"]
    bounded = sanitizer_job._bounded(gaps)
    assert len(bounded) == 21
    assert bounded[-1] == "5 further gaps omitted"


def test_protected_command_replay_and_baseline_validation_branches(tmp_path: Path) -> None:
    _config, _target, _fp, run_root, receipt, _ctx = _synthetic_fixture(tmp_path)

    # Missing recipe or image
    assert sanitizer_job._replay(run_root, {"recipe": None, "image": receipt["image"]}) == (
        None,
        "accepted build recipe or image is unavailable",
    )

    # Unavailable protected command file (escapes run_root or missing)
    missing_cmd = deepcopy(receipt)
    missing_cmd["commands"][0]["protected_argv"]["path"] = "../outside.json"
    assert sanitizer_job._replay(run_root, missing_cmd) == (
        None,
        "accepted protected build command is unavailable",
    )

    # Invalid protected command schema / argv
    bad_schema = _doctored(run_root, receipt, 0, lambda doc: doc.update(schema="wrong/1"))
    assert sanitizer_job._replay(run_root, bad_schema) == (
        None,
        "accepted protected build command is invalid",
    )

    # Redacted command
    redacted = _doctored(run_root, receipt, 0, lambda doc: doc.update(argv=["<redacted: secret scan>"]))
    assert sanitizer_job._replay(run_root, redacted) == (
        None,
        "accepted build command was redacted by the secret scan and cannot be replayed",
    )

    # Tampered protected command file sha256
    tampered_path = run_root / receipt["commands"][0]["protected_argv"]["path"]
    orig_bytes = tampered_path.read_bytes()
    tampered_path.write_bytes(orig_bytes.replace(b"cmake", b"cmakE"))
    with pytest.raises(sanitizer_job.FrameworkIntegrityError, match="identity changed"):
        sanitizer_job._replay(run_root, receipt)
    tampered_path.write_bytes(orig_bytes)

    # Working directory / image_id mismatch
    mismatch = deepcopy(receipt)
    mismatch["commands"][0]["working_directory"] = "other"
    with pytest.raises(sanitizer_job.FrameworkIntegrityError, match="identity mismatch"):
        sanitizer_job._replay(run_root, mismatch)

    # _baseline: non-matching, unavailable, changed sha256, stripped (no_symbol_tables), and resolved
    assert sanitizer_job._baseline(run_root, receipt, "missing/path", "executable") is None

    unavail_rec = {"artifacts": ["not-a-dict", {"workspace_path": "native/build/sample", "kind": "executable", "path": "missing"}]}
    assert sanitizer_job._baseline(run_root, unavail_rec, "native/build/sample", "executable")["evidence_status"] == "unavailable"

    changed_rec = deepcopy(receipt)
    changed_rec["artifacts"][0]["sha256"] = "0" * 64
    assert sanitizer_job._baseline(run_root, changed_rec, "native/build/sample", "executable")["evidence_status"] == "changed"

    stripped_bin = run_root / "stripped_sample"
    stripped_bin.write_bytes(instrumented_elf(symbol_tables=False))
    stripped_rec = {
        "artifacts": [
            {
                "workspace_path": "native/build/sample",
                "kind": "executable",
                "path": "stripped_sample",
                "sha256": file_sha256(stripped_bin),
            }
        ]
    }
    stripped_base = sanitizer_job._baseline(run_root, stripped_rec, "native/build/sample", "executable")
    assert stripped_base["evidence_status"] == "no_symbol_tables" and stripped_base["runtime_referenced"] is None


def test_catalog_and_judge_cover_exclusions_truncation_and_verdict_branches(tmp_path: Path) -> None:
    policy = parse_build_outputs(
        {
            "exclusions": [
                {
                    "name": "cmake-fetchcontent-subbuild",
                    "reason": "FetchContent download sub-builds",
                    "patterns": ["*-subbuild/"],
                    "families": ["native"],
                }
            ]
        }
    )
    workspace = tmp_path / "workspace"
    plain = elf_with_symbols(ET_REL, undefined=("puts",))
    unchanged_bin = instrumented_elf()
    for relative, data in {
        "native/README.txt": b"plain text\n",
        "native/a_prebuilt": unchanged_bin,
        "native/conftest": plain,
        "native/build/sample": instrumented_elf(),
        "native/build/extra": instrumented_elf(),
        "native/build/_deps/fmt-build/CMakeFiles/fmt.dir/format.cc.o": plain,
        "native/build/_deps/fmt-subbuild/CMakeFiles/probe.o": plain,
    }.items():
        (workspace / relative).parent.mkdir(parents=True, exist_ok=True)
        (workspace / relative).write_bytes(data)

    before = {"native/a_prebuilt": file_sha256(workspace / "native/a_prebuilt")}
    receipt = {
        "build_output_dispositions": {
            "roots": [
                "bad-entry",
                {
                    "root": "native/build/_deps/fmt-build",
                    "disposition": "supply_chain",
                    "basis": "build-system-fact",
                    "confidence": "high",
                    "name": "fmt",
                    "reason": "FetchContent binary directory",
                    "evidence_ref": "cmake-cache",
                    "pattern": None,
                    "scope": None,
                    "scope_role": "build_dependency",
                },
                {
                    "root": "native/build/odd",
                    "disposition": "per_file",
                    "basis": "build-system-fact",
                    "confidence": "high",
                    "name": "odd",
                    "reason": "conflict",
                    "evidence_ref": None,
                    "pattern": None,
                    "scope": None,
                    "scope_role": None,
                },
            ]
        }
    }
    # Bound at 1 output -> triggers truncation gap
    outputs, dispositions, gaps = sanitizer_job._catalog(
        tmp_path, workspace, before, receipt, _settings(artifact_count_limit=1), "unit", policy
    )
    assert len(outputs) == 1
    assert gaps == ["instrumented output catalog truncated at the configured count bound"]
    assert dispositions.document()["roots"][0]["disposition"] == "supply_chain"

    # _judge on unparsed ELF and plain objects without linked output
    unparsed_out = [
        {
            "workspace_path": "native/build/bad",
            "kind": "executable",
            "evidence": {"evidence_status": "unparsed", "sanitizers": {"address": {"runtime_referenced": False}}},
        }
    ]
    assert "ELF was not parseable" in sanitizer_job._judge(unparsed_out, _settings())[0]

    plain_obj_only = [
        {
            "workspace_path": "native/build/a.o",
            "kind": "object",
            "evidence": {"evidence_status": "resolved", "sanitizers": {"address": {"runtime_referenced": False}}},
        }
    ]
    assert "produced no linked output and no object references" in sanitizer_job._judge(plain_obj_only, _settings())[0]

    inst_obj_only = [
        {
            "workspace_path": "native/build/a.o",
            "kind": "object",
            "evidence": {"evidence_status": "resolved", "sanitizers": {"address": {"runtime_referenced": True}}},
        }
    ]
    assert sanitizer_job._judge(inst_obj_only, _settings()) == []


@pytest.mark.parametrize(
    ("mode", "fail_ordinal", "expected_status", "expected_gap"),
    [
        ("honor_env", None, "SUCCEEDED", None),
        ("ignore_env", None, "COMPLETED_WITH_GAPS", "no address sanitizer runtime reference"),
        ("stripped", None, "COMPLETED_WITH_GAPS", "no symbol tables (stripped)"),
        ("no_binaries", None, "COMPLETED_WITH_GAPS", "produced no native objects"),
        ("honor_env", 2, "FAILED", "instrumented build command 2 exited 2"),
        ("missing_runtime", 2, "FAILED", "lacks the sanitizer runtime libclang_rt.asan-x86_64.a"),
    ],
    ids=["succeeded", "ignored-flags", "stripped", "no-binaries", "cmd-failed", "missing-runtime"],
)
def test_build_unit_outcomes_over_docker_fake(
    tmp_path: Path, mode: str, fail_ordinal: int | None, expected_status: str, expected_gap: str | None
) -> None:
    _config, _target, _fp, run_root, receipt, ctx = _synthetic_fixture(tmp_path)
    fakes: list[DockerFake] = []

    def factory(_unit, profile: BuildProfile):
        fake = DockerFake(profile, mode=mode, fail_ordinal=fail_ordinal)
        fakes.append(fake)
        return fake.executor()

    unit_res = sanitizer_job._build_unit(ctx, receipt, _settings(), factory)
    assert unit_res["terminal_status"] == expected_status
    if expected_gap is None:
        assert unit_res["instrumented"] is True and unit_res["gaps"] == []
        by_path = {item["workspace_path"]: item for item in unit_res["outputs"]}
        assert set(by_path) == {"native/build/sample", "native/build/CMakeFiles/sample.dir/main.cpp.o"}
        assert by_path["native/build/sample"]["baseline"]["runtime_referenced"] is False
        assert file_sha256(run_root / unit_res["workspace_manifest"]["path"]) == unit_res["workspace_manifest"]["sha256"]
    else:
        assert unit_res["instrumented"] is False
        assert any(expected_gap in g for g in unit_res["gaps"])


def test_build_unit_conflicts_unsupported_and_failure_guards(tmp_path: Path, monkeypatch) -> None:
    _config, target, _fp, run_root, receipt, ctx = _synthetic_fixture(tmp_path)

    # Unsupported build system, failed receipt, missing protected_argv, incomplete commands
    assert "not enabled" in sanitizer_job._build_unit(
        ctx, receipt, _settings(build_systems=["meson"]), _never_started
    )["gaps"][0]
    assert "did not succeed" in sanitizer_job._build_unit(
        ctx, {**receipt, "terminal_status": "FAILED"}, _settings(), _never_started
    )["gaps"][0]
    # A built receipt whose provenance gaps flipped its status still has a recipe to instrument; a
    # receipt whose build failed has none whatever its status says.
    assert "not enabled" in sanitizer_job._build_unit(
        ctx, {**receipt, "terminal_status": "COMPLETED_WITH_GAPS", "build_outcome": "built"},
        _settings(build_systems=["meson"]), _never_started
    )["gaps"][0]
    assert "did not succeed" in sanitizer_job._build_unit(
        ctx, {**receipt, "terminal_status": "SUCCEEDED", "build_outcome": "failed"}, _settings(), _never_started
    )["gaps"][0]
    no_prot = deepcopy(receipt)
    for c in no_prot["commands"]:
        c.pop("protected_argv")
    assert "lacks its protected argv" in sanitizer_job._build_unit(ctx, no_prot, _settings(), _never_started)["gaps"][0]
    assert "incomplete" in sanitizer_job._build_unit(
        ctx, {**receipt, "commands": receipt["commands"][:1]}, _settings(), _never_started
    )["gaps"][0]

    # Recipe argument & environment conflicts
    masked = _doctored(run_root, receipt, 0, lambda doc: doc["argv"].append("-DCMAKE_CXX_FLAGS=-O0"))
    assert "cannot be injected" in sanitizer_job._build_unit(ctx, masked, _settings(), _never_started)["gaps"][0]
    env_conf = _doctored(run_root, receipt, 1, lambda doc: doc["environment"].update(CXXFLAGS="-fsanitize=thread"))
    assert "already selects sanitizer flags" in sanitizer_job._build_unit(
        ctx, env_conf, _settings(), _never_started
    )["gaps"][0]

    # An existing attempt directory is never cleared, even before a compiler starts.
    existing = run_root / "data" / "sanitizer" / "attempts" / ctx.job.attempt_id / receipt["build_unit_id"]
    existing.mkdir(parents=True, exist_ok=True)
    (existing / "retained").write_bytes(b"old evidence")
    assert "already exists" in sanitizer_job._build_unit(
        ctx, receipt, _settings(), _never_started
    )["gaps"][0]
    assert (existing / "retained").read_bytes() == b"old evidence"

    # _copy_source failure
    ctx.job.attempt_id = "attempt_0002"
    monkeypatch.setattr(sanitizer_job, "_copy_source", lambda *_a: (_ for _ in ()).throw(ValueError("bad symlink")))
    assert "could not be copied" in sanitizer_job._build_unit(ctx, receipt, _settings(), _never_started)["gaps"][0]
    monkeypatch.undo()

    # Pre-build _snapshot bound failure
    ctx.job.attempt_id = "attempt_0003"
    monkeypatch.setattr(sanitizer_job, "_snapshot", lambda *_a: (_ for _ in ()).throw(ValueError("too many files")))
    assert "accepted source exceeds the workspace file bound" in sanitizer_job._build_unit(
        ctx, receipt, _settings(), _never_started
    )["gaps"][0]
    monkeypatch.undo()

    # Image resolve failure
    ctx.job.attempt_id = "attempt_0004"
    class BrokenResolveExecutor:
        def resolve(self):
            raise RuntimeError("image missing")

    res_img = sanitizer_job._build_unit(ctx, receipt, _settings(), lambda _u, _p: BrokenResolveExecutor())
    assert res_img["terminal_status"] == "FAILED" and "image is unavailable" in res_img["gaps"][0]

    # Command execute exception
    ctx.job.attempt_id = "attempt_0005"
    class BrokenExecExecutor:
        def resolve(self):
            return None

        def execute(self, *_a, **_kw):
            raise OSError("docker daemon vanished")

    res_exec = sanitizer_job._build_unit(ctx, receipt, _settings(), lambda _u, _p: BrokenExecExecutor())
    assert res_exec["terminal_status"] == "FAILED" and "could not run (OSError)" in res_exec["gaps"][0]

    # Command timed out
    ctx.job.attempt_id = "attempt_0006"
    class TimeoutExecutor:
        def resolve(self):
            return None

        def execute(self, *_a, **_kw):
            return SimpleNamespace(
                exit_code=124,
                timed_out=True,
                stdout=b"",
                stderr=b"",
                stdout_bytes=0,
                stderr_bytes=0,
                stdout_truncated=False,
                stderr_truncated=False,
                stderr_tail=b"",
            )

    res_to = sanitizer_job._build_unit(ctx, receipt, _settings(), lambda _u, _p: TimeoutExecutor())
    assert res_to["terminal_status"] == "FAILED" and "timed out" in res_to["gaps"][0]

    # Post-build snapshot bound failure -> COMPLETED_WITH_GAPS without workspace_manifest
    ctx.job.attempt_id = "attempt_0007"
    real_snapshot = sanitizer_job._snapshot
    calls = []

    def fail_second_snapshot(root, limit):
        calls.append(root)
        if len(calls) == 2:
            raise ValueError("workspace file-count bound exceeded")
        return real_snapshot(root, limit)

    monkeypatch.setattr(sanitizer_job, "_snapshot", fail_second_snapshot)
    res_snap2 = sanitizer_job._build_unit(
        ctx, receipt, _settings(), lambda _u, p: DockerFake(p).executor()
    )
    assert res_snap2["terminal_status"] == "COMPLETED_WITH_GAPS" and "workspace_manifest" not in res_snap2
    monkeypatch.undo()

    # Target changed mid-build -> FrameworkIntegrityError
    ctx.job.attempt_id = "attempt_0008"
    class MutateTargetExecutor:
        def resolve(self):
            return None

        def execute(self, *_a, **_kw):
            (target / "native" / "main.cpp").write_text("int main() { return 1; }\n", encoding="utf-8")
            return SimpleNamespace(
                exit_code=0,
                timed_out=False,
                stdout=b"",
                stderr=b"",
                stdout_bytes=0,
                stderr_bytes=0,
                stdout_truncated=False,
                stderr_truncated=False,
                stderr_tail=b"",
            )

    with pytest.raises(sanitizer_job.FrameworkIntegrityError, match="target changed during the sanitizer build"):
        sanitizer_job._build_unit(ctx, receipt, _settings(), lambda _u, _p: MutateTargetExecutor())


def test_build_job_load_build_and_publish_units_plus_dataset_claims(tmp_path: Path, monkeypatch) -> None:
    config, _target, fingerprint, run_root, receipt, ctx = _synthetic_fixture(
        tmp_path, settings_override={"max_units": 1}
    )
    job = build_job(executor_factory=lambda _u, profile: DockerFake(profile).executor())
    load_fn, build_fn, publish_fn = (u.handler for u in job.units)

    # Snapshot mismatch + duplicate build_unit_ids in load.accepted_native
    monkeypatch.setattr(
        sanitizer_job,
        "load_accepted_language_build",
        lambda _r: {"source_fingerprint": "0" * 64, "language_build_handoff_sha256": "a" * 64, "receipts": []},
    )
    with pytest.raises(sanitizer_job.FrameworkIntegrityError, match="snapshot differs"):
        load_fn(ctx)

    monkeypatch.setattr(
        sanitizer_job,
        "load_accepted_language_build",
        lambda _r: {
            "source_fingerprint": fingerprint,
            "language_build_handoff_sha256": "a" * 64,
            "receipts": [receipt, receipt],
        },
    )
    with pytest.raises(sanitizer_job.FrameworkIntegrityError, match="duplicate build units"):
        load_fn(ctx)

    # Valid load with 1 planned, 1 omitted, 1 non-native not_applicable
    extra_native = {**deepcopy(receipt), "build_unit_id": "unit-2"}
    node_unit = {"build_unit_id": "unit-node", "family": "node", "root": "web", "build_system": "npm", "fingerprint": "2" * 64}
    accepted_doc = {
        "source_fingerprint": fingerprint,
        "language_build_handoff_sha256": "a" * 64,
        "receipts": [extra_native, receipt, node_unit],
    }
    monkeypatch.setattr(sanitizer_job, "load_accepted_language_build", lambda _r: accepted_doc)
    loaded = load_fn(ctx)
    assert [item["build_unit_id"] for item in loaded["planned"]] == ["unit-1"]
    assert [item["build_unit_id"] for item in loaded["omitted"]] == ["unit-2"]
    assert loaded["not_applicable"][0]["disposition"] == "SKIPPED_NA"

    # build.units: handoff changed between load and build -> FrameworkIntegrityError
    monkeypatch.setattr(
        sanitizer_job,
        "load_accepted_language_build",
        lambda _r: {**accepted_doc, "language_build_handoff_sha256": "b" * 64},
    )
    build_ctx = UnitContext(
        ctx.job, "build.units", "build", "units", ctx.unit_root, MappingProxyType({"load.accepted_native": loaded})
    )
    with pytest.raises(sanitizer_job.FrameworkIntegrityError, match="changed between load and build"):
        build_fn(build_ctx)

    # build.units: NOT_APPLICABLE when empty
    monkeypatch.setattr(sanitizer_job, "load_accepted_language_build", lambda _r: accepted_doc)
    empty_loaded = {"upstream": {"language_build_handoff_sha256": "a" * 64}, "planned": [], "omitted": [], "not_applicable": []}
    na_ctx = UnitContext(
        ctx.job, "build.units", "build", "units", ctx.unit_root, MappingProxyType({"load.accepted_native": empty_loaded})
    )
    assert build_fn(na_ctx)["terminal_status"] == "NOT_APPLICABLE"

    # build.units + publish_handoff cleanly succeeding (no omitted) and claiming all produced files
    clean_loaded = {**loaded, "omitted": []}
    clean_build_ctx = UnitContext(
        ctx.job, "build.units", "build", "units", ctx.unit_root, MappingProxyType({"load.accepted_native": clean_loaded})
    )
    built = build_fn(clean_build_ctx)
    assert built["terminal_status"] == "SUCCEEDED"

    pub_ctx = UnitContext(
        ctx.job,
        "acceptance.publish_handoff",
        "acceptance",
        "publish_handoff",
        ctx.unit_root,
        MappingProxyType({"load.accepted_native": clean_loaded, "build.units": built}),
    )
    published = publish_fn(pub_ctx)
    assert published["schema"] == SANITIZER_BUILD_HANDOFF_SCHEMA
    assert published["terminal_status"] == "SUCCEEDED"
    assert published["counts"]["instrumented_units"] == 1
    assert published["counts"]["instrumented_outputs"] == 2

    steps = tuple(config.job(JOB_ID).steps)
    claims = runtime_claims({JOB_ID: steps}) + [Claim(JOB_ID, item.step, item.output_kind, item) for item in DATASETS]
    tree = scan_run_tree(run_root, FileClaims(claims), max_files=100_000)
    mine = [p for p in tree.unaccounted if p.startswith(("data/sanitizer", f"data/jobs/{JOB_ID}"))]
    assert mine == []
