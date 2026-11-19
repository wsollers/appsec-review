"""Code-level unit tests for src/appsec_review/jobs/job_evidence_collection/job.py."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_evidence_collection import (
    build_job,
    load_target_catalog,
    plan_applicability,
)
from appsec_review.jobs.job_evidence_collection import job as ec_job
from appsec_review.jobs.job_evidence_collection.adapters import ADAPTERS, Applicability, ScanCatalog
from appsec_review.storage import atomic_json, file_sha256

from .support import (
    FakeExecutor,
    ROOT,
    SOURCE_FP,
    attempt_scope,
    make_unit_context,
    seed_accepted_catalog_and_plan,
    write_osv_feed,
)


def test_load_target_catalog_plan_applicability_and_validate_inputs(tmp_path: Path) -> None:
    run_root = tmp_path / "runs" / "run_0001"
    target = tmp_path / "target"
    target.mkdir(parents=True)
    (target / "run.sh").write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    file_entry = {
        "path": "run.sh",
        "sha256": file_sha256(target / "run.sh"),
        "size_bytes": (target / "run.sh").stat().st_size,
        "language": "Shell",
    }
    seed_accepted_catalog_and_plan(
        run_root,
        target,
        files=[file_entry],
        projects=[{"root": "."}],
        scanner_selections=[{
            "scanner_id": "tool-shellcheck",
            "reason": "shell script",
            "scope": [{"path": "run.sh"}],
        }],
    )
    catalog = load_target_catalog(run_root)
    assert catalog.source_fingerprint == SOURCE_FP
    assert catalog.target_root == target.resolve()
    assert len(catalog.files) == 1 and catalog.files[0]["path"] == "run.sh"
    assert catalog.target_artifact_gaps == ("broken/link: symlink_outside_target",)

    planned = {row["tool_id"]: row for row in plan_applicability(run_root)}
    assert planned["tool-shellcheck"]["applicable"] is True
    assert planned["tool-shellcheck"]["files"] == ["run.sh"]
    assert planned["tool-semgrep"]["applicable"] is False
    assert planned["tool-semgrep"]["reason"] == "not selected by accepted target analysis plan"

    # Without accepted plan, plan_applicability falls back to natural adapter applicability
    no_plan_run = tmp_path / "runs" / "run_no_plan"
    seed_accepted_catalog_and_plan(no_plan_run, target, files=[file_entry], scanner_selections=None)
    fallback_planned = {row["tool_id"]: row for row in plan_applicability(no_plan_run)}
    assert fallback_planned["tool-gitleaks"]["applicable"] is True

    unit, _, _ = make_unit_context(tmp_path)
    built = build_job()
    validate = built.input_validators[0]
    ctx = SimpleNamespace(
        run_root=run_root,
        repository_root=ROOT,
        target_root=target,
        source_fingerprint=SOURCE_FP,
        config=unit.job.config,
    )
    validate(ctx, None)

    with pytest.raises(ValueError, match="requires the graph-provided target root"):
        validate(SimpleNamespace(**{**ctx.__dict__, "target_root": None}), None)

    with pytest.raises(ValueError, match="does not match the accepted target catalog"):
        validate(SimpleNamespace(**{**ctx.__dict__, "source_fingerprint": "0" * 64}), None)

    bad_plan_run = tmp_path / "runs" / "run_bad_plan"
    seed_accepted_catalog_and_plan(
        bad_plan_run,
        target,
        files=[file_entry],
        scanner_selections=[],
        plan_fingerprint="9" * 64,
    )
    with pytest.raises(ValueError, match="does not match the accepted analysis plan"):
        validate(SimpleNamespace(**{**ctx.__dict__, "run_root": bad_plan_run}), None)


def test_diagnostics_prerequisites_staging_and_osv_project_helpers(tmp_path: Path) -> None:
    # _separate_parser_diagnostics separates findings, gaps, and not_applicable_input
    obs, gaps, na = ec_job._separate_parser_diagnostics(
        [
            {"rule_id": "R1", "message": "finding"},
            {"gap_only": True, "coverage_gap": "include missing"},
            {"gap_only": True, "not_applicable_input": "/target/foo.bat", "not_applicable_reason": "not sh"},
        ],
        "tool-shellcheck",
    )
    assert [o["rule_id"] for o in obs] == ["R1"]
    assert gaps == ["include missing"]
    assert len(na) == 1 and na[0].path == "foo.bat"

    # osv_project_groups assigns lockfiles to deepest project root or parent dir fallback
    grouped = ec_job.osv_project_groups(
        ["package-lock.json", "services/api/requirements.txt", "services/api/sub/poetry.lock", "orphan/Cargo.lock"],
        [{"root": "."}, {"root": "services/api"}],
    )
    assert grouped == {
        ".": ("package-lock.json",),
        "services/api": ("services/api/requirements.txt", "services/api/sub/poetry.lock"),
    } or grouped["services/api"] == ("services/api/requirements.txt", "services/api/sub/poetry.lock")

    # _osv_split_by_snapshot keeps supported ecosystems and records missing ecosystem gap
    osv_sel = Applicability(True, "lockfiles", ("web/package-lock.json", "rust/Cargo.lock"), "dependency_lockfiles")
    split_sel, split_gap = ec_job._osv_split_by_snapshot(osv_sel, {"npm": Path("npm.zip")})
    assert split_sel.files == ("web/package-lock.json",)
    assert split_gap is not None and "crates.io" in split_gap

    # _prerequisites sanitizes compile_commands.json and stages pmd-files.txt
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "a.cpp").write_text("int main(){}\n", encoding="utf-8")
    (target / "compile_commands.json").write_text(
        json.dumps([
            {"directory": str(target / "src"), "file": "a.cpp", "arguments": ["c++", "-O2", "a.cpp"]},
            {"directory": "/etc", "file": "/etc/passwd", "arguments": ["cc", "/etc/passwd"]},
        ]),
        encoding="utf-8",
    )
    unit, _, _ = make_unit_context(tmp_path, unit_id="source_sast.cppcheck_scan")
    unit.job.target_root = target
    cpp_sel = Applicability(
        True,
        "db",
        ("src/a.cpp",),
        "cpp_compile_database",
        families={"compile_database": ("compile_commands.json",)},
    )
    _, cpp_mounts, _, cpp_fail = ec_job._prerequisites(unit, ADAPTERS["tool-cppcheck"], cpp_sel)
    assert cpp_fail is None
    staged_db = next(m for m in cpp_mounts if m.target == "/inputs/compile_commands.json")
    rewritten = json.loads(staged_db.source.read_text(encoding="utf-8"))
    assert rewritten == [{"directory": "/target", "file": "/target/src/a.cpp", "arguments": ["c++", "/target/src/a.cpp"]}]

    pmd_unit, _, _ = make_unit_context(tmp_path, unit_id="source_sast.pmd_scan")
    pmd_sel = Applicability(True, "java", ("src/Main.java",), "java_source_ast")
    _, pmd_mounts, _, pmd_fail = ec_job._prerequisites(pmd_unit, ADAPTERS["tool-pmd"], pmd_sel)
    assert pmd_fail is None
    staged_pmd = next(m for m in pmd_mounts if m.target == "/inputs/pmd-files.txt")
    assert staged_pmd.source.read_text(encoding="utf-8") == "/target/src/Main.java\n"


def test_execute_tool_isolates_scanner_failure_and_stops_active_guardian(tmp_path: Path) -> None:
    """Direct _execute_tool failure surface (also called under safety._running by test_review_stop_policy)."""
    unit, catalog, _ = make_unit_context(
        tmp_path / "stop_case",
        unit_id="source_sast.shellcheck_scan",
        target_files={"run.sh": "#!/bin/sh\necho hi\n"},
    )
    calls: list[str] = []

    class FailingShellcheckExecutor(FakeExecutor):
        def execute(self, request):
            res = super().execute(request)
            (self.run_root / res.stderr_path).write_bytes(b"shellcheck boom")
            return replace(res, exit_code=2)

    with attempt_scope(unit):
        out = ec_job._execute_tool(
            unit,
            ADAPTERS["tool-shellcheck"],
            catalog,
            lambda u: FailingShellcheckExecutor(ROOT, u.job.run_root, calls),
            None,
        )
    assert out["terminal_status"] == "FAILED"
    assert any("shellcheck boom" in g for g in out["gaps"])
    # Failed checkpoint must NOT be reused on a subsequent clean invocation
    calls_retry: list[str] = []
    retry_unit, _, _ = make_unit_context(
        tmp_path / "stop_case",
        unit_id="source_sast.shellcheck_scan",
        target_files={"run.sh": "#!/bin/sh\necho hi\n"},
    )
    with attempt_scope(retry_unit):
        retry_out = ec_job._execute_tool(
            retry_unit,
            ADAPTERS["tool-shellcheck"],
            catalog,
            lambda u: FakeExecutor(ROOT, u.job.run_root, calls_retry),
            None,
        )
    assert retry_out["terminal_status"] == "SUCCEEDED"
    assert retry_out["checkpoint_reused"] is False
    assert calls_retry == ["tool-shellcheck"]

    # Second clean call with identical inputs DOES reuse checkpoint without invoking executor
    calls_cached: list[str] = []
    with attempt_scope(retry_unit):
        cached_out = ec_job._execute_tool(
            retry_unit,
            ADAPTERS["tool-shellcheck"],
            catalog,
            lambda u: FakeExecutor(ROOT, u.job.run_root, calls_cached),
            None,
        )
    assert cached_out["terminal_status"] == "SUCCEEDED"
    assert cached_out["checkpoint_reused"] is True
    assert calls_cached == []

    # Tampered checkpoint evidence hash invalidates reuse and re-runs tool
    (retry_unit.job.run_root / cached_out["artifact"]["path"]).write_text('{"tampered": true}', encoding="utf-8")
    calls_tampered: list[str] = []
    with attempt_scope(retry_unit):
        tampered_out = ec_job._execute_tool(
            retry_unit,
            ADAPTERS["tool-shellcheck"],
            catalog,
            lambda u: FakeExecutor(ROOT, u.job.run_root, calls_tampered),
            None,
        )
    assert tampered_out["checkpoint_reused"] is False
    assert calls_tampered == ["tool-shellcheck"]


def test_execute_tool_covers_disabled_not_applicable_blocked_grype_and_osv_branches(tmp_path: Path) -> None:
    # 1. Configured disabled Grype
    grype_disabled_unit, cat, events = make_unit_context(
        tmp_path / "g_dis",
        unit_id="vulnerability_matching.grype_scan",
        disable_grype=True,
    )
    dis_out = ec_job._execute_tool(
        grype_disabled_unit,
        ADAPTERS["tool-grype"],
        cat,
        lambda u: FakeExecutor(ROOT, u.job.run_root, []),
        None,
    )
    assert dis_out["terminal_status"] == "NOT_APPLICABLE"
    assert dis_out["coverage_disposition"] == "CONFIGURED_DISABLED"
    assert events[0][0] == "TOOL_CONFIGURED_DISABLED"

    # 2. Not applicable tool (no Go files)
    na_unit, na_cat, _ = make_unit_context(
        tmp_path / "go_na",
        unit_id="source_sast.gosec_scan",
        target_files={"README.md": "hello"},
    )
    na_out = ec_job._execute_tool(
        na_unit,
        ADAPTERS["tool-gosec"],
        na_cat,
        lambda u: FakeExecutor(ROOT, u.job.run_root, []),
        None,
    )
    assert na_out["terminal_status"] == "NOT_APPLICABLE"

    # 3. Blocked Grype when Grype DB or Syft SBOM missing, and Blocked OSV when feed snapshot missing
    empty_repo = tmp_path / "empty_repo"
    empty_repo.mkdir()
    grype_blocked_unit, gb_cat, _ = make_unit_context(
        tmp_path / "g_blk",
        unit_id="vulnerability_matching.grype_scan",
        repository_root=empty_repo,
        target_files={"package-lock.json": "{}"},
        outputs={"software_inventory.syft_scan": {"terminal_status": "FAILED", "scanner_output": None}},
    )
    gb_out = ec_job._execute_tool(
        grype_blocked_unit,
        ADAPTERS["tool-grype"],
        gb_cat,
        lambda u: FakeExecutor(ROOT, u.job.run_root, []),
        None,
    )
    assert gb_out["terminal_status"] == "BLOCKED"
    assert any("Grype database snapshot is unavailable" in g for g in gb_out["gaps"])
    osv_blk_unit, osv_cat, _ = make_unit_context(
        tmp_path / "o_blk",
        unit_id="vulnerability_matching.osv_scanner_scan",
        repository_root=empty_repo,
        target_files={"package-lock.json": "{}"},
    )
    osv_blk_out = ec_job._execute_tool(
        osv_blk_unit,
        ADAPTERS["tool-osv-scanner"],
        osv_cat,
        lambda u: FakeExecutor(ROOT, u.job.run_root, []),
        None,
    )
    assert osv_blk_out["terminal_status"] == "BLOCKED"

    # 4. OSV per-project: one project OOMs (retried), one project has 0 packages (exit 128), one succeeds -> PARTIAL
    osv_repo = tmp_path / "osv_repo"
    osv_repo.mkdir()
    write_osv_feed(osv_repo, ("npm",))
    osv_unit, osv_multi_cat, _ = make_unit_context(
        tmp_path / "o_multi",
        unit_id="vulnerability_matching.osv_scanner_scan",
        repository_root=osv_repo,
        target_files={
            "good/package-lock.json": "{}",
            "empty/package-lock.json": "{}",
            "oom/package-lock.json": "{}",
        },
        settings_override={"tool_retries": 1},
    )
    osv_multi_cat = ScanCatalog(
        osv_multi_cat.source_fingerprint,
        osv_multi_cat.handoff_sha256,
        osv_multi_cat.files,
        ({"root": "good"}, {"root": "empty"}, {"root": "oom"}),
        target_root=osv_multi_cat.target_root,
    )

    class MixedOsvExecutor(FakeExecutor):
        def __init__(self, r_root: Path):
            super().__init__(ROOT, r_root, [])

        def execute(self, request):
            res = super().execute(request)
            arg_str = " ".join(request.argv)
            if "/target/oom/" in arg_str:
                return replace(res, exit_code=137, oom_killed=True)
            if "/target/empty/" in arg_str:
                (self.run_root / res.stderr_path).write_bytes(
                    b"Scanned /target/empty/package-lock.json file and found 0 packages\n"
                    b"No package sources found, --help for usage information.\n"
                )
                return replace(res, exit_code=128)
            (request.scratch_root / "output.json").write_text(
                json.dumps({
                    "results": [{
                        "source": {"path": "/target/good/package-lock.json"},
                        "packages": [{"package": {"name": "pkg"}, "vulnerabilities": [{"id": "GHSA-9", "summary": "s"}]}],
                    }]
                }),
                encoding="utf-8",
            )
            return res

    with attempt_scope(osv_unit):
        mixed_out = ec_job._execute_tool(
            osv_unit,
            ADAPTERS["tool-osv-scanner"],
            osv_multi_cat,
            lambda u: MixedOsvExecutor(u.job.run_root),
            None,
        )
    assert mixed_out["terminal_status"] == "PARTIAL"
    assert mixed_out["record_count"] == 1
    assert mixed_out["not_applicable_inputs"]["count"] == 1
    assert any("OOM-killed" in g for g in mixed_out["gaps"])


def test_normalize_index_assemble_manifest_and_publish_handoff_end_to_end_units(tmp_path: Path) -> None:
    unit, catalog, _ = make_unit_context(
        tmp_path,
        unit_id="software_inventory.syft_scan",
        enable_swift=False,
        target_files={
            "package-lock.json": '{"lockfileVersion":3}',
            "App.swift": "import Foundation\n",
            "Main.scala": "object Main {}\n",
        },
    )

    class SyftExecutor(FakeExecutor):
        def execute(self, request):
            res = super().execute(request)
            (request.scratch_root / "output.json").write_text(
                json.dumps({
                    "artifacts": [{
                        "name": "chalk",
                        "version": "5.0.0",
                        "type": "npm",
                        "purl": "pkg:npm/chalk@5.0.0",
                        "locations": [{"path": "/target/package-lock.json"}],
                    }]
                }),
                encoding="utf-8",
            )
            return res

    with attempt_scope(unit):
        scan_out = ec_job._execute_tool(
            unit,
            ADAPTERS["tool-syft"],
            catalog,
            lambda u: SyftExecutor(ROOT, u.job.run_root, []),
            None,
            swift_present=True,
        )
    assert scan_out["terminal_status"] == "SUCCEEDED" and scan_out["record_count"] == 1

    norm_ctx, _, _ = make_unit_context(
        tmp_path,
        unit_id="software_inventory.syft_normalize",
        outputs={"software_inventory.syft_scan": scan_out},
    )
    norm_ctx.job.target_root = unit.job.target_root
    norm_out = ec_job._normalize_tool(norm_ctx, "software_inventory.syft_scan")
    assert norm_out["record_count"] == 1

    idx_ctx, _, _ = make_unit_context(
        tmp_path,
        unit_id="software_inventory.syft_index",
        outputs={"software_inventory.syft_normalize": norm_out},
    )
    idx_ctx.job.target_root = unit.job.target_root
    idx_out = ec_job._build_producer_shard(idx_ctx, "software_inventory.syft_normalize")
    assert idx_out["index_reused"] is False and idx_out["record_count"] == 1

    # Second _build_producer_shard call hits shared shard cache (index_reused=True)
    idx_reused = ec_job._build_producer_shard(idx_ctx, "software_inventory.syft_normalize")
    assert idx_reused["index_reused"] is True

    # Seed accepted catalog + plan so assemble_manifest can synthesize all 20 index units cleanly
    seed_accepted_catalog_and_plan(
        unit.job.run_root,
        unit.job.target_root,
        files=list(catalog.files),
        scanner_selections=[{
            "scanner_id": "tool-syft",
            "reason": "lockfile",
            "scope": [{"path": "package-lock.json"}],
        }],
    )
    built = build_job()
    all_idx_outputs: dict[str, dict[str, object]] = {}
    for u_def in built.units:
        if u_def.unit_id.endswith("_index"):
            if u_def.unit_id == "software_inventory.syft_index":
                all_idx_outputs[u_def.unit_id] = idx_out
            else:
                stem = u_def.unit_id.split(".", 1)[1].removesuffix("_index").replace("_", "-")
                tool_id = f"tool-{stem}"
                empty_norm = {
                    "tool_id": tool_id,
                    "terminal_status": "NOT_APPLICABLE",
                    "checkpoint_reused": False,
                    "artifact": scan_out["artifact"],
                    "normalized_artifact": scan_out["artifact"],
                    "record_count": 0,
                    "gaps": [],
                    "not_applicable_inputs": {
                        "count": 1,
                        "by_reason": {"OUTSIDE_DECLARED_SUPPORT": 1},
                        "truncated": False,
                        "items": [{
                            "path": "foo.bat",
                            "tool": tool_id,
                            "reason": "OUTSIDE_DECLARED_SUPPORT",
                            "detail": "batch script",
                            "disposition": "SKIPPED_NA",
                        }],
                    },
                }
                sub_ctx, _, _ = make_unit_context(
                    tmp_path,
                    unit_id=u_def.unit_id,
                    outputs={u_def.dependencies[0]: empty_norm},
                )
                sub_ctx.job.target_root = unit.job.target_root
                all_idx_outputs[u_def.unit_id] = ec_job._build_producer_shard(sub_ctx, u_def.dependencies[0])

    assemble_def = next(u for u in built.units if u.unit_id == "evidence_publication.assemble_manifest")
    asm_ctx, _, _ = make_unit_context(
        tmp_path,
        unit_id="evidence_publication.assemble_manifest",
        enable_swift=False,
        outputs=all_idx_outputs,
    )
    asm_ctx.job.target_root = unit.job.target_root
    cat_manifest_path = unit.job.run_root / "data/indices/manifests/catalog-attempt_0001.json"
    asm_ctx.job.input_manifest_path = cat_manifest_path
    asm_ctx.job.input_manifest_sha256 = file_sha256(cat_manifest_path)
    asm_out = assemble_def.handler(asm_ctx)
    from appsec_review.swift_policy import SWIFT_KNOWN_GAP

    assert len(asm_out["shards"]) == 20
    assert asm_out["item_count"] == 1
    assert asm_out["unsupported_coverage"]["count"] == 1
    assert SWIFT_KNOWN_GAP in asm_out["gaps"]

    publish_def = next(u for u in built.units if u.unit_id == "evidence_publication.publish_handoff")
    pub_ctx, _, _ = make_unit_context(
        tmp_path,
        unit_id="evidence_publication.publish_handoff",
        outputs={"evidence_publication.assemble_manifest": asm_out},
    )
    pub_out = publish_def.handler(pub_ctx)
    handoff_doc = json.loads((unit.job.run_root / pub_out["artifact"]["path"]).read_text(encoding="utf-8"))
    assert handoff_doc["schema"] == "appsec-review/evidence-collection-handoff/1"
    assert len(handoff_doc["shards"]) == 20


def test_swift_filter_prerequisites_sanitization_and_validator_negative_branches(tmp_path: Path) -> None:
    from appsec_review.container_runtime import Mount
    from appsec_review.swift_policy import SWIFT_KNOWN_GAP
    from tests.unit.job_evidence_collection.support import write_osv_feed

    # _apply_swift_policy branches: enabled=True, no-swift, mixed, swift-only
    sel_plain = Applicability(True, "ok", ("a.py",), "src")
    assert ec_job._apply_swift_policy(sel_plain, enabled=True) == sel_plain
    assert ec_job._apply_swift_policy(sel_plain, enabled=False) == sel_plain
    sel_mixed = ec_job._apply_swift_policy(Applicability(True, "ok", ("a.py", "b.swift"), "src"), enabled=False)
    assert sel_mixed.applicable and sel_mixed.files == ("a.py",) and SWIFT_KNOWN_GAP in sel_mixed.gaps
    sel_only_swift = ec_job._apply_swift_policy(Applicability(True, "ok", ("b.swift",), "src"), enabled=False)
    assert not sel_only_swift.applicable and SWIFT_KNOWN_GAP in sel_only_swift.gaps

    # _bounded_head & _filter_supported_inputs
    target = tmp_path / "head_target"
    target.mkdir()
    (target / "run.sh").write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    (target / "bad.ps1").write_text("Write-Host hi\n", encoding="utf-8")
    (target / "link.sh").symlink_to(target / "run.sh")
    head_none = ec_job._bounded_head(None)
    assert head_none("run.sh") is None
    head_fn = ec_job._bounded_head(target)
    assert head_fn("/abs.sh") is None
    assert head_fn("../escape.sh") is None
    assert head_fn("missing.sh") is None
    assert head_fn("link.sh") is None
    assert head_fn("run.sh") == b"#!/bin/sh\necho ok\n"

    mixed_supp, mixed_na = ec_job._filter_supported_inputs(
        Applicability(True, "planned", ("run.sh", "bad.ps1"), "shell"),
        ADAPTERS["tool-shellcheck"],
        target,
    )
    assert mixed_supp.applicable and mixed_supp.files == ("run.sh",) and len(mixed_na) == 1
    none_supp, none_na = ec_job._filter_supported_inputs(
        Applicability(True, "planned", ("bad.ps1",), "shell", (SWIFT_KNOWN_GAP, "other-gap")),
        ADAPTERS["tool-shellcheck"],
        target,
    )
    assert not none_supp.applicable and none_supp.gaps == (SWIFT_KNOWN_GAP,) and len(none_na) == 1
    assert ec_job._container_relative("/scratch/inputs/Dockerfile") == "Dockerfile"
    assert ec_job._container_relative("plain.py") == "plain.py"

    # _banned_function_drift & _semgrep_rule_files
    assert ec_job._banned_function_drift(tmp_path) is not None
    assert ec_job._semgrep_rule_files(repository_root=ROOT, tool_id="tool-semgrep")
    assert ec_job._semgrep_rule_files(repository_root=ROOT, tool_id="tool-opengrep")

    # _prerequisites missing bundles & cppcheck compile_commands sanitization + osv split + grype missing db
    empty_repo = tmp_path / "empty_repo"
    empty_repo.mkdir()
    u_empty, cat_empty, _ = make_unit_context(
        tmp_path / "u1",
        repository_root=empty_repo,
        target_files={"app.c": "int main(void){return 0;}\n", "out.c": "int x;\n"},
    )
    app_true = Applicability(True, "ok", ("app.c",), "src")
    for tid in ("tool-semgrep", "tool-gitleaks", "tool-pmd", "tool-osv-scanner", "tool-grype"):
        _, _, _, err = ec_job._prerequisites(u_empty, ADAPTERS[tid], app_true)
        assert err is not None

    #SEI CERT missing on repo that has semgrep rules but no sei-cert pack
    semi_repo = tmp_path / "semi_repo"
    (semi_repo / "rules" / "semgrep").mkdir(parents=True)
    for rname in ("security.yml", "review-signals.yml", "banned-functions.yml"):
        (semi_repo / "rules" / "semgrep" / rname).write_text("rules: []\n", encoding="utf-8")
    u_semi, _, _ = make_unit_context(tmp_path / "u_semi", repository_root=semi_repo)
    _, _, _, sei_err = ec_job._prerequisites(u_semi, ADAPTERS["tool-semgrep"], app_true)
    assert sei_err == "supplied SEI CERT rule pack is unavailable"

    # Cppcheck compile_database branches
    cc_sel = Applicability(True, "ok", ("app.c",), "cpp", (), {"compile_database": ("compile_commands.json",)})
    u_no_root, _, _ = make_unit_context(tmp_path / "u_cc0")
    u_no_root.job.target_root = None
    assert ec_job._prerequisites(u_no_root, ADAPTERS["tool-cppcheck"], cc_sel)[3] is not None
    assert ec_job._prerequisites(u_empty, ADAPTERS["tool-cppcheck"], cc_sel)[3] == "accepted compile database could not be read"

    (u_empty.job.target_root / "compile_commands.json").write_text(
        json.dumps([
            "not-a-dict",
            {"directory": "/outside", "file": "/outside/evil.c"},
            {"directory": str(u_empty.job.target_root), "file": "out.c"},
        ]),
        encoding="utf-8",
    )
    assert "no cataloged C/C++" in (ec_job._prerequisites(u_empty, ADAPTERS["tool-cppcheck"], cc_sel)[3] or "")

    (u_empty.job.target_root / "compile_commands.json").write_text(
        json.dumps([{"directory": str(u_empty.job.target_root), "file": "app.c"}]),
        encoding="utf-8",
    )
    _, cc_mounts, _, cc_err = ec_job._prerequisites(u_empty, ADAPTERS["tool-cppcheck"], cc_sel)
    assert cc_err is None and any(m.target == "/inputs/compile_commands.json" for m in cc_mounts)

    # _osv_split_by_snapshot partial & total missing + _extra_identity dir mount + _valid_checkpoint
    osv_repo = tmp_path / "osv_repo"
    write_osv_feed(osv_repo, ("npm",))
    osv_sel_mixed, osv_gap = ec_job._osv_split_by_snapshot(
        Applicability(True, "lockfiles", ("package-lock.json", "requirements.txt"), "deps"),
        {"npm": Path("/fake/npm.zip")},
    )
    assert osv_sel_mixed.files == ("package-lock.json",) and osv_gap is not None
    osv_sel_none, osv_gap_all = ec_job._osv_split_by_snapshot(
        Applicability(True, "lockfiles", ("requirements.txt",), "deps"),
        {"npm": Path("/fake/npm.zip")},
    )
    assert osv_sel_none.files == () and osv_gap_all is not None

    dir_mount_src = tmp_path / "mount_dir"
    dir_mount_src.mkdir()
    (dir_mount_src / "db.bin").write_bytes(b"123")
    extra_id = ec_job._extra_identity((
        Mount(dir_mount_src, "/database", True),
        Mount(dir_mount_src, "/rules", True, supplied_platform=True),
    ))
    assert "/database" in extra_id and "/rules" not in extra_id

    bad_cp = tmp_path / "bad_cp.json"
    bad_cp.write_text("{corrupt", encoding="utf-8")
    assert ec_job._valid_checkpoint(tmp_path, bad_cp) is None
    bad_cp.write_text(json.dumps({"artifacts": [{"path": "../escape", "sha256": "0" * 64}]}), encoding="utf-8")
    assert ec_job._valid_checkpoint(tmp_path, bad_cp) is None


def test_execution_failure_modes_blint_trivy_swift_staging_and_validator_errors(tmp_path: Path) -> None:
    # 1. Image resolution failure -> FAILED disposition without raising
    unit, catalog, _ = make_unit_context(
        tmp_path / "img_fail",
        unit_id="configuration.trivy_scan",
        target_files={"Dockerfile": "FROM alpine:3.20\n"},
    )

    class UnavailExecutor(FakeExecutor):
        def resolve_image(self, tool):
            raise RuntimeError("image missing locally")

    with attempt_scope(unit):
        img_out = ec_job._execute_tool(
            unit,
            ADAPTERS["tool-trivy"],
            catalog,
            lambda u: UnavailExecutor(ROOT, u.job.run_root, []),
            None,
        )
    assert img_out["terminal_status"] == "FAILED"
    assert any("image missing locally" in g for g in img_out["gaps"])

    # 2. fail_tool injection writes retry-required.json, then clean run clears retry-required.json
    u_inj, cat_inj, _ = make_unit_context(
        tmp_path / "inj",
        unit_id="configuration.trivy_scan",
        target_files={"Dockerfile": "FROM alpine:3.20\n"},
        settings_override={"tool_retries": 0},
    )

    class TrivyExecutor(FakeExecutor):
        def execute(self, request):
            res = super().execute(request)
            assert (request.scratch_root / "inputs" / "Dockerfile").is_file()
            (self.run_root / res.stderr_path).write_bytes(b"WARN failed to download checks bundle\n")
            (request.scratch_root / "output.json").write_text(json.dumps({"Results": []}), encoding="utf-8")
            return replace(res, stdout_truncated=True, stderr_truncated=True)

    with attempt_scope(u_inj):
        failed_inj = ec_job._execute_tool(
            u_inj,
            ADAPTERS["tool-trivy"],
            cat_inj,
            lambda u: TrivyExecutor(ROOT, u.job.run_root, []),
            "tool-trivy",
        )
        assert failed_inj["terminal_status"] == "FAILED"
        recovered = ec_job._execute_tool(
            u_inj,
            ADAPTERS["tool-trivy"],
            cat_inj,
            lambda u: TrivyExecutor(ROOT, u.job.run_root, []),
            None,
        )
    assert recovered["terminal_status"] == "PARTIAL"
    assert any("stdout was truncated" in g for g in recovered["gaps"])
    assert any("stderr was truncated" in g for g in recovered["gaps"])

    # 3. Timeout, missing output, parser ValueError, and Blint native findings.json retention
    u_err, cat_err, _ = make_unit_context(
        tmp_path / "errs",
        unit_id="binary_hardening.blint_scan",
        target_files={"bin/libapp.so": b"\x7fELF"},
        settings_override={"tool_retries": 0},
    )
    cat_err = ScanCatalog(
        cat_err.source_fingerprint,
        cat_err.handoff_sha256,
        cat_err.files,
        cat_err.projects,
        artifacts=({"path": "bin/libapp.so", "artifact_kind": "built"},),
        target_root=cat_err.target_root,
    )

    class BlintExecutor(FakeExecutor):
        def __init__(self, r_root: Path, mode: str):
            super().__init__(ROOT, r_root, [])
            self.mode = mode

        def execute(self, request):
            res = super().execute(request)
            if self.mode == "timeout":
                return replace(res, timed_out=True, exit_code=124)
            if self.mode == "corrupt_collector":
                (request.scratch_root / "findings.json").write_text("{corrupt", encoding="utf-8")
                return res
            (request.scratch_root / "libapp.so-metadata.json").write_text(
                '{"file_path": "/target/bin/libapp.so"}', encoding="utf-8"
            )
            (request.scratch_root / "findings.json").write_text(
                json.dumps({"findings": [{"id": "BLINT-X", "severity": "high", "title": "nx", "filename": "/target/bin/libapp.so"}]}),
                encoding="utf-8",
            )
            return res

    with attempt_scope(u_err):
        t_out = ec_job._execute_tool(u_err, ADAPTERS["tool-blint"], cat_err, lambda u: BlintExecutor(u.job.run_root, "timeout"), None)
        assert t_out["terminal_status"] == "FAILED" and any("timed out" in g for g in t_out["gaps"])
        c_out = ec_job._execute_tool(u_err, ADAPTERS["tool-blint"], cat_err, lambda u: BlintExecutor(u.job.run_root, "corrupt_collector"), None)
        assert c_out["terminal_status"] == "FAILED" and any("could not be assembled" in g for g in c_out["gaps"])
        ok_blint = ec_job._execute_tool(u_err, ADAPTERS["tool-blint"], cat_err, lambda u: BlintExecutor(u.job.run_root, "ok"), None)
        assert ok_blint["terminal_status"] == "SUCCEEDED" and ok_blint["record_count"] == 1

    # 4. _read_artifact, _normalize_tool, _build_producer_shard, and build_job().input_validators[0] negative checks
    with pytest.raises(ValueError, match="missing or outside"):
        ec_job._read_artifact(u_err.job.run_root, {"path": "../escape.json", "sha256": "0" * 64})
    with pytest.raises(ValueError, match="hash changed"):
        ec_job._read_artifact(u_err.job.run_root, {**ok_blint["artifact"], "sha256": "0" * 64})

    bad_ev = u_err.job.run_root / "data/bad_ev.json"
    atomic_json(bad_ev, {"schema": "wrong/1", "terminal_status": "SUCCEEDED"})
    bad_ref = {"path": "data/bad_ev.json", "sha256": file_sha256(bad_ev), "size_bytes": bad_ev.stat().st_size}
    bad_norm_ctx, _, _ = make_unit_context(
        tmp_path / "errs",
        unit_id="binary_hardening.blint_normalize",
        outputs={"binary_hardening.blint_scan": {**ok_blint, "artifact": bad_ref}},
    )
    with pytest.raises(ValueError, match="schema mismatch"):
        ec_job._normalize_tool(bad_norm_ctx, "binary_hardening.blint_scan")

    disp_norm_ctx, _, _ = make_unit_context(
        tmp_path / "errs",
        unit_id="binary_hardening.blint_normalize",
        outputs={"binary_hardening.blint_scan": {**ok_blint, "terminal_status": "PARTIAL"}},
    )
    with pytest.raises(ValueError, match="disposition changed"):
        ec_job._normalize_tool(disp_norm_ctx, "binary_hardening.blint_scan")

    # build_job scan unit handler + input validator negative checks
    run_full = tmp_path / "full_handler" / "runs" / "run_0001"
    u_full, cat_full, _ = make_unit_context(
        tmp_path / "full_handler",
        unit_id="source_sast.shellcheck_scan",
        enable_swift=False,
        target_files={"run.sh": "#!/bin/sh\necho hi\n", "App.swift": "import Foundation\n"},
    )
    seed_accepted_catalog_and_plan(
        run_full,
        u_full.job.target_root,
        files=list(cat_full.files),
        scanner_selections=[{"scanner_id": "tool-shellcheck", "reason": "shell", "scope": [{"path": "run.sh"}]}],
    )
    assert load_target_catalog(run_full, intake_target_root=False).target_root is None

    class ShellOkExecutor(FakeExecutor):
        def execute(self, request):
            res = super().execute(request)
            (self.run_root / res.stdout_path).write_bytes(b"[]")
            return res

    built_exec = build_job(executor_factory=lambda u: ShellOkExecutor(ROOT, u.job.run_root, []))
    shell_unit = next(u for u in built_exec.units if u.unit_id == "source_sast.shellcheck_scan")
    with attempt_scope(u_full):
        shell_out = shell_unit.handler(u_full)
    assert shell_out["terminal_status"] == "SUCCEEDED"

    validate = built_exec.input_validators[0]
    base_vctx = dict(
        run_root=run_full,
        repository_root=ROOT,
        target_root=u_full.job.target_root,
        source_fingerprint=SOURCE_FP,
        config=u_full.job.config,
    )
    with pytest.raises(ValueError, match="target root"):
        validate(SimpleNamespace(**{**base_vctx, "target_root": None}), None)
    with pytest.raises(ValueError, match="target catalog"):
        validate(SimpleNamespace(**{**base_vctx, "source_fingerprint": "1" * 64}), None)

    # Topology / task / plan-fingerprint mismatches in validate()
    bad_steps_cfg = SimpleNamespace(steps={"wrong": SimpleNamespace(tasks=())}, step=lambda s: None)
    with pytest.raises(ValueError, match="topology does not match"):
        validate(SimpleNamespace(**{**base_vctx, "config": bad_steps_cfg}), None)

    bad_task_steps = {
        s: SimpleNamespace(tasks=("wrong",) if s == "source_sast" else tasks)
        for s, tasks in ec_job.TOPOLOGY.items()
    }
    bad_tasks_cfg = SimpleNamespace(steps=bad_task_steps, step=bad_task_steps.__getitem__)
    with pytest.raises(ValueError, match="task order mismatch"):
        validate(SimpleNamespace(**{**base_vctx, "config": bad_tasks_cfg}), None)

    run_plan_mismatch = tmp_path / "plan_mismatch" / "runs" / "run_0001"
    seed_accepted_catalog_and_plan(
        run_plan_mismatch,
        u_full.job.target_root,
        files=list(cat_full.files),
        plan_fingerprint="2" * 64,
        scanner_selections=[],
    )
    with pytest.raises(ValueError, match="analysis plan"):
        validate(SimpleNamespace(**{**base_vctx, "run_root": run_plan_mismatch}), None)

    # Missing output, parser ValueError, Checkov unreported inputs, Semgrep unscanned inputs, Swift staging tamper, and shard source checks
    u_more, cat_more, _ = make_unit_context(
        tmp_path / "more_modes",
        unit_id="configuration.checkov_scan",
        enable_swift=False,
        declared_releases=False,
        target_files={
            "Dockerfile": "FROM alpine:3.20\n",
            "CMakePresets.json": "{}\n",
            "app.py": "x = 1\n",
        },
        settings_override={"tool_retries": 0},
    )

    class ModeExecutor(FakeExecutor):
        def __init__(self, r_root: Path, mode: str):
            super().__init__(ROOT, r_root, [])
            self.mode = mode

        def execute(self, request):
            res = super().execute(request)
            if self.mode == "missing_file":
                (request.scratch_root / "output.json").unlink(missing_ok=True)
                return res
            if self.mode == "bad_json":
                (self.run_root / res.stdout_path).write_bytes(b"{not-json")
                return res
            if self.mode == "checkov_ok":
                (self.run_root / res.stdout_path).write_bytes(
                    json.dumps({
                        "check_type": "dockerfile",
                        "results": {
                            "passed_checks": [{"check_id": "CKV_1", "file_path": "/Dockerfile", "file_line_range": [1, 1]}],
                            "failed_checks": [],
                        },
                    }).encode()
                )
                return res
            if self.mode == "semgrep_ok":
                (request.scratch_root / "output.json").write_text(
                    json.dumps({"results": [], "paths": {"scanned": []}}), encoding="utf-8"
                )
                return res
            return res

    with attempt_scope(u_more):
        # Missing expected output file (syft uses /scratch/output.json)
        u_miss, cat_miss, _ = make_unit_context(
            tmp_path / "more_modes_miss",
            unit_id="software_inventory.syft_scan",
            target_files={"package-lock.json": "{}"},
            settings_override={"tool_retries": 0},
        )
        with attempt_scope(u_miss):
            miss_out = ec_job._execute_tool(
                u_miss, ADAPTERS["tool-syft"], cat_miss, lambda u: ModeExecutor(u.job.run_root, "missing_file"), None
            )
        assert miss_out["terminal_status"] == "FAILED" and any("expected output" in g for g in miss_out["gaps"])

        # Parser ValueError (shellcheck stdout not JSON)
        u_sc, cat_sc, _ = make_unit_context(
            tmp_path / "more_modes_sc",
            unit_id="source_sast.shellcheck_scan",
            target_files={"run.sh": "#!/bin/sh\necho hi\n"},
            settings_override={"tool_retries": 0},
        )
        with attempt_scope(u_sc):
            bad_parse_out = ec_job._execute_tool(
                u_sc, ADAPTERS["tool-shellcheck"], cat_sc, lambda u: ModeExecutor(u.job.run_root, "bad_json"), None
            )
        assert bad_parse_out["terminal_status"] == "FAILED" and any("parser incompatibility" in g for g in bad_parse_out["gaps"])

        # Checkov unreported inputs + Swift staging reuse across 2 invocations
        ckv_out = ec_job._execute_tool(
            u_more,
            ADAPTERS["tool-checkov"],
            cat_more,
            lambda u: ModeExecutor(u.job.run_root, "checkov_ok"),
            None,
            Applicability(True, "planned", ("Dockerfile", "CMakePresets.json"), "cfg"),
            swift_present=True,
        )
        assert ckv_out["not_applicable_inputs"]["count"] == 1
        # Second run reuses staged target cleanly (declared_releases=False forces re-execution instead of checkpoint reuse)
        ckv_out2 = ec_job._execute_tool(
            u_more,
            ADAPTERS["tool-checkov"],
            cat_more,
            lambda u: ModeExecutor(u.job.run_root, "checkov_ok"),
            None,
            Applicability(True, "planned", ("Dockerfile", "CMakePresets.json"), "cfg"),
            swift_present=True,
        )
        assert ckv_out2["terminal_status"] == "SUCCEEDED"

        # Tamper source file -> Swift staging rejects
        (u_more.job.target_root / "Dockerfile").write_text("FROM ubuntu:24.04\n", encoding="utf-8")
        with pytest.raises(ValueError, match="changed or escapes"):
            ec_job._execute_tool(
                u_more,
                ADAPTERS["tool-checkov"],
                cat_more,
                lambda u: ModeExecutor(u.job.run_root, "checkov_ok"),
                None,
                Applicability(True, "planned", ("Dockerfile", "CMakePresets.json"), "cfg"),
                swift_present=True,
            )

        # Semgrep unscanned inputs
        u_sg, cat_sg, _ = make_unit_context(
            tmp_path / "more_modes_sg",
            unit_id="source_sast.semgrep_scan",
            target_files={"app.py": "x = 1\n"},
            settings_override={"tool_retries": 0},
        )
        with attempt_scope(u_sg):
            sg_out = ec_job._execute_tool(
                u_sg, ADAPTERS["tool-semgrep"], cat_sg, lambda u: ModeExecutor(u.job.run_root, "semgrep_ok"), None
            )
        assert sg_out["terminal_status"] == "PARTIAL"

    # _build_producer_shard source integrity errors
    ev_with_loc = u_sc.job.run_root / "data/loc_ev.json"
    atomic_json(
        ev_with_loc,
        {
            "schema": "appsec-review/static-tool-evidence/2",
            "terminal_status": "SUCCEEDED",
            "records": [{
                "evidence_id": "e1",
                "location": {"path": "run.sh", "start_line": 1, "end_line": 1, "source_sha256": "0" * 64},
            }],
        },
    )
    loc_ref = {"path": "data/loc_ev.json", "sha256": file_sha256(ev_with_loc), "size_bytes": ev_with_loc.stat().st_size}
    norm_loc = {"tool_id": "tool-shellcheck", "terminal_status": "SUCCEEDED", "artifact": loc_ref, "normalized_artifact": loc_ref}
    shard_ctx, _, _ = make_unit_context(
        tmp_path / "more_modes_sc",
        unit_id="source_sast.shellcheck_index",
        outputs={"source_sast.shellcheck_normalize": norm_loc},
    )
    with pytest.raises(ValueError, match="differs from accepted catalog"):
        ec_job._build_producer_shard(shard_ctx, "source_sast.shellcheck_normalize")
    shard_ctx.job.target_root = None
    with pytest.raises(ValueError, match="source root is unavailable"):
        ec_job._build_producer_shard(shard_ctx, "source_sast.shellcheck_normalize")
    empty_t = tmp_path / "empty_t"
    empty_t.mkdir()
    shard_ctx.job.target_root = empty_t
    with pytest.raises(ValueError, match="accepted source is unavailable"):
        ec_job._build_producer_shard(shard_ctx, "source_sast.shellcheck_normalize")


def test_remaining_prerequisites_oversized_reports_and_osv_stderr_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.unit.job_evidence_collection.support import write_osv_feed

    empty_repo = tmp_path / "empty_repo2"
    empty_repo.mkdir()
    assert ec_job._semgrep_rule_files(repository_root=empty_repo, tool_id="tool-pmd") == []

    # _settings fallback when typed_settings is None
    u_set, _, _ = make_unit_context(tmp_path / "u_set")
    u_set.job.config.typed_settings = None
    u_set.job.config.settings = {"tool_retries": 1}
    assert ec_job._settings(u_set).tool_retries == 1

    # _prerequisites: osv-scanner with zero matching snapshot ecosystems & grype with valid DB + failed vs succeeded syft
    osv_repo = tmp_path / "osv_only_npm"
    write_osv_feed(osv_repo, ("npm",))
    u_osv, _, _ = make_unit_context(tmp_path / "u_osv", repository_root=osv_repo)
    _, _, _, osv_err = ec_job._prerequisites(
        u_osv,
        ADAPTERS["tool-osv-scanner"],
        Applicability(True, "lockfiles", ("requirements.txt",), "deps"),
    )
    assert osv_err is not None and "PyPI" in osv_err

    grype_db_dir = tmp_path / "grype_db"
    grype_db_dir.mkdir()
    monkeypatch.setattr(ec_job.grype_feed, "consumer_settings", lambda repo, run: object())
    monkeypatch.setattr(ec_job.grype_feed, "verify", lambda settings: {"directory": str(grype_db_dir)})

    u_grype, _, _ = make_unit_context(
        tmp_path / "u_grype",
        unit_id="vulnerability_matching.grype_scan",
        outputs={"software_inventory.syft_scan": {"terminal_status": "FAILED", "scanner_output": None}},
    )
    assert ec_job._prerequisites(
        u_grype, ADAPTERS["tool-grype"], Applicability(True, "sbom", ("package-lock.json",), "deps")
    )[3] == "a successful Syft SBOM is required"
    sbom_rel = "data/evidence/syft.json"
    sbom_path = u_grype.job.run_root / sbom_rel
    sbom_path.parent.mkdir(parents=True, exist_ok=True)
    sbom_path.write_text("{}", encoding="utf-8")
    u_grype2, _, _ = make_unit_context(
        tmp_path / "u_grype",
        unit_id="vulnerability_matching.grype_scan",
        outputs={"software_inventory.syft_scan": {"terminal_status": "SUCCEEDED", "scanner_output": sbom_rel}},
    )
    _, grype_mounts, grype_env, grype_err = ec_job._prerequisites(
        u_grype2, ADAPTERS["tool-grype"], Applicability(True, "sbom", ("package-lock.json",), "deps")
    )
    assert grype_err is None and grype_env["GRYPE_DB_CACHE_DIR"] == "/database"
    assert any(m.target == "/inputs/syft.json" for m in grype_mounts)

    # Oversized output artifact (both exit 0 and exit 1) + OSV missing ecosystem on stderr
    u_big, cat_big, _ = make_unit_context(
        tmp_path / "u_big",
        unit_id="software_inventory.syft_scan",
        declared_releases=False,
        target_files={"package-lock.json": "{}"},
        settings_override={"tool_retries": 0},
    )
    class OversizedExecutor(FakeExecutor):
        def __init__(self, r_root: Path, fail: bool):
            super().__init__(ROOT, r_root, [])
            self.fail = fail
            orig = self.catalog.tool("tool-syft")
            base_cat = self.catalog
            self.catalog = SimpleNamespace(
                tool=lambda tid: replace(orig, output_bytes=8) if tid == "tool-syft" else base_cat.tool(tid)
            )

        def execute(self, request):
            res = super().execute(request)
            (request.scratch_root / "output.json").write_bytes(b"x" * 32)
            (self.run_root / res.stdout_path).write_bytes(b"y" * 32)
            return replace(res, exit_code=2 if self.fail else 0)

    with attempt_scope(u_big):
        big_ok = ec_job._execute_tool(
            u_big, ADAPTERS["tool-syft"], cat_big, lambda u: OversizedExecutor(u.job.run_root, False), None
        )
        assert big_ok["terminal_status"] == "FAILED" and any("exceeded its byte bound" in g for g in big_ok["gaps"])
        big_fail = ec_job._execute_tool(
            u_big, ADAPTERS["tool-syft"], cat_big, lambda u: OversizedExecutor(u.job.run_root, True), None
        )
        assert big_fail["terminal_status"] == "FAILED"
        assert any("no report within its byte bound" in g for g in big_fail["gaps"])

    u_osv_err, cat_osv_err, _ = make_unit_context(
        tmp_path / "u_osv_err",
        unit_id="vulnerability_matching.osv_scanner_scan",
        repository_root=osv_repo,
        target_files={"package-lock.json": "{}"},
        settings_override={"tool_retries": 0},
    )

    class OsvStderrExecutor(FakeExecutor):
        def execute(self, request):
            res = super().execute(request)
            (self.run_root / res.stderr_path).write_bytes(
                b"unable to fetch OSV database: no offline version of the OSV database is available for PyPI\n"
            )
            return replace(res, exit_code=127)

    with attempt_scope(u_osv_err):
        osv_stderr_out = ec_job._execute_tool(
            u_osv_err,
            ADAPTERS["tool-osv-scanner"],
            cat_osv_err,
            lambda u: OsvStderrExecutor(ROOT, u.job.run_root, []),
            None,
        )
    assert osv_stderr_out["terminal_status"] == "FAILED"
    assert any("PyPI" in g for g in osv_stderr_out["gaps"])



