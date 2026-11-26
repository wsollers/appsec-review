"""Focused unit tests for post-build inference compaction budgets, topology counts, and truncation gaps."""
from __future__ import annotations

from appsec_review.interchange import GapCode
from appsec_review.jobs.job_post_build_security_assessment.assessment import GUIDANCE_IDENTITY
from appsec_review.jobs.job_post_build_security_assessment.job import (
    _compact_inference_request,
    _compaction_gap_details,
)
from appsec_review.storage import canonical_json


def test_post_build_compact_inference_request_fits_token_safe_budget_and_keeps_failures() -> None:
    assert GUIDANCE_IDENTITY == "build-security-inference-guidance/2"
    big_symbols = [f"_Z6symbol_{i:04d}v" for i in range(600)]
    request = {
        "project_id": "root",
        "build_system": "cmake",
        "topology": {"actions": 60, "artifacts": 40},
        "actions": [
            {
                "build_action_id": f"act-{i:03d}",
                "classification": "compile" if i < 32 else "unknown",
                "toolchain": {"executable": "/usr/bin/clang++", "extra_blob": "x" * 2000},
                "argv": ["clang++", "-O2", "-g", f"src/file_{i}.cpp"],
                "discovered_inputs": [f"/usr/include/header_{j}.h" for j in range(150)],
                "outputs": [f"build/file_{i}.o"],
                "compile_unit_id": f"cu-{i:03d}",
            }
            for i in range(60)
        ],
        "artifacts": [
            {
                "artifact_id": f"art-{i:03d}",
                "sha256": f"{i:064x}",
                "format": "ELF",
                "kind": "executable" if i < 2 else "object",
                "architecture": "x86_64",
                "bits": 64,
                "debug": {"has_dwarf": True},
                "hardening": {"pie": i == 0, "nx": True, "relro": "full"},
                "symbols": big_symbols,
                "exports": big_symbols,
                "imports": big_symbols,
                "sections": [f".text.{j}" for j in range(200)],
                "gaps": [],
            }
            for i in range(40)
        ],
        "deterministic_results": [
            {
                "check_id": "HARDENING_PIE" if i < 5 else "HARDENING_NX",
                "scope": f"art-{i % 40:03d}",
                "status": "FAIL" if i < 5 else ("NOT_APPLICABLE" if i % 3 == 0 else "PASS"),
                "evidence": [f"evidence-{i}"],
                "verbose_blob": "y" * 500,
            }
            for i in range(700)
        ],
        "coverage_gaps": [f"gap-{i}" for i in range(80)],
    }
    raw = canonical_json(request)
    assert len(raw) > 500_000

    compacted, encoded = _compact_inference_request(request, 32_000 * 4)
    assert len(encoded) <= 40_000
    fail_checks = [c for c in compacted["deterministic_results"] if c["status"] == "FAIL"]
    assert len(fail_checks) == 5
    assert all("symbols" not in art and "sections" not in art for art in compacted["artifacts"])
    assert all(act["classification"] != "unknown" for act in compacted["actions"])
    assert compacted["topology"]["compacted"] is True
    assert compacted["topology"]["raw_actions"] == 60
    assert compacted["topology"]["raw_artifacts"] == 40
    assert compacted["topology"]["raw_deterministic_results"] == 700

    gap_info = _compaction_gap_details(compacted, unit_id="inference.native_units", scope_id="root")
    assert gap_info is not None
    assert gap_info["producer_gap"]["code"] == GapCode.TRUNCATED.value
    assert "actions=" in gap_info["message"]
    assert "deterministic_results=" in gap_info["message"]


def test_compact_inference_request_caps_over_500_artifacts_prefers_linked_binaries_and_converges() -> None:
    request = {
        "schema": "appsec-review/build-security-inference-request/1",
        "guidance": GUIDANCE_IDENTITY,
        "case_id": "mega-native",
        "topology": {"actions": 300, "artifacts": 600},
        "actions": [
            {
                "build_action_id": f"act-{i:04d}",
                "classification": "linker" if i < 6 else "compiler",
                "toolchain": {"executable": "/usr/bin/clang++"},
                "argv": ["clang++", "-O2", "-fstack-protector-strong", f"src/unit_{i:04d}.cpp"],
                "outputs": [f"build/unit_{i:04d}.o"],
                "compile_unit_id": f"cu-{i:04d}",
            }
            for i in range(300)
        ],
        "artifacts": [
            {
                "artifact_id": f"art-{i:04d}",
                "sha256": f"{i + 1:064x}",
                "format": "ELF",
                "kind": ("executable" if i == 598 else ("shared_library" if i == 599 else "object")),
                "architecture": "x86_64",
                "bits": 64,
                "rpath": "/opt/custom/lib",
                "dependencies": ["libc.so.6", "libpthread.so.0", "libssl.so.3"],
                "debug": {"has_dwarf": True, "dwarf_version": 5},
                "hardening": {"pie": False, "nx": True, "relro": "partial", "canary": True, "fortify": False},
                "imports": [f"imp_{j}" for j in range(40)],
                "exports": [f"exp_{j}" for j in range(40)],
                "gaps": ["probe note"],
            }
            for i in range(600)
        ],
        "deterministic_results": [
            {
                "check_id": f"CHECK_{i:03d}",
                "scope": f"art-{i:04d}",
                "status": "FAIL",
                "severity": "MEDIUM",
                "evidence": [f"ev-{i:04d}-a", f"ev-{i:04d}-b"],
                "message": "missing PIE hardening on binary artifact " + ("z" * 120),
            }
            for i in range(80)
        ],
        "coverage_gaps": [f"upstream gap {i:03d}: missing auxiliary linker map" for i in range(300)],
    }

    compacted, encoded = _compact_inference_request(request, 32_000 * 4)
    assert len(encoded) <= 40_000
    assert len(compacted["artifacts"]) < 600
    submitted_ids = {item["artifact_id"] for item in compacted["artifacts"]}
    assert "art-0598" in submitted_ids
    assert "art-0599" in submitted_ids

    topo = compacted["topology"]
    assert topo["compacted"] is True
    assert topo["raw_artifacts"] == 600
    assert topo["submitted_artifacts"] == len(compacted["artifacts"])
    assert topo["raw_deterministic_results"] == 80
    assert topo["submitted_deterministic_results"] == len(compacted["deterministic_results"])

    gap_info = _compaction_gap_details(compacted, unit_id="inference.native_units", scope_id="mega-native")
    assert gap_info is not None
    assert gap_info["producer_gap"]["code"] == GapCode.TRUNCATED.value
    assert f"artifacts={len(compacted['artifacts'])}/600" in gap_info["message"]

    # Also verify extreme tight budget (4096 bytes) still converges <= target_bytes
    tiny_doc, tiny_enc = _compact_inference_request(request, 4096)
    assert len(tiny_enc) <= 4096
