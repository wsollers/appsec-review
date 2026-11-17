"""Unit tests for packaged secret, container config, and ELF hardening lead promotion (T-171)."""

from __future__ import annotations

import struct

from appsec_review.interchange import ArtifactReference, NativeResultReference, ResultSelector
from appsec_review.jobs.job_artifact_security_analysis.findings import (
    classify_artifact_lead_promotion,
    scan_records,
)
from appsec_review.jobs.job_artifact_security_analysis.formats import (
    inspect_elf_hardening_indicators,
    inspect_packaged_text_risks,
)


def _minimal_elf64(*, e_type: int = 2, exec_stack: bool = True, include_relro: bool = False, include_canary: bool = False) -> bytes:
    ph_entries = [
        # PT_GNU_STACK (0x6474e551), p_flags = PF_R|PF_W|(PF_X if exec_stack)
        struct.pack("<IIQQQQQQ", 0x6474E551, 0x7 if exec_stack else 0x6, 0, 0, 0, 0, 0, 0x10),
    ]
    if include_relro:
        ph_entries.append(struct.pack("<IIQQQQQQ", 0x6474E552, 0x4, 0, 0, 0, 0, 0, 0x1))
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
        e_type,
        0x3E,
        1,
        0x400000,
        64,  # e_phoff
        0,
        0,
        64,
        56,  # e_phentsize
        len(ph_entries),
        0,
        0,
        0,
    )
    tail = b"\x00__stack_chk_fail\x00" if include_canary else b"\x00main\x00"
    return header + b"".join(ph_entries) + tail


def test_packaged_secrets_and_dangerous_container_configs_emit_lead_metadata() -> None:
    config_text = "\n".join(
        [
            "FROM ubuntu:22.04",
            "USER root",
            "EXPOSE 8080 9229",
            "ENV JWT_SECRET=super_secret_production_signing_key_12345",
            "# -----BEGIN RSA PRIVATE KEY-----",
        ]
    )
    compose_text = "services:\n  api:\n    privileged: true\n    network_mode: host\n"
    risks = inspect_packaged_text_risks(config_text, member_path="Dockerfile") + inspect_packaged_text_risks(
        compose_text, member_path="docker-compose.yml"
    )
    by_check = {r["check_id"]: r for r in risks}
    assert by_check["SECRET_PRIVATE_KEY"]["lead_candidate"] is True
    assert by_check["SECRET_PRIVATE_KEY"]["attack_class"] == "packaged_hardcoded_secret"
    assert by_check["SECRET_PRIVATE_KEY"]["severity_hint"] == "critical"
    assert by_check["SECRET_HARDCODED_CREDENTIAL"]["lead_candidate"] is True

    assert by_check["CONTAINER_PRIVILEGED_MODE"]["lead_candidate"] is True
    assert by_check["CONTAINER_PRIVILEGED_MODE"]["attack_class"] == "dangerous_container_configuration"
    assert by_check["CONTAINER_PRIVILEGED_MODE"]["severity_hint"] == "critical"
    assert by_check["CONTAINER_ROOT_USER"]["lead_candidate"] is True
    assert by_check["CONTAINER_DEBUG_PORT"]["port"] == "9229"
    assert by_check["CONTAINER_HOST_NETWORK"]["lead_candidate"] is True


def test_elf_missing_nx_pie_relro_canary_and_blint_scan_records_promote_leads() -> None:
    unhardened = _minimal_elf64(e_type=2, exec_stack=True, include_relro=False, include_canary=False)
    elf_risks = inspect_elf_hardening_indicators(unhardened, binary_name="daemon")
    checks = {r["check_id"]: r for r in elf_risks}
    assert {"CHECK_PIE", "CHECK_NX", "CHECK_RELRO", "CHECK_CANARY"} <= set(checks)
    assert checks["CHECK_NX"]["severity_hint"] == "critical"
    assert all(r["lead_candidate"] is True and r["attack_class"] == "binary_missing_hardening" for r in elf_risks)

    hardened = _minimal_elf64(e_type=3, exec_stack=False, include_relro=True, include_canary=True)
    assert inspect_elf_hardening_indicators(hardened, binary_name="hardened_daemon") == []

    native_ref = NativeResultReference(
        ArtifactReference("a", "1" * 64, 10),
        ResultSelector("document"),
        "p/1",
        ArtifactReference("e", "3" * 64, 10),
        ArtifactReference("r", "2" * 64, 10),
        True,
    ).as_dict()
    summary, findings = scan_records(
        {
            "artifact": {"path": "data/build/daemon", "canonical_identity": "asr:artifact:daemon"},
            "classification": {"format": "elf"},
            "capability": "blint",
            "fingerprint": "b" * 64,
            "scanner_identity": "s/1",
            "tool_identity": {"scanner": "tool-blint"},
            "gaps": [],
            "raw_artifacts": [],
            "attempt_identity": "a" * 64,
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 5,
            "result_artifact": {"path": "res.json", "sha256": "4" * 64, "size_bytes": 20},
            "native_output": native_ref,
            "observation": {
                "findings": [
                    {"id": "CHECK_NX", "severity": "critical", "title": "NX disabled", "exe_name": "daemon"},
                    {"id": "CHECK_PIE", "severity": "high", "title": "No PIE", "exe_name": "daemon"},
                ],
                "security_risks": inspect_packaged_text_risks("privileged: true\n", member_path="compose.yml"),
            },
        }
    )
    assert summary.payload.get("lead_candidate") is None
    assert len(findings) == 3
    assert findings[0].payload["lead_candidate"] is True
    assert findings[0].payload["attack_class"] == "binary_missing_hardening"
    assert findings[0].payload["severity_hint"] == "critical"
    assert findings[2].payload["attack_class"] == "dangerous_container_configuration"
    assert classify_artifact_lead_promotion(category="vulnerability_matching", check_id="CVE-1", severity="low")["lead_candidate"] is False
