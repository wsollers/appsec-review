"""Acceptance tests for gap punch list P01-P06 (binary evidence and LLVM IR facts).

docs/TODO/gap-punchlist-hello-autotools-2026-10-03.md. Each test encodes the behaviour wanted
after the fix and is an expected failure until then.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import binary_evidence_adapter as adapter  # noqa: E402
import binary_evidence_core as core  # noqa: E402
import ir_evidence as ir  # noqa: E402
from execution_state import atomic_json  # noqa: E402
from test_binary_evidence_core import BINARY, H, H2, H3, NATIVE, inputs, raw  # noqa: E402

ADAPTER_BINARY = {"binary_id": BINARY["binary_id"], "sha256": H,
                  "build_identity_sha256": H2}
CHECKSEC = "Full RELRO Canary found NX enabled PIE enabled\n"


def _evidence(root: Path, *, summary=None, nm="0000000000001000 T main\n",
              die=None, strings=None) -> Path:
    out = root / "scratch/evidence"; out.mkdir(parents=True)
    atomic_json(out / "summary.json", summary or {"format": "elf", "machine": "EM_X86_64",
        "sections": [".interp", ".text", ".rodata", ".data", ".bss", ".debug_info"],
        "symbol_count": 2, "has_debug_sections": True, "lief": {"libraries": ["libc.so.6"]}})
    (out / "nm-symbols.txt").write_text(nm, encoding="utf-8")
    (out / "checksec.txt").write_text(CHECKSEC, encoding="utf-8")
    if die is not None:
        atomic_json(out / "die.json", die)
    if strings is not None:
        (out / "strings.txt").write_text(strings, encoding="utf-8")
    return out


def _debug_record_fields(record: dict) -> dict:
    return {key: value for key, value in record.items()
            if key not in {"binary_id", "binary_sha256", "build_identity_sha256"}}


class BinaryEvidencePunchListTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(); self.root = Path(self.folder.name)

    def tearDown(self): self.folder.cleanup()

    def test_p01_die_without_packer_reads_packed_no(self):
        """P01: DIE parsed with no packer plus normal ELF sections classifies packed NO without a gap."""
        out = _evidence(self.root,
            die={"detects": [{"values": [{"type": "Compiler", "name": "GCC"}]}]},
            strings="GCC: (GNU) 13.2.0\nmain\n")
        record = adapter._triage_record(ADAPTER_BINARY, out)
        self.assertEqual(record["packed"], "NO")
        self.assertNotIn("static-packer-classification-inconclusive", record["gaps"])

    def test_p01_upx_marker_reads_packed_yes(self):
        """P01: a UPX! marker in strings.txt classifies the binary as packed YES."""
        out = _evidence(self.root,
            die={"detects": [{"values": [{"type": "Compiler", "name": "GCC"}]}]},
            strings="$Info: This file is packed with the UPX executable packer $\nUPX!\n")
        record = adapter._triage_record(ADAPTER_BINARY, out)
        self.assertEqual(record["packed"], "YES")

    def test_p02_stt_file_symbols_are_skipped_and_not_duplicates(self):
        """P02: nm kind 'a' (STT_FILE) entries are skipped so crtstuff.c does not raise duplicate-symbol-identity."""
        out = _evidence(self.root, nm="0000000000000000 a crtstuff.c\n"
                        "0000000000000000 a crtstuff.c\n0000000000001000 T main\n")
        record = _debug_record_fields(adapter._debug_record(ADAPTER_BINARY, out))
        job = "02-debug-symbol-index"
        normalized = core.normalize(job, inputs(job, raw(job, record)), "a-debug")["records"][0]
        self.assertEqual([item["name"] for item in normalized["symbols"]], ["main"])
        self.assertNotIn("duplicate-symbol-identity", normalized["gaps"])

    def test_p03_nm_line_location_becomes_repo_relative_source(self):
        """P03: a trailing nm -l file:line under /scratch/src/ yields a repo-relative source_path and line."""
        out = _evidence(self.root, nm="0000000000001000 T main\t/scratch/src/src/main.cpp:12\n")
        record = adapter._debug_record(ADAPTER_BINARY, out)
        symbol = record["symbols"][0]
        self.assertEqual(symbol["source_path"], "src/main.cpp")
        self.assertEqual(symbol["line"], 12)
        self.assertNotIn("source-locations-unavailable", record["gaps"])

    def test_p06_enabled_hardening_is_a_confirmed_defense_lead(self):
        """P06: hardening values ENABLED/FULL/PRESENT produce defense leads, not 'not confirmed' follow-ups."""
        image = raw("02-binary-triage", {})["image"]
        projection = raw("02-binary-triage", {})["native_build"]
        triage = {"native_build": projection, "image": image, "records": [{
            "binary_id": BINARY["binary_id"], "triage_id": "triage_" + "a" * 16,
            "hardening": {"nx": "ENABLED", "pie": "ENABLED", "relro": "FULL",
                          "stack_canary": "PRESENT"}, "imports": [], "gaps": []}]}
        cfg = {"native_build": projection, "image": image, "records": [{
            "binary_id": BINARY["binary_id"], "functions": [], "edges": [], "gaps": []}]}
        upstream = {
            "02-binary-triage": {"attempt_id": "a-triage", "result_sha256": H3, "result": triage},
            "02-binary-cfg": {"attempt_id": "a-cfg", "result_sha256": H2, "result": cfg}}
        derived = core._derive_intelligence_raw(copy.deepcopy(NATIVE), upstream)
        leads = {record["subject"].split(":")[0].rsplit(" ", 1)[-1]: record
                 for record in derived["records"]
                 if record["subject"].startswith("Binary hardening property")}
        self.assertEqual(set(leads), {"nx", "pie", "relro", "stack_canary"})
        for check, lead in sorted(leads.items()):
            self.assertNotIn("not confirmed", lead["subject"], check)
            self.assertEqual(lead["lead_type"], "defense", check)


H_MOD = "sha256:" + "c" * 64
LINEAGE = {"job_id": "02-ir-link", "attempt_id": "link-1", "accepted_pointer_sha256": H,
           "envelope_sha256": H2, "result_sha256": H3, "input_fingerprint": H}

P04_IR = """\
define i32 @main() !dbg !10 {
  %1 = load i32, ptr @g, align 4, !dbg !20
  store i32 1, ptr @g, align 4, !dbg !21
  ret i32 0
}
!3 = !DIFile(filename: "pointer.c", directory: "/workspace")
!10 = distinct !DISubprogram(name: "main", scope: !3, file: !3, line: 1, unit: !2)
!20 = distinct !DILocation(line: 5, column: 3, scope: !10)
!21 = !DILocation(line: 0, scope: !10)
"""

P05_IR = """\
define i32 @main() !dbg !10 {
  %1 = load i64, ptr %s, align 8, !dbg !21
  ret i32 0
}
!3 = !DIFile(filename: "pointer.c", directory: "/workspace")
!4 = !DIFile(filename: "/usr/include/c++/13/bits/basic_string.h", directory: "")
!10 = distinct !DISubprogram(name: "main", scope: !3, file: !3, line: 1, unit: !2)
!11 = distinct !DISubprogram(name: "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4sizeEv", scope: !4, file: !4, line: 1070, unit: !2)
!20 = !DILocation(line: 7, column: 5, scope: !10)
!21 = !DILocation(line: 1072, column: 16, scope: !11, inlinedAt: !20)
"""


class TextToolchain:
    """Returns hand-written IR text in place of llvm-dis; no LLVM toolchain is needed."""
    image_id = "image_build_aaaaaaaaaaaa"; image_digest = "sha256:" + "4" * 64
    toolchain_sha256 = "sha256:" + "d" * 64

    def __init__(self, text: str): self.text = text

    def disassemble(self, module): return self.text


class IrFactsPunchListTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(); self.target = Path(self.folder.name)
        (self.target / "pointer.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")

    def tearDown(self): self.folder.cleanup()

    def _facts(self, text: str) -> dict:
        toolchain = TextToolchain(text)
        linked = {"source_revision": "a" * 40, "source_snapshot_sha256": H,
            "source_tree_sha256": H2, "checkout_identity_sha256": H2,
            "toolchain_sha256": toolchain.toolchain_sha256, "image_id": toolchain.image_id,
            "image_digest": toolchain.image_digest, "variant_sha256": H3,
            "linked_module": {"path": "linked/application.bc", "sha256": H3},
            "sources": [{"module_id": "mod_pointer", "path": "pointer.c", "sha256": H_MOD}],
            "coverage_gaps": []}
        with mock.patch.object(ir, "_accepted", return_value=(self.target, linked, LINEAGE)), \
             mock.patch.object(ir, "_require_current_source", return_value=self.target), \
             mock.patch.object(ir, "_verify_artifact", return_value=self.target / "application.bc"):
            return ir.facts("run", self.target, toolchain=toolchain)

    @unittest.expectedFailure
    def test_p04_distinct_and_columnless_dilocations_map_to_source(self):
        """P04: distinct !DILocation and !DILocation(line: 0, scope: ...) enter the location map."""
        result = self._facts(P04_IR)
        reasons = [gap["reason"] for gap in result["coverage_gaps"]]
        self.assertNotIn("fact-source-ambiguous", reasons, json.dumps(result["coverage_gaps"]))
        self.assertEqual({fact["source_path"] for fact in result["facts"]}, {"pointer.c"})

    @unittest.expectedFailure
    def test_p05_inlined_header_location_follows_inlined_at_to_checkout(self):
        """P05: a header-scoped location inlined into pointer.c is attributed to pointer.c via inlinedAt."""
        result = self._facts(P05_IR)
        reasons = [gap["reason"] for gap in result["coverage_gaps"]]
        self.assertNotIn("debug-location-source-ambiguous", reasons,
                         json.dumps(result["coverage_gaps"]))
        self.assertEqual([fact["source_path"] for fact in result["facts"]], ["pointer.c"])


if __name__ == "__main__": unittest.main()
