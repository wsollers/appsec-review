from __future__ import annotations

from pathlib import Path
import struct
import sys

import pytest

from appsec_review.jobs.job_language_build import elf
from appsec_review.jobs.job_language_build.job import _catalog
from tests.capture_fakes import minimal_elf


def test_loader_facts_reads_needed_libraries_in_declared_order(tmp_path: Path) -> None:
    path = tmp_path / "sample"
    path.write_bytes(minimal_elf(("libgcc_s.so.1", "libc.so.6")))
    assert elf.loader_facts(path) == {"needed": ["libgcc_s.so.1", "libc.so.6"], "interpreter": None,
                                      "soname": None, "run_paths": [], "linkage": "dynamic"}


@pytest.mark.skipif(sys.platform != "linux", reason="reads the running ELF interpreter")
def test_loader_facts_agree_with_a_real_dynamic_executable() -> None:
    facts = elf.loader_facts(Path(sys.executable).resolve())
    assert facts["linkage"] == "dynamic" and facts["interpreter"].startswith("/lib")
    assert any(name.startswith("libc.so") for name in facts["needed"])


def test_loader_facts_reports_a_file_without_a_dynamic_segment_as_static(tmp_path: Path) -> None:
    data = bytearray(minimal_elf(()))
    struct.pack_into("<H", data, 0x38, 1)  # keep only the PT_LOAD program header
    path = tmp_path / "static"
    path.write_bytes(bytes(data))
    assert elf.loader_facts(path)["linkage"] == "static"
    assert elf.loader_facts(path)["needed"] == []


@pytest.mark.parametrize("data", [
    b"\x7fELFrust",
    b"\x7fELF" + bytes([3, 1]) + bytes(58),
    minimal_elf()[:100],
    minimal_elf()[:-12] + b"x" * 12,
], ids=["short", "class", "truncated", "unterminated-string"])
def test_loader_facts_rejects_malformed_files(tmp_path: Path, data: bytes) -> None:
    path = tmp_path / "broken"
    path.write_bytes(data)
    with pytest.raises(ValueError):
        elf.loader_facts(path)


def test_loader_facts_bounds_the_program_header_table(tmp_path: Path) -> None:
    data = bytearray(minimal_elf())
    struct.pack_into("<H", data, 0x38, 0xFFFF)
    path = tmp_path / "many-headers"
    path.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="program header table"):
        elf.loader_facts(path)


def test_catalog_resolves_loader_dependencies_and_names_unparseable_outputs(tmp_path: Path) -> None:
    (tmp_path / "app").write_bytes(minimal_elf(("libssl.so.3",)))
    (tmp_path / "broken").write_bytes(b"\x7fELFfixture")
    artifacts, gaps = _catalog(tmp_path, tmp_path, {}, 100, "build-unit-fixture")
    by_path = {item["workspace_path"]: item for item in artifacts}
    assert by_path["app"]["loader_dependencies"] == ["libssl.so.3"]
    assert by_path["app"]["loader_dependency_status"] == "resolved"
    assert by_path["app"]["loader_parser"] == elf.PARSER_IDENTITY
    assert by_path["broken"]["loader_dependency_status"] == "unparsed"
    assert len(gaps) == 1 and gaps[0].startswith("broken: loader dependencies were not parseable")
