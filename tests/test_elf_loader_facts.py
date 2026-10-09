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


def _dynamic(data: bytes) -> tuple[int, int]:
    """File offset of the dynamic section and of its string table in a `minimal_elf` image."""
    count, = struct.unpack_from("<H", data, 0x38)
    start = 64 + count * 56
    index = 0
    while struct.unpack_from("<q", data, start + index * 16)[0] != 5:
        index += 1
    return start, struct.unpack_from("<Q", data, start + index * 16 + 8)[0]


def _entry(data: bytes, tag: int) -> int:
    start, _table = _dynamic(data)
    index = 0
    while struct.unpack_from("<q", data, start + index * 16)[0] != tag:
        index += 1
    return start + index * 16


def test_loader_facts_reads_the_interpreter_inside_its_segment(tmp_path: Path) -> None:
    path = tmp_path / "dynamic"
    path.write_bytes(minimal_elf(interpreter="/lib64/ld-linux-x86-64.so.2"))
    facts = elf.loader_facts(path)
    assert facts["interpreter"] == "/lib64/ld-linux-x86-64.so.2" and facts["needed"] == ["libc.so.6"]


def test_loader_facts_never_reads_a_name_from_outside_the_declared_string_table(tmp_path: Path) -> None:
    # Bytes that follow the string table hold a plausible name a lax reader would publish.
    image = minimal_elf(("libc.so.6",)) + b"libplanted.so\0"
    _start, table = _dynamic(image)
    table_size = len(b"\0libc.so.6\0")
    planted = bytearray(image)
    struct.pack_into("<Q", planted, _entry(image, 1) + 8, table_size)   # DT_NEEDED -> first byte past the table
    struct.pack_into("<Q", planted, 0x60, len(planted))                 # PT_LOAD p_filesz covers the planted bytes
    path = tmp_path / "planted"
    path.write_bytes(bytes(planted))
    assert bytes(planted)[table + table_size:].startswith(b"libplanted.so")
    with pytest.raises(ValueError, match="outside its declared region"):
        elf.loader_facts(path)


def _without_string_size(image: bytearray) -> None:
    struct.pack_into("<q", image, _entry(bytes(image), 10), 0x6FFFFFFF)  # DT_STRSZ -> an ignored tag


def _oversized_string_table(image: bytearray) -> None:
    struct.pack_into("<Q", image, _entry(bytes(image), 10) + 8, 1 << 20)


def _unterminated_final_string(image: bytearray) -> None:
    image[-1] = ord("x")


def _name_straddling_the_table_end(image: bytearray) -> None:
    struct.pack_into("<Q", image, _entry(bytes(image), 10) + 8, 5)       # table ends inside "libc.so.6"


@pytest.mark.parametrize(("mutate", "message"), [
    (_without_string_size, "address or size is missing"),
    (_oversized_string_table, "not mapped by a loadable segment"),
    (_unterminated_final_string, "unterminated within its declared region"),
    (_name_straddling_the_table_end, "unterminated within its declared region"),
], ids=["no-strsz", "strsz-past-segment", "unterminated", "straddles-table-end"])
def test_loader_facts_requires_every_name_to_terminate_inside_the_string_table(
        tmp_path: Path, mutate, message: str) -> None:
    image = bytearray(minimal_elf(("libc.so.6",)))
    mutate(image)
    path = tmp_path / "bounded"
    path.write_bytes(bytes(image))
    with pytest.raises(ValueError, match=message):
        elf.loader_facts(path)


def test_loader_facts_bounds_the_interpreter_to_its_segment(tmp_path: Path) -> None:
    image = bytearray(minimal_elf(interpreter="/lib64/ld-linux-x86-64.so.2") + b"trailing\0")
    image[len(image) - len(b"trailing\0") - 1] = ord("!")   # drop the terminator inside PT_INTERP
    path = tmp_path / "interp"
    path.write_bytes(bytes(image))
    with pytest.raises(ValueError, match="unterminated within its declared region"):
        elf.loader_facts(path)


def test_catalog_reports_an_out_of_table_dependency_as_unparsed_not_resolved(tmp_path: Path) -> None:
    image = bytearray(minimal_elf(("libc.so.6",)) + b"libplanted.so\0")
    struct.pack_into("<Q", image, _entry(bytes(image), 1) + 8, len(b"\0libc.so.6\0"))
    struct.pack_into("<Q", image, 0x60, len(image))
    (tmp_path / "app").write_bytes(bytes(image))
    artifacts, gaps = _catalog(tmp_path, tmp_path, {}, 100, "build-unit-fixture")
    assert artifacts[0]["loader_dependency_status"] == "unparsed"
    assert artifacts[0]["loader_dependencies"] == [] and "libplanted" not in str(artifacts)
    assert len(gaps) == 1 and "loader dependencies were not parseable" in gaps[0]


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
