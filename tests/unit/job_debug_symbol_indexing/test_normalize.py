"""Source binding during normalization: a recorded span becomes an exact ``source_span`` only when
its checksum matches accepted source bytes from the run's own index; recorded private paths never
reach the normalized shard."""
from __future__ import annotations

import hashlib
import json

import pytest

from appsec_review.debug_symbols.contract import (
    AddressRange, Extraction, RecordKind, SourceSpan, SymbolRecord,
)
from appsec_review.retrieval import EntityKind, LogicalIdentity
from tests.unit.job_debug_symbol_indexing.support import (
    ELF, SNAPSHOT, accepted_inputs, artifact, build_job, decide, extracted, handlers, job_context, manifest, payloads,
    shard, source_shard, unit,
)

CONTENT = b"int main() {\n  return 0;\n}\n"


def _extract(tmp_path, monkeypatch, records, *, content=CONTENT, store_object=True, source_path="src/main.cc",
             text=None):
    context = job_context(tmp_path)
    run_root = context.run_root
    shard_identity = source_shard(run_root, content, path=source_path, store_object=store_object, text=text)
    binary = artifact(run_root, "bin/program", ELF)
    job = build_job(extractor=lambda *a, **k: extracted(records))
    decision = decide(monkeypatch, job, context, accepted_inputs([binary], manifest(run_root, [shard_identity])))
    result = handlers(job)["extract.clang_dwarf"](unit(context, "extract.clang_dwarf", {"decide.target": decision}))
    return context, binary, result


@pytest.mark.parametrize("algorithm", ["sha256", "md5"])
def test_checksum_binds_source_ranges_to_accepted_source_bytes(tmp_path, monkeypatch, algorithm):
    checksum = hashlib.new(algorithm, CONTENT).hexdigest()
    records = (SymbolRecord("line:1", RecordKind.SOURCE_RANGE, ranges=(AddressRange(4096, 4100),),
                            source=SourceSpan("C:\\private-secret\\src\\main.cc", 2, checksum=checksum.upper(),
                                              checksum_kind=algorithm.upper())),)
    context, binary, result = _extract(tmp_path, monkeypatch, records)
    assert result["terminal_status"] == "SUCCEEDED" and result["gaps"] == []
    expected = LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT,
                                      {"path": "src/main.cc", "sha256": hashlib.sha256(CONTENT).hexdigest()})
    with shard(context, result) as database:
        identity, kind, payload_json = database.execute("SELECT identity, kind, payload_json FROM entities").fetchone()
        payload = json.loads(payload_json)
        assert kind == "source_span" and "private-secret" not in payload_json
        assert (payload["source_identity"], payload["source_path"], payload["source_mapping"], payload["line"]) == (
            expected.value, "src/main.cc", "checksum-verified", 2)
        assert payload["source_name_sha256"] == hashlib.sha256(b"C:\\private-secret\\src\\main.cc").hexdigest()
        location = database.execute("SELECT path, file_sha256, start_byte, end_byte, start_line FROM locations WHERE entity_id=?",
                                    (identity,)).fetchone()
        assert location == ("src/main.cc", hashlib.sha256(CONTENT).hexdigest(), 13, 25, 2)
        relations = database.execute("SELECT kind, target_id FROM relations ORDER BY kind").fetchall()
        assert relations == [("DERIVED_FROM", binary["artifact_identity"]), ("OBSERVED_AT", expected.value)]
        assert "private-secret" not in json.dumps(database.execute("SELECT * FROM search_fts").fetchall())


def test_unbound_private_paths_never_enter_normalized_sqlite(tmp_path, monkeypatch):
    private = "C:\\private-secret\\build\\main.cc"
    records = (SymbolRecord("source:1", RecordKind.COMPILATION_UNIT, private, source=SourceSpan(private, 3),
                            data={"compilation_directory": "C:\\private-secret\\build", "source_path": private}),)
    context, binary, result = _extract(tmp_path, monkeypatch, records)
    with shard(context, result) as database:
        rows = database.execute("SELECT name, text, payload_json FROM entities").fetchall()
        assert "private-secret" not in json.dumps(rows)
        assert "private-secret" not in json.dumps(database.execute("SELECT * FROM search_fts").fetchall())
        (name, _, payload_json) = rows[0]
    payload = json.loads(payload_json)
    assert name == "compilation-unit:" + hashlib.sha256(private.encode()).hexdigest()
    assert payload["source_mapping"] == "unverified" and payload["line"] == 3
    assert "source_identity" not in payload and "source_path" not in payload
    assert payload["source_name_sha256"] == hashlib.sha256(private.encode()).hexdigest()
    assert payload["compilation_directory_sha256"] and payload["source_path_sha256"]
    assert result["gaps"] == [f"{binary['artifact_identity']}: source_mapping_unverified: checksum unavailable"]
    assert "private-secret" in (context.run_root / result["artifact"]["path"]).read_text(), "raw refs stay protected"


def test_checksum_mismatch_or_missing_source_bytes_is_not_exact(tmp_path, monkeypatch):
    records = (SymbolRecord("line:1", RecordKind.SOURCE_RANGE,
                            source=SourceSpan("src/main.cc", 1, checksum="f" * 64, checksum_kind="sha256")),)
    context, binary, result = _extract(tmp_path, monkeypatch, records, content=b"accepted bytes")
    (payload,) = payloads(context, result)
    assert "source_identity" not in payload and payload["source_mapping"] == "unverified"
    assert result["gaps"] == [f"{binary['artifact_identity']}: source_checksum_unverified"]
    with shard(context, result) as database:
        assert database.execute("SELECT kind FROM entities").fetchone() == ("ir_entity",)
        assert database.execute("SELECT COUNT(*) FROM locations").fetchone() == (0,)


def test_source_binding_can_use_hash_verified_accepted_sqlite_text(tmp_path, monkeypatch):
    content = b"int main() { return 0; }\n"
    checksum = hashlib.sha256(content).hexdigest()
    records = (SymbolRecord("line:1", RecordKind.SOURCE_RANGE, source=SourceSpan(
        "/untrusted/build/root/main.cc", 1, checksum=checksum, checksum_kind="sha256")),)
    context, _, result = _extract(tmp_path, monkeypatch, records, content=content, store_object=False)
    assert result["terminal_status"] == "SUCCEEDED"
    (payload,) = payloads(context, result)
    assert payload["source_mapping"] == "checksum-verified" and payload["source_path"] == "src/main.cc"


def test_truncated_or_converted_sqlite_text_cannot_establish_the_binding(tmp_path, monkeypatch):
    content = b"int main() {\r\n return 0; }\r\n"
    checksum = hashlib.sha256(content).hexdigest()
    records = (SymbolRecord("line:1", RecordKind.SOURCE_RANGE, source=SourceSpan(
        "main.cc", 1, checksum=checksum, checksum_kind="sha256")),)
    context, binary, result = _extract(tmp_path, monkeypatch, records, content=content, store_object=False,
                                       text=content.decode().replace("\r\n", "\n"))
    (payload,) = payloads(context, result)
    assert payload["source_mapping"] == "unverified"
    assert result["gaps"] == [f"{binary['artifact_identity']}: source_checksum_unverified"]


@pytest.mark.parametrize("span,gap", [
    (SourceSpan("src/main.cc", 1, checksum="f" * 64), "source_mapping_unverified: checksum unavailable"),
    (SourceSpan("src/main.cc", 1, checksum="zz", checksum_kind="sha256"), "source_checksum_invalid"),
    (SourceSpan("src/main.cc", 1, checksum="a" * 40, checksum_kind="sha1"), "source_checksum_algorithm_unsupported"),
    (SourceSpan("src/main.cc", 99, checksum=hashlib.sha256(CONTENT).hexdigest(), checksum_kind="sha256"),
     "source_checksum_unverified"),
], ids=["no-kind", "invalid", "sha1", "line-out-of-range"])
def test_each_unverifiable_span_names_its_gap_and_stays_unbound(tmp_path, monkeypatch, span, gap):
    records = (SymbolRecord("line:1", RecordKind.SOURCE_RANGE, source=span),)
    context, binary, result = _extract(tmp_path, monkeypatch, records)
    assert result["gaps"] == [f"{binary['artifact_identity']}: {gap}"]
    (payload,) = payloads(context, result)
    assert payload["source_mapping"] == "unverified"


def test_a_record_named_after_its_bound_source_takes_the_accepted_path_as_its_name(tmp_path, monkeypatch):
    checksum = hashlib.sha256(CONTENT).hexdigest()
    private = "/home/dev/src/main.cc"
    records = (SymbolRecord("cu:1", RecordKind.COMPILATION_UNIT, private,
                            source=SourceSpan(private, 1, checksum=checksum, checksum_kind="sha256")),
               SymbolRecord("fn:1", RecordKind.SYMBOL, private, (AddressRange(1, 2),),
                            SourceSpan(private, 2, checksum=checksum, checksum_kind="sha256"), "cu:1"))
    context, _, result = _extract(tmp_path, monkeypatch, records)
    assert result["gaps"] == []
    with shard(context, result) as database:
        names = database.execute("SELECT kind, name FROM entities ORDER BY kind").fetchall()
        assert names == [("compile_unit", "src/main.cc"), ("symbol", "src/main.cc")]
        assert database.execute("SELECT COUNT(*) FROM relations WHERE kind='CONTAINS'").fetchone() == (1,)
        assert database.execute("SELECT COUNT(*) FROM relations WHERE kind='OBSERVED_AT'").fetchone() == (2,)
        assert "/home/dev" not in json.dumps(database.execute("SELECT * FROM entities").fetchall())


def test_extraction_gaps_from_the_reader_are_privatised_and_kept_with_a_partial_coverage(tmp_path, monkeypatch):
    extraction = Extraction((SymbolRecord("fn:1", RecordKind.SYMBOL, "f"),),
                            ("/private/path missing", "inline_frames_truncated"), "fixture/1")
    context = job_context(tmp_path)
    binary = artifact(context.run_root, "bin/program", ELF)
    job = build_job(extractor=lambda *a, **k: extraction)
    decision = decide(monkeypatch, job, context, accepted_inputs([binary], manifest(context.run_root)))
    result = handlers(job)["extract.clang_dwarf"](unit(context, "extract.clang_dwarf", {"decide.target": decision}))
    hashed = "source-name-sha256:" + hashlib.sha256(b"/private/path missing").hexdigest()
    assert result["gaps"] == sorted([f"{binary['artifact_identity']}: {hashed}",
                                     f"{binary['artifact_identity']}: inline_frames_truncated"])
    with shard(context, result) as database:
        assert database.execute("SELECT status, gap FROM coverage").fetchone() == ("partial", f"inline_frames_truncated; {hashed}")
