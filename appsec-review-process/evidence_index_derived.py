"""Accepted ``02-evidence-index-derived``: the derived-record and build-input index, after its producers.

``02-evidence-index`` is built on the source branch right after intake, before any tool runs, and
nothing writes its run-owned producer selection, so its derived tables are always empty
(``no-derived-producers-selected``). This deterministic job runs after the producers instead. Python
computes the selection from what the run holds: every ``evidence_index_enrichment.PROFILES`` producer
with an accepted OK/OK_WITH_GAPS publication that ``load_producer`` admits (common pointer, envelope,
tree hashes, result schema, F02 receipts) and whose source generation is this run's is included;
every other one is excluded with its disposition (absent, skipped, failed, not-admissible,
other-generation, not-selectable, not-indexable) and reason, and each exclusion is a coverage gap.
Producers keep their own build lineage (each record carries it), so different build generations do
not block; a different source generation excludes the producer.

Two text-bearing inputs are chunked into ``text_chunks`` (FTS5) with provenance:

- the build-input corpus of the accepted ``02-native-build``: each unit's ``build-dependencies.json``
  (include and library dirs, consumed files with class, sha256 and packages, packages, link lines,
  DT_NEEDED) as derived records, and its configure-generated headers as text chunks. Out-of-checkout
  headers the build consumed are recorded by path, sha256 and package only: 02-native-build does
  not retain their bytes, which is a gap per unit (see ``OUT_OF_CHECKOUT_GAP``);
- a ``derived-text-manifest.json`` any included producer lists in its accepted envelope
  (``derived-text-manifest.schema.json``: per document the text artifact path and sha256, source
  path and sha256, converter and version, optional page line ranges), e.g. converted documents.

Text is bounded by file count, bytes per file, total bytes and line length, and must be strict UTF-8;
whatever falls outside is listed with its status and is a gap. Rows are locators, never findings.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import tempfile
import time
from typing import Any

import evidence_index_enrichment as enrichment
import evidence_store
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, now, read_json, run_path, tree_hashes
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
import registry_paths
from schema_validate import validate_document
import tunables

JOB = "02-evidence-index-derived"
CONTRACT = "evidence-index-derived"
SCHEMA = "appsec-review/evidence-index-derived/1.0"
SCHEMA_FILE = "evidence-index-derived.schema.json"
RESULT = "evidence-index-derived.json"
ENRICHMENT = enrichment.RESULT
SQLITE = "evidence-index-derived.sqlite"
SUMMARY = "evidence-index-derived-summary.md"
INDEX_JOB = "02-evidence-index"
BUILD_JOB, BUILD_RESULT = "02-native-build", "native-build.json"
TEXT_MANIFEST, TEXT_MANIFEST_SCHEMA = "derived-text-manifest.json", "derived-text-manifest.schema.json"
CONSUMER = "02-evidence-assembly"
# Producers that run after this job's consumer: an edge to them would be a graph cycle.
UNSELECTABLE = {"01-component-characterization":
                "runs after 02-evidence-assembly, which consumes this index; a graph edge would be a cycle"}
OUT_OF_CHECKOUT_GAP = ("out-of-checkout-headers-not-retained:{unit}:{count} header(s) the build consumed "
                       "outside the checkout are indexed by path, sha256 and package only; 02-native-build "
                       "does not keep their bytes (build_replay must copy them, bounded and hash-bound, "
                       "into outputs/<unit>/consumed-headers/ for them to be searchable)")
LIMITS = {name: tunables.value(JOB, name) for name in (
    "text_max_files", "text_max_file_bytes", "text_max_total_bytes", "text_chunk_lines",
    "text_max_line_chars", "build_records_max")}
TEXT_DDL = '''
      CREATE TABLE text_files(doc_id TEXT PRIMARY KEY, kind TEXT NOT NULL, producer_job_id TEXT NOT NULL,
        producer_attempt_id TEXT NOT NULL, artifact_path TEXT NOT NULL, sha256 TEXT NOT NULL,
        source_path TEXT NOT NULL, status TEXT NOT NULL);
      CREATE VIRTUAL TABLE text_chunks USING fts5(doc_id UNINDEXED, artifact_path UNINDEXED,
        source_path UNINDEXED, page UNINDEXED, start_line UNINDEXED, end_line UNINDEXED, content,
        tokenize='unicode61');'''
_POINTER_KEYS = {"schema", "status", "run_id", "job", "attempt_id", "fingerprint", "envelope_path",
                 "envelope_sha256", "hashes", "accepted_at"}
_OUTSIDE = ("toolchain", "system-package", "unattributed")


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _code() -> dict[str, str]:
    paths = ("evidence_index_derived.py", "evidence_index_enrichment.py", "evidence_store.py",
             registry_paths.template_rel(JOB), registry_paths.contract_rel(CONTRACT))
    values = {name: file_hash(ROOT / name) for name in paths}
    for name in (SCHEMA_FILE, TEXT_MANIFEST_SCHEMA, "evidence-index-enrichment.schema.json",
                 "evidence-index-derived-record.schema.json", "build-dependencies.schema.json"):
        values["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    return values


def _accepted(run_id: str, job: str) -> tuple[str, str, Path | None, dict[str, Any] | None]:
    """(state, detail, attempt, pointer) of a job's accepted publication: accepted | absent | skipped
    | failed. An accepted attempt has a common pointer, the latest attempt, its tree and envelope."""
    jobs = data_path(run_id, "jobs")
    for base in (jobs / job, jobs / job / "whole"):
        path = base / "accepted.json"
        if base.is_symlink() or path.is_symlink() or not path.is_file():
            continue
        try:
            pointer = read_json(path)
            status = pointer.get("status")
            if status == "SKIPPED":
                return "skipped", str(pointer.get("reason") or "no skip reason recorded"), None, None
            if status not in ("OK", "OK_WITH_GAPS"):
                return "failed", f"accepted status {status}", None, None
            attempt = base / "attempts" / str(pointer["attempt_id"])
            if (set(pointer) != _POINTER_KEYS or pointer["run_id"] != run_id or pointer["job"] != job or
                    read_json(base / "latest.json").get("attempt_id") != pointer["attempt_id"] or
                    attempt.is_symlink() or not attempt.is_dir() or tree_hashes(attempt) != pointer["hashes"] or
                    file_hash(attempt / "result.json") != pointer["envelope_sha256"]):
                return "failed", "accepted pointer, envelope or attempt tree does not verify", None, None
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return "failed", "accepted pointer is unreadable", None, None
        return "accepted", status, attempt, {**pointer, "pointer_sha256": "sha256:" + file_hash(path)}
    return "absent", "no accepted publication in this run", None, None


def _index(run_id: str) -> dict[str, Any]:
    state, detail, attempt, pointer = _accepted(run_id, INDEX_JOB)
    if attempt is None:
        raise Blocked(f"{JOB}: no accepted {INDEX_JOB} ({state}: {detail})")
    source = read_json(attempt / "lineage.json").get("source_snapshot_sha256")
    if not isinstance(source, str):
        raise Blocked(f"{JOB}: {INDEX_JOB} lineage names no source generation")
    return {"attempt_id": pointer["attempt_id"], "accepted_pointer_sha256": pointer["pointer_sha256"],
            "source_snapshot_sha256": source}


def _sources(run_id: str, canonical: str) -> set[str]:
    """The canonical source identity plus the staged artifact-manifest alias some producers bind."""
    manifest = run_path(run_id) / "inputs" / "artifact-manifest.json"
    alias = {"sha256:" + file_hash(manifest)} if manifest.is_file() and not manifest.is_symlink() else set()
    return {canonical} | alias


def select(run_id: str, sources: set[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(included load_producer bindings, excluded {job_id, disposition, reason}) over every profile."""
    included, excluded = [], []
    for job in sorted(set(enrichment.PROFILES) | set(enrichment.NOT_INDEXABLE)):
        if job in enrichment.NOT_INDEXABLE:
            excluded.append({"job_id": job, "disposition": "not-indexable", "reason": enrichment.NOT_INDEXABLE[job]})
            continue
        if job in UNSELECTABLE:
            excluded.append({"job_id": job, "disposition": "not-selectable", "reason": UNSELECTABLE[job]})
            continue
        state, detail, _attempt, _pointer = _accepted(run_id, job)
        if state != "accepted":
            excluded.append({"job_id": job, "disposition": state, "reason": detail})
            continue
        try:
            producer = enrichment.load_producer(run_id, job)
        except Blocked as exc:
            excluded.append({"job_id": job, "disposition": "not-admissible", "reason": str(exc)})
            continue
        if producer["source_snapshot_sha256"] not in sources:
            excluded.append({"job_id": job, "disposition": "other-generation",
                             "reason": "producer source generation is not this run's accepted source"})
            continue
        included.append(producer)
    return included, excluded


def _build(run_id: str) -> dict[str, Any]:
    state, detail, attempt, pointer = _accepted(run_id, BUILD_JOB)
    if attempt is None:
        return {"state": state, "detail": detail, "attempt_id": None}
    return {"state": state, "detail": detail, "attempt_id": pointer["attempt_id"],
            "accepted_pointer_sha256": pointer["pointer_sha256"], "fingerprint": pointer["fingerprint"],
            "result_sha256": "sha256:" + file_hash(attempt / BUILD_RESULT)}


def current_inputs(run_id: str) -> dict[str, Any]:
    index = _index(run_id)
    included, excluded = select(run_id, _sources(run_id, index["source_snapshot_sha256"]))
    return {"run_id": run_id, "job": JOB, "source_snapshot_sha256": index["source_snapshot_sha256"],
            "index": index, "included": included, "excluded": excluded, "native_build": _build(run_id),
            "limits": LIMITS, "code": _code()}


# --- text corpus ----------------------------------------------------------------------------------

def _relative(value: Any) -> str:
    path = PurePosixPath(value) if isinstance(value, str) else PurePosixPath("..")
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise Blocked(f"{JOB}: text artifact path is not a normalized relative path")
    return path.as_posix()


class _Text:
    """Bounded text corpus: documents, chunks, per-document status and gaps."""

    def __init__(self):
        self.files, self.chunks, self.gaps, self.total = [], [], [], 0

    def add(self, attempt: Path, doc: dict[str, Any], pages: list[dict[str, Any]] | None = None) -> None:
        doc = {**doc, "doc_id": "text_" + digest((doc["producer_job_id"], doc["producer_attempt_id"], doc["artifact_path"]))[:24]}
        label = f"{doc['producer_job_id']}:{doc['artifact_path']}"
        status, lines = "indexed", None
        path = attempt / _relative(doc["artifact_path"])
        if len([item for item in self.files if item["status"] != "over-file-count"]) >= LIMITS["text_max_files"]:
            status = "over-file-count"
        elif path.is_symlink() or not path.is_file() or "sha256:" + file_hash(path) != doc["sha256"]:
            raise Blocked(f"{JOB}: text artifact does not match its bound sha256: {label}")
        elif path.stat().st_size > LIMITS["text_max_file_bytes"]:
            status = "over-file-bytes"
        elif self.total + path.stat().st_size > LIMITS["text_max_total_bytes"]:
            status = "over-total-bytes"
        else:
            try:
                lines = path.read_bytes().decode("utf-8-sig").splitlines()
            except UnicodeDecodeError:
                status = "not-utf8"
            if lines is not None and any(len(line) > LIMITS["text_max_line_chars"] for line in lines):
                status, lines = "line-too-long", None
        doc["bytes"] = path.stat().st_size if path.is_file() else 0
        doc["chunks"] = 0
        if lines is not None:
            self.total += doc["bytes"]
            step = LIMITS["text_chunk_lines"]
            segments = ([(item["page"], item["start_line"], min(item["end_line"], len(lines))) for item in pages]
                        if pages else [(None, 1, len(lines))])
            for page, first, last in segments:
                for start in range(first, last + 1, step):
                    end = min(last, start + step - 1)
                    self.chunks.append((doc["doc_id"], doc["artifact_path"], doc["source_path"], page, start, end,
                                        "\n".join(lines[start - 1:end])))
                    doc["chunks"] += 1
        else:
            self.gaps.append(f"text-not-indexed:{status}:{label}")
        self.files.append({**doc, "status": status})


def _text_manifests(run_id: str, included: list[dict[str, Any]], corpus: _Text) -> None:
    """Chunk the documents of every included producer's derived-text-manifest.json."""
    for producer in included:
        attempt = enrichment._producer_root(run_id, producer["job_id"]) / "attempts" / producer["attempt_id"]
        artifacts = {item["path"]: item["sha256"] for item in read_json(attempt / "result.json")["artifacts"]}
        if TEXT_MANIFEST not in artifacts:
            continue
        manifest = read_json(attempt / TEXT_MANIFEST)
        if file_hash(attempt / TEXT_MANIFEST) != artifacts[TEXT_MANIFEST] or validate_document(manifest, TEXT_MANIFEST_SCHEMA):
            corpus.gaps.append(f"text-manifest-invalid:{producer['job_id']}")
            continue
        for document in manifest["documents"]:
            if artifacts.get(document["artifact_path"]) != document["sha256"].removeprefix("sha256:"):
                corpus.gaps.append(f"text-artifact-unbound:{producer['job_id']}:{document['artifact_path']}")
                continue
            corpus.add(attempt, {"kind": "converted-document", "producer_job_id": producer["job_id"],
                "producer_attempt_id": producer["attempt_id"], "artifact_path": document["artifact_path"],
                "sha256": document["sha256"], "source_path": document["source_path"],
                "source_sha256": document["source_sha256"], "converter": document["converter"],
                "converter_version": document["converter_version"]}, document.get("pages"))


# --- build-input corpus ---------------------------------------------------------------------------

def _build_texts(name: str, item: Any) -> str:
    if name in ("search_dirs/include", "search_dirs/library"):
        return f"{name.split('/')[1]}-dir {item['path']}"
    if name == "files":
        return (f"{item['class']} {' '.join(item['kinds'])} {item['path']} {item['sha256'] or 'unhashed'} "
                f"packages {' '.join(item['packages']) or 'none'}")
    if name == "packages":
        return f"package {item['package']} {item['name']} {item['version']} source {item['source'] or ''} {item['source_version'] or ''}"
    if name == "link_commands":
        return (f"link {item['output'] or ''} binary {item['binary'] or ''} libraries "
                f"{' '.join(lib['spec'] for lib in item['libraries'])} dirs {' '.join(item['library_dirs'])}")
    return (f"binary {item['path']} needed {' '.join(need['soname'] for need in item['needed'])} "
            f"runpath {' '.join(item['runpath'])} rpath {' '.join(item['rpath'])}")


def _build_inputs(run_id: str, inputs: dict[str, Any], corpus: _Text) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    """(summary, derived records, gaps) of the accepted 02-native-build's build-input corpus."""
    bound = inputs["native_build"]
    if bound["attempt_id"] is None:
        return ({"status": bound["state"], "attempt_id": None, "units": []}, [],
                [f"build-inputs-{bound['state']}:{BUILD_JOB}: {bound['detail']}"])
    attempt = data_path(run_id, "jobs", BUILD_JOB, "attempts", bound["attempt_id"])
    if "sha256:" + file_hash(attempt / BUILD_RESULT) != bound["result_sha256"]:
        raise Blocked(f"{JOB}: accepted {BUILD_JOB} result changed after binding")
    result, records, gaps, units = read_json(attempt / BUILD_RESULT), [], [], []
    artifacts = {item["path"]: item["sha256"] for item in read_json(attempt / "result.json")["artifacts"]}
    if not result.get("units"):
        gaps.append(f"build-inputs-no-units:{BUILD_JOB} published no build unit")
    omitted = 0
    for unit in result.get("units", []):
        unit_id = unit["unit_id"]
        row = {"unit_id": unit_id, "build_dependencies": None, "records": 0, "generated_headers": 0,
               "generated_headers_omitted_at_build": 0, "out_of_checkout_headers": 0}
        descriptor = unit.get("build_dependencies")
        if descriptor is None:
            gaps.append(f"build-dependencies-absent:{unit_id}")
        else:
            path = attempt / _relative(descriptor["path"])
            if (artifacts.get(descriptor["path"]) != descriptor["sha256"].removeprefix("sha256:") or
                    path.is_symlink() or "sha256:" + file_hash(path) != descriptor["sha256"]):
                raise Blocked(f"{JOB}: {BUILD_JOB} build-dependencies artifact does not match its hash: {unit_id}")
            dependencies = read_json(path)
            if validate_document(dependencies, "build-dependencies.schema.json"):
                raise Blocked(f"{JOB}: {BUILD_JOB} build-dependencies fails its schema: {unit_id}")
            row["build_dependencies"] = dict(descriptor)
            producer = {"job_id": BUILD_JOB, "attempt_id": bound["attempt_id"], "contract": "native-build",
                        "artifact_path": descriptor["path"], "artifact_sha256": descriptor["sha256"],
                        "authority": "derived_evidence", "source_snapshot_sha256": inputs["source_snapshot_sha256"],
                        "build_lineage_sha256": bound["fingerprint"]}
            sections = [(name, [{"path": value} for value in dependencies["search_dirs"][name.split("/")[1]]])
                        for name in ("search_dirs/include", "search_dirs/library")]
            sections += [(name, dependencies[name]) for name in ("files", "packages", "link_commands", "binaries")]
            for name, items in sections:
                for index, item in enumerate(items):
                    if len(records) >= LIMITS["build_records_max"]:
                        omitted += 1
                        continue
                    records.append(enrichment.derived_record(producer, name, index, item,
                        text=enrichment.redacted(_build_texts(name, item)),
                        type_label="build-dependencies:" + name.replace("search_dirs/", "") ))
                    row["records"] += 1
            outside = [item for item in dependencies["files"] if "header" in item["kinds"] and item["class"] in _OUTSIDE]
            row["out_of_checkout_headers"] = len(outside)
            if outside:
                gaps.append(OUT_OF_CHECKOUT_GAP.format(unit=unit_id, count=len(outside)))
        generated = unit.get("generated_headers") or {"root": "", "headers": [], "omitted": 0}
        row["generated_headers_omitted_at_build"] = generated["omitted"]
        if generated["omitted"]:
            gaps.append(f"generated-headers-omitted-at-build:{unit_id}:{generated['omitted']}")
        for header in generated["headers"]:
            relative = generated["root"] + "/" + header["path"]
            if artifacts.get(relative) != header["sha256"].removeprefix("sha256:"):
                raise Blocked(f"{JOB}: {BUILD_JOB} generated header is not a bound artifact: {relative}")
            corpus.add(attempt, {"kind": "generated-header", "producer_job_id": BUILD_JOB,
                "producer_attempt_id": bound["attempt_id"], "artifact_path": relative, "sha256": header["sha256"],
                "source_path": header["path"], "source_sha256": None, "converter": None, "converter_version": None})
            row["generated_headers"] += 1
        units.append(row)
    if omitted:
        gaps.append(f"build-records-omitted:{omitted} beyond build_records_max {LIMITS['build_records_max']}")
    return {"status": "indexed", "attempt_id": bound["attempt_id"], "units": units}, records, gaps


# --- derivation, database, validation -------------------------------------------------------------

def _content_sha256(database: Path) -> str:
    db = sqlite3.connect(database.as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        value = hashlib.sha256()
        for table, order in (("derived_records", "record_id"), ("derived_chunks", "record_id"),
                             ("text_files", "doc_id"), ("text_chunks", "doc_id, start_line")):
            for row in db.execute(f"SELECT * FROM {table} ORDER BY {order}"):
                value.update((json.dumps([table, *row], ensure_ascii=True) + "\n").encode("ascii"))
        return "sha256:" + value.hexdigest()
    finally:
        db.close()


def _derive(run_id: str, inputs: dict[str, Any], attempt: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Write the enrichment and database into ``attempt``; return (result without sqlite, enrichment)."""
    included = inputs["included"]
    records, partitions, components = enrichment.build_records(run_id, included, JOB)
    corpus = _Text()
    build_inputs, build_records, build_gaps = _build_inputs(run_id, inputs, corpus)
    _text_manifests(run_id, included, corpus)
    gaps = [f"producer-{item['disposition']}:{item['job_id']}: {item['reason']}" for item in inputs["excluded"]]
    gaps += build_gaps + corpus.gaps
    if not included and not build_records and not corpus.chunks:
        gaps.append("no-derived-producers-selected")
    document = enrichment.document(run_id, records + build_records, partitions, components,
        producer_count=len(included) + (1 if build_inputs["attempt_id"] else 0),
        source_snapshot_sha256=inputs["source_snapshot_sha256"],
        build_lineage_sha256="sha256:" + digest(inputs), gaps=gaps, job=JOB)
    atomic_json(attempt / ENRICHMENT, document)
    database = attempt / SQLITE
    if database.exists():
        raise Blocked(f"{JOB}: attempt already holds a database")
    db = sqlite3.connect(database)
    try:
        db.executescript("PRAGMA journal_mode=DELETE;" + evidence_store.DERIVED_DDL + TEXT_DDL)
        evidence_store.insert_derived(db, document["records"])
        for item in corpus.files:
            db.execute("INSERT INTO text_files VALUES (?,?,?,?,?,?,?,?)", (item["doc_id"], item["kind"],
                       item["producer_job_id"], item["producer_attempt_id"], item["artifact_path"], item["sha256"],
                       item["source_path"], item["status"]))
        db.executemany("INSERT INTO text_chunks VALUES (?,?,?,?,?,?,?)", corpus.chunks)
        db.commit()
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise Blocked(f"{JOB}: SQLite integrity check failed")
    finally:
        db.close()
    result = {"schema": SCHEMA, "run_id": run_id, "status": "OK_WITH_GAPS" if gaps else "OK",
              "source_snapshot_sha256": inputs["source_snapshot_sha256"], "index": inputs["index"],
              "selection": {"included": [{"job_id": item["job_id"], "attempt_id": item["attempt_id"],
                                          "pointer_sha256": item["pointer_sha256"], "artifact_path": item["artifact_path"],
                                          "artifact_sha256": item["artifact_sha256"]} for item in included],
                            "excluded": inputs["excluded"]},
              "build_inputs": build_inputs,
              "enrichment": {"artifact": ENRICHMENT, "sha256": "sha256:" + file_hash(attempt / ENRICHMENT),
                             "record_count": document["record_count"], "producer_count": document["producer_count"]},
              "text": {"files": corpus.files, "chunk_count": len(corpus.chunks)},
              "content_sha256": _content_sha256(database), "limits": LIMITS, "coverage_gaps": gaps,
              "claim_boundary": "DERIVED_INDEX_NOT_AUTHORITY_OR_RUNTIME_PROOF"}
    return result, document


def _receipts(run_id: str, inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    template = read_json(registry_paths.template(JOB))
    common = {"run_id": run_id, "job_id": JOB, "source_snapshot_sha256": inputs["source_snapshot_sha256"]}
    return ({"schema": enrichment.PERMISSION_SCHEMA, **common, "permissions": template["permissions"]},
            {"schema": enrichment.LINEAGE_SCHEMA, **common, "build_lineage_sha256": "sha256:" + digest(inputs)})


def _validate_attempt(run_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs:
        raise Blocked(f"{JOB}: immutable attempt inputs changed")
    result = read_json(attempt / RESULT)
    if validate_document(result, SCHEMA_FILE):
        raise Blocked(f"{JOB}: result fails schema validation")
    database = attempt / SQLITE
    if (database.is_symlink() or not database.is_file() or "sha256:" + file_hash(database) != result["sqlite"]["sha256"]
            or _content_sha256(database) != result["content_sha256"]):
        raise Blocked(f"{JOB}: published database does not match its recorded hashes")
    scratch = Path(tempfile.mkdtemp(prefix="evidence-index-derived-validate-"))
    try:
        rebuilt, document = _derive(run_id, inputs, scratch)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    if {key: value for key, value in result.items() if key != "sqlite"} != rebuilt or read_json(attempt / ENRICHMENT) != document:
        raise Blocked(f"{JOB}: derived index no longer matches its hash-bound producers")
    evidence_store.check_derived_rows(database, document["records"])
    permission, lineage = _receipts(run_id, inputs)
    if read_json(attempt / "permission.json") != permission or read_json(attempt / "lineage.json") != lineage:
        raise Blocked(f"{JOB}: canonical producer receipts changed")


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        attempt = allocation["attempt"]
        if inputs["code"] != _code():
            raise Blocked(f"{JOB}: implementation changed before execution")
        started = time.monotonic()
        result, document = _derive(run_id, inputs, attempt)
        database = attempt / SQLITE
        result["sqlite"] = {"path": SQLITE, "sha256": "sha256:" + file_hash(database), "bytes": database.stat().st_size}
        atomic_json(attempt / RESULT, result)
        seconds = round(time.monotonic() - started, 3)
        selection = result["selection"]
        (attempt / SUMMARY).write_text(
            "# Derived evidence index\n\n"
            f"- Producers included {len(selection['included'])}, excluded {len(selection['excluded'])} "
            "(each exclusion is a gap with its reason).\n"
            f"- Derived records {document['record_count']}, text documents {len(result['text']['files'])}, "
            f"text chunks {result['text']['chunk_count']}.\n"
            f"- Build inputs: {result['build_inputs']['status']}, {len(result['build_inputs']['units'])} unit(s).\n"
            f"- Gaps: {len(result['coverage_gaps'])}. Built in {seconds}s.\n"
            "- Rows are locators to producer records; read the record and its source before citing.\n",
            encoding="utf-8")
        status = {"process": JOB, "status": result["status"], "run_id": run_id, "dagster_run_id": dagster_id,
                  "attempt_id": allocation["attempt_id"], "records": document["record_count"],
                  "text_chunks": result["text"]["chunk_count"], "network": "none",
                  "qualification": "implemented_not_qualified", "ended_at": now()}
        atomic_json(attempt / "status.json", status)
        permission, lineage = _receipts(run_id, inputs)
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
            worker_kind="deterministic_python", output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=result["status"],
            summary=f"Derived index: {document['record_count']} records, {result['text']['chunk_count']} text chunks.",
            status_record=status,
            artifact_paths=[RESULT, ENRICHMENT, SQLITE, SUMMARY, "status.json", "permission.json", "lineage.json"],
            gaps=result["coverage_gaps"] or None, consumer_job_id=CONSUMER,
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, inputs))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
        worker_kind="deterministic_python", output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/evidence_index_derived.py {run_id}",
        derive_inputs=lambda: current_inputs(run_id), fingerprint_inputs=lambda value: "sha256:" + digest(value),
        execute_attempt=execute, preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code()}, force=force,
        post_validate=lambda attempt, _envelope, record: _validate_attempt(run_id, attempt, record),
        consumer_job_id=CONSUMER,
        blocked_summary="Derived index preflight did not complete.",
        failed_summary="Derived index did not publish; no older success may be used.")


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id); inputs = current_inputs(run_id)
    pointer = pointer or read_json(base / "accepted.json")
    attempt, _ = validate_published(base, pointer, "sha256:" + digest(inputs), expected_run_id=run_id,
                                    expected_job_id=JOB, consumer_job_id=CONSUMER)
    _validate_attempt(run_id, attempt, inputs)
    return attempt


# --- query (the evidence_derived tool) ------------------------------------------------------------

def query(run_id: str, text: str = "", partition_id: str = "", component_id: str = "", limit: int = 10) -> dict[str, Any]:
    """Search the accepted derived index: records (derived_chunks) and, without a partition/component
    filter, text chunks. The accepted attempt is integrity-checked (pointer, latest, tree, envelope),
    not re-derived: a model job must not be blinded mid-run (ADR-0013). Not accepted: no hits and a gap."""
    if not 1 <= limit <= enrichment.LIMITS["max_query_results"] or len(text) > enrichment.LIMITS["max_search_text"]:
        raise ValueError("derived query bounds: limit 1..50 and text <=1000 characters")
    state, detail, attempt, pointer = _accepted(run_id, JOB)
    common = {"run_id": run_id, "job_id": JOB, "untrusted_content": True,
              "claim_boundary": "INDEX_HIT_IS_LOCATOR_REQUIRES_PRODUCER_RECORD_DEREFERENCE"}
    if attempt is None:
        return {**common, "attempt_id": None, "results": [], "text_hits": [],
                "coverage_gaps": [f"derived-index-{state}:{JOB}: {detail}; derived records and build inputs "
                                  "cannot be searched in this run (not evidence of absence)"]}
    result = read_json(attempt / RESULT)
    db = sqlite3.connect((attempt / SQLITE).as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        ids = evidence_store.search_derived(db, text, partition_id, component_id, limit)
        hits = []
        if text.strip() and not partition_id and not component_id:
            match = " AND ".join('"' + word.replace('"', '""') + '"' for word in text.split())
            hits = [{"producer_job_id": row[6], "producer_attempt_id": row[7], "artifact_path": row[1],
                     "source_path": row[2], "page": row[3], "start_line": row[4], "end_line": row[5],
                     "excerpt": row[0]}
                    for row in db.execute(
                        "SELECT snippet(text_chunks,6,'[',']',' ... ',32), c.artifact_path, c.source_path, c.page, "
                        "c.start_line, c.end_line, f.producer_job_id, f.producer_attempt_id FROM text_chunks c "
                        "JOIN text_files f ON f.doc_id=c.doc_id WHERE text_chunks MATCH ? "
                        "ORDER BY bm25(text_chunks), c.artifact_path, c.start_line LIMIT ?", (match, limit))]
    finally:
        db.close()
    records = {record["record_id"]: record for record in read_json(attempt / ENRICHMENT)["records"]}
    if read_json(root(run_id) / "accepted.json").get("attempt_id") != pointer["attempt_id"]:
        raise Blocked(f"{JOB}: acceptance changed during derived retrieval; retry")
    gaps = result["coverage_gaps"]
    return {**common, "attempt_id": pointer["attempt_id"], "results": [records[item] for item in ids],
            "text_hits": hits, "coverage_gaps": gaps[:50], "coverage_gaps_total": len(gaps)}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument("run_id"); parser.add_argument("--dagster-id", default="manual")
    parser.add_argument("--force", action="store_true"); args = parser.parse_args()
    print(run(args.run_id, args.dagster_id, args.force))
