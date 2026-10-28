"""Bounded retrieval indices over frozen binary decompilation publications.

The job consumes only the accepted ``job_review_intake`` handoff, whose ``binary_evidence`` step
froze each configured binary's publication identity and manifest hash. For every resolved binary
it re-verifies the publication chain, detaches each decompiled function's pseudo-C into the run,
and builds one ``binary`` retrieval shard with:

* ``binary_function`` entities, located in ``@binary/<sha256>/<address>.c`` pseudo-C;
* ``binary_call_site`` entities, located on the pseudo-C line that names the callee when exactly
  one line does (otherwise ambiguous or unlocated);
* ``binary_import`` and ``binary_string`` entities, which are never located and so never cited;
* ``CALLS`` (call neighbourhood, import callers) and ``REFERENCES`` (string uses, thunks) edges.

Every table is bounded by central settings and every truncation, unavailable binary, managed-code
binary and unapplied debug-symbol file is a named coverage gap. Decompiled text, names and strings
are binary-derived data, never instructions.
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from appsec_review.jobs.cpp_index_scopes import artifact, publish_scope_indexes
from appsec_review.interchange import decode_handoff
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, SourceLocation, index_fingerprint,
)
from appsec_review.retrieval.source_resolution import binary_source_path, publish_binary_source
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, file_sha256

from appsec_review.jobs.job_binary_evidence_indexing.datasets import CONSUMES, DATASETS


JOB_ID = "job_binary_evidence_indexing"
SCHEMA = "appsec-review/binary-evidence-index/1"
INTAKE_SCHEMA = "appsec-review/binary-evidence-intake/1"
NORMALIZER = "binary-evidence-normalizer/1"
MAPPING = "ghidra-pseudo-c-lines/1"
TOPOLOGY = {"load": ("accepted_publications",), "index": ("binaries",), "acceptance": ("publish_handoff",)}
SETTINGS = ("max_functions_per_binary", "max_call_sites_per_binary", "max_imports_per_binary",
            "max_strings_per_binary", "max_string_xrefs", "max_entity_text_bytes", "max_string_chars")
MANAGED_TOOLS = {"CIL": "ILSpy (ilspycmd)", "JVM": "jadx or CFR", "Dalvik": "jadx"}
_ADDRESS = re.compile(r"0x[0-9a-f]{1,16}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _settings(unit: UnitContext) -> dict[str, int]:
    values = unit.job.config.settings
    limits = {name: values.get(name) for name in SETTINGS}
    if any(type(value) is not int or value < 1 for value in limits.values()):
        raise ValueError("binary evidence index settings must be positive integers")
    return limits


def _read_verified(run_root: Path, identity: Mapping[str, Any]) -> Mapping[str, Any]:
    path = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file():
        raise ValueError("accepted upstream artifact is unavailable or outside the run")
    if file_sha256(path) != identity.get("sha256"):
        raise ValueError("accepted upstream artifact hash changed")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("accepted upstream artifact must be an object")
    return value


def accepted_binary_evidence(run_root: Path) -> tuple[Mapping[str, Any], str]:
    """The binary-evidence document the accepted intake froze, and the intake handoff hash."""
    pointer_path = run_root / "data" / "jobs" / "job_review_intake" / "latest.json"
    if not pointer_path.is_file():
        raise ValueError("accepted job_review_intake handoff is required")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff = decode_handoff(
        _read_verified(run_root, {"path": pointer["handoff_path"], "sha256": pointer["handoff_sha256"]}),
        run_id=run_root.name, job_id="job_review_intake")
    output = handoff.get("outputs", {}).get("publish_intake.publish_handoff", {})
    intake = _read_verified(run_root, output.get("artifact", {}))
    if intake.get("schema") != "appsec-review/review-intake/1":
        raise ValueError("accepted review intake uses an unsupported schema")
    reference = intake.get("binary_evidence")
    if not isinstance(reference, Mapping) or reference.get("schema") != INTAKE_SCHEMA:
        raise ValueError("accepted review intake has no binary-evidence record")
    document = _read_verified(run_root, reference.get("artifact", {}))
    if document.get("schema") != INTAKE_SCHEMA or not isinstance(document.get("binaries"), list):
        raise ValueError("binary-evidence record uses an unsupported schema")
    return document, str(pointer["handoff_sha256"])


def verified_publication(document: Mapping[str, Any], entry: Mapping[str, Any]) -> tuple[Path, Mapping[str, Any]]:
    """Re-verify one frozen publication; it must be byte-identical to what intake recorded."""
    from appsec_review.binary_decompilation import store_root, verify_publication

    store = store_root(Path(str(document["data_dir"]))).resolve()
    relative = str(entry.get("publication", ""))
    root = (store / relative).resolve()
    if store not in root.parents or not root.is_dir() or root.is_symlink():
        raise ValueError(f"binary {entry.get('binary_id')}: publication is outside the store")
    manifest = verify_publication(root)
    if (file_sha256(root / "manifest.json") != entry.get("manifest_sha256")
            or manifest.get("identity") != entry.get("identity")
            or manifest.get("binary", {}).get("sha256") != entry.get("binary_sha256")):
        raise ValueError(f"binary {entry.get('binary_id')}: publication changed after intake froze it")
    return root, manifest


def managed_routing(manifest: Mapping[str, Any]) -> str | None:
    """Managed code is routed to its own decompiler; native pseudo-C of it is never evidence."""
    if not manifest.get("coverage", {}).get("managed_code"):
        return None
    program = manifest.get("program", {})
    language = str(program.get("language", ""))
    family = "CIL" if str(program.get("compiler") or "").lower() == "cli" else language.split(":", 1)[0]
    tool = MANAGED_TOOLS.get(family, "a managed-code decompiler")
    return (f"managed_code: {language or 'managed runtime'} needs {tool}; Ghidra pseudo-C of managed "
            "code is not indexed as evidence")


def _clip(text: str, limit: int) -> str:
    data = text.encode("utf-8")
    return text if len(data) <= limit else data[:limit].decode("utf-8", errors="ignore")


def _short(name: Any) -> str:
    return str(name or "").rsplit("::", 1)[-1]


def _line_of(text: str, callee: str) -> tuple[int, int, int, int, bool] | None:
    """The pseudo-C line that names ``callee`` as a call: (line, start_byte, end_byte, columns, ambiguous)."""
    if not callee or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_@$.]*", callee):
        return None
    pattern = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(callee) + r"\s*\(")
    offset, found = 0, []
    for number, line in enumerate(text.split("\n")[:-1], start=1):
        if pattern.search(line):
            found.append((number, offset, offset + len(line.encode("utf-8")), len(line) + 1))
        offset += len(line.encode("utf-8")) + 1
    if not found:
        return None
    number, start, end, columns = found[0]
    return number, start, end, columns, len(found) > 1


class _Binary:
    """Builds the shard for one verified binary publication."""

    def __init__(self, unit: UnitContext, entry: Mapping[str, Any], root: Path, manifest: Mapping[str, Any],
                 limits: Mapping[str, int], builder: IndexBuilder):
        from appsec_review.binary_decompilation import load_table

        self.unit, self.entry, self.root, self.manifest, self.limits, self.builder = (
            unit, entry, root, manifest, limits, builder)
        self.snapshot = unit.job.source_fingerprint
        self.sha = str(entry["binary_sha256"])
        self.tables = {name: load_table(root, name) for name in ("functions", "calls", "imports", "strings", "gaps")}
        self.gaps: list[str] = []
        self.counts = {key: 0 for key in ("functions", "located_functions", "call_sites", "located_call_sites",
                                          "imports", "strings", "relations")}
        self.functions: dict[str, str] = {}
        self.names: dict[str, str] = {}
        self.texts: dict[str, str] = {}
        self.locations: dict[str, SourceLocation] = {}
        self.imports: dict[str, str] = {}
        self.thunk_imports: dict[str, str] = {}

    def _identity(self, kind: EntityKind, native: Mapping[str, Any]) -> str:
        return LogicalIdentity.derive(kind, self.snapshot, {"binary_sha256": self.sha, **native}).value

    def _common(self, address: str | None = None) -> dict[str, Any]:
        value = {"binary_id": self.entry["binary_id"], "binary_sha256": self.sha,
                 "publication_identity": self.entry["identity"], "provenance": "binary-derived"}
        if address is not None:
            value["function_address"] = address
        return value

    def _relation(self, kind: RelationKind, source: str, target: str, **payload: Any) -> None:
        self.builder.add_relation(RelationRecord(kind, source, target, True, 1.0, None,
                                                 {"producer": "ghidra", **payload}))
        self.counts["relations"] += 1

    def _bounded(self, name: str, rows: list[Mapping[str, Any]], limit: str) -> list[Mapping[str, Any]]:
        if len(rows) > self.limits[limit]:
            self.gaps.append(f"{name}_truncated: indexed {self.limits[limit]} of {len(rows)}")
            return rows[:self.limits[limit]]
        return rows

    def build(self, managed: str | None) -> None:
        if managed is not None:
            self.gaps.append(managed)
        for row in self.tables["gaps"]:
            if row.get("kind") != "managed_code":
                self.gaps.append(f"publication_gap: {row.get('kind')}"
                                 + (f" at {row['address']}" if row.get("address") else ""))
        self.gaps.extend(f"publication_coverage: {name}" for name, flag in (
            ("analysis_timed_out", self.manifest["coverage"].get("analysis_timed_out")),
            ("functions_not_exported", self.manifest["coverage"].get("functions_not_exported")),
            ("strings_not_exported", self.manifest["coverage"].get("strings_not_exported"))) if flag)
        self._imports()
        for row in self._bounded("functions", self.tables["functions"], "max_functions_per_binary"):
            self._function(row, located=managed is None)
        self._calls()
        self._strings()
        self.gaps = list(dict.fromkeys(self.gaps))

    def _imports(self) -> None:
        for row in self._bounded("imports", self.tables["imports"], "max_imports_per_binary"):
            name, library = str(row.get("name", "")), str(row.get("library", ""))
            identity = self._identity(EntityKind.BINARY_IMPORT, {"library": library, "name": name})
            thunks = [item for item in row.get("thunks") or () if isinstance(item, str) and _ADDRESS.fullmatch(item)]
            self.builder.add_entity(EntityRecord(
                LogicalIdentity.parse(identity), f"{self.sha}:{library}::{name}", name, f"{library} {name}",
                {**self._common(), "name": name, "library": library, "kind": row.get("kind"), "thunks": thunks}))
            self.imports[f"{library}::{name}"] = identity
            for thunk in thunks:
                self.thunk_imports[thunk] = identity
            self.counts["imports"] += 1

    def _function(self, row: Mapping[str, Any], *, located: bool) -> None:
        address = str(row["address"])
        identity = self._identity(EntityKind.BINARY_FUNCTION, {"address": address})
        self.functions[address] = identity
        name = str(row.get("qualified_name") or row.get("name") or address)
        self.names[address] = name
        pseudo_c = row.get("pseudo_c") if isinstance(row.get("pseudo_c"), Mapping) else None
        payload = {**self._common(address), "name": name, "signature": row.get("signature"),
                   "name_source": row.get("name_source"), "is_thunk": bool(row.get("is_thunk")),
                   "thunk_target": row.get("thunk_target"), "is_export": bool(row.get("is_export")),
                   "decompile_status": row.get("decompile_status")}
        location, text = None, name
        if pseudo_c is not None:
            payload["pseudo_c"] = {key: pseudo_c.get(key) for key in ("sha256", "bytes", "lines", "truncated")}
            if pseudo_c.get("truncated"):
                self.gaps.append(f"pseudo_c_truncated: {address}")
        if pseudo_c is not None and located:
            data = (self.root / str(pseudo_c["path"])).read_bytes()
            if hashlib.sha256(data).hexdigest() != pseudo_c.get("sha256"):
                raise ValueError(f"binary {self.entry['binary_id']}: pseudo-C {address} changed after verification")
            decoded = data.decode("utf-8", errors="replace")
            backing = publish_binary_source(
                self.unit.job.run_root, target_snapshot=self.snapshot, binary_sha256=self.sha, address=address,
                publication_identity=str(self.entry["identity"]),
                manifest_sha256=str(self.entry["manifest_sha256"]), data=data)
            lines = decoded.split("\n")[:-1] or [""]
            location = SourceLocation(
                self.snapshot, binary_source_path(self.sha, address), str(pseudo_c["sha256"]), 0, len(data),
                1, len(lines), 1, len(lines[-1]) + 1, {"source_domain": "binary", "source_backing": backing},
                MAPPING, 1.0)
            self.texts[address] = decoded
            self.locations[address] = location
            text = _clip(f"{name}\n{decoded}", self.limits["max_entity_text_bytes"])
            self.counts["located_functions"] += 1
        self.builder.add_entity(EntityRecord(LogicalIdentity.parse(identity), f"{self.sha}@{address}", name,
                                             text, payload, location))
        self.counts["functions"] += 1
        thunk = self.thunk_imports.get(address)
        if thunk is not None:
            self._relation(RelationKind.REFERENCES, identity, thunk, role="import_thunk")

    def _callee(self, row: Mapping[str, Any]) -> str | None:
        target = row.get("to")
        if isinstance(target, str) and target in self.thunk_imports:
            return self.thunk_imports[target]
        if row.get("resolved_external"):
            return self.imports.get(str(row.get("resolved_name", "")))
        return self.functions.get(target) if isinstance(target, str) else None

    def _calls(self) -> None:
        rows = [row for row in self.tables["calls"] if row.get("from_function") in self.functions]
        for row in self._bounded("call_sites", rows, "max_call_sites_per_binary"):
            caller, site = str(row["from_function"]), str(row.get("call_site", ""))
            if not _ADDRESS.fullmatch(site):
                self.gaps.append(f"call_site_unaddressed: {caller}")
                continue
            callee = self._callee(row)
            name = _short(row.get("resolved_name") or row.get("to_name"))
            identity = self._identity(EntityKind.BINARY_CALL_SITE, {"call_site": site, "caller": caller,
                                                                    "to": row.get("to")})
            location, ambiguous = None, False
            text = self.texts.get(caller)
            found = _line_of(text, name) if text is not None else None
            if found is not None:
                number, start, end, columns, ambiguous = found
                base = self.locations[caller]
                location = SourceLocation(self.snapshot, base.path, base.file_sha256, start, end, number, number,
                                          1, columns, base.producer_location, MAPPING,
                                          0.6 if ambiguous else 0.9, ambiguous)
                self.counts["located_call_sites"] += 1
            payload = {**self._common(caller), "call_site": site, "callee_name": name, "callee_address": row.get("to"),
                       "external": bool(row.get("resolved_external")), "computed": bool(row.get("computed")),
                       "call_kind": row.get("kind"), "line_match": "ambiguous" if ambiguous else
                       "unique" if location is not None else "unlocated"}
            self.builder.add_entity(EntityRecord(LogicalIdentity.parse(identity), f"{self.sha}@{site}",
                                                 f"{_short(self.names[caller])} -> {name}",
                                                 f"call {name}", payload, location))
            self.counts["call_sites"] += 1
            self._relation(RelationKind.CONTAINS, self.functions[caller], identity)
            if callee is not None:
                self._relation(RelationKind.CALLS, identity, callee)
                self._relation(RelationKind.CALLS, self.functions[caller], callee, call_site=site)
            elif row.get("to") is None or row.get("computed"):
                self.gaps.append(f"unresolved_call: {site}")

    def _strings(self) -> None:
        for row in self._bounded("strings", self.tables["strings"], "max_strings_per_binary"):
            address = str(row.get("address", ""))
            if not _ADDRESS.fullmatch(address):
                continue
            value = str(row.get("value", ""))[:self.limits["max_string_chars"]]
            identity = self._identity(EntityKind.BINARY_STRING, {"address": address})
            xrefs = [item for item in row.get("xrefs") or () if isinstance(item, Mapping)]
            if len(xrefs) > self.limits["max_string_xrefs"] or row.get("xrefs_truncated"):
                self.gaps.append(f"string_xrefs_truncated: {address}")
                xrefs = xrefs[:self.limits["max_string_xrefs"]]
            self.builder.add_entity(EntityRecord(
                LogicalIdentity.parse(identity), f"{self.sha}@{address}", value[:256], value,
                {**self._common(), "address": address, "value": value, "length": row.get("length"),
                 "truncated": bool(row.get("truncated")) or len(str(row.get("value", ""))) > len(value),
                 "xrefs": [{"from": item.get("from"), "function": item.get("function")} for item in xrefs]}))
            self.counts["strings"] += 1
            for function in sorted({str(item.get("function")) for item in xrefs if item.get("function") in self.functions}):
                self._relation(RelationKind.REFERENCES, self.functions[function], identity, role="string_use")


def index_binary(unit: UnitContext, document: Mapping[str, Any], entry: Mapping[str, Any],
                 limits: Mapping[str, int]) -> dict[str, Any]:
    root, manifest = verified_publication(document, entry)
    shard = f"binary-{entry['binary_id']}"[:128]
    fingerprint = index_fingerprint(
        name="binary", target_snapshot=unit.job.source_fingerprint,
        producer_artifacts=[{"binary_sha256": entry["binary_sha256"], "publication_identity": entry["identity"],
                             "manifest_sha256": entry["manifest_sha256"]}],
        tool_identity={"tool": "ghidra", **{key: manifest.get("tool", {}).get(key)
                                            for key in ("tool_id", "image_id", "ghidra_version", "export_schema")}},
        parser_identity="binary-decompilation-publication/1", normalizer_identity=NORMALIZER,
        mapping_identity=json.dumps({"mapping": MAPPING, "limits": dict(sorted(limits.items()))}, sort_keys=True))
    path = (unit.job.run_root / "data" / "indices" / "binary" /
            f"{fingerprint}-{hashlib.sha256(shard.encode()).hexdigest()[:16]}.sqlite")
    builder = IndexBuilder(path, name="binary", fingerprint=fingerprint,
                           target_snapshot=unit.job.source_fingerprint, shard_id=shard)
    binary = _Binary(unit, entry, root, manifest, limits, builder)
    binary.build(managed_routing(manifest))
    status = "partial" if binary.gaps else "complete"
    builder.add_coverage(f"binary:{entry['binary_id']}"[:256], status, "; ".join(binary.gaps[:10]) or None)
    sha = file_sha256(path) if path.exists() else builder.build()
    gaps = [f"{entry['binary_id']}: {gap}" for gap in binary.gaps]
    index = IndexIdentity("binary", "appsec-review/retrieval-index/2", sha, fingerprint,
                          path.relative_to(unit.job.run_root).as_posix(),
                          {"job": JOB_ID, "unit": unit.unit_id, "binary_id": str(entry["binary_id"])},
                          tuple(gaps), shard)
    return {"scope_id": str(entry["binary_id"]), "binary_id": entry["binary_id"],
            "binary_sha256": entry["binary_sha256"], "publication_identity": entry["identity"],
            "manifest_sha256": entry["manifest_sha256"], "managed_code": bool(manifest["coverage"].get("managed_code")),
            "index_identity": asdict(index), "counts": binary.counts, "gaps": gaps,
            "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}


def _validate(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("binary evidence index topology does not match central configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"binary evidence index task configuration mismatch: {step}")


def build_job() -> Job:
    def load(unit: UnitContext) -> Mapping[str, Any]:
        _settings(unit)
        document, handoff_sha = accepted_binary_evidence(unit.job.run_root)
        resolved = [item for item in document["binaries"] if item.get("status") == "resolved"]
        unavailable = {str(item["binary_id"]): f"binary_decompilation_unavailable: {item.get('reason', '')}"[:500]
                       for item in document["binaries"] if item.get("status") != "resolved"}
        for entry in resolved:
            if (not _SHA256.fullmatch(str(entry.get("manifest_sha256"))) or
                    not _SHA256.fullmatch(str(entry.get("identity")))):
                raise ValueError(f"binary {entry.get('binary_id')}: intake record has no publication identity")
            verified_publication(document, entry)
        unit.job.events.write("BINARY_EVIDENCE_PUBLICATIONS_LOADED", resolved=len(resolved),
                              unavailable=len(unavailable))
        return {"upstream": {"intake_handoff_sha256": handoff_sha},
                "binaries": [{key: entry[key] for key in ("binary_id", "binary_sha256", "identity", "manifest_sha256")}
                             for entry in resolved],
                "unavailable": unavailable}

    def index(unit: UnitContext) -> Mapping[str, Any]:
        limits = _settings(unit)
        document, _ = accepted_binary_evidence(unit.job.run_root)
        planned = unit.output("load.accepted_publications")
        entries = {str(item["binary_id"]): item for item in document["binaries"] if item.get("status") == "resolved"}
        if sorted(entries) != sorted(str(item["binary_id"]) for item in planned["binaries"]):
            raise ValueError("frozen binary publications changed between load and index")
        results = [index_binary(unit, document, entries[binary_id], limits) for binary_id in sorted(entries)]
        gaps = [gap for item in results for gap in item["gaps"]]
        gaps.extend(f"{binary_id}: {reason}" for binary_id, reason in sorted(planned["unavailable"].items()))
        status = ("NOT_APPLICABLE" if not results and not planned["unavailable"] else
                  "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED")
        return {"binaries": results, "gaps": gaps, "terminal_status": status}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        loaded, indexed = unit.output("load.accepted_publications"), unit.output("index.binaries")
        manifest = publish_scope_indexes(unit, job_id=JOB_ID, index_name="binary", prefix="binary",
                                         results=indexed["binaries"], unavailable=loaded["unavailable"],
                                         gaps=indexed["gaps"], empty_reason="no binaries are configured for review")
        counts = {key: sum(int(item["counts"][key]) for item in indexed["binaries"])
                  for key in ("functions", "located_functions", "call_sites", "located_call_sites",
                              "imports", "strings", "relations")}
        summary_path = unit.unit_root / "binary-evidence-index-summary.json"
        atomic_json(summary_path, {"schema": SCHEMA, "upstream": loaded["upstream"], "counts": counts,
                                   "binaries": indexed["binaries"], "unavailable": loaded["unavailable"],
                                   "gaps": indexed["gaps"]})
        unit.job.events.write("BINARY_EVIDENCE_INDEX_COMPLETED", **counts, gap_count=len(indexed["gaps"]))
        return {"schema": SCHEMA, "artifact": artifact(unit.job.run_root, summary_path),
                "index_manifest": manifest, "item_count": counts["functions"], "counts": counts,
                "gaps": indexed["gaps"], "terminal_status": indexed["terminal_status"]}

    units = (
        Unit("load.accepted_publications", load),
        Unit("index.binaries", index, ("load.accepted_publications",)),
        Unit("acceptance.publish_handoff", publish, ("load.accepted_publications", "index.binaries")),
    )
    return Job(JOB_ID, "binary_evidence_indexing", UnitExecutor(units).execute, input_validators=(_validate,),
               schema_identity=SCHEMA, implementation_identity=None, units=units,
               datasets=DATASETS, consumes=CONSUMES)
