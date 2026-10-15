"""Assemble blint 3.4.0's report directory into one bounded JSON document.

blint 3.4.0 has no ``--format``/``--output`` options and never writes JSON to stdout (stdout is a
rich-text table). With ``--reports <dir>`` it writes, per run:

* ``findings.json`` ``{"scan_id", "created", "findings": [...]}`` only when there are findings;
* ``reviews.json`` ``{"scan_id", "created", "reviews": [...]}`` only when there are reviews;
* ``<lowercased basename>-metadata.json`` for every binary it actually analyzed;
* ``blint-output.html``, a console rendering (ignored here).

A binary with no findings therefore has a metadata file but no ``findings.json``; an input blint
did not analyze has neither. The assembled ``analyzed`` list is what distinguishes "clean" from
"not analyzed", so callers can keep the latter a coverage gap.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
from typing import Any


SCHEMA = "appsec-review/blint-report/1"
FINDINGS_FILE = "findings.json"
REVIEWS_FILE = "reviews.json"
METADATA_SUFFIX = "-metadata.json"
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_ITEMS = 20_000
# Hardening facts kept from each per-binary metadata file (the rest — strings, symbols — is large).
METADATA_FIELDS = ("file_path", "binary_type", "exe_type", "file_type", "machine_type", "is_pie",
                   "has_nx", "relro", "static", "is_shared_library", "has_canary", "fortify",
                   "llvm_target_tuple")
FINDING_FIELDS = ("id", "title", "severity", "filename", "exe_name", "exe_type")


def _load(path: Path) -> Any:
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError(f"blint report exceeds the parser byte bound: {path.name}")
    return json.loads(path.read_text(encoding="utf-8"))


def _items(document: Any, key: str) -> list[dict[str, Any]]:
    values = document.get(key, []) if isinstance(document, Mapping) else []
    if not isinstance(values, list):
        raise ValueError(f"blint {key} report is malformed")
    return [dict(item) for item in values[:MAX_ITEMS] if isinstance(item, Mapping)]


def assemble(reports_dir: Path) -> dict[str, Any]:
    """Read a blint ``--reports`` directory; malformed JSON raises (a parse gap, never 'clean')."""
    findings_path, reviews_path = reports_dir / FINDINGS_FILE, reports_dir / REVIEWS_FILE
    findings = [{key: item.get(key) for key in FINDING_FIELDS if key in item}
                for item in _items(_load(findings_path), "findings")] if findings_path.is_file() else []
    reviews = [{key: item.get(key) for key in ("id", "title", "severity", "filename", "exe_name")
                if key in item}
               for item in _items(_load(reviews_path), "reviews")] if reviews_path.is_file() else []
    analyzed = []
    for path in sorted(reports_dir.glob("*" + METADATA_SUFFIX))[:MAX_ITEMS]:
        document = _load(path)
        if not isinstance(document, Mapping):
            raise ValueError(f"blint metadata report is malformed: {path.name}")
        analyzed.append({"report": path.name,
                         **{key: document.get(key) for key in METADATA_FIELDS if key in document}})
    return {"schema": SCHEMA, "findings": findings, "finding_count": len(findings),
            "reviews": reviews, "analyzed": analyzed, "analyzed_count": len(analyzed)}


def write(reports_dir: Path, destination: Path) -> Path:
    destination.write_text(json.dumps(assemble(reports_dir), sort_keys=True), encoding="utf-8")
    return destination
