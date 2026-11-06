"""Reproducible JSON and JSON-valued CSV exports; immutable publication by content hash."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from appsec_review.storage import canonical_json, protected_json

from .contracts import (
    ADJUDICATIONS, COMPLETION, LAUNCH, MEMBERSHIP, OUTPUT, GROUP_METRICS, RUN_METRICS, digest, validate,
)
from .metrics import rebuild


def _verify(snapshot: dict[str, Any]) -> None:
    validate(snapshot, OUTPUT)
    if rebuild(snapshot["source"]) != snapshot:
        raise ValueError("quality snapshot does not match a rebuild of its immutable source")


def csv_exports(snapshot: dict[str, Any]) -> dict[str, str]:
    """Every data cell is JSON, including null and strings; spreadsheets cannot execute IDs."""
    _verify(snapshot)
    provenance = {name: snapshot[name] for name in (
        "experiment_id", "source_sha256", "matching_snapshot_id", "normalizer_version",
        "matching_revision", "label_snapshot_id", "label_revision")}
    provenance["snapshot_id"] = digest(snapshot)
    tables = {
        "runs": (snapshot["runs"], RUN_METRICS),
        "groups": (snapshot["groups"], GROUP_METRICS),
        "membership": (snapshot["membership"], MEMBERSHIP),
        "launches": (snapshot["source"]["launches"], LAUNCH),
        "completions": (snapshot["source"]["completions"], COMPLETION),
        "adjudications": (snapshot["source"]["adjudications"]["labels"], ADJUDICATIONS["properties"]["labels"]["items"]),
    }
    exports = {}
    for name, (rows, schema) in tables.items():
        fields = list(provenance) + list(schema["properties"])
        stream = io.StringIO(newline="")
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(fields)
        for row in rows:
            combined = {**provenance, **row}
            writer.writerow(json.dumps(combined[field], sort_keys=True, ensure_ascii=True, separators=(",", ":"),
                                       allow_nan=False) for field in fields)
        exports[name + ".csv"] = stream.getvalue()
    return exports


def publish_snapshot(directory: Path, snapshot: dict[str, Any]) -> dict[str, str]:
    """Pin run identities first, then publish the self-contained snapshot as the commit marker."""
    _verify(snapshot)
    snapshot_id = digest(snapshot)
    directory = Path(directory)
    source = snapshot["source"]
    experiment_id = source["experiment_id"]
    for launch in source["launches"]:
        key = digest({"experiment_id": experiment_id, "run_id": launch["run_id"]})
        index_key = digest({"experiment_id": experiment_id, "run_index": launch["run_index"]})
        _publish_immutable(directory / "launches" / (key + ".json"), launch)
        _publish_immutable(directory / "indices" / (index_key + ".json"), launch)
    for completion in source["completions"]:
        key = digest({"experiment_id": experiment_id, "run_id": completion["run_id"]})
        _publish_immutable(directory / "completions" / (key + ".json"), completion)
    _publish_immutable(directory / "matching" / (snapshot["matching_snapshot_id"] + ".json"), source["matching"])
    _publish_immutable(directory / "adjudications" / (snapshot["label_snapshot_id"] + ".json"), source["adjudications"])
    path = directory / (snapshot_id + ".json")
    status = _publish_immutable(path, snapshot)
    return {"status": status, "snapshot_id": snapshot_id, "path": str(path)}


def _publish_immutable(path: Path, value: Any) -> str:
    try:
        protected_json(path, value)
    except FileExistsError:
        if path.read_bytes() != canonical_json(value):
            raise ValueError(f"immutable quality record conflict or incomplete publication: {path}") from None
        return "duplicate"
    return "published"
