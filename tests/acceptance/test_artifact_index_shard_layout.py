"""Acceptance invariants for the per-build-unit artifact-index shard layout (build-unit-batch/1).

The pinned ``cpp-multivuln-v1`` oracle is checked directly. When ``APPSEC_ACCEPTANCE_RUN_ROOT``
names a run root that holds an accepted ``job_artifact_indexing`` publication, the same invariants
are checked against its verified index manifest, and each produced artifact must have coverage.
"""
from __future__ import annotations

from collections import defaultdict
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Iterable, Mapping

import pytest

from appsec_review.jobs.job_artifact_indexing import job as artifact_indexing

ROOT = Path(__file__).parents[2]
ORACLE = ROOT / "test" / "acceptance" / "cpp-multivuln-v1" / "job_artifact_indexing.json"
BATCHED = re.compile(r"^(relations|members)-(?P<unit>build-unit-[A-Za-z0-9_.-]+)-(?P<batch>\d{4})$")
FAMILIES = {"relations": "relationships", "members": "members"}


def _layout_problems(shards: Iterable[Mapping[str, Any]]) -> list[str]:
    problems: list[str] = []
    batches: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for shard in shards:
        shard_id = str(shard.get("shard_id", ""))
        if len(shard_id) > 128 or not re.fullmatch(r"[A-Za-z0-9_.-]+", shard_id):
            problems.append(f"{shard_id}: shard id is not bounded and portable")
        if shard_id.startswith("catalog-"):
            if set(shard.get("producer", {})) - {"job", "unit", "family"}:
                problems.append(f"{shard_id}: catalog producer gained batch fields")
            continue
        match = BATCHED.match(shard_id)
        if match is None:
            problems.append(f"{shard_id}: relations/members shard is not per build unit")
            continue
        prefix = shard_id.split("-", 1)[0]
        producer = shard.get("producer", {})
        if producer.get("family") != FAMILIES[prefix]:
            problems.append(f"{shard_id}: producer family {producer.get('family')!r} does not match prefix")
        if producer.get("build_unit_id") != match["unit"]:
            problems.append(f"{shard_id}: producer build unit differs from the shard id")
        if producer.get("batch") != int(match["batch"]):
            problems.append(f"{shard_id}: producer batch differs from the shard id")
        batches[(prefix, match["unit"])].append(shard)
    for (prefix, unit), members in sorted(batches.items()):
        counts = {item["producer"].get("batch_count") for item in members}
        numbers = sorted(item["producer"]["batch"] for item in members)
        if counts != {len(members)}:
            problems.append(f"{prefix}-{unit}: batch_count {sorted(counts, key=str)} != {len(members)} shards")
        if numbers != list(range(len(members))):
            problems.append(f"{prefix}-{unit}: batches {numbers} are not contiguous from 0000")
    return problems


def test_pinned_oracle_uses_one_relations_batch_per_build_unit() -> None:
    document = json.loads(ORACLE.read_text(encoding="utf-8"))
    outputs = document["outputs"]
    shards = [shard for unit in ("index.catalogs", "index.members", "index.relationships")
              for shard in outputs[unit]["indexes"]]
    assert _layout_problems(shards) == []
    units = {artifact["build_unit_id"] for receipt in outputs["load.accepted_builds"]["receipts"]
             for artifact in receipt["artifacts"]}
    relations = outputs["index.relationships"]["indexes"]
    # The corpus is far below MAX_ARTIFACTS_PER_SHARD/MAX_ROWS_PER_SHARD, so each unit is one batch.
    assert sorted(item["shard_id"] for item in relations) == sorted(f"relations-{unit}-0000" for unit in units)
    assert outputs["index.relationships"]["shard_count"] == len(relations)
    assert all(item["shard_id"].startswith("catalog-") for item in outputs["index.catalogs"]["indexes"])
    assert outputs["acceptance.publish_handoff"]["item_count"] == len(shards)


def _accepted_run_root() -> Path:
    selected = os.environ.get("APPSEC_ACCEPTANCE_RUN_ROOT")
    if not selected:
        pytest.skip("APPSEC_ACCEPTANCE_RUN_ROOT does not name an accepted acceptance run")
    return Path(selected).resolve()


def test_accepted_publication_layout_and_per_artifact_coverage() -> None:
    run_root = _accepted_run_root()
    accepted = artifact_indexing.load_accepted_artifact_index(run_root)
    manifest = json.loads((run_root / accepted["index_manifest"]["path"]).read_text(encoding="utf-8"))
    shards = [item for item in manifest["indexes"] if item["name"] == "artifacts"]
    assert _layout_problems(shards) == []
    assert accepted["artifact_shard_count"] == len(shards)
    limits = (artifact_indexing.MAX_ARTIFACTS_PER_SHARD, artifact_indexing.MAX_ROWS_PER_SHARD)
    covered: set[tuple[str, str]] = set()
    for shard in shards:
        if not shard["shard_id"].startswith("relations-"):
            continue
        unit = shard["producer"]["build_unit_id"]
        uri = f"{(run_root / shard['relative_path']).resolve().as_uri()}?mode=ro&immutable=1"
        with sqlite3.connect(uri, uri=True) as database:
            areas = {(unit, row[0]) for row in database.execute("SELECT area FROM coverage")}
            relations = database.execute("SELECT COUNT(*) FROM relations").fetchone()[0]
        assert len(areas) <= limits[0], shard["shard_id"]
        assert relations <= limits[1] or len(areas) == 1, shard["shard_id"]
        assert not covered.intersection(areas), f"{shard['shard_id']}: artifact covered by two batches"
        covered.update(areas)
    from appsec_review.jobs.job_language_build import load_accepted_language_build
    produced = {(receipt["build_unit_id"], artifact["workspace_path"])
                for receipt in load_accepted_language_build(run_root)["receipts"]
                for artifact in receipt.get("artifacts", ())}
    assert produced, "acceptance corpus produced no artifacts"
    assert produced <= covered
