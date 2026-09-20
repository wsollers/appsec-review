#!/usr/bin/env python3
"""Materialize and verify immutable OWASP/OpenCRE reference snapshots.

Materialization consumes explicit local checkouts pinned by ``source-lock.json``.  It never
resolves a branch, tag, or live API itself.  OpenCRE's dated API export is likewise supplied as a
raw file produced by the pinned upstream exporter.  Verification is entirely offline.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import uuid
from typing import Any, Iterable

import yaml

from schema_validate import SchemaStore, validate_document


SCHEMA = "appsec-review/reference-snapshot-manifest/1.0"
EXTRACTOR_NAME = "appsec-review/reference_snapshots.py"
EXTRACTOR_VERSION = "1.0"
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOCK = REPO_ROOT / "data/reference/source-lock.json"
DEFAULT_OUTPUT = REPO_ROOT / "data/reference"


class SnapshotError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_record(path: Path, relative_to: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(relative_to).as_posix(),
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


def normalized_rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def source_map(values: Iterable[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise SnapshotError(f"source root must be FAMILY=PATH: {value!r}")
        family, raw_path = value.split("=", 1)
        path = Path(raw_path).resolve()
        if family in result:
            raise SnapshotError(f"duplicate source root for {family}")
        if not path.is_dir():
            raise SnapshotError(f"source root is not a directory: {path}")
        result[family] = path
    return result


def expand_inputs(root: Path, patterns: list[str]) -> list[Path]:
    found: dict[str, Path] = {}
    for pattern in patterns:
        for path in root.glob(pattern):
            if path.is_file():
                relative = normalized_rel(path, root)
                found[relative] = path
    missing = [pattern for pattern in patterns if not any(root.glob(pattern))]
    if missing:
        raise SnapshotError(f"source {root} did not match required patterns: {missing}")
    return [found[key] for key in sorted(found)]


def git_output(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args], check=False, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise SnapshotError(f"git {' '.join(args)} failed for {root}: {detail}")
    return completed.stdout.strip()


def verify_source_checkout(source: dict[str, Any], root: Path, inputs: list[Path], license_path: Path) -> None:
    if not (root / ".git").exists():
        raise SnapshotError(f"source root is not a Git checkout: {root}")
    head = git_output(root, "rev-parse", "HEAD")
    if head != source["resolved_commit"]:
        raise SnapshotError(
            f"{source['family']} checkout is {head}, expected {source['resolved_commit']}"
        )
    generated = set(source.get("generated_inputs", []))
    tracked = [path for path in [*inputs, license_path] if normalized_rel(path, root) not in generated]
    for path in tracked:
        relative = normalized_rel(path, root)
        git_output(root, "ls-files", "--error-unmatch", "--", relative)
        completed = subprocess.run(
            ["git", "-C", str(root), "diff", "--quiet", "HEAD", "--", relative],
            check=False,
        )
        if completed.returncode != 0:
            raise SnapshotError(f"tracked source differs from pinned commit: {root / relative}")


def parse_sections(text: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current = ""
    for line in text.splitlines():
        if line.startswith("## "):
            current = line[3:].strip().lower()
            sections.setdefault(current, [])
        elif current:
            sections[current].append(line)
    return {key: "\n".join(lines).strip() for key, lines in sections.items()}


def citation(snapshot_id: str, raw_path: str, raw_hashes: dict[str, str], row: int | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {
        "snapshot_id": snapshot_id,
        "raw_path": f"raw/{raw_path}",
        "raw_sha256": raw_hashes[raw_path],
    }
    if row is not None:
        value["raw_row"] = row
    return value


def control_record(
    *, family: str, edition: str, control_id: str, title: str, text: str,
    source: dict[str, Any], profiles: list[str], group: dict[str, str] | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": "appsec-review/owasp-control-record/1.0",
        "record_type": "control",
        "standard_family": family,
        "standard_version": edition,
        "control_id": control_id,
        "title": title,
        "text": text,
        "profiles": profiles,
        "proof_obligations": [{
            "obligation_id": f"{control_id}:1",
            "text": text,
            "evidence_classification": "unclassified_requires_policy",
            "minimum_evidence_modes": [],
        }],
        "source": source,
    }
    if group:
        value["group"] = group
    return value


def normalize_asvs(source: dict[str, Any], root: Path, snapshot_id: str, hashes: dict[str, str]) -> list[dict[str, Any]]:
    candidates = [p for p in expand_inputs(root, source["raw_includes"]) if p.name.endswith(".flat.json")]
    if len(candidates) != 1:
        raise SnapshotError("ASVS source must contain exactly one flat JSON catalog")
    path = candidates[0]
    relative = normalized_rel(path, root)
    payload = load_json(path)
    records = []
    for item in payload.get("requirements", []):
        control_id = str(item.get("req_id", "")).strip()
        text = str(item.get("req_description", "")).strip()
        level = str(item.get("L", "")).strip()
        if not control_id or not text or level not in {"1", "2", "3"}:
            raise SnapshotError(f"invalid ASVS requirement in {relative}: {item!r}")
        records.append(control_record(
            family=source["family"], edition=source["edition"], control_id=control_id,
            title=str(item.get("section_name", "")).strip() or control_id, text=text,
            profiles=[f"L{level}"], source=citation(snapshot_id, relative, hashes),
            group={
                "chapter_id": str(item.get("chapter_id", "")),
                "chapter_name": str(item.get("chapter_name", "")),
                "section_id": str(item.get("section_id", "")),
                "section_name": str(item.get("section_name", "")),
            },
        ))
    ids = [row["control_id"] for row in records]
    if len(ids) != len(set(ids)):
        raise SnapshotError("ASVS catalog contains duplicate control IDs")
    return sorted(records, key=lambda row: row["control_id"])


def normalize_masvs(source: dict[str, Any], root: Path, snapshot_id: str, hashes: dict[str, str]) -> list[dict[str, Any]]:
    records = []
    for path in expand_inputs(root, source["raw_includes"]):
        relative = normalized_rel(path, root)
        control_id = path.stem
        sections = parse_sections(path.read_text(encoding="utf-8"))
        title = sections.get("control", "").strip()
        description = sections.get("description", "").strip()
        if not re.fullmatch(r"MASVS-[A-Z]+-[0-9]+", control_id) or not title:
            raise SnapshotError(f"invalid MASVS control: {relative}")
        records.append(control_record(
            family=source["family"], edition=source["edition"], control_id=control_id,
            title=title, text=description or title, profiles=[],
            source=citation(snapshot_id, relative, hashes),
            group={"category": control_id.rsplit("-", 1)[0]},
        ))
    ids = [row["control_id"] for row in records]
    if len(ids) != len(set(ids)):
        raise SnapshotError("MASVS catalog contains duplicate control IDs")
    return sorted(records, key=lambda row: row["control_id"])


def split_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text
    try:
        end = lines.index("---", 1)
    except ValueError as exc:
        raise SnapshotError("unterminated YAML frontmatter") from exc
    metadata = yaml.safe_load("\n".join(lines[1:end])) or {}
    if not isinstance(metadata, dict):
        raise SnapshotError("frontmatter is not an object")
    return metadata, "\n".join(lines[end + 1 :])


def strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)]


def normalize_mastg(source: dict[str, Any], root: Path, snapshot_id: str, hashes: dict[str, str]) -> list[dict[str, Any]]:
    records = []
    for path in expand_inputs(root, source["raw_includes"]):
        relative = normalized_rel(path, root)
        metadata, body = split_frontmatter(path.read_text(encoding="utf-8"))
        modes = []
        if re.search(r"^## Static Analysis\s*$", body, flags=re.MULTILINE):
            modes.append("static")
        if re.search(r"^## Dynamic Analysis\s*$", body, flags=re.MULTILINE):
            modes.append("dynamic")
        if not modes:
            modes.append("manual_or_unspecified")
        platform = str(metadata.get("platform") or path.parts[-3]).lower()
        record = {
            "schema": "appsec-review/owasp-test-record/1.0",
            "record_type": "test",
            "standard_family": source["family"],
            "standard_version": source["edition"],
            "test_id": path.stem,
            "title": str(metadata.get("title") or path.stem).strip(),
            "platform": platform,
            "catalog_stage": "beta" if relative.startswith("tests-beta/") else "stable",
            "status": str(metadata["status"]) if metadata.get("status") is not None else None,
            "profiles": strings(metadata.get("profiles")),
            "legacy_control_ids": strings(metadata.get("masvs_v1_id")),
            "covers_control_ids": strings(metadata.get("masvs_v2_id")),
            "test_modes": modes,
            "source": citation(snapshot_id, relative, hashes),
        }
        records.append(record)
    ids = [row["test_id"] for row in records]
    if len(ids) != len(set(ids)):
        raise SnapshotError("MASTG stable and beta catalogs contain duplicate test IDs")
    return sorted(records, key=lambda row: row["test_id"])


def first_heading(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return ""


def context_id(family: str, stem: str) -> str | None:
    if family == "owasp_top_10":
        match = re.search(r"(A(?:0[1-9]|10))_2025", stem, flags=re.IGNORECASE)
        return match.group(1).upper() if match else None
    if family == "owasp_api_security_top_10":
        match = re.fullmatch(r"0xa([1-9a])-.*", stem, flags=re.IGNORECASE)
        if not match:
            return None
        return "API10" if match.group(1).lower() == "a" else f"API{match.group(1)}"
    match = re.match(r"LLM(0[1-9]|10)_", stem)
    return f"LLM{match.group(1)}" if match else None


def normalize_context(source: dict[str, Any], root: Path, snapshot_id: str, hashes: dict[str, str]) -> list[dict[str, Any]]:
    records = []
    for path in expand_inputs(root, source["raw_includes"]):
        if path.suffix.lower() != ".md":
            continue
        category_id = context_id(source["family"], path.stem)
        if category_id is None:
            continue
        relative = normalized_rel(path, root)
        text = path.read_text(encoding="utf-8").strip()
        records.append({
            "schema": "appsec-review/owasp-context-record/1.0",
            "record_type": "context_category",
            "standard_family": source["family"],
            "standard_version": source["edition"],
            "category_id": category_id,
            "title": first_heading(text) or category_id,
            "text": text,
            "role": "routing_context_only",
            "source": citation(snapshot_id, relative, hashes),
        })
    ids = [row["category_id"] for row in records]
    if len(ids) != 10 or len(set(ids)) != 10:
        raise SnapshotError(f"{source['family']} must normalize to exactly ten unique categories")
    return sorted(records, key=lambda row: row["category_id"])


def split_aligned(value: str) -> list[str]:
    return value.split("|") if value else []


def normalize_opencre(source: dict[str, Any], root: Path, snapshot_id: str, hashes: dict[str, str]) -> list[dict[str, Any]]:
    csv_paths = [p for p in expand_inputs(root, source["raw_includes"]) if p.suffix.lower() == ".csv"]
    if len(csv_paths) != 1:
        raise SnapshotError("OpenCRE source must contain exactly one CSV export")
    path = csv_paths[0]
    relative = normalized_rel(path, root)
    records = []
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            raise SnapshotError("OpenCRE CSV has no header")
        cre_columns = sorted(
            (name for name in reader.fieldnames if re.fullmatch(r"CRE [0-9]+", name)),
            key=lambda name: int(name.split()[1]),
        )
        standards = sorted({name[:-3] for name in reader.fieldnames if name.endswith("|id")})
        for row_number, row in enumerate(reader, start=2):
            cre_path = []
            for name in cre_columns:
                value = (row.get(name) or "").strip()
                if not value:
                    continue
                cre_id, _, title = value.partition("|")
                cre_path.append({"cre_id": cre_id.strip(), "title": title.strip()})
            if not cre_path:
                raise SnapshotError(f"OpenCRE row {row_number} has no CRE path")
            mappings = []
            for standard in standards:
                ids = split_aligned((row.get(f"{standard}|id") or "").strip())
                if not ids:
                    continue
                columns = {
                    key: split_aligned((row.get(f"{standard}|{suffix}") or "").strip())
                    for key, suffix in (
                        ("section_name", "name"), ("subsection", "section"),
                        ("hyperlink", "hyperlink"), ("description", "description"),
                        ("version", "version"), ("tooltype", "tooltype"),
                        ("link_type", "link_type"),
                    )
                }
                for index, section_id in enumerate(ids):
                    def at(key: str) -> str:
                        values = columns[key]
                        return values[index].strip() if index < len(values) else ""
                    mappings.append({
                        "standard": standard,
                        "section_id": section_id.strip(),
                        "section_name": at("section_name"),
                        "subsection": at("subsection"),
                        "hyperlink": at("hyperlink"),
                        "description": at("description"),
                        "version": at("version"),
                        "tooltype": at("tooltype"),
                        "link_type": at("link_type"),
                    })
            identity = {
                "cre_path": cre_path,
                "description": (row.get("CRE Description") or "").strip(),
                "tags": sorted(filter(None, (part.strip() for part in (row.get("CRE Tags") or "").split(";")))),
                "mappings": mappings,
            }
            records.append({
                "schema": "appsec-review/opencre-crosswalk-record/1.0",
                "record_type": "crosswalk",
                "record_id": f"sha256:{sha256_bytes(canonical_json(identity))}",
                "cre_path": cre_path,
                "cre_leaf_id": cre_path[-1]["cre_id"],
                "description": identity["description"],
                "tags": identity["tags"],
                "mappings": mappings,
                "source": citation(snapshot_id, relative, hashes, row_number),
            })
    ids = [row["record_id"] for row in records]
    if len(ids) != len(set(ids)):
        raise SnapshotError("OpenCRE export produced duplicate normalized rows")
    return sorted(records, key=lambda row: (row["cre_leaf_id"], row["record_id"]))


NORMALIZERS = {
    "asvs_flat_json": (normalize_asvs, "owasp-control-record.schema.json"),
    "masvs_markdown": (normalize_masvs, "owasp-control-record.schema.json"),
    "mastg_markdown": (normalize_mastg, "owasp-test-record.schema.json"),
    "context_markdown": (normalize_context, "owasp-context-record.schema.json"),
    "opencre_csv": (normalize_opencre, "opencre-crosswalk-record.schema.json"),
}


def identity_digest(source: dict[str, Any], raw_files: list[dict[str, Any]], license_hash: str) -> str:
    basis = {
        "family": source["family"],
        "edition": source["edition"],
        "upstream_url": source["upstream_url"],
        "immutable_ref": source["immutable_ref"],
        "resolved_commit": source["resolved_commit"],
        "license_sha256": license_hash,
        "extractor": {"name": EXTRACTOR_NAME, "version": EXTRACTOR_VERSION},
        "raw_files": raw_files,
    }
    return sha256_bytes(canonical_json(basis))


def destination_root(output: Path, source: dict[str, Any], snapshot_id: str) -> Path:
    if source["family"] == "opencre":
        return output / "opencre" / snapshot_id
    return output / "owasp" / source["family"] / source["edition"] / snapshot_id


def validate_records(records: list[dict[str, Any]], schema_name: str) -> None:
    store = SchemaStore()
    errors = []
    for index, record in enumerate(records):
        errors.extend(f"record[{index}] {error}" for error in validate_document(record, schema_name, store))
    if errors:
        raise SnapshotError("normalized record validation failed:\n" + "\n".join(errors[:50]))


def materialize_one(source: dict[str, Any], root: Path, output: Path, retrieved_at: str) -> Path:
    inputs = expand_inputs(root, source["raw_includes"])
    license_source = root / PurePosixPath(source["license_path"])
    if not license_source.is_file():
        raise SnapshotError(f"missing license/usage file: {license_source}")
    verify_source_checkout(source, root, inputs, license_source)
    raw_source_records = [{
        "path": f"raw/{normalized_rel(path, root)}",
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    } for path in inputs]
    license_hash = sha256_file(license_source)
    identity = identity_digest(source, raw_source_records, license_hash)
    snapshot_id = f"sha256-{identity[:16]}"
    final = destination_root(output, source, snapshot_id)
    if final.exists():
        verify_snapshot(final)
        return final

    staging = output / f".staging-{source['family']}-{uuid.uuid4().hex}"
    try:
        for path in inputs:
            relative = Path(normalized_rel(path, root))
            target = staging / "raw" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
        staging.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(license_source, staging / "LICENSE-or-usage.txt")
        raw_hashes = {normalized_rel(path, root): sha256_file(path) for path in inputs}
        normalizer, schema_name = NORMALIZERS[source["source_kind"]]
        records = normalizer(source, root, snapshot_id, raw_hashes)
        if len(records) != source["expected_record_count"]:
            raise SnapshotError(
                f"{source['family']} normalized {len(records)} records; "
                f"expected {source['expected_record_count']}"
            )
        validate_records(records, schema_name)
        write_json(staging / "normalized/catalog.json", {
            "schema": "appsec-review/reference-catalog/1.0",
            "family": source["family"],
            "edition": source["edition"],
            "snapshot_id": snapshot_id,
            "records": records,
        })
        raw_files = [file_record(path, staging) for path in sorted((staging / "raw").rglob("*")) if path.is_file()]
        normalized_files = [file_record(path, staging) for path in sorted((staging / "normalized").rglob("*")) if path.is_file()]
        content_digest = sha256_bytes(canonical_json({
            "raw_files": raw_files,
            "normalized_files": normalized_files,
            "license_sha256": license_hash,
            "extractor": {"name": EXTRACTOR_NAME, "version": EXTRACTOR_VERSION},
        }))
        manifest = {
            "schema": SCHEMA,
            "snapshot_id": snapshot_id,
            "family": source["family"],
            "edition": source["edition"],
            "upstream": {
                "url": source["upstream_url"],
                "immutable_ref": source["immutable_ref"],
                "resolved_commit": source["resolved_commit"],
                "tag_object": source.get("tag_object"),
            },
            "retrieved_at": retrieved_at,
            "license": {
                "identifier": source["license_identifier"],
                "source_path": source["license_path"],
                "sha256": license_hash,
            },
            "extractor": {"name": EXTRACTOR_NAME, "version": EXTRACTOR_VERSION, "source_path": "appsec-review-process/reference_snapshots.py"},
            "raw_files": raw_files,
            "normalized_files": normalized_files,
            "lineage": [{
                "normalized_path": "normalized/catalog.json",
                "raw_paths": [record["path"] for record in raw_files],
            }],
            "record_counts": {
                "records": len(records),
                "raw_files": len(raw_files),
                "normalized_files": len(normalized_files),
            },
            "content_digest": content_digest,
            "validation": {"status": "PASS", "checks": ["manifest schema", "file hashes", "record schema", "unique record identity"]},
        }
        errors = validate_document(manifest, "reference-snapshot-manifest.schema.json")
        if errors:
            raise SnapshotError("manifest validation failed:\n" + "\n".join(errors))
        write_json(staging / "manifest.json", manifest)
        final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staging, final)
        verify_snapshot(final)
        return final
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise


def verify_snapshot(root: Path) -> dict[str, Any]:
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise SnapshotError(f"missing manifest: {manifest_path}")
    manifest = load_json(manifest_path)
    errors = validate_document(manifest, "reference-snapshot-manifest.schema.json")
    if errors:
        raise SnapshotError(f"invalid manifest {manifest_path}:\n" + "\n".join(errors))
    if root.name != manifest["snapshot_id"]:
        raise SnapshotError(f"snapshot directory/name mismatch: {root}")
    for collection in ("raw_files", "normalized_files"):
        for record in manifest[collection]:
            path = root / PurePosixPath(record["path"])
            if not path.is_file() or path.stat().st_size != record["bytes"] or sha256_file(path) != record["sha256"]:
                raise SnapshotError(f"snapshot file mismatch: {path}")
    license_path = root / "LICENSE-or-usage.txt"
    if not license_path.is_file() or sha256_file(license_path) != manifest["license"]["sha256"]:
        raise SnapshotError(f"license file mismatch: {license_path}")
    content_digest = sha256_bytes(canonical_json({
        "raw_files": manifest["raw_files"],
        "normalized_files": manifest["normalized_files"],
        "license_sha256": manifest["license"]["sha256"],
        "extractor": {"name": manifest["extractor"]["name"], "version": manifest["extractor"]["version"]},
    }))
    if content_digest != manifest["content_digest"]:
        raise SnapshotError(f"content digest mismatch: {manifest_path}")
    catalog = load_json(root / "normalized/catalog.json")
    if catalog.get("snapshot_id") != manifest["snapshot_id"] or len(catalog.get("records", [])) != manifest["record_counts"]["records"]:
        raise SnapshotError(f"catalog identity/count mismatch: {root}")
    schema_name = {
        "owasp_asvs": "owasp-control-record.schema.json",
        "owasp_masvs": "owasp-control-record.schema.json",
        "owasp_mastg": "owasp-test-record.schema.json",
        "owasp_top_10": "owasp-context-record.schema.json",
        "owasp_api_security_top_10": "owasp-context-record.schema.json",
        "owasp_llm_top_10": "owasp-context-record.schema.json",
        "opencre": "opencre-crosswalk-record.schema.json",
    }.get(manifest["family"])
    if not schema_name:
        raise SnapshotError(f"unsupported snapshot family: {manifest['family']}")
    validate_records(catalog["records"], schema_name)
    return manifest


def verify_tree(root: Path) -> list[Path]:
    manifests = sorted(root.glob("**/manifest.json"))
    if not manifests:
        raise SnapshotError(f"no snapshot manifests found under {root}")
    verified = []
    for manifest in manifests:
        verify_snapshot(manifest.parent)
        verified.append(manifest.parent)
    return verified


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    materialize = subparsers.add_parser("materialize")
    materialize.add_argument("--source-lock", type=Path, default=DEFAULT_LOCK)
    materialize.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    materialize.add_argument("--source-root", action="append", default=[], metavar="FAMILY=PATH")
    materialize.add_argument("--retrieved-at", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--root", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            verified = verify_tree(args.root.resolve())
            print(json.dumps({"status": "PASS", "snapshots": [str(path) for path in verified]}, indent=2))
            return 0
        lock = load_json(args.source_lock.resolve())
        lock_errors = validate_document(lock, "reference-source-lock.schema.json")
        if lock_errors:
            raise SnapshotError("source lock validation failed:\n" + "\n".join(lock_errors))
        roots = source_map(args.source_root)
        expected = {source["family"] for source in lock.get("sources", [])}
        missing = sorted(expected - set(roots))
        unexpected = sorted(set(roots) - expected)
        if missing or unexpected:
            raise SnapshotError(f"source-root mismatch; missing={missing}, unexpected={unexpected}")
        outputs = [
            materialize_one(source, roots[source["family"]], args.output.resolve(), args.retrieved_at)
            for source in lock["sources"]
        ]
        print(json.dumps({"status": "PASS", "snapshots": [str(path) for path in outputs]}, indent=2))
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, yaml.YAMLError, SnapshotError) as exc:
        print(f"reference snapshot error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
