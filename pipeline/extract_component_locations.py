#!/usr/bin/env python3
"""Extract Syft component locations from a CycloneDX SBOM.

This is a deterministic legacy-engagement transform. It does not classify a
component as shipped, reachable, vulnerable, or in scope; it only preserves
the location and cataloger metadata present in the supplied SBOM.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Iterable


MAX_INPUT_BYTES = 128 * 1024 * 1024
MAX_COMPONENTS = 500_000
LOCATION_PROPERTY = re.compile(r"^syft:location:\d+:path$")
CSV_FIELDS = ("Package", "Group", "Version", "Purl", "FoundBy", "PkgType", "Language", "Location")


def scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    raise ValueError("component metadata values must be scalar")


def property_values(properties: Any, name: str | re.Pattern[str]) -> list[str]:
    if properties is None:
        return []
    if not isinstance(properties, list):
        raise ValueError("component properties must be an array")
    values: list[str] = []
    for item in properties:
        if not isinstance(item, dict):
            raise ValueError("component property must be an object")
        key = item.get("name")
        matched = bool(name.fullmatch(key)) if isinstance(name, re.Pattern) and isinstance(key, str) else key == name
        if matched:
            values.append(scalar(item.get("value")))
    return values


def extract_rows(document: dict[str, Any]) -> list[dict[str, str]]:
    components = document.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("CycloneDX document must contain a non-empty components array")
    if len(components) > MAX_COMPONENTS:
        raise ValueError(f"component count exceeds {MAX_COMPONENTS}")

    rows: list[dict[str, str]] = []
    for index, component in enumerate(components, 1):
        if not isinstance(component, dict):
            raise ValueError(f"component {index} must be an object")
        properties = component.get("properties")
        found_by = property_values(properties, "syft:package:foundBy")
        package_type = property_values(properties, "syft:package:type")
        language = property_values(properties, "syft:package:language")
        locations = property_values(properties, LOCATION_PROPERTY) or [""]
        common = {
            "Package": scalar(component.get("name")),
            "Group": scalar(component.get("group")),
            "Version": scalar(component.get("version")),
            "Purl": scalar(component.get("purl")),
            "FoundBy": found_by[0] if found_by else "",
            "PkgType": package_type[0] if package_type else "",
            "Language": language[0] if language else "",
        }
        for location in locations:
            rows.append({**common, "Location": location})
    return rows


def location_prefix(location: str, levels: int) -> str:
    segments = [segment for segment in location.replace("\\", "/").split("/") if segment]
    return "/" + "/".join(segments[:levels]) if segments else "(no location data)"


def summaries(rows: Iterable[dict[str, str]], levels: int) -> tuple[Counter[str], Counter[str], dict[str, list[str]]]:
    if levels <= 0:
        raise ValueError("summary top levels must be positive")
    materialized = list(rows)
    prefixes = Counter(location_prefix(row["Location"], levels) for row in materialized)
    missing = Counter()
    samples: dict[str, list[str]] = defaultdict(list)
    for row in materialized:
        if row["Location"].strip():
            continue
        key = " | ".join((row["FoundBy"] or "(none)", row["PkgType"] or "(none)", row["Language"] or "(none)"))
        missing[key] += 1
        if len(samples[key]) < 5:
            samples[key].append(f'{row["Package"]}@{row["Version"]}')
    return prefixes, missing, dict(samples)


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    parent = path.parent.resolve(strict=True)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("output must be a regular file or a new path")
    handle, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS, quoting=csv.QUOTE_ALL)
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def load(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("SBOM input must be a regular file")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"SBOM input exceeds {MAX_INPUT_BYTES} bytes")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("CycloneDX document must be an object")
    return value


def render_summary(rows: list[dict[str, str]], levels: int) -> str:
    prefixes, missing, samples = summaries(rows, levels)
    lines = [f"Total (package, version, location) rows: {len(rows)}", "",
             f"=== Path-prefix summary (top {levels} segments), component-instance counts ==="]
    lines.extend(f"{count:6}  {key}" for key, count in sorted(prefixes.items(), key=lambda item: (-item[1], item[0])))
    lines.extend(("", "=== No-location breakdown by (FoundBy | PkgType | Language), row counts ===",
                  f"Total rows with no location data: {sum(missing.values())}"))
    lines.extend(f"{count:6}  {key}" for key, count in sorted(missing.items(), key=lambda item: (-item[1], item[0])))
    lines.extend(("", "=== Sample package names per no-location bucket (up to 5 each) ==="))
    for key, count in sorted(missing.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"  [{count}] {key}")
        lines.append("      e.g. " + ", ".join(samples[key]))
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", required=True, type=Path, help="CycloneDX JSON produced by Syft")
    parser.add_argument("--out", required=True, type=Path, help="CSV destination")
    parser.add_argument("--summary-top-levels", type=int, default=3)
    args = parser.parse_args(argv)
    if args.summary_top_levels <= 0:
        parser.error("--summary-top-levels must be positive")
    document = load(args.sbom)
    rows = extract_rows(document)
    write_csv(args.out, rows)
    print(f'Total components in SBOM: {len(document["components"])}')
    print(render_summary(rows, args.summary_top_levels), end="")
    print(f"Wrote full location data to: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
