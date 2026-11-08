"""Run build discovery over a folder and judge it against a discovery case.

``python -m appsec_review.acceptance.discovery assign <folder> [--json]`` prints the total assignment
of the folder's paths (plan §2) and a summary; ``check <case-dir>`` evaluates a
``test/discovery/cases/<NNN>-<slug>/`` case (``tree/`` + ``expect.json``) and prints each check with
its verdict; ``new <case-dir>`` writes a draft ``expect.json`` from what discovery currently says,
for an author to correct into the contract. Only the standard library is imported at module level.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import fnmatch
import json
from pathlib import Path
import sys
from typing import Any

CASE_SCHEMA = "appsec-review/discovery-case/1"


@dataclass(frozen=True)
class Check:
    id: str
    ok: bool
    detail: str = ""


def run_discovery(folder: Path) -> dict[str, Any]:
    """Inventory + discovery + source-only scopes + assignment for one folder, deterministically."""
    from appsec_review.jobs.build_discovery import discover_build_inventory, source_only_scopes
    from appsec_review.jobs.cataloging import Bounds, inventory
    from appsec_review.jobs.discovery_assignment import assign_paths, summarize

    folder = Path(folder).resolve()
    snapshot = inventory(folder, Bounds())
    files = snapshot["files"]
    accepted = {str(item["path"]): item for item in files}

    def read_text(relative: str) -> str | None:
        identity = accepted.get(relative)
        if identity is None or int(identity["size_bytes"]) > 64 * 1024:
            return None
        try:
            return (folder / relative).read_bytes().decode("utf-8")
        except (OSError, UnicodeError):
            return None

    discovered = discover_build_inventory(files, read_text=read_text)
    scopes = source_only_scopes(files, discovered["units"])
    assignment = assign_paths(files, discovered, source_only_scopes=scopes)
    return {"files": [str(item["path"]) for item in files], "units": discovered["units"],
            "orphaned_sources": discovered["orphaned_sources"], "source_only_scopes": scopes,
            "assignment": assignment, "summary": summarize(assignment)}


def _label(unit: dict[str, Any]) -> str:
    return f"{unit['root']}|{unit['build_system']}"


def _subset(expected: Any, actual: Any) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(key in actual and _subset(value, actual[key]) for key, value in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and expected == actual
    return expected == actual


def evaluate_case(case_dir: Path) -> tuple[dict[str, Any], list[Check]]:
    """Every check of a case, each with its verdict. Pending checks are not filtered here."""
    from appsec_review.jobs.build_discovery import required_image_profile

    case_dir = Path(case_dir)
    expect = json.loads((case_dir / "expect.json").read_text(encoding="utf-8"))
    if expect.get("schema") != CASE_SCHEMA:
        raise ValueError(f"{case_dir}: expect.json schema is not {CASE_SCHEMA}")
    result = run_discovery(case_dir / "tree")
    second = run_discovery(case_dir / "tree")
    checks: list[Check] = []
    units = {_label(unit): unit for unit in result["units"]}
    expected_labels = set()
    for spec in expect["units"]:
        label = f"{spec['root']}|{spec['build_system']}"
        expected_labels.add(label)
        unit = units.get(label)
        checks.append(Check(f"unit:{label}", unit is not None, "unit not discovered" if unit is None else ""))
        if unit is None:
            continue
        checks.append(Check(f"unit:{label}.family", unit["family"] == spec["family"],
                            f"family {unit['family']!r} != {spec['family']!r}"))
        if "profile" in spec:
            profile = required_image_profile(unit)
            checks.append(Check(f"unit:{label}.profile", profile == spec["profile"], f"profile {profile!r} != {spec['profile']!r}"))
        if "markers" in spec:
            markers = sorted(str(m["path"]) for m in unit.get("markers", ()))
            checks.append(Check(f"unit:{label}.markers", markers == sorted(spec["markers"]), f"markers {markers}"))
        if "facts" in spec:
            checks.append(Check(f"unit:{label}.facts", _subset(spec["facts"], unit), "facts differ: " + json.dumps(
                {key: unit.get(key) for key in spec["facts"]}, sort_keys=True, default=str)[:400]))
        for point in spec.get("build_points", ()):
            actual = next((bp for bp in unit.get("build_points", ()) if bp.get("name") == point["name"]), None)
            ok = actual is not None and actual.get("kind") == point["kind"] and (
                "evidence" not in point or actual.get("evidence") == point["evidence"])
            checks.append(Check(f"unit:{label}.build_point:{point['name']}", ok,
                                "build point missing" if actual is None else f"build point {actual}"))
    declared_absent = {f"{spec['root']}|{spec['build_system']}" for spec in expect["not_units"] if "build_system" in spec}
    declared_absent |= {label for label in units if any(
        "build_system" not in spec and units[label]["root"] == spec["root"] for spec in expect["not_units"])}
    for label in sorted(set(units) - expected_labels - declared_absent):
        checks.append(Check(f"unexpected_unit:{label}", False, "discovered a unit the case does not describe"))
    for spec in expect["not_units"]:
        if "build_system" in spec:
            present = f"{spec['root']}|{spec['build_system']}" in units
        else:
            present = any(unit["root"] == spec["root"] for unit in result["units"])
        checks.append(Check(f"not_unit:{spec['root']}" + (f"|{spec['build_system']}" if "build_system" in spec else ""),
                            not present, "a unit exists here: " + spec["reason"]))
        if "marker" in spec and "role" in spec and spec["marker"] not in expect["assignment"]:
            actual = result["assignment"].get(spec["marker"])
            checks.append(Check(f"assignment:{spec['marker']}", actual == spec["role"], f"{actual!r} != {spec['role']!r}"))
    for path, role in sorted(expect["assignment"].items()):
        actual = result["assignment"].get(path)
        checks.append(Check(f"assignment:{path}", actual == role, f"{actual!r} != {role!r}" if actual != role else ""))
    defaults = expect.get("assignment_defaults", [])
    uncovered = []
    for path in result["files"]:
        if path in expect["assignment"]:
            continue
        rule = next((d for d in defaults if fnmatch.fnmatchcase(path, d["glob"])), None)
        if rule is None:
            uncovered.append(path)
            continue
        actual = result["assignment"].get(path)
        if actual != rule["role"]:
            checks.append(Check(f"assignment:{path}", False, f"{actual!r} != default {rule['role']!r} ({rule['glob']})"))
    checks.append(Check("coverage", not uncovered, "paths the case does not assign: " + ", ".join(uncovered[:10])))
    if "orphaned_sources" in expect:
        actual = [{"path": o["path"], "language": o["language"], "reason": o["reason"],
                   "nearest_unit": (o["nearest_unit"] or {}).get("root")} for o in result["orphaned_sources"]]
        wanted = [{"path": o["path"], "language": o.get("language"), "reason": o["reason"],
                   "nearest_unit": o.get("nearest_unit")} for o in expect["orphaned_sources"]]
        for item in wanted:
            if item["language"] is None:
                match = next((a for a in actual if a["path"] == item["path"]), None)
                item["language"] = match["language"] if match else None
        checks.append(Check("orphaned_sources", sorted(actual, key=lambda o: o["path"]) == sorted(wanted, key=lambda o: o["path"]),
                            json.dumps(actual, sort_keys=True)[:600]))
    if "source_only_scopes" in expect:
        actual_scopes = sorted((s["root"], s["language"]) for s in result["source_only_scopes"])
        wanted_scopes = sorted((s["root"], s["language"]) for s in expect["source_only_scopes"])
        checks.append(Check("source_only_scopes", actual_scopes == wanted_scopes, str(actual_scopes)))
    unclaimed = result["summary"]["unclaimed"]
    checks.append(Check("no_unclaimed", not unclaimed, "unclaimed: " + ", ".join(unclaimed[:10])))
    stable = json.dumps(result, sort_keys=True, default=str) == json.dumps(second, sort_keys=True, default=str)
    checks.append(Check("determinism", stable, "two runs over the same tree differ"))
    return expect, checks


def pending_refs(expect: dict[str, Any]) -> dict[str, str]:
    return {item["check"]: item["ref"] for item in expect.get("pending", [])}


def draft_expectation(case_dir: Path) -> dict[str, Any]:
    """A starting expect.json from current behaviour — to be corrected into the contract, never accepted as is."""
    from appsec_review.jobs.build_discovery import required_image_profile
    result = run_discovery(Path(case_dir) / "tree")
    return {
        "schema": CASE_SCHEMA, "case": Path(case_dir).name, "matrix": "A1", "polarity": "positive",
        "mirrors": "", "units": [
            {"root": u["root"], "build_system": u["build_system"], "family": u["family"],
             "profile": required_image_profile(u), "markers": sorted(str(m["path"]) for m in u.get("markers", ()))}
            for u in result["units"]],
        "not_units": [], "assignment": dict(sorted(result["assignment"].items())),
        "orphaned_sources": [{"path": o["path"], "language": o["language"], "reason": o["reason"],
                              "nearest_unit": (o["nearest_unit"] or {}).get("root")} for o in result["orphaned_sources"]],
        "source_only_scopes": [{"root": s["root"], "language": s["language"]} for s in result["source_only_scopes"]],
        "pending": [], "notes": "DRAFT from current behaviour: review every line against the contract before committing.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m appsec_review.acceptance.discovery")
    sub = parser.add_subparsers(dest="command", required=True)
    assign = sub.add_parser("assign", help="print the total assignment of a folder")
    assign.add_argument("folder", type=Path)
    assign.add_argument("--json", action="store_true")
    check = sub.add_parser("check", help="evaluate a discovery case directory")
    check.add_argument("case_dir", type=Path)
    new = sub.add_parser("new", help="write a draft expect.json for a case directory from current behaviour")
    new.add_argument("case_dir", type=Path)
    args = parser.parse_args(argv)
    if args.command == "assign":
        result = run_discovery(args.folder)
        if args.json:
            print(json.dumps({"assignment": result["assignment"], "summary": result["summary"],
                              "units": [_label(u) for u in result["units"]]}, indent=2, sort_keys=True))
        else:
            for path, role in sorted(result["assignment"].items()):
                print(f"{role:48s} {path}")
            print(json.dumps(result["summary"], sort_keys=True))
        return 0
    if args.command == "new":
        target = Path(args.case_dir) / "expect.json"
        if target.exists():
            print(f"{target} exists; refusing to overwrite", file=sys.stderr)
            return 2
        target.write_text(json.dumps(draft_expectation(args.case_dir), indent=2) + "\n", encoding="utf-8")
        print(f"draft written: {target}")
        return 0
    expect, checks = evaluate_case(args.case_dir)
    pending = pending_refs(expect)
    failed = 0
    for item in checks:
        if item.ok and item.id in pending:
            verdict, failed = f"XPASS ({pending[item.id]}: remove pending)", failed + 1
        elif item.ok:
            verdict = "ok"
        elif item.id in pending:
            verdict = f"pending ({pending[item.id]})"
        else:
            verdict, failed = "FAIL", failed + 1
        print(f"{verdict:36s} {item.id}" + (f"  — {item.detail}" if item.detail and not item.ok else ""))
    return 1 if failed else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
