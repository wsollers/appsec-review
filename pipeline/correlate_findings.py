#!/usr/bin/env python3
"""Normalize and correlate findings across static and native evidence.

This is deterministic evidence shaping, not verification. It groups findings by
nearby file/line and exposes corroboration for the LLM and reviewer.
"""
from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def norm_path(path: str | None) -> str:
    if not path:
        return ""
    p = path.replace("\\", "/")
    for marker in ("/workspace/", "/home/", "/mnt/"):
        if marker in p:
            if marker == "/workspace/":
                return p.split(marker, 1)[1]
            return p.lstrip("/")
    return p.lstrip("/")


def add(out: list[dict], *, tool: str, rule: str, file: str = "", line: int = 0,
        message: str = "", severity: str = "UNKNOWN", source: str = "",
        status: str = "", cwe: str = "", kind: str = "sast") -> None:
    out.append({
        "tool": tool,
        "kind": kind,
        "rule": rule or "unknown",
        "cwe": cwe or "",
        "severity": (severity or "UNKNOWN").upper(),
        "file": norm_path(file),
        "line": int(line or 0),
        "message": (message or "")[:500],
        "source": source,
        "verification_status": status or "",
    })


def semgrep(static_root: Path) -> list[dict]:
    out: list[dict] = []
    for p in sorted((static_root / "sast-multi").glob("semgrep*.json")):
        data = load_json(p)
        if not isinstance(data, dict):
            continue
        for r in data.get("results", []) or []:
            extra = r.get("extra", {}) if isinstance(r.get("extra"), dict) else {}
            loc = r.get("start", {}) if isinstance(r.get("start"), dict) else {}
            cwe = ""
            for item in extra.get("metadata", {}).get("cwe", []) if isinstance(extra.get("metadata"), dict) else []:
                m = re.search(r"CWE-\d+", str(item), re.I)
                if m:
                    cwe = m.group(0).upper()
                    break
            add(out, tool="semgrep", rule=r.get("check_id", ""), file=r.get("path", ""),
                line=loc.get("line", 0), message=extra.get("message", ""),
                severity=extra.get("severity", "UNKNOWN"), source=str(p), cwe=cwe)
    return out


def clang_tidy(native_root: Path) -> list[dict]:
    out: list[dict] = []
    p = native_root / "native-sast" / "findings-clang-tidy.json"
    data = load_json(p)
    if not isinstance(data, dict):
        return out
    for r in data.get("findings", []) or []:
        add(out, tool="clang-tidy", rule=r.get("check", ""), file=r.get("file", ""),
            line=r.get("line", 0), message=r.get("message", ""), severity=r.get("level", "UNKNOWN"), source=str(p))
    return out


def cppcheck_from(path: Path, tool: str = "cppcheck") -> list[dict]:
    out: list[dict] = []
    if not path.exists():
        return out
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return out
    for err in root.iter("error"):
        loc = next(err.iter("location"), None)
        add(out, tool=tool, rule=err.get("id", ""), file=loc.get("file", "") if loc is not None else "",
            line=int(loc.get("line", 0)) if loc is not None and loc.get("line") else 0,
            message=err.get("msg", ""), severity=err.get("severity", "UNKNOWN"), source=str(path),
            cwe=("CWE-" + err.get("cwe")) if err.get("cwe") else "")
    return out


def sarif_file(path: Path, tool: str) -> list[dict]:
    out: list[dict] = []
    data = load_json(path)
    if not isinstance(data, dict):
        return out
    rule_meta: dict[str, dict] = {}
    for run in data.get("runs", []) or []:
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []) or []:
            rid = rule.get("id", "")
            props = rule.get("properties", {}) if isinstance(rule.get("properties"), dict) else {}
            rule_meta[rid] = {
                "severity": props.get("security-severity") or props.get("problem.severity") or props.get("precision") or "",
                "cwe": ",".join(str(t) for t in props.get("tags", []) if str(t).upper().startswith("CWE-")),
            }
        for r in run.get("results", []) or []:
            locs = r.get("locations", []) or []
            phys = locs[0].get("physicalLocation", {}) if locs and isinstance(locs[0], dict) else {}
            art = phys.get("artifactLocation", {}) if isinstance(phys.get("artifactLocation"), dict) else {}
            reg = phys.get("region", {}) if isinstance(phys.get("region"), dict) else {}
            rid = r.get("ruleId", "")
            meta = rule_meta.get(rid, {})
            add(out, tool=tool, rule=rid, file=art.get("uri", ""), line=reg.get("startLine", 0),
                message=r.get("message", {}).get("text", "") if isinstance(r.get("message"), dict) else "",
                severity=r.get("level", "") or meta.get("severity") or "UNKNOWN",
                source=str(path), cwe=meta.get("cwe", ""))
    return out


def native_bundle(bundle_path: Path) -> list[dict]:
    out: list[dict] = []
    data = load_json(bundle_path)
    if not isinstance(data, dict):
        return out
    for section in ("verified_primitive", "unresolved", "refuted"):
        for r in data.get(section, []) or []:
            add(out, tool="native-bundle", kind="native", rule=r.get("rule", ""), file=r.get("file", ""),
                line=r.get("line", 0), message=r.get("message", ""), source=str(bundle_path),
                status=r.get("verification", {}).get("status", section.upper()))
    for r in data.get("informational", {}).get("items", []) or []:
        add(out, tool="native-informational", kind="native-info", rule=r.get("rule", ""), file=r.get("file", ""),
            line=r.get("line", 0), message=r.get("message", ""), source=str(bundle_path), status="INFORMATIONAL")
    return out


def collect(static_root: Path, native_root: Path, bundle_path: Path) -> list[dict]:
    findings: list[dict] = []
    findings += semgrep(static_root)
    findings += cppcheck_from(static_root / "sast-cpp" / "cppcheck.xml", "cppcheck-static")
    findings += clang_tidy(native_root)
    findings += cppcheck_from(native_root / "native-sast" / "cppcheck.xml", "cppcheck-native")
    findings += sarif_file(static_root / "binskim" / "binskim.sarif", "binskim")
    findings += sarif_file(static_root / "sast-mobile" / "mobsfscan-android.sarif", "mobsfscan-android")
    findings += sarif_file(static_root / "sast-mobile" / "mobsfscan-ios.sarif", "mobsfscan-ios")
    findings += sarif_file(native_root / "codeql" / "cpp.sarif", "codeql-cpp-security-extended")
    findings += sarif_file(native_root / "codeql" / "mythos.sarif", "codeql-mythos")
    findings += native_bundle(bundle_path)
    return [f for f in findings if f["file"] or f["tool"] in {"binskim"}]


def cluster_key(f: dict, window: int) -> tuple[str, int]:
    line = int(f.get("line") or 0)
    bucket = line // window if line > 0 else 0
    return f.get("file", ""), bucket


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--static-evidence", required=True)
    ap.add_argument("--native-scratch", required=True)
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--line-window", type=int, default=8)
    args = ap.parse_args()

    findings = collect(Path(args.static_evidence), Path(args.native_scratch), Path(args.bundle))
    grouped: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for f in findings:
        grouped[cluster_key(f, args.line_window)].append(f)

    clusters = []
    for (file, bucket), items in grouped.items():
        lines = [int(i.get("line") or 0) for i in items if int(i.get("line") or 0) > 0]
        clusters.append({
            "id": f"C{len(clusters)+1:05d}",
            "file": file,
            "line_min": min(lines) if lines else 0,
            "line_max": max(lines) if lines else 0,
            "tools": sorted(set(i["tool"] for i in items)),
            "rules": sorted(set(i["rule"] for i in items)),
            "cwes": sorted(set(i["cwe"] for i in items if i.get("cwe"))),
            "verification_statuses": dict(Counter(i.get("verification_status") or "UNVERIFIED" for i in items)),
            "finding_count": len(items),
            "findings": sorted(items, key=lambda i: (i["tool"], i["line"], i["rule"])),
        })
    clusters.sort(key=lambda c: (-len(c["tools"]), c["file"], c["line_min"], -c["finding_count"]))

    out = {
        "schema": "appsec-review/correlated-findings/0.1",
        "counts": {
            "findings": len(findings),
            "clusters": len(clusters),
            "by_tool": dict(Counter(f["tool"] for f in findings).most_common()),
        },
        "clusters": clusters,
    }
    Path(args.out).write_text(json.dumps(out, indent=1), encoding="utf-8")

    md = Path(args.out).with_suffix(".md")
    lines = ["# Correlated Findings", "", f"Findings: {len(findings)} · clusters: {len(clusters)}", ""]
    for c in clusters[:80]:
        lines.append(f"## {c['id']} `{c['file']}:{c['line_min']}-{c['line_max']}`")
        lines.append(f"- tools: {', '.join(c['tools'])}")
        lines.append(f"- statuses: {c['verification_statuses']}")
        for f in c["findings"][:8]:
            loc = f":{f['line']}" if f.get("line") else ""
            lines.append(f"  - `{f['tool']}` `{f['rule']}` `{f['file']}{loc}` {f['message'][:180]}")
        lines.append("")
    md.write_text("\n".join(lines), encoding="utf-8")
    print(f"correlated {len(findings)} findings into {len(clusters)} clusters -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
