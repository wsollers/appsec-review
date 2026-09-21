#!/usr/bin/env python3
"""
check_mobile_source.py — answers the specific open question left in
session-status-2026-09-03-server-analysis.md's punch list: "sast-mobile —
confirmed never run [against fsh-server]... need to actually be launched."
Rather than spending a full Docker/mobsfscan cycle just to confirm the
expected no-op, this is a five-minute, dependency-free pass that walks a
repo tree and answers, with evidence: is there any Android or iOS source
here at all?

This is NOT a replacement for mobsfscan/sast-mobile-android/sast-mobile-ios
against fsh-client, where real mobile source is expected and needs actual
security-pattern scanning, not just a presence check. This script's only
job is the narrower "prove a negative" case for fsh-server (and it's
reusable as a fast pre-flight check before pointing the real mobsfscan step
at fsh-client too, to sanity-check the target path before spending the
Docker cycle).

Detection is evidence-based and deliberately over-inclusive — every match is
reported with its path so a human can judge relevance, rather than the
script silently deciding something doesn't count (same philosophy as
profile_repo.py's "Needs follow-up" list). Two independent signal classes
per platform, so a single false-positive file extension match doesn't by
itself flip the verdict:

  Android:
    - source files: *.java, *.kt, *.kts
    - project markers: AndroidManifest.xml, build.gradle / build.gradle.kts
      containing an Android Gradle Plugin reference, a res/ directory
      containing a values/ subdirectory (the standard Android resource
      layout — generic enough alone that it's reported as a WEAK signal,
      only escalated to STRONG when paired with source files or a manifest)

  iOS:
    - source files: *.swift, *.m, *.mm
    - project markers: Info.plist, *.xcodeproj, *.xcworkspace, Podfile,
      Podfile.lock

Output (to -o/--output):
  - mobile-source-check.json — full detail, every match with its path
  - mobile-source-check.md   — human-readable summary + verdict
  - android-coverage.txt / ios-coverage.txt — written in the SAME format
    Invoke-VendorAuditPrePass.ps1's sast-mobile-android/-ios steps already
    write (see that script's own Note text), so this can drop straight into
    an existing evidence directory as a corroborating, independently-derived
    check alongside — not instead of — the real mobsfscan run wherever real
    mobile source is expected.

Exit code: 0 if zero STRONG signals found for both platforms (safe to treat
sast-mobile as a confirmed no-op for this root), 1 if anything was found
(do not treat sast-mobile as a no-op — investigate the paths listed before
assuming either explanation). This makes it usable as a gate in a script,
not just an informational report.

Pure stdlib. No pip installs, no Docker — same "run anywhere" philosophy as
profile_repo.py and fingerprint_native_binaries.py.

Usage:
    # The immediate case this was written for — confirm fsh-server really
    # has zero mobile source before treating that punch-list item as closed:
    python3 check_mobile_source.py "F:\\Barracuda\\fsh-server" -o F:\\Barracuda\\evidence-server\\sast-mobile

    # Pre-flight check before running the real mobsfscan step against the
    # client (confirms the target path actually has source to scan):
    python3 check_mobile_source.py "F:\\Barracuda\\fsh-client" -o F:\\Barracuda\\evidence-client\\sast-mobile-preflight
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_EXCLUDE_DIRS = {
    ".git", ".svn", ".hg",
    "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache",
    "bin", "obj", "Library", "Temp", "Logs", "UserSettings", "MemoryCaptures",
    "build", "dist", "target", "out", ".gradle", ".idea", ".vs", ".vscode",
}

ANDROID_SOURCE_EXTS = {".java", ".kt", ".kts"}
IOS_SOURCE_EXTS = {".swift", ".m", ".mm"}

ANDROID_GRADLE_PLUGIN_RE = re.compile(
    r"(com\.android\.(application|library)|apply\s+plugin:\s*['\"]com\.android)",
    re.IGNORECASE,
)

MAX_SNIFF_BYTES = 200_000


def safe_read_text(path: Path, max_bytes: int = MAX_SNIFF_BYTES) -> str | None:
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except OSError:
        return None


@dataclass
class PlatformFindings:
    source_files: list[str] = field(default_factory=list)
    strong_markers: list[str] = field(default_factory=list)   # e.g. AndroidManifest.xml, Info.plist, *.xcodeproj
    weak_markers: list[str] = field(default_factory=list)     # e.g. a bare res/values/ dir with no other signal

    def strong_signal_count(self) -> int:
        return len(self.source_files) + len(self.strong_markers)


def scan_root(root: Path, exclude_dirs: set[str]) -> tuple[PlatformFindings, PlatformFindings, dict[str, Any]]:
    android = PlatformFindings()
    ios = PlatformFindings()
    stats = {"files_scanned": 0, "dirs_scanned": 0}

    has_res_values = False  # tracked separately since it's a directory-shape signal, not a per-file one

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=lambda e: None):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        stats["dirs_scanned"] += 1
        rel_dir = Path(dirpath).relative_to(root)

        # directory-shape markers
        base = os.path.basename(dirpath)
        if base.endswith(".xcodeproj") or base.endswith(".xcworkspace"):
            ios.strong_markers.append(str(rel_dir).replace("\\", "/"))
        if base == "values" and Path(dirpath).parent.name == "res":
            has_res_values = True
            android.weak_markers.append(str(rel_dir).replace("\\", "/"))

        for fname in filenames:
            fpath = Path(dirpath) / fname
            rel_path = str(fpath.relative_to(root)).replace("\\", "/")
            stats["files_scanned"] += 1
            ext = fpath.suffix.lower()

            if ext in ANDROID_SOURCE_EXTS:
                android.source_files.append(rel_path)
            elif ext in IOS_SOURCE_EXTS:
                ios.source_files.append(rel_path)

            if fname == "AndroidManifest.xml":
                android.strong_markers.append(rel_path)
            elif fname in ("build.gradle", "build.gradle.kts"):
                text = safe_read_text(fpath) or ""
                if ANDROID_GRADLE_PLUGIN_RE.search(text):
                    android.strong_markers.append(rel_path)
            elif fname == "Info.plist":
                ios.strong_markers.append(rel_path)
            elif fname in ("Podfile", "Podfile.lock"):
                ios.strong_markers.append(rel_path)

    return android, ios, stats


def render_markdown(root: str, android: PlatformFindings, ios: PlatformFindings, stats: dict[str, Any]) -> str:
    lines = ["# Mobile source presence check\n"]
    lines.append(f"Generated {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Root scanned: `{root}`")
    lines.append(f"{stats['files_scanned']:,} files across {stats['dirs_scanned']:,} directories scanned.\n")

    for name, pf in (("Android", android), ("iOS", ios)):
        lines.append(f"## {name}\n")
        strong = pf.strong_signal_count()
        if strong == 0 and not pf.weak_markers:
            lines.append(f"**CONFIRMED: no {name} source or project markers found.** Zero source files, zero strong markers.\n")
        elif strong == 0 and pf.weak_markers:
            lines.append(f"**WEAK SIGNAL ONLY — not confirmed clean.** No source files or strong project markers found, "
                         f"but {len(pf.weak_markers)} weak marker(s) (a bare `res/values/`-shaped directory, which can "
                         f"occur outside a real Android project) — worth a manual look before treating this as a "
                         f"confirmed no-op.\n")
            for m in pf.weak_markers[:10]:
                lines.append(f"- `{m}`")
            if len(pf.weak_markers) > 10:
                lines.append(f"- ... (+{len(pf.weak_markers) - 10} more)")
            lines.append("")
        else:
            lines.append(f"**FOUND {name} SOURCE/PROJECT EVIDENCE — do not treat sast-mobile as a confirmed no-op.** "
                         f"{len(pf.source_files)} source file(s), {len(pf.strong_markers)} strong project marker(s).\n")
            if pf.source_files:
                lines.append(f"**Source files** (first 20 of {len(pf.source_files)}):\n")
                for f in pf.source_files[:20]:
                    lines.append(f"- `{f}`")
                if len(pf.source_files) > 20:
                    lines.append(f"- ... (+{len(pf.source_files) - 20} more, see the JSON)")
                lines.append("")
            if pf.strong_markers:
                lines.append(f"**Project markers:**\n")
                for f in pf.strong_markers:
                    lines.append(f"- `{f}`")
                lines.append("")

    return "\n".join(lines)


def write_coverage_txt(output_dir: Path, platform: str, pf: PlatformFindings) -> None:
    """Matches the format Invoke-VendorAuditPrePass.ps1's sast-mobile-android
    / sast-mobile-ios steps already write, so this can sit in the same
    evidence subdirectory as a corroborating, independently-derived check."""
    fname = f"{platform}-coverage.txt"
    count = len(pf.source_files)
    display_name = "iOS" if platform == "ios" else platform.capitalize()
    lines = [f"{display_name} source files found: {count}"]
    if count == 0 and not pf.strong_markers:
        lines.append(f"WARNING: zero matching source files and zero strong project markers - if this repo was "
                      f"expected to contain {platform} source, investigate before treating as clean. "
                      f"(Independent check, not a substitute for a real mobsfscan run where source IS expected.)")
    elif count == 0 and pf.strong_markers:
        lines.append(f"NOTE: zero source files found by extension, but {len(pf.strong_markers)} strong project "
                     f"marker(s) present ({', '.join(pf.strong_markers[:5])}) - investigate before concluding no-op.")
    (output_dir / fname).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", type=Path, help="Root directory to check for Android/iOS source")
    ap.add_argument("-o", "--output", type=Path, required=True, help="Output directory")
    ap.add_argument("--exclude-dir", action="append", default=[], help="Additional directory NAME to skip (repeatable)")
    args = ap.parse_args()

    if not args.root.exists():
        sys.exit(f"Root does not exist: {args.root}")

    exclude_dirs = set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir)
    args.output.mkdir(parents=True, exist_ok=True)

    root = args.root.resolve()
    print(f"Scanning {root} for Android/iOS source and project markers ...", file=sys.stderr)
    android, ios, stats = scan_root(root, exclude_dirs)

    result = {
        "root": str(root),
        "generated": datetime.now(timezone.utc).isoformat(),
        "stats": stats,
        "android": {
            "source_files": android.source_files,
            "strong_markers": android.strong_markers,
            "weak_markers": android.weak_markers,
            "strong_signal_count": android.strong_signal_count(),
        },
        "ios": {
            "source_files": ios.source_files,
            "strong_markers": ios.strong_markers,
            "weak_markers": ios.weak_markers,
            "strong_signal_count": ios.strong_signal_count(),
        },
    }

    (args.output / "mobile-source-check.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (args.output / "mobile-source-check.md").write_text(render_markdown(str(root), android, ios, stats), encoding="utf-8")
    write_coverage_txt(args.output, "android", android)
    write_coverage_txt(args.output, "ios", ios)

    print(f"\nWrote {args.output / 'mobile-source-check.json'}", file=sys.stderr)
    print(f"Wrote {args.output / 'mobile-source-check.md'}", file=sys.stderr)
    print(f"Wrote {args.output / 'android-coverage.txt'} / ios-coverage.txt", file=sys.stderr)

    android_strong = android.strong_signal_count()
    ios_strong = ios.strong_signal_count()
    print(f"\nAndroid: {len(android.source_files)} source file(s), {len(android.strong_markers)} strong marker(s), "
          f"{len(android.weak_markers)} weak marker(s)", file=sys.stderr)
    print(f"iOS:     {len(ios.source_files)} source file(s), {len(ios.strong_markers)} strong marker(s)", file=sys.stderr)

    if android_strong == 0 and ios_strong == 0:
        if android.weak_markers:
            print(f"\nRESULT: no strong signal either platform, but {len(android.weak_markers)} weak Android "
                  f"marker(s) found — review before fully closing this out. Exit code 0 (no STRONG signal).", file=sys.stderr)
        else:
            print("\nRESULT: CONFIRMED — zero Android/iOS source or project markers found under this root.", file=sys.stderr)
        sys.exit(0)
    else:
        print("\nRESULT: mobile source/project evidence found — do NOT treat sast-mobile as a confirmed no-op "
              "for this root. See mobile-source-check.md for exact paths.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
