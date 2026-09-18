#!/usr/bin/env python3
"""
extract_vendor_candidates.py -- Tier B, pass 2 (heuristic pass) of the L12
native-vendored-dependency-inference job (see docs/design-v3.md §4.2).

Deliberately dumb and deterministic. Does NOT call an LLM. Its whole job is
to take the compile/assemble/link command lines a real build actually used
(captured by capture_build_commands.py, or any other producer of the same
build-commands.jsonl shape) and narrow a whole source tree down to a SMALL
set of candidate out-of-tree/vendored library locations with some heuristic
evidence attached -- small enough that an inference pass over just this
candidate list is cheap, instead of an inference pass over the whole tree.

Why command lines, not just source-tree walking: a real build's -I/-L/-l
flags and any positional .a/.so/.lib/.o paths on the link line are ground
truth for "what this target actually pulled in," including out-of-tree
vendor drops with no manifest a source-only scan would have to guess at.

Input shape (build-commands.jsonl, one JSON object per line):
    {"kind": "compile"|"assemble"|"link"|"other", "argv": [...], "cwd": "...", "tu": "<path>|null"}

Pipeline:
    1. Parse every record's argv for -I/-L/-l flags and any positional
       object/library/archive paths (.a/.so/.dylib/.lib/.o/.obj).
    2. Resolve every path to absolute, using the record's cwd for relative
       paths.
    3. Classify each resolved path as in-tree (under --repo-root) or
       out-of-tree. Out-of-tree is the strong "manually vendored, no
       package-manager manifest" signal this script exists to catch; an
       in-tree -I/-L pointing at something that looks like a vendor drop
       (matched against --in-tree-vendor-dirnames) is still recorded, just
       tagged separately and at lower default confidence, so nothing is
       silently dropped.
    4. Dedupe to distinct candidate directories. For -I/-L flags this is the
       flag's own directory; for a positional lib/object file it's the
       file's parent directory.
    5. For each distinct candidate directory, walk it (bounded to
       --max-depth levels, default 4, from that directory as the root --
       NOT from the repo root) looking for:
         - filenames that usually carry a version: version.h, Version.h,
           VERSION, VERSION.txt, version.hpp, *-config.cmake, *.pc,
           CHANGELOG*, RELEASE-NOTES*, README* (README is recorded but
           doesn't score confidence on its own).
         - `#define`-style version macros inside small text/header files
           (skipped once a file is too large to plausibly be a header).
         - a version-looking suffix in the candidate directory's own name
           or any ancestor directory within the walk (path segments like
           "2.2.4" or "libfoo-20.4").
    6. Score a confidence level per candidate from what was found, and
       write one JSON record per candidate -- never a verdict, only
       evidence -- to the output file.

This is intentionally the *last* deterministic pass before any LLM sees
this data. The output is small (one record per distinct vendor directory,
not per file), so an inference disambiguation step run against it later is
cheap and focused, per the design decision behind this whole job: keep
inference scoped to the leftover candidate set, not the whole tree, and
keep it separate from any one-time/offline pass used to *tune* the
heuristics below.

--libdir-reference points at scripts/native-libdir-reference.json (same
pattern as analyze_dependency_lifecycle.py's --eol-reference: a curated,
hand-maintained data file, not a live/derived source), which supplies both
the system-libdir exclusion prefixes and the in-tree vendor-dirname list.
Optional -- when omitted, this script falls back to its own built-in
defaults (kept in sync with that file's initial content) and says so, the
same graceful-degradation discipline the rest of this pipeline uses.

Usage:
    python3 extract_vendor_candidates.py \\
        --build-commands /scratch/native-build/build-commands.jsonl \\
        --repo-root /workspace \\
        --libdir-reference scripts/native-libdir-reference.json \\
        -o /evidence/sbom/native-vendor-candidates.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Object/library/archive extensions that can appear as bare positional
# arguments on a compile or (especially) link command line.
LIB_OBJ_EXTENSIONS = {".a", ".so", ".dylib", ".lib", ".o", ".obj"}

# Filenames, case-insensitive, that are strong "this directory declares its
# own version" signals when found inside a candidate directory.
VERSION_FILENAMES = {
    "version.h", "version.hpp", "version.hh", "version",
    "version.txt", "version.cmake", "version.in",
}
VERSION_FILENAME_PREFIXES = ("changelog", "release-notes", "releasenotes", "news")
VERSION_FILENAME_SUFFIXES = ("-config.cmake", ".pc", ".pc.in")
README_FILENAMES = {"readme", "readme.md", "readme.txt", "readme.rst"}

# Only grep inside files that are plausibly a header/text file (by
# extension) and small enough to be one -- never binary objects.
GREPPABLE_EXTENSIONS = {
    ".h", ".hh", ".hpp", ".hxx", ".inc", ".def", ".cmake", ".txt", ".pc",
    ".in", ".cfg", ".ini", ".md",
}
MAX_GREPPABLE_BYTES = 200_000

VERSION_DEFINE_RE = re.compile(
    r"#\s*define\s+\w*VERSION\w*\s+\"?v?(\d+(?:\.\d+){1,3})\"?",
    re.IGNORECASE,
)
# A version-looking path segment: "2.2.4", "v1.9", "libfoo-20.4", "boost_1_87_0".
PATH_VERSION_RE = re.compile(
    r"(?:^|[-_/])v?(\d+(?:[._]\d+){1,3})(?:$|[-_/])"
)

FLAG_PATH_RE = re.compile(r"^-(I|L)(.*)$")


@dataclass
class RawHit:
    resolved_path: Path
    origin_flag: str  # "-I", "-L", "positional-lib"
    record_kind: str  # compile/assemble/link/other
    in_tree: bool


@dataclass
class Candidate:
    path: str
    origin_flags: set[str] = field(default_factory=set)
    record_kinds: set[str] = field(default_factory=set)
    in_tree: bool = False
    version_files_found: list[str] = field(default_factory=list)
    version_defines_found: list[str] = field(default_factory=list)
    path_version_strings: list[str] = field(default_factory=list)
    readme_present: bool = False
    walk_truncated: bool = False


def resolve_path(raw: str, cwd: str | None) -> Path:
    p = Path(raw)
    if not p.is_absolute():
        base = Path(cwd) if cwd else Path(".")
        p = (base / p)
    try:
        return p.resolve()
    except OSError:
        return p.absolute()


def is_lib_obj_positional(token: str) -> bool:
    if token.startswith("-"):
        return False
    return Path(token).suffix.lower() in LIB_OBJ_EXTENSIONS


def parse_record_argv(argv: list[str], cwd: str | None, kind: str) -> list[RawHit]:
    hits: list[RawHit] = []
    i = 0
    n = len(argv)
    while i < n:
        tok = argv[i]
        m = FLAG_PATH_RE.match(tok)
        if m:
            flag, rest = m.group(1), m.group(2)
            if rest:
                raw_path = rest
            elif i + 1 < n:
                i += 1
                raw_path = argv[i]
            else:
                i += 1
                continue
            resolved = resolve_path(raw_path, cwd)
            hits.append(RawHit(resolved, f"-{flag}", kind, in_tree=False))
        elif tok.startswith("-l") and len(tok) > 2:
            # -lfoo has no filesystem path of its own to record; the -L
            # search paths already collected are what matters for a
            # candidate directory. Intentionally not turned into a hit.
            pass
        elif is_lib_obj_positional(tok):
            resolved = resolve_path(tok, cwd)
            hits.append(RawHit(resolved.parent, "positional-lib", kind, in_tree=False))
        i += 1
    return hits


def load_build_commands(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"WARNING: {path}:{lineno}: could not parse JSON line, skipping ({e})", file=sys.stderr)
    return records


def is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def looks_like_in_tree_vendor_dir(path: Path, vendor_dirnames: set[str]) -> bool:
    return any(part.lower() in vendor_dirnames for part in path.parts)


def scan_candidate_dir(root: Path, max_depth: int) -> tuple[list[str], list[str], list[str], bool, bool]:
    """Bounded walk of one candidate directory. Returns
    (version_files_found, version_defines_found, path_version_strings,
    readme_present, truncated)."""
    version_files: list[str] = []
    version_defines: list[str] = []
    path_versions: list[str] = []
    readme_present = False
    truncated = False

    root_depth = len(root.parts)
    stack = [root]
    visited = 0
    VISIT_CAP = 4000  # hard safety cap independent of depth, for pathological trees

    m = PATH_VERSION_RE.search(root.name)
    if m:
        path_versions.append(m.group(1).replace("_", "."))

    # A version often lives in an ancestor of the exact flag path -- e.g.
    # -I points at ".../protobuf-2.5.0/include", not at the versioned
    # directory itself. Check a few levels up too, stopping at the
    # filesystem root or after ANCESTOR_LEVELS hops.
    ANCESTOR_LEVELS = 3
    ancestor = root.parent
    for _ in range(ANCESTOR_LEVELS):
        if ancestor is None or ancestor == ancestor.parent:
            break
        m = PATH_VERSION_RE.search(ancestor.name)
        if m:
            v = m.group(1).replace("_", ".")
            if v not in path_versions:
                path_versions.append(v)
        ancestor = ancestor.parent

    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except (PermissionError, OSError):
            continue
        for entry in entries:
            visited += 1
            if visited > VISIT_CAP:
                truncated = True
                break
            name_lower = entry.name.lower()
            if entry.is_dir():
                depth = len(entry.parts) - root_depth
                if depth < max_depth:
                    stack.append(entry)
                    m = PATH_VERSION_RE.search(entry.name)
                    if m:
                        v = m.group(1).replace("_", ".")
                        if v not in path_versions:
                            path_versions.append(v)
                else:
                    truncated = True
                continue
            # file
            if name_lower in VERSION_FILENAMES:
                version_files.append(str(entry))
            elif name_lower.startswith(VERSION_FILENAME_PREFIXES):
                version_files.append(str(entry))
            elif name_lower.endswith(VERSION_FILENAME_SUFFIXES):
                version_files.append(str(entry))
            elif name_lower in README_FILENAMES:
                readme_present = True

            suffix = entry.suffix.lower()
            if suffix in GREPPABLE_EXTENSIONS:
                try:
                    if entry.stat().st_size <= MAX_GREPPABLE_BYTES:
                        text = entry.read_text(encoding="utf-8", errors="ignore")
                        for dm in VERSION_DEFINE_RE.finditer(text):
                            v = dm.group(1)
                            if v not in version_defines:
                                version_defines.append(v)
                except OSError:
                    pass
        if visited > VISIT_CAP:
            break

    return version_files, version_defines, path_versions, readme_present, truncated


def score_confidence(c: Candidate) -> str:
    if c.version_files_found and (c.version_defines_found or c.path_version_strings):
        return "high"
    if c.version_files_found or c.version_defines_found:
        return "medium"
    if c.path_version_strings:
        return "medium" if c.in_tree is False else "low"
    return "low"


def cmd_extract(args: argparse.Namespace) -> None:
    build_commands_path = Path(args.build_commands)
    repo_root = Path(args.repo_root).resolve()
    ref_vendor_dirnames, ref_system_prefixes = load_libdir_reference(
        Path(args.libdir_reference) if args.libdir_reference else None
    )
    # Precedence: explicit CLI override > --libdir-reference file > built-in default.
    vendor_dirnames = {d.lower() for d in (
        args.in_tree_vendor_dirnames or ref_vendor_dirnames or DEFAULT_VENDOR_DIRNAMES
    )}
    system_libdir_prefixes = tuple(
        args.system_libdir_prefix or ref_system_prefixes or DEFAULT_SYSTEM_LIBDIR_PREFIXES
    )

    records = load_build_commands(build_commands_path)
    print(f"Loaded {len(records)} build-command record(s) from {build_commands_path}", file=sys.stderr)

    all_hits: list[RawHit] = []
    for rec in records:
        kind = rec.get("kind", "other")
        argv = rec.get("argv") or []
        cwd = rec.get("cwd")
        hits = parse_record_argv(argv, cwd, kind)
        all_hits.extend(hits)

    # Dedupe to distinct candidate directories.
    by_path: dict[str, Candidate] = {}
    in_tree_count = 0
    out_of_tree_count = 0
    for hit in all_hits:
        resolved = hit.resolved_path
        in_tree = is_under(resolved, repo_root)
        key = str(resolved)
        cand = by_path.get(key)
        if cand is None:
            cand = Candidate(path=key, in_tree=in_tree)
            by_path[key] = cand
        cand.origin_flags.add(hit.origin_flag)
        cand.record_kinds.add(hit.record_kind)
        if in_tree:
            in_tree_count += 1
        else:
            out_of_tree_count += 1

    print(f"{len(by_path)} distinct candidate director{'y' if len(by_path)==1 else 'ies'} "
          f"(from {out_of_tree_count} out-of-tree flag/positional hits and {in_tree_count} "
          f"in-tree flag/positional hits, before dedup -- one directory can absorb multiple hits)",
          file=sys.stderr)

    output_candidates = []
    scanned = 0
    excluded_system = 0
    for key, cand in sorted(by_path.items()):
        p = Path(key)
        if not cand.in_tree and not args.include_system_libdirs and is_system_libdir(p, system_libdir_prefixes):
            excluded_system += 1
            continue
        if not p.exists() or not p.is_dir():
            # A -I/-L flag or positional lib pointing at a path that
            # doesn't exist in *this* filesystem view -- record it as a
            # zero-evidence candidate rather than silently dropping it;
            # this pipeline's "never infer clean" discipline applies here
            # too. No heuristic walk possible.
            output_candidates.append({
                "path": key,
                "exists": False,
                "in_tree": cand.in_tree,
                "in_tree_vendor_dirname_match": False,
                "origin_flags": sorted(cand.origin_flags),
                "record_kinds": sorted(cand.record_kinds),
                "version_files_found": [],
                "version_defines_found": [],
                "path_version_strings": [],
                "readme_present": False,
                "walk_truncated": False,
                "confidence": "low",
                "notes": "path referenced by a build command but not found on disk at extraction time",
            })
            continue

        if cand.in_tree and not args.include_in_tree:
            vendor_like = looks_like_in_tree_vendor_dir(p, vendor_dirnames)
            if not vendor_like:
                continue  # in-tree, not vendor-looking, and --include-in-tree not set: skip

        vendor_like = looks_like_in_tree_vendor_dir(p, vendor_dirnames) if cand.in_tree else False
        scanned += 1
        vf, vd, pv, readme, truncated = scan_candidate_dir(p, args.max_depth)
        cand.version_files_found = vf
        cand.version_defines_found = vd
        cand.path_version_strings = pv
        cand.readme_present = readme
        cand.walk_truncated = truncated

        output_candidates.append({
            "path": key,
            "exists": True,
            "in_tree": cand.in_tree,
            "in_tree_vendor_dirname_match": vendor_like,
            "origin_flags": sorted(cand.origin_flags),
            "record_kinds": sorted(cand.record_kinds),
            "version_files_found": vf,
            "version_defines_found": vd,
            "path_version_strings": pv,
            "readme_present": readme,
            "walk_truncated": truncated,
            "confidence": score_confidence(cand),
            "notes": "",
        })

    out = {
        "schema": "appsec-review/native-vendor-candidates/0.1",
        "generated": datetime.now(timezone.utc).isoformat(),
        "build_commands_source": str(build_commands_path),
        "repo_root": str(repo_root),
        "max_depth": args.max_depth,
        "include_in_tree": args.include_in_tree,
        "summary": {
            "distinct_candidate_dirs_total": len(by_path),
            "candidate_dirs_excluded_as_system_libdirs": excluded_system,
            "candidate_dirs_scanned": scanned,
            "candidate_dirs_emitted": len(output_candidates),
        },
        "candidates": output_candidates,
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    by_conf: dict[str, int] = {}
    for c in output_candidates:
        by_conf[c["confidence"]] = by_conf.get(c["confidence"], 0) + 1
    print(f"Wrote {out_path} -- {len(output_candidates)} candidate(s) "
          f"(confidence: {by_conf})", file=sys.stderr)
    print("This is evidence, not a verdict -- feed 'candidates' to a scoped inference pass "
          "for product/version disambiguation, never accept a candidate as a component on "
          "heuristic evidence alone.", file=sys.stderr)


DEFAULT_VENDOR_DIRNAMES = {
    "vendor", "vendored", "third_party", "thirdparty", "3rdparty", "extern",
    "external", "deps", "dependencies", "libs", "lib", "sdk", "tools",
    "shared", "contrib", "submodules",
}

# Standard toolchain/OS library search directories that show up on nearly
# every real link command line via the compiler driver's own default -L
# search path (glibc, libgcc, libstdc++, and whatever OS packages happen to
# be installed on the build host). These are never the "manually vendored,
# no manifest" signal this script exists to find -- surfacing them just
# floods the candidate list with system noise (confirmed empirically: an
# unfiltered real `clang++ ... -o app` link on a stock Ubuntu host pulled in
# 80+ .pc files from /usr/lib/x86_64-linux-gnu alone). Prefix-matched, not
# exact-matched, so both a base dir and anything nested under it (e.g.
# /usr/lib/gcc/x86_64-linux-gnu/13) are excluded.
DEFAULT_SYSTEM_LIBDIR_PREFIXES = (
    "/usr/lib", "/usr/lib64", "/usr/local/lib", "/usr/local/lib64",
    "/lib", "/lib64",
)


def is_system_libdir(path: Path, prefixes: tuple[str, ...]) -> bool:
    s = str(path)
    return any(s == pfx or s.startswith(pfx.rstrip("/") + "/") for pfx in prefixes)


def load_libdir_reference(path: Path | None) -> tuple[set[str] | None, tuple[str, ...] | None]:
    """Returns (in_tree_vendor_dirnames, system_libdir_prefixes) from a
    native-libdir-reference.json-shaped file, or (None, None) if path is
    None -- caller falls back to its own built-in defaults in that case."""
    if path is None:
        return None, None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"WARNING: could not read/parse --libdir-reference {path} ({e}); "
              f"falling back to built-in defaults", file=sys.stderr)
        return None, None
    vendor_dirnames = {
        entry["dirname"].lower()
        for entry in data.get("in_tree_vendor_dirnames", [])
        if entry.get("dirname")
    } or None
    system_prefixes = tuple(
        entry["prefix"]
        for entry in data.get("system_libdir_prefixes", [])
        if entry.get("prefix")
    ) or None
    print(f"Loaded libdir reference from {path}: "
          f"{len(vendor_dirnames or [])} vendor dirname(s), "
          f"{len(system_prefixes or [])} system libdir prefix(es)", file=sys.stderr)
    return vendor_dirnames, system_prefixes


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build-commands", required=True, help="Path to build-commands.jsonl")
    ap.add_argument("--repo-root", required=True, help="Root of the target source tree (for in-tree/out-of-tree classification)")
    ap.add_argument("-o", "--output", required=True, help="Output path for native-vendor-candidates.json")
    ap.add_argument("--max-depth", type=int, default=4, help="Max directory-walk depth from each candidate directory (default: 4)")
    ap.add_argument("--include-in-tree", action="store_true",
                     help="Also scan/emit in-tree candidate directories that don't match a vendor-looking dirname (default: skip those, only conventionally-named vendor dirs and all out-of-tree dirs are scanned)")
    ap.add_argument("--in-tree-vendor-dirnames", action="append",
                     help="Override the default vendor-looking directory name list (repeatable). Matched case-insensitively against any path segment.")
    ap.add_argument("--include-system-libdirs", action="store_true",
                     help="Don't exclude standard toolchain/OS library search paths (/usr/lib, /lib, etc. -- see DEFAULT_SYSTEM_LIBDIR_PREFIXES). Off by default: these are near-universal link-command noise, not vendored dependencies.")
    ap.add_argument("--system-libdir-prefix", action="append",
                     help="Override the default system-libdir exclusion prefix list (repeatable). Takes precedence over --libdir-reference.")
    ap.add_argument("--libdir-reference",
                     help="Path to a native-libdir-reference.json-shaped file (see scripts/native-libdir-reference.json) supplying both list defaults. Optional -- falls back to this script's own built-in defaults if omitted.")
    ap.set_defaults(func=cmd_extract)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
