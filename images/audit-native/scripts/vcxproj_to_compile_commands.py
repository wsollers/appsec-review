#!/usr/bin/env python3
"""
vcxproj_to_compile_commands.py — build a clang-cl compile_commands.json from
Visual Studio .vcxproj files WITHOUT MSBuild.

Also emits the seed of compile-command-audit.json (design §23.4): every
security-relevant compiler setting it saw, every MSBuild macro it could not
resolve, and every forced include / plugin-ish flag, so the compilation
database enters the pipeline with an explicit trust state instead of an
implied one.

Scope (deliberately narrow — this is a converter, not an MSBuild reimplementation):
  * Reads <ClCompile Include=...> items, per-item metadata, and the
    <ItemDefinitionGroup> for the selected Configuration|Platform.
  * Resolves $(SolutionDir) $(ProjectDir) $(ProjectName) $(Configuration)
    $(Platform) $(PlatformTarget) $(IntDir) $(OutDir) and -D/-I style props.
    Anything else stays as-is and is reported as UNRESOLVED_MACRO.
  * Honors: PreprocessorDefinitions, UndefinePreprocessorDefinitions,
    AdditionalIncludeDirectories, ForcedIncludeFiles, PrecompiledHeader*,
    LanguageStandard, RuntimeLibrary, ExceptionHandling, AdditionalOptions,
    ExcludedFromBuild, CompileAs.
  * Imports of .props files are followed one level (common shared props).
    .targets files and Directory.Build.props are NOT evaluated; their
    presence is reported so a human can decide whether that matters.

Usage:
  vcxproj_to_compile_commands.py --root /workspace \
      --config Release --platform x64 \
      --msvc-root /msvc --toolset-compat 19.44 \
      --out /scratch/compile_commands.json \
      --audit /scratch/compile-command-audit.seed.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path, PureWindowsPath
from xml.etree import ElementTree as ET

NS = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}
MACRO_RE = re.compile(r"\$\(([A-Za-z_][A-Za-z0-9_]*)\)")

SECURITY_RELEVANT_MACROS = {
    "_CRT_SECURE_NO_WARNINGS", "_CRT_SECURE_NO_DEPRECATE", "_SCL_SECURE_NO_WARNINGS",
    "_HAS_ITERATOR_DEBUGGING", "_SECURE_SCL", "_ALLOW_RTCc_IN_STL", "NDEBUG", "_DEBUG",
    "_WIN32_WINNT", "WINVER", "_USING_V110_SDK71_", "_ITERATOR_DEBUG_LEVEL",
}
# Defines added to every TU for analysis only. Each is recorded in the audit
# seed as ANALYSIS_ONLY_MACRO_DIFFERENCE (design §23.4) because the analyzed
# program differs from the shipped one by exactly these.
ANALYSIS_ONLY_DEFINES = [
    # UCRT secure-overload templates (_CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES)
    # re-declare printf-family functions at block scope with __inline; MSVC
    # accepts that, clang rejects it ("inline declaration ... not allowed in
    # block scope", corecrt_wstdio.h:1109, 74 Notepad++ TUs on 2026-09-11).
    # _NO_CRT_STDIO_INLINE makes those declarations plain extern. Effect on
    # semantics: printf family is not inlined; we never link, so none.
    "_NO_CRT_STDIO_INLINE",
]


def write_vfs_overlay(root: Path, out: Path) -> int:
    """Clang VFS overlay with case-sensitive:false over `root`, so #include
    directives and /I paths resolve the way they do on Windows. Needs the full
    tree enumerated (directory-remap delegates to the real FS and stays
    case-sensitive). Skips .git. Returns file count. JSON is valid YAML."""
    n = 0
    def tree(d: Path):
        nonlocal n
        ents = []
        for c in sorted(d.iterdir(), key=lambda x: x.name):
            if c.name == ".git":
                continue
            if c.is_dir():
                ents.append({"name": c.name, "type": "directory", "contents": tree(c)})
            elif c.is_file():
                n += 1
                ents.append({"name": c.name, "type": "file", "external-contents": str(c)})
        return ents
    doc = {"version": 0, "case-sensitive": "false",
           "roots": [{"name": str(root), "type": "directory", "contents": tree(root)}]}
    out.write_text(json.dumps(doc))
    return n


PLUGIN_FLAG_RE = re.compile(r"(/|-)(fplugin|Xclang|clang:|analyze|d1|d2|Brepro|experimental:)", re.I)


def q(s: str) -> str:
    return '"' + s.replace('"', '\\"') + '"' if any(c in s for c in ' \t"') else s


def ci_resolve(p: Path) -> Path:
    """Case-insensitive path resolution (Windows semantics on a Linux FS).
    Returns the on-disk path if a case-insensitive match exists, else p unchanged."""
    if p.exists():
        return p
    cur = Path(p.anchor or "/")
    for part in p.parts[1:] if p.is_absolute() else p.parts:
        if part in ("", "."):
            continue
        if part == "..":
            cur = cur.parent
            continue
        nxt = cur / part
        if not nxt.exists():
            try:
                match = next((c for c in cur.iterdir() if c.name.lower() == part.lower()), None)
            except (FileNotFoundError, NotADirectoryError, PermissionError):
                match = None
            if match is None:
                return p  # give up; caller reports missing
            nxt = match
        cur = nxt
    return cur


def win_to_posix(root: Path, base: Path, p: str) -> Path:
    p = p.strip().strip('"')
    wp = PureWindowsPath(p)
    if wp.is_absolute():
        # absolute Windows path: try to re-root under /workspace by tail match
        parts = list(wp.parts[1:])
        cand = (root / Path(*parts)) if parts else root
    else:
        cand = base / Path(*wp.parts)
    cand = Path(os.path.normpath(cand))
    return ci_resolve(cand)


def expand_wildcards(p: Path) -> list[Path]:
    """MSBuild Include supports * and ? (and **). Expand relative to the resolved parent."""
    s = str(p)
    if not any(ch in s for ch in "*?"):
        return [p]
    parent = ci_resolve(p.parent)
    pattern = p.name
    if "**" in s:
        return sorted(x for x in Path(str(p).split("**")[0] or ".").rglob(pattern) if x.is_file())
    return sorted(x for x in parent.glob(pattern) if x.is_file())

def msvc_flags(msvc_root: str, platform: str) -> list[str]:
    """Header/lib flags for whichever MSVC layout is mounted (ADR-0003).
    xwin `splat` layout : <root>/crt/include, <root>/sdk/include/{ucrt,um,shared,winrt}
    Visual Studio layout: <root>/VC/Tools/MSVC/<ver>/include + <root>/Windows Kits/10/...
    Empty root -> no flags (headers expected on the default search path)."""
    if not msvc_root:
        return []
    r = Path(msvc_root)
    if (r / "crt" / "include").is_dir():
        flags = ["-imsvc", str(r / "crt" / "include")]
        for sub in ("ucrt", "um", "shared", "winrt", "cppwinrt"):
            d = r / "sdk" / "include" / sub
            if d.is_dir():
                flags += ["-imsvc", str(d)]
        return flags
    if (r / "VC" / "Tools" / "MSVC").is_dir() or (r / "VC" / "include").is_dir():
        return ["/winsysroot", str(r)]
    return ["/winsysroot", str(r)]  # unknown layout; let clang complain loudly


class Project:
    def __init__(self, path: Path, root: Path, config: str, platform: str, audit: dict):
        self.path = path
        self.root = root
        self.dir = path.parent
        self.config = config
        self.platform = platform
        self.audit = audit
        self.tree = ET.parse(path)
        self.xml = self.tree.getroot()
        self.macros = {
            "SolutionDir": self._solution_dir(),
            "ProjectDir": str(self.dir) + "/",
            "ProjectName": path.stem,
            "ProjectPath": str(path),
            "Configuration": config,
            "Platform": platform,
            "PlatformTarget": "x86" if platform.lower() == "win32" else platform.lower(),
            "PlatformShortName": "x86" if platform.lower() == "win32" else platform.lower(),
            "IntDir": f"{platform}/{config}/",
            "OutDir": f"{platform}/{config}/",
            "MSBuildProjectDirectory": str(self.dir),
            "MSBuildThisFileDirectory": str(self.dir) + "/",
        }
        self.props_notes: list[str] = []
        self._load_props()

    def _solution_dir(self) -> str:
        d = self.dir
        for _ in range(6):
            if any(d.glob("*.sln")):
                return str(d) + "/"
            if d == self.root or d.parent == d:
                break
            d = d.parent
        return str(self.root) + "/"

    def cond_matches(self, el) -> bool:
        cond = el.get("Condition")
        if not cond:
            return True
        want = f"{self.config}|{self.platform}".lower()
        c = cond.replace(" ", "").lower()
        if "$(configuration)|$(platform)" in c:
            return f"=='{want}'" in c
        # other conditions: unknown, treat as not matching but record
        self.audit["conditions_not_evaluated"].append({"project": str(self.path), "condition": cond})
        return False

    def expand(self, s: str) -> str:
        def rep(m):
            k = m.group(1)
            if k in self.macros:
                return self.macros[k]
            self.audit["unresolved_macros"].setdefault(k, []).append(str(self.path))
            return m.group(0)
        prev = None
        while prev != s:
            prev, s = s, MACRO_RE.sub(rep, s)
        return s

    def _load_props(self):
        # PropertyGroup user macros in the project itself
        for pg in self.xml.findall("m:PropertyGroup", NS):
            if not self.cond_matches(pg):
                continue
            for child in pg:
                tag = child.tag.split("}")[-1]
                if child.text and tag not in self.macros and tag not in ("ProjectGuid", "Keyword"):
                    self.macros[tag] = self.expand(child.text)
        # one level of .props imports
        for imp in self.xml.findall(".//m:Import", NS):
            proj = imp.get("Project", "")
            if not proj.lower().endswith(".props"):
                if proj.lower().endswith(".targets"):
                    self.audit["targets_not_evaluated"].append({"project": str(self.path), "import": proj})
                continue
            if "$(VCTargetsPath)" in proj or "$(MSBuild" in proj:
                continue
            pp = win_to_posix(self.root, self.dir, self.expand(proj))
            if not pp.exists():
                self.audit["props_missing"].append({"project": str(self.path), "import": proj, "resolved": str(pp)})
                continue
            try:
                px = ET.parse(pp).getroot()
            except ET.ParseError as e:
                self.audit["props_missing"].append({"project": str(self.path), "import": proj, "error": str(e)})
                continue
            for pg in px.findall("m:PropertyGroup", NS):
                for child in pg:
                    tag = child.tag.split("}")[-1]
                    if child.text and tag not in self.macros:
                        self.macros[tag] = self.expand(child.text)
            # ItemDefinitionGroup in props: merge as base settings
            self._props_idg = getattr(self, "_props_idg", []) + px.findall("m:ItemDefinitionGroup", NS)
        # Directory.Build.props presence
        for d in [self.dir, *self.dir.parents]:
            if (d / "Directory.Build.props").exists():
                self.audit["directory_build_props_present"].append(str(d / "Directory.Build.props"))
                break
            if d == self.root:
                break

    def _clcompile_settings(self, idg_list) -> dict:
        s: dict[str, str] = {}
        for idg in idg_list:
            if not self.cond_matches(idg):
                continue
            cl = idg.find("m:ClCompile", NS)
            if cl is None:
                continue
            for child in cl:
                tag = child.tag.split("}")[-1]
                s[tag] = (child.text or "").strip()
        return s

    def base_settings(self) -> dict:
        s = self._clcompile_settings(getattr(self, "_props_idg", []))
        s.update(self._clcompile_settings(self.xml.findall("m:ItemDefinitionGroup", NS)))
        return s

    def items(self):
        for ig in self.xml.findall("m:ItemGroup", NS):
            for cl in ig.findall("m:ClCompile", NS):
                inc = cl.get("Include")
                if not inc:
                    continue
                meta: dict[str, str] = {}
                excluded = False
                for child in cl:
                    tag = child.tag.split("}")[-1]
                    if tag == "ExcludedFromBuild":
                        if self.cond_matches(child) and (child.text or "").strip().lower() == "true":
                            excluded = True
                        continue
                    if self.cond_matches(child):
                        meta[tag] = (child.text or "").strip()
                yield inc, meta, excluded


def project_id(vcxproj: Path, root: Path) -> str:
    """Stable, unique id: vcxproj path relative to root, extension dropped,
    '/' -> '__'. Stem alone collides (scintilla and lexilla both have
    test/unit/UnitTester.vcxproj)."""
    try:
        rel = vcxproj.relative_to(root)
    except ValueError:
        rel = vcxproj
    return str(rel.with_suffix("")).replace("/", "__")


def split_list(v: str, inherit_from: str = "") -> list[str]:
    out = []
    for part in v.split(";"):
        part = part.strip()
        if not part:
            continue
        if part.startswith("%("):  # %(PreprocessorDefinitions) inheritance
            out.extend(split_list(inherit_from))
            continue
        out.append(part)
    return out


def build_command(proj: Project, src: Path, settings: dict, args) -> tuple[list[str], dict]:
    cmd = ["clang-cl", "/c", "/nologo"]
    target = "i686-pc-windows-msvc" if proj.platform.lower() == "win32" else "x86_64-pc-windows-msvc"
    cmd += [f"--target={target}", f"-fms-compatibility-version={args.toolset_compat}"]
    cmd += msvc_flags(args.msvc_root, proj.platform)
    notes: dict = {"defines": [], "undefines": [], "includes": [], "forced_includes": [], "flags": []}
    for d in ANALYSIS_ONLY_DEFINES:
        cmd.append(f"/D{d}")
    if args.vfs_overlay:
        cmd += ["/clang:-ivfsoverlay", f"/clang:{args.vfs_overlay}", "-Wno-nonportable-include-path"]

    defs = split_list(proj.expand(settings.get("PreprocessorDefinitions", "")))
    for d in defs:
        cmd.append(f"/D{d}")
        notes["defines"].append(d)
    for u in split_list(proj.expand(settings.get("UndefinePreprocessorDefinitions", ""))):
        cmd.append(f"/U{u}")
        notes["undefines"].append(u)
    for inc in split_list(proj.expand(settings.get("AdditionalIncludeDirectories", ""))):
        p = win_to_posix(proj.root, proj.dir, inc)
        cmd.append(f"/I{p}")
        notes["includes"].append(str(p))
    # MSBuild property-level include paths (VS2019+): <IncludePath> behaves like
    # /I, <ExternalIncludePath> like /external:I (warnings suppressed; we map it
    # to -imsvc which is clang-cl's system-include form). Notepad++ declares
    # scintilla/lexilla/tinyxml/json this way in notepadPlus.Cpp.props — the 71
    # "file not found" TUs on 2026-09-11. Entries that still contain $(...)
    # (typically the trailing self-reference) are dropped.
    for prop, flag in (("IncludePath", "/I"), ("ExternalIncludePath", "-imsvc")):
        for inc in split_list(proj.macros.get(prop, "")):
            if "$(" in inc:
                continue
            p_ = win_to_posix(proj.root, proj.dir, inc)
            if flag == "/I":
                cmd.append(f"/I{p_}")
            else:
                cmd += ["-imsvc", str(p_)]
            notes["includes"].append(str(p_))
    for fi in split_list(proj.expand(settings.get("ForcedIncludeFiles", ""))):
        cmd.append(f"/FI{fi}")
        notes["forced_includes"].append(fi)

    pch = settings.get("PrecompiledHeader", "").lower()
    pch_file = settings.get("PrecompiledHeaderFile", "stdafx.h")
    if pch == "use":
        # clang-cl can't consume MSVC .pch; treat the PCH header as a forced include instead
        cmd.append(f"/FI{pch_file}")
        notes["flags"].append(f"PCH_USE_AS_FORCED_INCLUDE:{pch_file}")
    elif pch == "create":
        notes["flags"].append(f"PCH_CREATE_IGNORED:{pch_file}")

    std = settings.get("LanguageStandard", "")
    std_map = {"stdcpp14": "/std:c++14", "stdcpp17": "/std:c++17", "stdcpp20": "/std:c++20", "stdcpplatest": "/std:c++latest"}
    if std in std_map:
        cmd.append(std_map[std])
    rt = settings.get("RuntimeLibrary", "")
    rt_map = {"MultiThreaded": "/MT", "MultiThreadedDebug": "/MTd", "MultiThreadedDLL": "/MD", "MultiThreadedDebugDLL": "/MDd"}
    if rt in rt_map:
        cmd.append(rt_map[rt])
    # MSBuild's default for an unset <ExceptionHandling> is Sync (/EHsc); only an
    # explicit "false" disables it. Scintilla/Lexilla rely on the default —
    # 34 TUs failed "cannot use 'try' with exceptions disabled" on 2026-09-11.
    eh = settings.get("ExceptionHandling", "Sync") or "Sync"
    if eh == "Sync":
        cmd.append("/EHsc")
    elif eh == "Async":
        cmd.append("/EHa")
    elif eh == "SyncCThrow":
        cmd.append("/EHs")
    elif eh.lower() == "false":
        notes["flags"].append("EXCEPTIONS_DISABLED")
    ca = settings.get("CompileAs", "")
    if ca == "CompileAsC":
        cmd.append("/TC")
    elif ca == "CompileAsCpp":
        cmd.append("/TP")
    if settings.get("TreatWChar_tAsBuiltInType", "").lower() == "false":
        cmd.append("/Zc:wchar_t-")
    if settings.get("CharacterSet_UNICODE"):  # set by caller from PropertyGroup CharacterSet
        pass

    add = proj.expand(settings.get("AdditionalOptions", "")).replace("%(AdditionalOptions)", "").strip()
    if add:
        for tok in add.split():
            cmd.append(tok)
            notes["flags"].append(tok)

    # "--" terminates option parsing. Without it an absolute source path such as
    # /workspace/... is parsed by clang-cl as the /wo<n> option and the TU is
    # silently dropped ("no input files") — 320/320 failures on 2026-09-11.
    cmd += ["--", str(src)]
    return cmd, notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="source root (e.g. /workspace)")
    ap.add_argument("--config", default="Release")
    ap.add_argument("--platform", default="x64", help="Win32 or x64")
    ap.add_argument("--msvc-root", default="/msvc", help="xwin splat root passed as /winsysroot; '' to omit")
    ap.add_argument("--toolset-compat", default="19.44", help="-fms-compatibility-version (VS2013 = 18.00; see ADR-0003)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--audit", required=True)
    ap.add_argument("--include", action="append", default=[], help="only .vcxproj paths containing this substring")
    ap.add_argument("--vfs-overlay", default=None,
                    help="path for the case-insensitive VFS overlay (default: next to --out); 'none' to disable")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if args.vfs_overlay == "none":
        args.vfs_overlay = None
    else:
        ov = Path(args.vfs_overlay) if args.vfs_overlay else Path(args.out).with_name("vfs-overlay.yaml")
        nfiles = write_vfs_overlay(root, ov)
        args.vfs_overlay = str(ov)
        print(f"vfs overlay ({nfiles} files, case-insensitive) -> {ov}")
    audit = {
        "generator": "vcxproj_to_compile_commands.py",
        "config": args.config, "platform": args.platform,
        "msvc_root": args.msvc_root, "toolset_compat": args.toolset_compat,
        "vfs_overlay": args.vfs_overlay, "analysis_only_defines": ANALYSIS_ONLY_DEFINES,
        "projects": [], "unresolved_macros": {}, "conditions_not_evaluated": [],
        "targets_not_evaluated": [], "props_missing": [], "directory_build_props_present": [],
        "excluded_from_build": [], "missing_sources": [], "wildcard_includes": [],
        "flags": [], "trust_state": "UNTRUSTED",
        "trust_state_note": "Set by the orchestrator after review of this seed; generator never asserts VALIDATED.",
    }
    entries = []
    vcxprojs = sorted(p for p in root.rglob("*.vcxproj") if not args.include or any(s in str(p) for s in args.include))
    if not vcxprojs:
        print("no .vcxproj found under", root, file=sys.stderr)
        sys.exit(2)

    for vp in vcxprojs:
        try:
            proj = Project(vp, root, args.config, args.platform, audit)
        except ET.ParseError as e:
            audit["projects"].append({"path": str(vp), "error": f"parse: {e}"})
            continue
        # CharacterSet -> _UNICODE/UNICODE like MSBuild does
        charset = proj.macros.get("CharacterSet", "")
        base = proj.base_settings()
        n = 0
        for inc, meta, excluded in proj.items():
          raw_src = win_to_posix(root, proj.dir, proj.expand(inc))
          expanded = expand_wildcards(raw_src)
          if expanded != [raw_src]:
              audit["wildcard_includes"].append({"project": str(vp), "raw": inc, "expanded_to": len(expanded)})
          for src in expanded:
            if excluded:
                audit["excluded_from_build"].append({"project": str(vp), "source": str(src)})
                continue
            if not src.exists():
                audit["missing_sources"].append({"project": str(vp), "source": str(src), "raw": inc})
                continue
            settings = dict(base)
            for k, v in meta.items():
                if k in ("PreprocessorDefinitions", "AdditionalIncludeDirectories", "ForcedIncludeFiles",
                         "UndefinePreprocessorDefinitions", "AdditionalOptions"):
                    settings[k] = v.replace(f"%({k})", base.get(k, ""))
                else:
                    settings[k] = v
            if charset == "Unicode":
                settings["PreprocessorDefinitions"] = "_UNICODE;UNICODE;" + settings.get("PreprocessorDefinitions", "")
            elif charset == "MultiByte":
                settings["PreprocessorDefinitions"] = "_MBCS;" + settings.get("PreprocessorDefinitions", "")
            cmd, notes = build_command(proj, src, settings, args)
            # "project" is an extra key (clang tooling ignores unknown keys). The
            # gate uses it to place bitcode per project so the same source compiled
            # by two projects (Scintilla src in Scintilla + UnitTester) doesn't collide,
            # and link_ir.py links per project = per deployable.
            entries.append({"directory": str(proj.dir), "file": str(src), "arguments": cmd,
                            "output": str(src.with_suffix(".obj")), "project": project_id(vp, root)})
            n += 1
            # --- audit flags (§23.4) ---
            for d in notes["defines"]:
                name = d.split("=")[0]
                if name in SECURITY_RELEVANT_MACROS:
                    audit["flags"].append({"flag": "SECURITY_RELEVANT_MACRO", "project": str(vp), "file": str(src), "value": d})
            for fi in notes["forced_includes"]:
                audit["flags"].append({"flag": "UNEXPECTED_FORCED_INCLUDE", "project": str(vp), "file": str(src), "value": fi,
                                       "note": "review: forced includes can redefine the program before the first line of source"})
            for ip in notes["includes"]:
                if not ip.startswith(str(root)):
                    audit["flags"].append({"flag": "UNEXPECTED_INCLUDE_PATH", "project": str(vp), "file": str(src), "value": ip})
            for f in notes["flags"]:
                if PLUGIN_FLAG_RE.search(f):
                    audit["flags"].append({"flag": "EXTERNAL_COMPILER_PLUGIN", "project": str(vp), "file": str(src), "value": f})
        audit["projects"].append({"path": str(vp), "translation_units": n, "solution_dir": proj.macros["SolutionDir"],
                                  "props_notes": proj.props_notes})

    for d in ANALYSIS_ONLY_DEFINES:
        audit["flags"].append({"flag": "ANALYSIS_ONLY_MACRO_DIFFERENCE", "value": d,
                               "note": "added to every TU by the converter; see ANALYSIS_ONLY_DEFINES"})
    if audit["unresolved_macros"]:
        audit["flags"].append({"flag": "SOURCE_PATH_MISMATCH", "value": sorted(audit["unresolved_macros"]),
                               "note": "unresolved MSBuild macros; paths containing them are wrong"})
    audit["translation_units_total"] = len(entries)

    Path(args.out).write_text(json.dumps(entries, indent=1))
    Path(args.audit).write_text(json.dumps(audit, indent=1, sort_keys=True))
    print(f"{len(entries)} TUs from {len(vcxprojs)} projects -> {args.out}")
    print(f"audit seed -> {args.audit}  (flags: {len(audit['flags'])}, unresolved macros: {len(audit['unresolved_macros'])}, "
          f"missing sources: {len(audit['missing_sources'])})")


if __name__ == "__main__":
    main()
