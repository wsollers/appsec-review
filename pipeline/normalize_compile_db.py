#!/usr/bin/env python3
"""normalize_compile_db.py <src> <root> <out> <project> — host compile_commands.json -> container form (shared by pregather.sh/.ps1)."""
import json, sys, shlex, os, re
src, root, out, proj = sys.argv[1:]
# cmake emits the "command" string form with the HOST compiler path (/usr/bin/clang++); the
# image has /opt/llvm/bin/{clang,clang++} and no /usr/bin/clang. Normalise to "arguments",
# map the compiler by basename, rewrite host paths to /workspace. (EASTL first run, 2026-09-15:
# 126/126 COMPILER_NOT_FOUND before this.)
COMPILER = {"clang": "clang", "clang++": "clang++", "clang-cl": "clang-cl", "cc": "clang", "c++": "clang++",
            "gcc": "clang", "g++": "clang++"}
def is_cxx(f): return os.path.splitext(f)[1].lower() in (".cpp", ".cxx", ".cc", ".c++", ".mm")
db = json.load(open(src)); n = 0

def norm_path(p):
    return p.replace("\\", "/")

def root_aliases(root):
    aliases = [root, norm_path(root)]
    # Windows PowerShell can pass WSL paths as \\wsl.localhost\Distro\home\...
    # while compile_commands.json produced inside WSL records /home/... paths.
    # Treat the path after the distro name as an equivalent source root.
    m = re.match(r"^//wsl(?:\.localhost)?/[^/]+(/.*)$", norm_path(root), re.IGNORECASE)
    if m:
        aliases.append(m.group(1))
    return sorted({a.rstrip("/") for a in aliases if a}, key=len, reverse=True)

ROOT_ALIASES = root_aliases(root)

def rewrite_workspace_path(value):
    if not isinstance(value, str):
        return value
    out = value
    for alias in ROOT_ALIASES:
        if out == alias:
            return "/workspace"
        if out.startswith(alias + "/") or out.startswith(alias + "\\"):
            return "/workspace" + out[len(alias):].replace("\\", "/")
    return out

def rewrite_arg(arg):
    if not isinstance(arg, str):
        return arg
    joined_prefixes = ("-I", "-isystem", "-iquote", "-idirafter", "--sysroot=")
    for prefix in joined_prefixes:
        if arg.startswith(prefix) and len(arg) > len(prefix):
            return prefix + rewrite_workspace_path(arg[len(prefix):])
    return rewrite_workspace_path(arg)

for e in db:
    e["project"] = e.get("project", proj)
    args = e.get("arguments") or shlex.split(e["command"])
    e.pop("command", None)
    base = os.path.basename(args[0])
    for k, v in COMPILER.items():
        if base == k or base.startswith(k + "-"): args[0] = v; break
    else:
        args[0] = "clang++" if is_cxx(e["file"]) else "clang"
    e["arguments"] = [rewrite_arg(a) for a in args]
    for k in ("directory", "file", "output"):
        if k in e: e[k] = rewrite_workspace_path(e[k])
    n += 1
json.dump(db, open(out, "w"), indent=1); print(f"{n} entries normalised (arguments form, image compiler) -> {out}")
