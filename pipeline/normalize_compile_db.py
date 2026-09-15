#!/usr/bin/env python3
"""normalize_compile_db.py <src> <root> <out> <project> — host compile_commands.json -> container form (shared by pregather.sh/.ps1)."""
import json, sys, shlex, os
src, root, out, proj = sys.argv[1:]
# cmake emits the "command" string form with the HOST compiler path (/usr/bin/clang++); the
# image has /opt/llvm/bin/{clang,clang++} and no /usr/bin/clang. Normalise to "arguments",
# map the compiler by basename, rewrite host paths to /workspace. (EASTL first run, 2026-09-15:
# 126/126 COMPILER_NOT_FOUND before this.)
COMPILER = {"clang": "clang", "clang++": "clang++", "clang-cl": "clang-cl", "cc": "clang", "c++": "clang++",
            "gcc": "clang", "g++": "clang++"}
def is_cxx(f): return os.path.splitext(f)[1].lower() in (".cpp", ".cxx", ".cc", ".c++", ".mm")
db = json.load(open(src)); n = 0
for e in db:
    e["project"] = e.get("project", proj)
    args = e.get("arguments") or shlex.split(e["command"])
    e.pop("command", None)
    base = os.path.basename(args[0])
    for k, v in COMPILER.items():
        if base == k or base.startswith(k + "-"): args[0] = v; break
    else:
        args[0] = "clang++" if is_cxx(e["file"]) else "clang"
    e["arguments"] = [a.replace(root, "/workspace") for a in args]
    for k in ("directory", "file", "output"):
        if k in e and e[k].startswith(root): e[k] = "/workspace" + e[k][len(root):]
    n += 1
json.dump(db, open(out, "w"), indent=1); print(f"{n} entries normalised (arguments form, image compiler) -> {out}")
