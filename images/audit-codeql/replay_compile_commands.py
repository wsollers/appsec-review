#!/usr/bin/env python3
"""replay_compile_commands.py — replay an audit-native compile_commands.json so CodeQL's
build tracer can observe the compiler invocations (--traced-cpp mode). Runs each entry's
argv (clang-cl) in its directory; failures are counted, not fatal, so one bad TU doesn't
empty the database. Requires clang-cl on PATH and /msvc mounted, i.e. an image that has
both; audit-codeql alone does not. Experimental: CodeQL's clang-cl support is preliminary."""
import json, subprocess, sys
entries = json.load(open(sys.argv[1]))
ok = bad = 0
for e in entries:
    args = list(e.get("arguments") or [])
    gnu = not args[0].endswith("clang-cl")
    if gnu:
        # GNU driver (EASTL/yquake2/Unreal on Linux): keep -c, redirect -o into /scratch/obj, no "--" games
        import os, hashlib
        os.makedirs("/scratch/obj", exist_ok=True)
        obj = "/scratch/obj/" + hashlib.sha1(e["file"].encode()).hexdigest()[:12] + ".o"
        if "-c" not in args: args.insert(1, "-c")
        if "-o" in args:
            i = args.index("-o"); args[i + 1] = obj
        else:
            args += ["-o", obj]
        r = subprocess.run(args, cwd=e.get("directory"), capture_output=True, text=True)
        if r.returncode == 0: ok += 1
        else:
            bad += 1; print(f"FAIL {e['file']}: {r.stderr.strip().splitlines()[-1:]}", file=sys.stderr)
        continue
    if "/c" not in args and "-c" not in args:
        args.insert(1, "/c")
    # /c writes <name>.obj into the cwd, which is the read-only /workspace -> "unable to
    # open output file ... Read-only file system" (2026-09-12). Redirect to /scratch/obj.
    # /clang:-o rather than /Fo: with "--" present clang-cl drops /Fo (see audit-native).
    import os, hashlib
    os.makedirs("/scratch/obj", exist_ok=True)
    obj = "/scratch/obj/" + hashlib.sha1(e["file"].encode()).hexdigest()[:12] + ".obj"
    args = [a for a in args if not a.startswith("/Fo") and not a.startswith("/clang:-o")]
    # CodeQL's extractor does not understand "--" ("Unrecognized command line argument --")
    # and then sees no source file at all: 346 compiles, 0 TRAP files (2026-09-12). The
    # converter emits "--" because clang-cl parses /workspace/x.cpp as the /wo option. A
    # path relative to the working dir satisfies both: no leading slash, no separator.
    if "--" in args:
        i = args.index("--")
        rel = os.path.relpath(e["file"], e.get("directory") or "/")
        args = args[:i] + ["/clang:-o" + obj, rel]
    else:
        args.insert(len(args) - 1, "/clang:-o" + obj)
    r = subprocess.run(args, cwd=e.get("directory"), capture_output=True, text=True)
    if r.returncode == 0: ok += 1
    else:
        bad += 1; print(f"FAIL {e['file']}: {r.stderr.strip().splitlines()[-1:] }", file=sys.stderr)
print(f"replay: {ok} ok, {bad} failed of {len(entries)}", file=sys.stderr)
sys.exit(0 if ok else 1)
