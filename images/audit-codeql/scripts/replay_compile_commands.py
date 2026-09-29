#!/usr/bin/env python3
"""replay_compile_commands.py COMPILE_COMMANDS [--stats PATH]

Replay a compile_commands.json under CodeQL's build tracer (codeql database create --command ...):
each entry's argv runs in its directory with its object output redirected to /scratch/obj, so the
tracer sees exactly the recorded compiler invocations and nothing else. Used by
codeql-sast-lane.sh (traced, audit-codeql-native; GNU-style clang from 02-native-build's adapted
database) and run-codeql.sh --traced-cpp (clang-cl + /msvc, experimental).

Only compiler invocations run: an entry whose compiler is not the in-image clang, that uses a
response file, or that can load or wrap compiler code (-Xclang, -fplugin, -fpass-plugin, -load,
-wrapper, --config, -specs=, -B) is refused and counted. Dependency-file outputs (-MD/-MF/...) are
dropped because /workspace is read-only. One failing TU never empties the database: failures are
counted, and the exit status is 0 when at least one TU compiled.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys

COMPILERS = ("/opt/llvm/bin/clang", "/opt/llvm/bin/clang++", "/opt/llvm/bin/clang-cl",
             "clang", "clang++", "clang-cl")
UNSAFE_EXACT = {"-load", "-plugin", "-add-plugin", "-wrapper", "-cc1"}
UNSAFE_PREFIX = ("-xclang", "-fplugin", "-fpass-plugin", "--config", "-specs=", "--gcc-toolchain",
                 "/clang:-load", "/clang:-plugin", "/clang:-fplugin", "/clang:-xclang")
DEPFILE_WITH_VALUE = {"-MF", "-MT", "-MQ"}
DEPFILE_FLAGS = {"-MD", "-MMD", "-M", "-MM", "-MP"}
TIMEOUT_SECONDS = 600
OBJ_DIR = os.environ.get("REPLAY_OBJ_DIR", "/scratch/obj")


def refused(args):
    """Why this argv may not run, or None."""
    if not args or args[0] not in COMPILERS:
        return "compiler is not the in-image clang"
    for word in args[1:]:
        lowered = word.lower()
        if word.startswith("@"):
            return "response file"
        if word.startswith("-B") or word.startswith("--prefix"):
            return "compiler search path override"
        if lowered in UNSAFE_EXACT or lowered.startswith(UNSAFE_PREFIX):
            return "flag can load or wrap compiler code"
    return None


def object_path(entry, suffix):
    os.makedirs(OBJ_DIR, exist_ok=True)
    return os.path.join(OBJ_DIR, hashlib.sha1(entry["file"].encode()).hexdigest()[:12] + suffix)


def gnu_argv(entry, args):
    out, skip = [args[0]], False
    for word in args[1:]:
        if skip:
            skip = False
            continue
        if word in DEPFILE_WITH_VALUE:
            skip = True
            continue
        if word in DEPFILE_FLAGS or any(word.startswith(flag) and len(word) > len(flag) for flag in DEPFILE_WITH_VALUE):
            continue
        out.append(word)
    if "-c" not in out:
        out.insert(1, "-c")
    obj = object_path(entry, ".o")
    if "-o" in out:
        index = out.index("-o")
        if index + 1 < len(out):
            out[index + 1] = obj
        else:
            out.append(obj)
    else:
        out += ["-o", obj]
    return out


def clang_cl_argv(entry, args):
    if "/c" not in args and "-c" not in args:
        args.insert(1, "/c")
    # /c writes <name>.obj into the cwd (read-only /workspace); /clang:-o redirects it. With "--"
    # present clang-cl drops /Fo, and CodeQL's extractor rejects "--", so the file is passed relative.
    obj = object_path(entry, ".obj")
    args = [a for a in args if not a.startswith("/Fo") and not a.startswith("/clang:-o")]
    if "--" in args:
        index = args.index("--")
        rel = os.path.relpath(entry["file"], entry.get("directory") or "/")
        return args[:index] + ["/clang:-o" + obj, rel]
    args.insert(len(args) - 1, "/clang:-o" + obj)
    return args


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("compile_commands")
    parser.add_argument("--stats")
    options = parser.parse_args()
    with open(options.compile_commands, encoding="utf-8") as handle:
        entries = json.load(handle)
    ok = failed = refused_count = 0
    for entry in entries:
        args = list(entry.get("arguments") or [])
        reason = refused(args)
        if reason:
            refused_count += 1
            print(f"REFUSED {entry.get('file')}: {reason}", file=sys.stderr)
            continue
        argv = clang_cl_argv(entry, args) if args[0].endswith("clang-cl") else gnu_argv(entry, args)
        try:
            result = subprocess.run(argv, cwd=entry.get("directory") or "/workspace", capture_output=True,
                                    text=True, timeout=TIMEOUT_SECONDS)
            code = result.returncode
            tail = result.stderr.strip().splitlines()[-1:] if result.stderr else []
        except (OSError, subprocess.TimeoutExpired) as exc:
            code, tail = 1, [type(exc).__name__]
        if code == 0:
            ok += 1
        else:
            failed += 1
            print(f"FAIL {entry.get('file')}: {tail}", file=sys.stderr)
    stats = {"total": len(entries), "ok": ok, "failed": failed, "refused": refused_count}
    print(f"replay: {ok} ok, {failed} failed, {refused_count} refused of {len(entries)}", file=sys.stderr)
    if options.stats:
        with open(options.stats, "w", encoding="utf-8") as handle:
            json.dump(stats, handle, sort_keys=True)
            handle.write("\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
