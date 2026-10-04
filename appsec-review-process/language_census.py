#!/usr/bin/env python3
"""Accepted ``02-language-census``: one deterministic answer to "what is this file" for the snapshot.

Every regular file of the staged checkout (``inputs/artifact-manifest.json`` ``target.repo_path``,
walked by ``treesitter_ast.iter_files``: sorted, ``.git`` skipped, symlinks never followed) gets exactly
one class, decided in this order and recorded with its ``basis``:

1. ``path``: the rule table's ``vendored`` and ``generated`` exclusion globs
   (``data/owasp-asvs/category-rules-v1.json``) give ``vendored`` / ``generated``;
2. ``name``: exact file names (``Makefile``, ``Dockerfile``, ``config.guess``, ``install-sh``, ``configure``,
   lock files, ``README``/``LICENSE`` and their ``README.*`` forms, ``.gitignore``);
3. ``suffix``: program languages (``program:<language>``, the tree-sitter names where a grammar
   exists), build-system, documentation, data/config, binary/media, patch/diff and generated suffixes;
4. ``shebang``: line 1 ``#!`` (``env`` forms followed): sh/bash/dash/zsh/ksh -> bash, python*, perl,
   ruby, node -> javascript, php; ``make`` -> build_system; another interpreter -> ``unknown_text`` with
   its ``interpreter`` recorded;
5. ``sniff``: a NUL byte in the first 8 KiB or a known magic number -> ``binary_media``; any other
   content -> ``unknown_text``.

Classes: ``program:<language>``, ``build_system``, ``documentation``, ``data_config``, ``binary_media``,
``patch_diff``, ``generated``, ``vendored``, ``unknown_text``. ``language`` is set for program files only.
``languages_needing_server`` lists the program languages whose language server
``tooling/buildenv-catalog.json`` names (image and servers). Rows are bounded by ``max_rows``; per-class
and per-language counts always cover every file, and unlisted rows, unreadable files and skipped
links are gaps. Nothing here executes target content; file bytes are data.

    python3 language_census.py RUN_ID            # the graph job
    python3 language_census.py --root DIR [--out census.json]   # the census of a plain directory
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Callable, Iterable

from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, now, read_json, run_path
import treesitter_ast

JOB = "02-language-census"
CONTRACT = "language-census"
SCHEMA = "appsec-review/language-census/1.0"
SCHEMA_FILE = "language-census.schema.json"
RESULT = "language-census.json"
SUMMARY = "language-census-summary.md"
RULES_PATH = "data/owasp-asvs/category-rules-v1.json"
CATALOG_PATH = "tooling/buildenv-catalog.json"
PERMISSIONS = ["read-source", "write-run-data"]
HEAD_BYTES = 8192
DEFAULT_MAX_ROWS = 200_000
PROGRAM = "program:"
CLASSES = ("build_system", "documentation", "data_config", "binary_media", "patch_diff", "generated", "vendored",
           "unknown_text")
PATH_CLASSES = {"vendored": "vendored", "generated": "generated"}   # rule-table exclusion_id -> class
BODY = ("schema", "limits", "totals", "classes", "languages", "languages_needing_server", "files", "gaps")

_NAMES = {
    "build_system": "makefile gnumakefile cmakelists.txt cmakepresets.json meson.build meson_options.txt dockerfile "
                    "containerfile jenkinsfile vagrantfile gemfile rakefile podfile build.gradle build.gradle.kts "
                    "settings.gradle settings.gradle.kts gradlew gradlew.bat pom.xml package.json pyproject.toml "
                    "setup.cfg cargo.toml go.mod go.work composer.json pipfile requirements.txt build.bazel "
                    "workspace workspace.bazel module.bazel sconstruct sconscript configure.ac configure.in "
                    "makefile.am config.guess config.sub config.rpath install-sh missing depcomp compile ltmain.sh "
                    "test-driver ar-lib mkinstalldirs py-compile ylwrap tsconfig.json jsconfig.json",
    "generated": "configure config.status libtool makefile.in aclocal.m4 config.h.in cargo.lock composer.lock "
                 "gemfile.lock go.sum package-lock.json pipfile.lock pnpm-lock.yaml poetry.lock yarn.lock uv.lock",
    "documentation": "readme license licence copying copying.lib authors news changelog changes install thanks todo "
                     "notice contributing security hacking maintainers history credits bugs code_of_conduct",
    "data_config": ".gitignore .gitattributes .gitmodules .editorconfig .clang-format .clang-tidy .dockerignore "
                   ".mailmap codeowners .npmrc .nvmrc .env .prettierrc .eslintrc .travis.yml .gitlab-ci.yml",
}
NAMES = {name: cls for cls, names in _NAMES.items() for name in names.split()}
# README.md, LICENSE.GPL, CHANGELOG.old: documentation by name unless the suffix is program source.
DOC_STEMS = frozenset(name for name in _NAMES["documentation"].split())
_PROGRAM = {
    "bash": "sh bash ksh zsh", "c": "c h", "c_sharp": "cs", "cpp": "cc cpp cxx c++ hh hpp hxx inl ipp tpp",
    "go": "go", "java": "java", "javascript": "js jsx mjs cjs", "php": "php phtml", "python": "py pyi pyw",
    "ruby": "rb", "rust": "rs", "typescript": "ts mts cts", "tsx": "tsx", "kotlin": "kt kts", "swift": "swift",
    "objective-c": "m", "objective-cpp": "mm", "scala": "scala sc", "dart": "dart", "lua": "lua", "perl": "pl pm",
    "r": "r", "groovy": "groovy", "assembly": "s asm", "sql": "sql", "powershell": "ps1 psm1 psd1",
    "batch": "bat cmd", "visual-basic": "vb", "fsharp": "fs fsx", "erlang": "erl hrl", "elixir": "ex exs",
    "haskell": "hs", "ocaml": "ml mli", "clojure": "clj cljs cljc", "julia": "jl", "zig": "zig", "nim": "nim",
    "vue": "vue", "svelte": "svelte", "tcl": "tcl", "awk": "awk", "fortran": "f f90 f95 for", "solidity": "sol",
    "cuda": "cu cuh", "yacc": "y yy", "lex": "l ll", "vala": "vala", "pascal": "pas",
}
_SUFFIXES = {
    "build_system": "am ac m4 mk mak cmake in gradle bzl bazel ninja gyp gypi pro pri sln vcxproj vcproj csproj "
                    "fsproj vbproj props targets spec",
    "documentation": "md markdown rst txt texi texinfo info adoc asciidoc tex rtf html htm xhtml pdf doc docx odt "
                     "man pod",
    "data_config": "json jsonc json5 yml yaml toml ini cfg conf config xml xsd xsl xslt properties env csv tsv plist "
                   "proto thrift graphql gql po pot desktop service socket timer pc rc def pem crt cer key pub asc "
                   "sig gpg editorconfig",
    "binary_media": "png jpg jpeg gif bmp ico icns svg webp tif tiff psd xcf mp3 mp4 wav ogg flac avi mov webm ttf "
                    "otf woff woff2 eot zip gz tgz bz2 xz zst lz lzma 7z tar rar jar war ear aar apk class o obj a "
                    "lib so dll dylib exe bin elf pyc pyo wasm db sqlite sqlite3 mo gmo pdb dex",
    "patch_diff": "patch diff rej",
    "generated": "lock map",
}
SUFFIX_CLASSES = {"." + suffix: (PROGRAM + language, language) for language, suffixes in _PROGRAM.items()
                  for suffix in suffixes.split()}
SUFFIX_CLASSES.update({"." + suffix: (cls, None) for cls, suffixes in _SUFFIXES.items() for suffix in suffixes.split()})
GENERATED_ENDINGS = (".min.js", ".min.css", ".pb.go", ".pb.cc", ".pb.h", "_pb2.py", "_pb2_grpc.py", ".g.cs",
                     ".designer.cs", ".generated.cs")
SHEBANG_CLASSES = {"make": "build_system", "gmake": "build_system"}
MAGIC = (b"\x7fELF", b"\x89PNG", b"GIF8", b"\xff\xd8\xff", b"%PDF-", b"PK\x03\x04", b"\x1f\x8b", b"BZh",
         b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa", b"\xcf\xfa\xed\xfe",
         b"\xce\xfa\xed\xfe", b"\x00asm", b"RIFF", b"OggS", b"ID3", b"wOFF", b"wOF2", b"SQLite format 3\x00",
         b"!<arch>\n", b"Rar!\x1a\x07", b"\x28\xb5\x2f\xfd")
_MAN_SECTION = re.compile(r"\.[1-9]")
# Census language -> buildenv-catalog language whose image ships a language server.
CATALOG_LANGUAGES = {"c": "cpp", "cpp": "cpp", "objective-c": "cpp", "objective-cpp": "cpp", "cuda": "cpp",
                     "c_sharp": "dotnet", "fsharp": "dotnet", "visual-basic": "dotnet", "java": "java", "go": "go",
                     "javascript": "typescript", "typescript": "typescript", "tsx": "typescript", "vue": "typescript",
                     "svelte": "typescript", "php": "php", "python": "python", "rust": "rust"}


def _glob_regex(pattern: str) -> re.Pattern[str]:
    from component_characterization import _glob_regex as compile_glob
    return compile_glob(pattern)


def path_classifier(rules: dict[str, Any]) -> Callable[[str], tuple[str, str] | None]:
    """``path -> (class, glob)`` from the rule table's vendored and generated exclusion globs."""
    table = [(PATH_CLASSES[row["exclusion_id"]], glob, _glob_regex(glob)) for row in rules.get("exclusions", [])
             if row.get("exclusion_id") in PATH_CLASSES for glob in row["path_globs"]]
    return lambda path: next(((cls, glob) for cls, glob, pattern in table if pattern.match(path)), None)


def classify(path: str, head: bytes, by_path: Callable[[str], tuple[str, str] | None] | None = None
             ) -> tuple[str, str | None, str, str | None]:
    """``(class, language, basis, interpreter)`` of one file from its relative path and first bytes."""
    found = by_path(path) if by_path else None
    if found:
        return found[0], None, "path", None
    name = PurePosixPath(path).name
    lowered = name.lower()
    suffix = PurePosixPath(lowered).suffix
    if lowered in NAMES:
        return NAMES[lowered], None, "name", None
    if lowered.endswith(GENERATED_ENDINGS):
        return "generated", None, "suffix", None
    by_suffix = SUFFIX_CLASSES.get(suffix)
    if lowered.split(".", 1)[0] in DOC_STEMS and (by_suffix is None or by_suffix[0] == "documentation"):
        return "documentation", None, "name", None
    if by_suffix:
        return by_suffix[0], by_suffix[1], "suffix", None
    binary = b"\x00" in head[:HEAD_BYTES] or head.startswith(MAGIC)
    if _MAN_SECTION.fullmatch(suffix) and not binary:   # hello.1 is a man page; libfoo.so.1 is not
        return "documentation", None, "suffix", None
    interpreter = treesitter_ast.shebang_interpreter(head)
    if interpreter:
        language = treesitter_ast.SHEBANG_LANGUAGES.get(interpreter)
        if language:
            return PROGRAM + language, language, "shebang", interpreter
        return SHEBANG_CLASSES.get(interpreter, "unknown_text"), None, "shebang", interpreter
    if binary:
        return "binary_media", None, "sniff", None
    return "unknown_text", None, "sniff", None


def _read(path: Path) -> tuple[bytes, str, int]:
    """(first HEAD_BYTES, sha256 ref, size) streamed in one pass."""
    sha, head, size = hashlib.sha256(), b"", 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            if len(head) < HEAD_BYTES:
                head += chunk[:HEAD_BYTES - len(head)]
            sha.update(chunk); size += len(chunk)
    return head, "sha256:" + sha.hexdigest(), size


def catalog_servers(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Catalog language -> the first image (catalog order) that ships a language server."""
    out: dict[str, dict[str, Any]] = {}
    for row in catalog.get("images") or []:
        if isinstance(row, dict) and row.get("lsp") and row.get("language") not in out:
            out[row["language"]] = {"image": row["image"], "servers": sorted(row["lsp"])}
    return out


def census(root: Path, rules: dict[str, Any], catalog: dict[str, Any], *, max_rows: int = DEFAULT_MAX_ROWS,
           file_list: Iterable[str] | None = None) -> dict[str, Any]:
    """The census body of ``root``: deterministic for the same bytes, rule table and catalog."""
    by_path = path_classifier(rules)
    rows, gaps, counts, languages = [], [], {}, {}
    total = total_bytes = unlisted = 0
    for relative, path, problem in treesitter_ast.iter_files(Path(root), file_list):
        if problem:
            gaps.append({"kind": problem, "path": relative, "detail": f"{problem}: not classified"})
            continue
        try:
            head, sha, size = _read(path)
        except OSError as exc:
            gaps.append({"kind": "unreadable", "path": relative, "detail": f"unreadable ({type(exc).__name__}): not classified"})
            continue
        cls, language, basis, interpreter = classify(relative, head, by_path)
        total += 1; total_bytes += size
        counts[cls] = counts.get(cls, 0) + 1
        if language:
            languages[language] = languages.get(language, 0) + 1
        if len(rows) < max_rows:
            rows.append({"path": relative, "sha256": sha, "bytes": size, "class": cls, "language": language,
                         "basis": basis, "interpreter": interpreter})
        else:
            unlisted += 1
    if unlisted:
        gaps.append({"kind": "rows-overflow", "path": None, "detail": f"{unlisted} file(s) beyond max_rows {max_rows} are "
                     "counted but not listed: their per-file class is unknown to consumers"})
    unknown = [row for row in rows if row["class"] == "unknown_text"]
    if unknown:
        gaps.append({"kind": "unknown-text", "path": None, "detail": f"{counts['unknown_text']} text file(s) no name, suffix "
                     "or shebang rule classifies: " + ", ".join(row["path"] for row in unknown[:10])[:900]})
    servers = catalog_servers(catalog)
    needing = [{"language": language, "catalog_language": CATALOG_LANGUAGES[language], "file_count": count,
                **servers[CATALOG_LANGUAGES[language]]}
               for language, count in sorted(languages.items())
               if CATALOG_LANGUAGES.get(language) in servers]
    return {"schema": SCHEMA, "limits": {"max_rows": max_rows, "head_bytes": HEAD_BYTES},
            "totals": {"files": total, "bytes": total_bytes, "listed": len(rows), "unlisted": unlisted},
            "classes": [{"class": cls, "file_count": count} for cls, count in sorted(counts.items())],
            "languages": [{"language": language, "file_count": count} for language, count in sorted(languages.items())],
            "languages_needing_server": needing, "files": rows,
            "gaps": sorted(gaps, key=lambda gap: (gap["kind"], gap["path"] or "", gap["detail"]))}


def content_sha256(body: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(treesitter_ast.canonical(body)).hexdigest()


# --- graph job ------------------------------------------------------------------------------------

def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _max_rows() -> int:
    import tunables
    return int(tunables.value(JOB, "max_rows"))


def _code() -> dict[str, str]:
    import registry_paths
    paths = ("language_census.py", "treesitter_ast.py", "component_characterization.py",
             registry_paths.template_rel(JOB), registry_paths.contract_rel(CONTRACT), CATALOG_PATH)
    values = {name: file_hash(ROOT / name) for name in paths}
    values["schemas/" + SCHEMA_FILE] = file_hash(ROOT.parent / "schemas" / SCHEMA_FILE)
    values[RULES_PATH] = file_hash(ROOT.parent / RULES_PATH)
    return values


def _target(run_id: str) -> tuple[Path, str]:
    manifest = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not manifest.is_file() or manifest.is_symlink():
        raise Blocked(f"{JOB}: staged artifact manifest is required")
    value = (read_json(manifest).get("target") or {}).get("repo_path")
    target = Path(value) if isinstance(value, str) and value else Path()
    if not value or not target.is_absolute() or not target.is_dir() or target.is_symlink():
        raise Blocked(f"{JOB}: target must be an absolute real checkout")
    return target.resolve(), "sha256:" + file_hash(manifest)


def current_inputs(run_id: str) -> dict[str, Any]:
    from code_graph_evidence import source_tree_sha256
    target, source = _target(run_id)
    return {"run_id": run_id, "job": JOB, "target_path": str(target), "source_snapshot_sha256": source,
            "source_tree_sha256": source_tree_sha256(target), "max_rows": _max_rows(), "code": _code()}


def document(body: dict[str, Any], *, run_id: str, source_snapshot_sha256: str, source_tree_sha256: str,
             rules_sha256: str) -> dict[str, Any]:
    """The published ``language-census.schema.json`` document around a ``census`` body."""
    return {**body, "run_id": run_id, "job_id": JOB, "source_snapshot_sha256": source_snapshot_sha256,
            "source_tree_sha256": source_tree_sha256, "status": "OK_WITH_GAPS" if body["gaps"] else "OK",
            "rule_table": {"path": RULES_PATH, "sha256": rules_sha256},
            "claim_boundary": "FILE_CLASSIFICATION_NOT_FINDING", "content_sha256": content_sha256(body)}


def result_document(run_id: str, inputs: dict[str, Any]) -> dict[str, Any]:
    body = census(Path(inputs["target_path"]), read_json(ROOT.parent / RULES_PATH), read_json(ROOT / CATALOG_PATH),
                  max_rows=inputs["max_rows"])
    return document(body, run_id=run_id, source_snapshot_sha256=inputs["source_snapshot_sha256"],
                    source_tree_sha256=inputs["source_tree_sha256"], rules_sha256=inputs["code"][RULES_PATH])


def load(attempt: Path) -> dict[str, Any]:
    """An accepted attempt's census, schema- and hash-checked (the candidate search's input)."""
    from schema_validate import validate_document
    value = read_json(Path(attempt) / RESULT)
    if validate_document(value, SCHEMA_FILE):
        raise ValueError(f"{JOB}: census fails its schema")
    body = {key: value[key] for key in BODY}
    if content_sha256(body) != value["content_sha256"]:
        raise ValueError(f"{JOB}: census does not match its content_sha256")
    return value


def _receipts(run_id: str, inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    common = {"run_id": run_id, "job_id": JOB, "source_snapshot_sha256": inputs["source_snapshot_sha256"]}
    return ({"schema": "appsec-review/producer-permission-receipt/1.0", **common, "permissions": PERMISSIONS},
            {"schema": "appsec-review/producer-lineage-receipt/1.0", **common,
             "build_lineage_sha256": "sha256:" + digest(inputs)})


def _validate_attempt(run_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs or current_inputs(run_id) != inputs:
        raise Blocked(f"{JOB}: inputs or source generation changed")
    try:
        document = load(attempt)
    except ValueError as exc:
        raise Blocked(str(exc)) from exc
    if document != result_document(run_id, inputs):
        raise Blocked(f"{JOB}: published census differs from a re-derivation over the bound snapshot")
    permission, lineage = _receipts(run_id, inputs)
    if read_json(attempt / "permission.json") != permission or read_json(attempt / "lineage.json") != lineage:
        raise Blocked(f"{JOB}: producer permission or lineage receipt changed")


def _summary(document: dict[str, Any]) -> str:
    classes = ", ".join(f"{row['class']} {row['file_count']}" for row in document["classes"]) or "none"
    servers = ", ".join(row["language"] for row in document["languages_needing_server"]) or "none"
    return ("# Language census\n\n"
            f"- Files: {document['totals']['files']} ({document['totals']['unlisted']} not listed by row).\n"
            f"- Classes: {classes}.\n- Languages with a catalog language server: {servers}.\n"
            f"- Gaps: {len(document['gaps'])}.\n- Classes are file-level facts, never findings.\n")


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    from publish_job_output import coordinate_worker_lifecycle, record_terminal_current
    base = root(run_id)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        if current_inputs(run_id) != inputs:
            raise Blocked(f"{JOB}: source or implementation changed before execution")
        attempt = allocation["attempt"]
        document = result_document(run_id, inputs)
        atomic_json(attempt / RESULT, document)
        (attempt / SUMMARY).write_text(_summary(document), encoding="utf-8")
        permission, lineage = _receipts(run_id, inputs)
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        status = {"process": JOB, "status": document["status"], "run_id": run_id, "dagster_run_id": dagster_id,
                  "attempt_id": allocation["attempt_id"], "files": document["totals"]["files"],
                  "gaps": len(document["gaps"]), "network": "none", "qualification": "implemented_not_qualified",
                  "ended_at": now()}
        atomic_json(attempt / "status.json", status)
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
            worker_kind="deterministic_python", output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=document["status"],
            summary=f"Language census: {document['totals']['files']} file(s).", status_record=status,
            artifact_paths=[RESULT, SUMMARY, "status.json", "permission.json", "lineage.json"],
            gaps=sorted({gap["kind"] for gap in document["gaps"]}) or None,
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, inputs))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
        worker_kind="deterministic_python", output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/language_census.py {run_id}",
        derive_inputs=lambda: current_inputs(run_id), fingerprint_inputs=lambda value: "sha256:" + digest(value),
        execute_attempt=execute, preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code()}, force=force,
        post_validate=lambda attempt, _envelope, record: _validate_attempt(run_id, attempt, record),
        blocked_summary="Language census preflight did not complete.",
        failed_summary="Language census did not publish; no older success may be used.")


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    from publish_job_output import validate_published
    base = root(run_id); inputs = current_inputs(run_id)
    pointer = pointer or read_json(base / "accepted.json")
    attempt, _ = validate_published(base, pointer, "sha256:" + digest(inputs), expected_run_id=run_id,
                                    expected_job_id=JOB)
    _validate_attempt(run_id, attempt, inputs)
    return attempt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("run_id", nargs="?")
    parser.add_argument("--root", type=Path, help="classify this directory instead of a run's snapshot")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--dagster-id", default="manual")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    if args.root is None:
        if not args.run_id:
            parser.error("give a run id or --root")
        print(run(args.run_id, args.dagster_id, args.force))
        return 0
    body = census(args.root, read_json(ROOT.parent / RULES_PATH), read_json(ROOT / CATALOG_PATH))
    text = json.dumps({**body, "content_sha256": content_sha256(body)}, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
