"""Shared harness for the seeded Clang producers: a 12-translation-unit project, recorded clang output.

``tests/fixtures/seeded_clang/project`` is compiled for real once (``record.py``); this module plays the
recordings back through an injected ``tool-native-cpp`` executor that behaves like the container driver:
it reads ``replay-<mode>.json`` when the job wrote one (rows renumbered from zero) and the whole
normalized database otherwise, and it records which translation units each call replayed.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
from types import SimpleNamespace
from typing import Any, Mapping

from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, SourceLocation, write_manifest,
)
from appsec_review.retrieval.index import INDEX_SCHEMA
from appsec_review.storage import file_sha256

FIXTURE = Path(__file__).parent / "fixtures" / "seeded_clang"
PROJECT = FIXTURE / "project"
RECORDED = FIXTURE / "recorded"
DIGEST = "sha256:" + "c" * 64
SNAPSHOT = "f" * 64
ROOT = "proj"
CASE = "project-seeded0000000001"
SOURCES = sorted(path.stem for path in (PROJECT / "src").glob("*.cpp"))
# One finding in util.cpp (the memcpy in copy_field) and one in net.cpp (the copy_field call).
SEEDS = (("src/util.cpp", 14, 14), ("src/net.cpp", 6, 6))
SEEDED = {"mode": "seeded", "depth": 3, "seed_limit": 200, "function_limit": 400, "unit_limit": 64,
          "block_limit": 2000, "include_scan_files": 4000}


class FixtureExecutor:
    """Plays the recorded clang output back the way ``containers/tools/native-cpp/native.py`` writes it."""

    def __init__(self, run_root: Path, *, fail: tuple[tuple[str, str], ...] = (), exit_code: int = 0) -> None:
        self.run_root, self.fail, self.exit_code = run_root, set(fail), exit_code
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def execute(self, request):
        root, mode = request.scratch_root, request.argv[1]
        replay = root / f"replay-{mode}.json"
        rows = json.loads((replay if replay.is_file() else root / "normalized-compile-commands.json").read_text())
        destination = root / "analysis" / mode
        shutil.rmtree(destination, ignore_errors=True) if not replay.is_file() else None
        destination.mkdir(parents=True, exist_ok=True)
        receipt, replayed = [], []
        for index, row in enumerate(rows):
            stem = Path(row["file"]).stem
            replayed.append(row["target_path"])
            failed = (mode, stem) in self.fail
            if mode == "ir":
                if not failed:
                    shutil.copyfile(RECORDED / "ir" / f"{stem}.ll", destination / f"tu-{index:04d}.ll")
            elif mode == "cfg":
                if not failed:
                    shutil.copyfile(RECORDED / "cfg" / f"{stem}.cfg.txt", destination / f"tu-{index:04d}.cfg.txt")
            else:
                names = row.get("ast_filters") or sorted(path.stem for path in (RECORDED / "ast" / stem).glob("*.json"))
                text = "".join((RECORDED / "ast" / stem / f"{name}.json").read_text()
                               for name in names if (RECORDED / "ast" / stem / f"{name}.json").is_file())
                if not failed:
                    (destination / f"tu-{index:04d}.json").write_text(text, encoding="utf-8")
            receipt.append({"index": index, "source": row["file"], "exit_code": 1 if failed else 0,
                            "output": f"analysis/{mode}/tu-{index:04d}", "stderr": "error: fixture failure" if failed else ""})
        (destination / "receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
        self.calls.append((mode, tuple(replayed)))
        raw = root / "raw"
        raw.mkdir(exist_ok=True)
        (raw / "stdout.bin").write_bytes(b"")
        (raw / "stderr.bin").write_bytes(b"")
        (root / "execution.json").write_text("{}", encoding="utf-8")
        relative = lambda path: path.relative_to(self.run_root).as_posix()
        code = self.exit_code or (2 if any(item[0] == mode for item in self.fail) else 0)
        return ExecutionResult("appsec-review/container-execution/1", request.tool_id,
            "appsec-review/tool-native-cpp:1.0.0", DIGEST, DIGEST, "argv", (), {}, "start", "end", code, False,
            False, False, False, relative(raw / "stdout.bin"), relative(raw / "stderr.bin"),
            relative(root / "execution.json"))


class Events:
    def __init__(self) -> None:
        self.items: list[tuple[str, dict]] = []

    def write(self, name: str, **values: Any) -> None:
        self.items.append((name, values))


class Staged(SimpleNamespace):
    """One accepted native project on disk plus the pieces a job unit reads."""

    def unit(self, unit_id: str, outputs: Mapping[str, Any] | None = None, *, seeded: Mapping[str, Any] | None = SEEDED,
             job_id: str = "job_cpp_compiled_analysis") -> SimpleNamespace:
        settings = {} if seeded is None else {"seeded": dict(seeded)}
        unit_root = self.run_root / "data" / "units" / unit_id
        unit_root.mkdir(parents=True, exist_ok=True)
        values = dict(outputs or {})
        return SimpleNamespace(
            job=SimpleNamespace(run_root=self.run_root, target_root=self.target, repository_root=self.repository,
                                source_fingerprint=SNAPSHOT, events=Events(), attempt_id="attempt_0001", run_id="run",
                                input_manifest_path=self.manifest_path, input_manifest_sha256=self.manifest_sha,
                                config=SimpleNamespace(settings=settings)),
            unit_id=unit_id, unit_root=unit_root, output=lambda key: values[key])


def observation(path: str, line: int, *, rule: str = "r1", tool: str = "tool-cppcheck", severity: str = "HIGH",
                end: int | None = None) -> dict[str, Any]:
    return {"path": path, "start": line, "end": end or line, "tool": tool, "rule": rule, "severity": severity,
            "category": "source_sast"}


def _observation_shard(run_root: Path, shard_id: str, items: list[dict[str, Any]]) -> IndexIdentity:
    fingerprint = hashlib.sha256((shard_id + json.dumps(items, sort_keys=True)).encode()).hexdigest()
    path = run_root / "data" / "indices" / "observations" / shard_id / f"{fingerprint}.sqlite"
    builder = IndexBuilder(path, name="observations", fingerprint=fingerprint, target_snapshot=SNAPSHOT, shard_id=shard_id)
    for ordinal, item in enumerate(items):
        identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAPSHOT, {"shard": shard_id, "ordinal": ordinal})
        builder.add_entity(EntityRecord(
            identity, f"{shard_id}-{ordinal}", item["rule"], item["rule"],
            {"tool_id": item["tool"], "native_rule_id": item["rule"], "native_severity": item["severity"],
             "category": item["category"]},
            SourceLocation(SNAPSHOT, item["path"], "a" * 64, 0, 10, item["start"], item["end"], 1, 1,
                           {"tool": item["tool"]}, "producer-line-location", 1.0)))
    sha = builder.build()
    return IndexIdentity("observations", INDEX_SCHEMA, sha, fingerprint, path.relative_to(run_root).as_posix(),
                         {"job": "job_evidence_collection", "producer": shard_id}, (), shard_id)


def compile_rows(case_id: str = CASE) -> list[dict[str, Any]]:
    rows = []
    for stem in SOURCES:
        arguments = ["clang++-18", "-std=c++17", "-I/scratch/source/include", "-c", f"/scratch/source/src/{stem}.cpp"]
        row = {"project_key": case_id, "directory": "/scratch/source", "file": f"/scratch/source/src/{stem}.cpp",
               "target_path": f"{ROOT}/src/{stem}.cpp", "arguments": arguments, "output_path": None,
               "source_sha256": file_sha256(PROJECT / "src" / f"{stem}.cpp"),
               "command_sha256": hashlib.sha256(json.dumps(arguments).encode()).hexdigest()}
        row["compile_unit_id"] = hashlib.sha256(json.dumps([row["target_path"], row["command_sha256"]]).encode()).hexdigest()
        rows.append(row)
    rows.sort(key=lambda item: (item["target_path"], item["command_sha256"]))
    for index, row in enumerate(rows):
        row["index"] = index
    return rows


def stage(tmp_path: Path, observations: list[dict[str, Any]] | None = None, *, run_root: Path | None = None,
          target: Path | None = None) -> Staged:
    """A run with one accepted project (12 units), the observation manifest and the project's scratch tree.

    ``run_root`` and ``target`` place the project in an existing run (the end-to-end test); they default to
    ``<tmp_path>/run`` and ``<tmp_path>/target``.
    """
    run_root, target = run_root or tmp_path / "run", target or tmp_path / "target"
    shutil.copytree(PROJECT, target / ROOT)
    case_root = run_root / "data" / "cpp" / "projects" / CASE
    shutil.copytree(PROJECT, case_root / "source")
    rows = compile_rows()
    (case_root / "normalized-compile-commands.json").write_text(json.dumps(rows), encoding="utf-8")
    database = {"path": (case_root / "normalized-compile-commands.json").relative_to(run_root).as_posix(),
                "sha256": file_sha256(case_root / "normalized-compile-commands.json"),
                "size_bytes": (case_root / "normalized-compile-commands.json").stat().st_size}
    files = [{"target_path": f"{ROOT}/{path.relative_to(PROJECT).as_posix()}", "scratch_path": f"source/{path.relative_to(PROJECT).as_posix()}",
              "sha256": file_sha256(path)} for path in sorted(PROJECT.rglob("*")) if path.is_file()]
    mapping = {"project_key": CASE, "project_id": "project-id-1", "root": ROOT, "case_snapshot": hashlib.sha256(b"case").hexdigest(),
               "files": files, "display_name": ROOT}
    shard = _observation_shard(run_root, "evidence", observations if observations is not None else
                               [observation(f"{ROOT}/{path}", line) for path, line, _ in SEEDS])
    manifest = run_root / "data" / "indices" / "manifests" / "upstream.json"
    write_manifest(manifest, run_id="run", target_snapshot=SNAPSHOT, target_root=target, indexes=[shard])
    (tmp_path / "repository").mkdir(exist_ok=True)
    cataloged = {"project_key": CASE, "mapping": mapping, "compile_commands": rows, "compile_database": database,
                 "artifact_catalog": {**database, "sha256": "1" * 64}, "link_database": {**database, "sha256": "2" * 64},
                 "gaps": [], "terminal_status": "SUCCEEDED"}
    return Staged(run_root=run_root, target=target, repository=tmp_path / "repository", case_root=case_root, rows=rows,
                  mapping=mapping, cataloged=cataloged, manifest_path=manifest, manifest_sha=file_sha256(manifest))


# ---- Clang-Tidy / Static Analyzer playback -------------------------------------------------------------
# (line, rule, trace steps, fix-it) per (engine action, source stem): util.cpp:14 and net.cpp:6 are the seeds.
STATIC_DIAGNOSTICS = {
    ("tidy", "util"): [(14, "bugprone-not-null-terminated-result", 0, True), (5, "readability-magic-numbers", 0, False),
                       (2, "misc-use-internal-linkage", 0, False)],
    ("analyze", "util"): [(14, "unix.cstring.NullArg", 3, False)],
    ("tidy", "net"): [(4, "cppcoreguidelines-avoid-c-arrays", 0, False), (2, "bugprone-easily-swappable-parameters", 0, False)],
    ("analyze", "net"): [(6, "core.uninitialized.Assign", 2, False)],
}


class StaticExecutor:
    """Plays ``tool-clang-static-analysis`` back: one result document per engine, per-unit outcomes included."""

    def __init__(self, run_root: Path, *, fail: tuple[tuple[str, str], ...] = (), diagnostics=None,
                 report_units: bool = True) -> None:
        self.run_root, self.fail, self.report_units = run_root, set(fail), report_units
        self.diagnostics = STATIC_DIAGNOSTICS if diagnostics is None else diagnostics
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def execute(self, request):
        root, action = request.scratch_root, request.argv[1]
        rows = json.loads((root / "compile_commands.json").read_text())
        engine = "clang-tidy" if action == "tidy" else "clang-static-analyzer"
        diagnostics, units = [], []
        for row in rows:
            stem = Path(row["file"]).stem
            failed = (action, stem) in self.fail
            units.append({"file": row["file"], "exit_code": 1 if failed else 0,
                          "message": f"{row['file']}:1:1: error: fixture failure" if failed else ""})
            if failed:
                continue
            for line, rule, steps, fix_it in self.diagnostics.get((action, stem), ()):
                diagnostics.append({"rule_id": rule, "message": f"{rule} fixture", "severity": "warning",
                                    "path": row["file"], "line": line, "column": 3, "fix_it": fix_it,
                                    "notes": [{"message": f"step {n}", "line": line, "column": 3} for n in range(steps)]})
        document = {"schema": "appsec-review/clang-static-output/1", "engine": engine, "truncated": False,
                    "diagnostics": diagnostics}
        if self.report_units:
            document["units"] = units
        (root / f"{action}.json").write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
        self.calls.append((engine, tuple(sorted(Path(row["file"]).relative_to("/target/source").as_posix() for row in rows))))
        raw = root / "raw"
        raw.mkdir(exist_ok=True)
        (raw / "stdout.bin").write_bytes(b"")
        (raw / "stderr.bin").write_bytes(b"")
        (root / "execution.json").write_text("{}", encoding="utf-8")
        relative = lambda path: path.relative_to(self.run_root).as_posix()
        return ExecutionResult("appsec-review/container-execution/1", request.tool_id,
            "appsec-review/tool-clang-static-analysis:1.0.0", DIGEST, DIGEST, "argv", (), {}, "start", "end",
            1 if any(unit["exit_code"] for unit in units) else 0, False, False, False, False,
            relative(raw / "stdout.bin"), relative(raw / "stderr.bin"), relative(root / "execution.json"),
            request.file_size_limit_bytes, False)


def index_scope(staged):
    """The staged project as the ``IndexScope`` the indexing jobs derive from the accepted handoff."""
    from appsec_review.jobs.cpp_index_scopes import IndexScope

    mapping = staged.mapping
    by_relative = {item["scratch_path"][len("source/"):]: item for item in mapping["files"]}
    return IndexScope("cpp-scope-seeded", CASE, mapping["project_id"], mapping["root"], mapping["case_snapshot"],
                      staged.case_root, tuple(mapping["files"]), tuple(staged.rows),
                      staged.cataloged["compile_database"], by_relative)


STATIC_SETTINGS = {"workers": 1, "max_output_bytes": 1 << 20, "max_diagnostics_per_scope": 1000,
                   "clang_tidy_checks": ["bugprone-*"], "clang_analyzer_checkers": ["core", "unix"]}


CPG_SETTINGS = {"workers": 1, "max_cpg_bytes": 1 << 20, "enabled": True}


class CpgExecutor:
    """Plays ``tool-joern`` back: writes a CPG and records the units and the argv c2cpg was given. Runs no Joern."""

    def __init__(self, run_root: Path, *, exit_code: int = 0, export_exit_code: int = 0) -> None:
        self.run_root, self.exit_code, self.export_exit_code = run_root, exit_code, export_exit_code
        self.calls: list[tuple[tuple[str, ...], tuple[str, ...]]] = []
        self.exports: list[tuple[str, ...]] = []

    def execute(self, request):
        root = request.scratch_root
        if request.argv[0].endswith("joern-export"):
            self.exports.append(tuple(request.argv))
            assert (root / "cpg.bin").is_file() and not (root / "export").exists()
            if self.export_exit_code == 0:
                shutil.copytree(RECORDED / "cpg" / "export", root / "export")
            return self._result(request, root, self.export_exit_code)
        rows = json.loads((root / "compile_commands.json").read_text())
        self.calls.append((tuple(sorted(Path(row["file"]).relative_to("/target/source").as_posix() for row in rows)),
                           tuple(request.argv)))
        if self.exit_code == 0:
            (root / "cpg.bin").write_bytes(b"cpg:" + b",".join(sorted(row["file"].encode() for row in rows)))
        return self._result(request, root, self.exit_code)

    def _result(self, request, root, exit_code):
        raw = root / "raw"
        raw.mkdir(exist_ok=True)
        (raw / "stdout.bin").write_bytes(b"")
        (raw / "stderr.bin").write_bytes(b"")
        (root / "execution.json").write_text("{}", encoding="utf-8")
        relative = lambda path: path.relative_to(self.run_root).as_posix()
        return ExecutionResult("appsec-review/container-execution/1", request.tool_id,
            "appsec-review/tool-joern:1.0.0", DIGEST, DIGEST, "argv", (), {}, "start", "end",
            exit_code, False, False, False, False,
            relative(raw / "stdout.bin"), relative(raw / "stderr.bin"), relative(root / "execution.json"),
            request.file_size_limit_bytes, False)
