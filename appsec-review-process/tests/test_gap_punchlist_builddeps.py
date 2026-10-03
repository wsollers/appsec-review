"""Acceptance tests for gap punch list P36 and P37 (hello-autotools, 2026-10-03; owner request: "the builds
should publish link and include and third party libs headers etc. so that sbom can use them for inference").

P36: 02-native-build records, per unit and inside the build image after a successful build, the headers each
translation unit includes, the include/library search dirs, the link commands with -l/-L/rpath, DT_NEEDED and
RUNPATH of each built binary resolved to real files, and the owning OS package of every out-of-checkout file;
bounded, hash-bound, classified, published as build-dependencies.json.
P37: 02-sbom-inventory consumes it over an optional edge from 02-native-build.

See docs/TODO/gap-punchlist-hello-autotools-2026-10-03.md.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import registry_paths  # noqa: E402

import build_replay  # noqa: E402
import sbom_family_contracts as contracts  # noqa: E402
from execution_state import Blocked, file_hash, read_json  # noqa: E402
from schema_validate import validate_document  # noqa: E402
from worker_result import artifact_records, terminal_envelope  # noqa: E402
import test_dependency_workers as tdw  # noqa: E402  (module, so its tests do not re-run here)

FIXTURE = ROOT / "tests/fixtures/build-deps-make"
RECORD_SCHEMA = "build-dependencies.schema.json"
TOOLS = all(shutil.which(name) for name in ("clang", "readelf", "dpkg-query", "make")) and Path("/usr/include/zlib.h").is_file()
LIMITS = {"files": 4096, "translation_units": 4096, "link_commands": 512, "edges": 262144,
          "hash_max_bytes": 64 << 20, "seconds": 300}


def _collector():
    source = getattr(build_replay, "DEPENDENCY_COLLECTOR", None)
    if source is None:
        return None
    namespace: dict = {}
    exec(build_replay.HEADER_COLLECTOR + source, namespace)  # the exact text the in-container runner executes
    return namespace


def _tree(root: Path) -> dict:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def _os_release() -> dict:
    values = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        key, _, value = line.partition("=")
        values[key] = value.strip().strip('"')
    return values


class _Build:
    """A real clang build of the make fixture outside Docker: what the runner sees after a successful build."""

    def __init__(self, folder: Path):
        self.pristine, self.scratch = folder / "workspace", folder / "scratch"
        self.src = self.scratch / "src"
        shutil.copytree(FIXTURE, self.pristine)
        shutil.copytree(self.pristine, self.src)
        (self.scratch / "build-deps").mkdir()
        self.log = self.scratch / "build-deps" / "clang-jobs.log"
        env = {**os.environ, "CC": "clang", "CC_PRINT_OPTIONS": "1", "CC_PRINT_OPTIONS_FILE": str(self.log)}
        subprocess.run(["make", "-s"], cwd=self.src, env=env, check=True, capture_output=True)
        self.entries = json.loads((self.src / "compile_commands.json").read_text())
        self.before = _tree(self.src)

    def cfg(self, **overrides):
        value = {"src": str(self.src), "pristine": str(self.pristine), "entries": self.entries,
                 "clang_log": str(self.log), "binaries": ["bin/hello"], "limits": dict(LIMITS),
                 "tools": {"readelf": "readelf", "dpkg_query": "dpkg-query", "ldconfig": "ldconfig"},
                 "os_release": "/etc/os-release"}
        value.update(overrides)
        return value


class BuildDependencyCaptureTests(unittest.TestCase):
    def collect(self, build: _Build, **overrides) -> dict:
        namespace = _collector()
        self.assertIsNotNone(namespace, "build_replay has no build-dependency collector")
        record = namespace["build_dependencies"](build.cfg(**overrides))
        self.assertEqual(_tree(build.src), build.before, "the capture wrote into the build tree")
        self.assertEqual(validate_document(record, RECORD_SCHEMA), [])
        return record

    @staticmethod
    def file(record: dict, path: str) -> dict:
        return next((item for item in record["files"] if item["path"] == path), {})

    @unittest.skipUnless(TOOLS, "needs clang, readelf, dpkg-query, make and zlib headers on the host")
    def test_p36_headers_per_translation_unit_are_classified_and_hash_bound(self):
        """P36: compiler -M over each compile-DB entry: checkout, generated, vendored and system headers per TU."""
        with tempfile.TemporaryDirectory() as folder:
            build = _Build(Path(folder))
            record = self.collect(build)
        files = record["files"]
        classes = {item["path"]: item["class"] for item in files}
        self.assertEqual(classes.get("config.h"), "generated")
        self.assertEqual(classes.get("include/app.h"), "checkout")
        self.assertEqual(classes.get("third_party/minijson/minijson.h"), "third-party-in-checkout")
        self.assertEqual(classes.get("/usr/include/zlib.h"), "system-package")
        vendored = self.file(record, "third_party/minijson/minijson.h")
        self.assertEqual(vendored["sha256"], "sha256:" + file_hash(FIXTURE / "third_party/minijson/minijson.h"))
        self.assertTrue(any(p.startswith("zlib1g-dev") for p in self.file(record, "/usr/include/zlib.h")["packages"]))
        units = {unit["file"]: {files[i]["path"] for i in unit["headers"]} for unit in record["translation_units"]}
        self.assertLessEqual({"config.h", "include/app.h", "third_party/minijson/minijson.h", "/usr/include/zlib.h"},
                             units.get("src/main.c", set()))
        self.assertNotIn("/usr/include/zlib.h", units.get("third_party/minijson/minijson.c", set()))
        self.assertIn("include", record["search_dirs"]["include"])
        self.assertTrue(any(d.startswith("/usr/include") for d in record["search_dirs"]["include"]))
        self.assertEqual(record["distro"]["id"], _os_release().get("ID"))
        self.assertEqual(record["package_manager"], "dpkg")

    @unittest.skipUnless(TOOLS, "needs clang, readelf, dpkg-query, make and zlib headers on the host")
    def test_p36_link_commands_and_dt_needed_resolve_to_owned_files(self):
        """P36: the traced link line gives -l/-L/rpath; DT_NEEDED and RUNPATH resolve to real, package-owned files."""
        with tempfile.TemporaryDirectory() as folder:
            record = self.collect(_Build(Path(folder)))
        files = record["files"]
        links = [item for item in record["link_commands"] if item["binary"] == "bin/hello"]
        self.assertEqual(len(links), 1, record["link_commands"])
        libraries = {item["spec"]: item for item in links[0]["libraries"]}
        self.assertIn("-lz", libraries)
        self.assertIsNotNone(libraries["-lz"]["file"])
        self.assertEqual(files[libraries["-lz"]["file"]]["class"], "system-package")
        self.assertIn("/opt/fixture/lib", links[0]["rpath"])
        self.assertTrue(any(d.startswith("/") for d in links[0]["library_dirs"]))
        binary = next(item for item in record["binaries"] if item["path"] == "bin/hello")
        self.assertEqual(binary["runpath"], ["/opt/fixture/lib"])
        needed = {item["soname"]: item for item in binary["needed"]}
        self.assertIn("libz.so.1", needed)
        libz = files[needed["libz.so.1"]["file"]]
        self.assertIn("needed", libz["kinds"])
        self.assertTrue(libz["sha256"].startswith("sha256:"))
        self.assertTrue(any(p.startswith("zlib1g:") or p == "zlib1g" for p in libz["packages"]), libz)
        packages = {item["name"]: item for item in record["packages"]}
        self.assertIn("zlib1g", packages)
        self.assertTrue(packages["zlib1g"]["version"])
        self.assertTrue(packages["zlib1g"]["arch"])

    @unittest.skipUnless(TOOLS, "needs clang, readelf, dpkg-query, make and zlib headers on the host")
    def test_p36_capture_is_bounded_and_omissions_are_gaps(self):
        """P36: files beyond the bound are counted and reported, never silently dropped."""
        with tempfile.TemporaryDirectory() as folder:
            record = self.collect(_Build(Path(folder)), limits={**LIMITS, "files": 3})
        self.assertLessEqual(len(record["files"]), 3)
        self.assertGreater(record["omitted"]["files"], 0)
        self.assertTrue(any("omitted" in gap for gap in record["coverage_gaps"]), record["coverage_gaps"])

    @unittest.skipUnless(TOOLS, "needs clang, readelf, dpkg-query, make and zlib headers on the host")
    def test_p36_non_dpkg_image_is_an_explicit_gap(self):
        """P36: without dpkg the out-of-checkout files are unattributed and the missing package manager is a gap."""
        with tempfile.TemporaryDirectory() as folder:
            build = _Build(Path(folder))
            record = self.collect(build, tools={"readelf": "readelf", "dpkg_query": str(Path(folder, "no-dpkg-query")),
                                                "ldconfig": "ldconfig"})
        self.assertIsNone(record["package_manager"])
        self.assertEqual(self.file(record, "/usr/include/zlib.h").get("class"), "unattributed")
        self.assertTrue(any(gap.startswith("package-manager-unavailable") for gap in record["coverage_gaps"]))
        self.assertTrue(any(gap.startswith("unattributed-files") for gap in record["coverage_gaps"]))

    def test_p36_link_log_parsing_reads_the_linker_job(self):
        """P36: the clang driver's job log (CC_PRINT_OPTIONS_FILE) yields the linker argv, not the -cc1 jobs."""
        namespace = _collector()
        self.assertIsNotNone(namespace, "build_replay has no build-dependency collector")
        log = ('[Logging clang options]\n "/opt/llvm/bin/clang-21" "-cc1" "-triple" "x86_64-pc-linux-gnu" "-o" "a.o" "a.c"\n'
               '[Logging clang options]\n "/usr/bin/ld" "-pie" "-o" "bin/hello" "/lib/x86_64-linux-gnu/Scrt1.o" '
               '"-L/usr/lib/x86_64-linux-gnu" "-Lrel/lib" "a.o" "-Bstatic" "-lfoo" "-Bdynamic" "-lz" "-l:libbar.so.2" '
               '"-rpath" "/opt/x" "--rpath=/opt/y" "-lc"\n')
        commands, unparsed = namespace["link_commands"](log)
        self.assertEqual(unparsed, 0)
        self.assertEqual(len(commands), 1)
        parsed = namespace["parse_link"](commands[0])
        self.assertEqual(parsed["output"], "bin/hello")
        self.assertEqual([(item["spec"], item["static"]) for item in parsed["libraries"]],
                         [("-lfoo", True), ("-lz", False), ("-l:libbar.so.2", False), ("-lc", False)])
        self.assertEqual(parsed["library_dirs"], ["/usr/lib/x86_64-linux-gnu", "rel/lib"])
        self.assertEqual(parsed["rpath"], ["/opt/x", "/opt/y"])

    def test_p36_runner_traces_build_phase_through_the_clang_job_log(self):
        """P36: the native replay asks the runner for the capture and sets the driver job log for build commands only."""
        self.assertIn("CC_PRINT_OPTIONS_FILE", build_replay.RUNNER)
        self.assertTrue(hasattr(build_replay, "DEPENDENCY_LIMITS"), "build_replay declares no capture bounds")
        from unittest import mock
        record = {"image_id": "image_build_123456789abc", "digest": "sha256:" + "b" * 64}
        lock = {"unit_id": "dir:.", "configure": [], "build": [{"phase": "build", "argv": ["make"], "cwd": "."}],
                "compile_database": {"method": "bear", "entries": 1, "compiler_allowlist": ["/opt/llvm/bin/clang"]}}
        inputs = {"target_path": "/target", "source_snapshot_sha256": "sha256:" + "a" * 64,
                  "control": {"value": {"timeout_seconds": 60}}}
        with mock.patch.object(build_replay, "_permission", return_value={"requirement": {}, "grants": [], "decision": {}}):
            native = json.loads(build_replay._request("run", "02-native-build", "a", record, lock, inputs)["argv"][3])
            configure = json.loads(build_replay._request("run", "02-build-configure", "a", record, lock, inputs)["argv"][3])
        self.assertEqual(native.get("dependencies", {}).get("limits"), build_replay.DEPENDENCY_LIMITS)
        self.assertNotIn("dependencies", configure)

    @unittest.skipUnless(TOOLS, "needs clang, readelf, dpkg-query, make and zlib headers on the host")
    def test_p36_runner_end_to_end_on_the_make_fixture(self):
        """P36: the exact runner text replays make on a scratch copy and leaves a schema-valid record beside the result."""
        with tempfile.TemporaryDirectory() as folder:
            workspace, scratch = Path(folder, "workspace"), Path(folder, "scratch")
            shutil.copytree(FIXTURE, workspace); scratch.mkdir()
            cfg = {"runner": build_replay.RUNNER_VERSION, "mode": "native", "compile_database": "fixture",
                   "commands": [{"phase": "build", "argv": ["make", "-s", "CC=clang"], "cwd": "."}],
                   "headers": {"limit": 8, "max_bytes": 1 << 20, "suffixes": [".h"]},
                   "dependencies": {"limits": LIMITS, "record": "build-dependencies.json"},
                   "roots": {"workspace": str(workspace), "scratch": str(scratch)}}
            done = subprocess.run([sys.executable, "-c", build_replay.RUNNER, json.dumps(cfg)], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr[-2000:])
            replay = json.loads((scratch / "replay-result.json").read_text())
            record = json.loads((scratch / "build-dependencies.json").read_text())
        self.assertEqual([item["path"] for item in replay["binaries"]], ["bin/hello"])
        self.assertEqual(validate_document(record, RECORD_SCHEMA), [])
        self.assertEqual([item["binary"] for item in record["link_commands"]], ["bin/hello"])
        self.assertIn("system-package", {item["class"] for item in record["files"]})

    def test_p36_native_build_publishes_and_revalidates_the_hash_bound_record(self):
        """P36: build-dependencies.json is copied out, bound by sha256 in native-build.json and re-verified."""
        publish = getattr(build_replay, "_publish_dependencies", None)
        verify = getattr(build_replay, "_verify_dependencies", None)
        self.assertIsNotNone(publish, "build_replay does not publish build-dependencies.json")
        self.assertIsNotNone(verify, "build_replay does not re-verify build-dependencies.json")
        with tempfile.TemporaryDirectory() as folder:
            attempt = Path(folder, "attempt"); scratch = Path(folder, "scratch"); (scratch / "src").mkdir(parents=True)
            (scratch / "src/a.h").write_bytes(b"#define A 1\n")
            record = _record({"path": "a.h", "class": "checkout", "kinds": ["header"],
                              "sha256": "sha256:" + hashlib.sha256(b"#define A 1\n").hexdigest(), "size_bytes": 12,
                              "packages": []})
            (scratch / "build-dependencies.json").write_text(json.dumps(record))
            unit = {"unit_id": "dir:.", "build_dependencies": publish(scratch, attempt / "outputs/u", attempt)}
            descriptor = unit["build_dependencies"]
            self.assertEqual(descriptor["path"], "outputs/u/build-dependencies.json")
            self.assertEqual(descriptor["sha256"], "sha256:" + file_hash(attempt / descriptor["path"]))
            verify(attempt, unit)
            unit_schema = read_json(ROOT.parent / "schemas/native-build.schema.json")["properties"]["units"]["items"]
            self.assertIn("build_dependencies", unit_schema["properties"])
            (attempt / descriptor["path"]).write_text(json.dumps({**record, "coverage_gaps": ["forged"]}))
            with self.assertRaises(Blocked):
                verify(attempt, unit)
            (scratch / "src/a.h").write_bytes(b"#define A 2\n")
            with self.assertRaises(RuntimeError):
                publish(scratch, Path(folder, "attempt2/outputs/u"), Path(folder, "attempt2"))


def _record(*files, packages=(), units=(), links=(), binaries=(), gaps=(), distro=None):
    return {"schema": "appsec-review/build-dependencies/1",
            "distro": distro if distro is not None else {"id": "ubuntu", "version_id": "24.04", "codename": "noble"},
            "package_manager": "dpkg", "limits": dict(LIMITS),
            "search_dirs": {"include": ["include", "/usr/include"], "library": ["/usr/lib/x86_64-linux-gnu"]},
            "files": list(files), "packages": list(packages), "translation_units": list(units),
            "link_commands": list(links), "binaries": list(binaries),
            "omitted": {"files": 0, "translation_units": 0, "link_commands": 0, "edges": 0, "hashes": 0},
            "coverage_gaps": list(gaps)}


MINIJSON = '#ifndef MINIJSON_H\n#define MINIJSON_VERSION_MAJOR 2\n#define MINIJSON_VERSION_MINOR 4\n#define MINIJSON_VERSION_PATCH 1\n#endif\n'
CJSON = ("#define CJSON_VERSION_MAJOR 1\n#define CJSON_VERSION_MINOR 7\n#define CJSON_VERSION_PATCH 18\n")
ZLIB_VERSION = "1:1.3.dfsg-3.1ubuntu2.1"


class SbomBuildDependencyTests(unittest.TestCase):
    """Drives build_sbom through test_dependency_workers.DependencyWorkersTest's fixture harness."""

    def setUp(self):
        self.h = tdw.DependencyWorkersTest()
        self.h.setUp()

    def tearDown(self):
        self.h.tearDown()

    def vendored(self, rel: str, text: str) -> dict:
        path = self.h.target / rel; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)
        return {"path": rel, "class": "third-party-in-checkout", "kinds": ["header"],
                "sha256": "sha256:" + file_hash(path), "size_bytes": path.stat().st_size, "packages": []}

    def native_build(self, records: list[dict | None], status: str = "OK") -> dict:
        """An accepted 02-native-build attempt in the harness run whose units publish ``records``."""
        h = self.h
        base = h.out / "02-native-build"; attempt = base / "attempts" / "nb-one"; attempt.mkdir(parents=True)
        units, paths = [], ["native-build.json"]
        for index, record in enumerate(records):
            unit = {"unit_id": f"dir:u{index}", "status": "OK", "image_id": "image_build_123456789abc",
                    "image_digest": "sha256:" + "5" * 64, "commands": [{}],
                    "compile_database": {"path": f"outputs/u{index}/compile_commands.json", "sha256": "sha256:" + "1" * 64,
                                         "entries": 1},
                    "binaries": [{"source_path": "bin/hello", "artifact_path": f"outputs/u{index}/binaries/bin/hello",
                                  "sha256": "sha256:" + "2" * 64, "size_bytes": 1}]}
            if record is not None:
                rel = f"outputs/u{index}/build-dependencies.json"
                (attempt / rel).parent.mkdir(parents=True, exist_ok=True)
                (attempt / rel).write_bytes(tdw.payload(record))
                unit["build_dependencies"] = {"path": rel, "sha256": "sha256:" + file_hash(attempt / rel)}
                paths.append(rel)
            units.append(unit)
        result = {"schema": "appsec-review/native-build/1", "run_id": h.run_id, "source_revision": "x",
                  "upstream": {"resolution": {"job": "02-build-resolution", "attempt_id": "a", "lock_sha256": "sha256:" + "4" * 64},
                               "configured": {"job": "02-build-configure", "attempt_id": "c", "result_sha256": "sha256:" + "4" * 64,
                                              "envelope_sha256": "sha256:" + "4" * 64}},
                  "status": "OK", "units": units, "coverage_gaps": []}
        self.assertEqual(validate_document(result, "native-build.schema.json"), [])
        (attempt / "native-build.json").write_bytes(tdw.payload(result))
        envelope = terminal_envelope(run_id=h.run_id, job_id="02-native-build", attempt_id="nb-one",
            worker_kind="pinned_container", execution_status=status, acceptance_status="CURRENT",
            input_fingerprint="sha256:" + "7" * 64, output_contract="native-build", started_at=h.when,
            finished_at=h.when, summary="native build", artifacts=artifact_records(attempt, paths))
        (attempt / "result.json").write_bytes(tdw.payload(envelope))
        pointer = base / "accepted.json"
        pointer.write_bytes(tdw.payload({"schema": "appsec-review/accepted-worker-result/1.0", "run_id": h.run_id,
            "job": "02-native-build", "attempt_id": "nb-one", "status": status, "fingerprint": envelope["input_fingerprint"],
            "envelope_path": "result.json", "envelope_sha256": file_hash(attempt / "result.json")}))
        return {"attempt_id": "nb-one", "path": str(attempt / "native-build.json"),
                "sha256": "sha256:" + file_hash(attempt / "native-build.json"), "accepted_path": str(pointer)}

    def sbom(self, native_build, syft_components=(), extra_files=None):
        h = self.h
        files = {"package-lock.json": "sha256:" + "2" * 64, **(extra_files or {})}
        output, receipt, expected = h.tool("02-sbom-inventory", "syft", {
            "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": list(syft_components)})
        envelope = h.run_request("sbom", "builddeps-" + str(h.tool_counter), h.request(
            tool_output=str(output), tool_receipt=str(receipt), expected_tool=expected, source_files=files,
            native_build=native_build))
        result = json.loads(h.result_path(envelope, "outputs/sbom-manifest.json").read_text())
        cdx = json.loads(h.result_path(envelope, "outputs/sbom.cdx.json").read_text())
        return envelope, result, cdx

    def zlib_record(self) -> tuple[dict, dict]:
        minijson = self.vendored("third_party/minijson/minijson.h", MINIJSON)
        record = _record(
            {"path": "/usr/include/zlib.h", "class": "system-package", "kinds": ["header"], "sha256": "sha256:" + "a" * 64,
             "size_bytes": 10, "packages": ["zlib1g-dev:amd64"]},
            {"path": "/usr/lib/x86_64-linux-gnu/libz.so.1.3", "class": "system-package", "kinds": ["shared-library", "needed"],
             "sha256": "sha256:" + "b" * 64, "size_bytes": 10, "packages": ["zlib1g:amd64"]},
            {"path": "/usr/lib/x86_64-linux-gnu/libz.so", "class": "system-package", "kinds": ["shared-library"],
             "sha256": None, "size_bytes": None, "packages": ["zlib1g-dev:amd64"]},
            minijson,
            {"path": "/opt/sdk/include/sdk.h", "class": "unattributed", "kinds": ["header"], "sha256": "sha256:" + "c" * 64,
             "size_bytes": 3, "packages": []},
            packages=[{"package": "zlib1g:amd64", "name": "zlib1g", "arch": "amd64", "version": ZLIB_VERSION,
                       "source": "zlib", "source_version": ZLIB_VERSION},
                      {"package": "zlib1g-dev:amd64", "name": "zlib1g-dev", "arch": "amd64", "version": ZLIB_VERSION,
                       "source": "zlib", "source_version": ZLIB_VERSION}],
            units=[{"file": "src/main.c", "exit_code": 0, "headers": [0, 3, 4]},
                   {"file": "third_party/minijson/minijson.c", "exit_code": 0, "headers": [3]}],
            binaries=[{"path": "bin/hello", "needed": [{"soname": "libz.so.1", "file": 1, "via": "cache"}],
                       "runpath": [], "rpath": []}])
        return record, {minijson["path"]: minijson["sha256"]}

    def test_p37_os_packages_become_deb_components_with_scope_and_evidence(self):
        """P37: pkg:deb/<distro>/<name>@<version>?arch=<arch>, runtime for DT_NEEDED, build for headers/dev links."""
        record, files = self.zlib_record()
        envelope, result, cdx = self.sbom(self.native_build([record]), extra_files=files)
        rows = {row["name"]: row for row in result["components"]}
        self.assertIn("zlib1g", rows, envelope["gaps"])
        runtime, build = rows["zlib1g"], rows.get("zlib1g-dev", {})
        self.assertTrue(runtime["purl"].startswith(f"pkg:deb/ubuntu/zlib1g@{ZLIB_VERSION}?arch=amd64"), runtime["purl"])
        self.assertIn("distro=ubuntu-24.04", runtime["purl"])
        self.assertEqual((runtime["ecosystem"], runtime["version"], runtime.get("scope")), ("deb", ZLIB_VERSION, "load-time"))
        self.assertEqual(build.get("scope"), "build-time")
        self.assertIn("/usr/lib/x86_64-linux-gnu/libz.so.1.3", runtime["build_evidence"]["paths"])
        self.assertIn("/usr/include/zlib.h", build["build_evidence"]["paths"])
        listed = {item["name"]: item for item in cdx["components"]}
        self.assertEqual(listed["zlib1g"].get("scope"), "required")
        self.assertEqual(listed["zlib1g-dev"].get("scope"), "excluded")
        self.assertIn({"location": "/usr/include/zlib.h"}, listed["zlib1g-dev"]["evidence"]["occurrences"])
        self.assertEqual(validate_document(result, "sbom-inventory.schema.json"), [])
        attempt = self.h.result_path(envelope, "")
        raw = (attempt / result["build_dependency_document"]["path"]).read_bytes()
        self.assertEqual(contracts.build_dependency_enrichment_errors(result, raw), [])
        # The worker's ids are content hashes, not the contract's ordinals (test_dependency_workers filters alike).
        self.assertEqual([e for e in contracts._component_errors(result["components"])
                          if not e.startswith("record-id-order")], [])
        self.assertEqual(contracts._cdx_errors((attempt / "outputs/sbom.cdx.json").read_bytes(), result), [])

    def test_p37_vendored_header_trees_are_versioned_from_macros(self):
        """P37: third-party-in-checkout headers become a vendored candidate versioned from *_VERSION_* macros."""
        record, files = self.zlib_record()
        _envelope, result, _cdx = self.sbom(self.native_build([record]), extra_files=files)
        rows = {row["name"]: row for row in result["components"]}
        self.assertIn("minijson", rows)
        row = rows["minijson"]
        self.assertEqual((row["version"], row["purl"], row["cpe"], row["declaration"]),
                         ("2.4.1", "pkg:generic/minijson@2.4.1", None, "inferred-vendored"))
        self.assertEqual(row["source"]["path"], "third_party/minijson/minijson.h")
        self.assertEqual(row.get("scope"), "load-time", "a vendored tree compiled into the unit ships with it")

    def test_p37_cjson_keeps_its_exact_identifiers_and_is_not_duplicated(self):
        """P37: cJSON is one case of the generic rule with P19's purl/CPE; a build-index row is not repeated."""
        cjson = self.vendored("vendor/cJSON/cJSON.h", CJSON)
        record = _record(cjson, units=[{"file": "src/main.c", "exit_code": 0, "headers": [0]}])
        _envelope, result, _cdx = self.sbom(self.native_build([record]), extra_files={cjson["path"]: cjson["sha256"]})
        rows = [(row["name"], row["version"], row["purl"], row["cpe"]) for row in result["components"]]
        self.assertEqual(rows, [("cJSON", "1.7.18", "pkg:github/davegamble/cjson@v1.7.18",
                                 "cpe:2.3:a:cjson_project:cjson:1.7.18:*:*:*:*:*:*:*")])

    def test_p37_unattributed_and_record_gaps_surface_as_sbom_gaps(self):
        """P37: an out-of-checkout file no package owns is a gap, as are the record's own capture gaps."""
        record, files = self.zlib_record()
        record["coverage_gaps"] = ["link-command-not-captured:bin/other"]
        envelope, _result, _cdx = self.sbom(self.native_build([record]), extra_files=files)
        gaps = " ".join(envelope["gaps"])
        self.assertIn("/opt/sdk/include/sdk.h", gaps)
        self.assertIn("link-command-not-captured:bin/other", gaps)

    def test_p37_unit_without_a_record_is_a_gap_and_a_skipped_build_is_not(self):
        """P37: a native unit that published no record is a gap; a skipped native build binds nothing, no gap."""
        envelope, _result, _cdx = self.sbom(self.native_build([None]))
        self.assertTrue(any("build-dependencies-not-published" in gap for gap in envelope["gaps"]), envelope["gaps"])
        skipped, _result, _cdx = self.sbom({"skipped": "not-applicable-non-native"})
        self.assertFalse(any("build-dependencies" in gap for gap in skipped["gaps"]), skipped["gaps"])
        absent, _result, _cdx = self.sbom(None)
        self.assertTrue(any("build-dependencies-unavailable" in gap for gap in absent["gaps"]), absent["gaps"])

    def test_p37_deb_rows_dedupe_with_syft(self):
        """P37: a deb package Syft already reported is not listed twice."""
        record, files = self.zlib_record()
        purl = f"pkg:deb/ubuntu/zlib1g@{ZLIB_VERSION}?arch=amd64&distro=ubuntu-24.04&upstream=zlib"
        self.h.target.joinpath("var/lib/dpkg").mkdir(parents=True)
        (self.h.target / "var/lib/dpkg/status").write_text("Package: zlib1g\n")
        status = {"var/lib/dpkg/status": "sha256:" + file_hash(self.h.target / "var/lib/dpkg/status")}
        syft = {"name": "zlib1g", "version": ZLIB_VERSION, "purl": purl, "type": "library",
                "properties": [{"name": "syft:location:0:path", "value": "/var/lib/dpkg/status"}]}
        _envelope, result, _cdx = self.sbom(self.native_build([record]), syft_components=[syft],
                                            extra_files={**files, **status})
        self.assertEqual([row["name"] for row in result["components"]].count("zlib1g"), 1)


class GraphTests(unittest.TestCase):
    def test_p37_sbom_takes_an_optional_skip_propagated_native_build_edge(self):
        """P37: 02-sbom-inventory depends optionally on 02-native-build with the native skip reasons."""
        graph = read_json(registry_paths.REGISTRY / "job-graph.json")
        edges = {dep["job"]: dep for dep in graph["jobs"]["02-sbom-inventory"]["dependencies"]}
        self.assertIn("02-native-build", edges)
        self.assertEqual(edges["02-native-build"]["kind"], "optional")
        self.assertEqual(edges["02-native-build"]["contract"], "native-build")
        self.assertLessEqual({"not-applicable-non-native", "not-applicable-no-native-binaries"},
                             set(edges["02-native-build"]["allowed_skip_reasons"]))
        template = read_json(registry_paths.JOB_TEMPLATES_DIR / "02-sbom-inventory.json")
        self.assertTrue(any("02-native-build" in item for item in template["inputs"]["optional"]))

    def test_p37_automatic_sbom_request_binds_the_native_build(self):
        """P37: the SBOM's automatic request carries the native-build binding (or its skip) in its closed payload."""
        import dependency_orchestration as orchestration
        self.assertIn("native_build", orchestration._OPTIONAL_PAYLOAD_KEYS["sbom"])
        import automatic_evidence_inputs
        self.assertEqual(automatic_evidence_inputs.RESULTS["02-native-build"], "native-build.json")


if __name__ == "__main__":
    unittest.main()
