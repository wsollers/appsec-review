"""Regression tests for tool-adapter defects seen on a live multi-language run.

Each test pins the real output shape or invocation contract of a pinned tool (observed against the
pinned versions) so an adapter that reads the wrong file, passes the wrong argument shape, or hides
an input cannot pass. Every runner and executor is injected; nothing here needs Docker or network.
"""

from __future__ import annotations

import json
from pathlib import Path
import zipfile

from appsec_review import blint_report
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_artifact_security_analysis import (
    build_job as build_artifact_security, load_accepted_artifact_security_analysis,
)
from appsec_review.jobs.job_artifact_security_analysis.formats import ArchiveLimits, classify, inspect_archive
from appsec_review.jobs.job_artifact_security_analysis.scanners import ContainerScannerRunner
from appsec_review.jobs.job_evidence_collection import build_job as build_evidence
from appsec_review.jobs.job_evidence_collection.adapters import (
    Applicability, adapter_registry, semgrep_rule_languages, semgrep_unscanned_inputs,
)
from appsec_review.jobs.job_evidence_collection.job import _container_relative, _osv_split_by_snapshot
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import build_job as build_analysis_plan
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_third_party_data_sync.publication import publish_snapshot
from appsec_review.osv_offline import offline_database_mounts, snapshot_ecosystems
from appsec_review.runtime import GraphRunner
from appsec_review.tool_inputs import (
    osv_ecosystem, osv_missing_ecosystems, partition_artifacts, partition_formats,
)

from tests import test_artifact_security_analysis as asa_tests
from tests import test_evidence_collection_job as evidence_tests


ROOT = Path(__file__).parents[1]
ELF = b"\x7fELF\x02\x01\x01" + b"\0" * 64

# blint 3.4.0 findings.json, as written for an executable built with -z execstack -no-pie
# (description text shortened; keys and nesting are exactly as emitted).
BLINT_FINDINGS = {
    "scan_id": "82f9131b-7ad1-4c18-8a0a-372b15d46e7f", "created": "2026-10-15 03:58:34",
    "findings": [
        {"id": "CHECK_NX", "title": "Missing Non-Executable Memory Protection", "description": "...",
         "severity": "critical", "exe_types": ["genericbinary", "x86_64-executable", "PE32", "MachO"],
         "filename": "/target/case083", "exe_name": "/target/case083", "exe_type": "genericbinary"},
        {"id": "CHECK_PIE", "title": "Missing Position-Independent Executable (PIE) Protection",
         "description": "...", "severity": "high", "exe_types": ["genericbinary"],
         "filename": "/target/case083", "exe_name": "/target/case083", "exe_type": "genericbinary"},
        {"id": "CHECK_ABI_FLOOR", "title": "ABI floor", "description": "...", "severity": "medium",
         "baseline_version": "GLIBC_2.34", "exe_types": ["genericbinary"],
         "filename": "/target/case083", "exe_name": "/target/case083", "exe_type": "genericbinary"},
    ]}
BLINT_METADATA = {"file_path": "/target/case083", "binary_type": "ELF", "exe_type": "genericbinary",
                  "is_pie": False, "has_nx": False, "relro": "partial", "static": False,
                  "strings": ["x" * 64] * 4, "symtab_symbols": [{"name": "main"}]}


def _blint_reports(directory: Path, *, findings: bool = True, metadata: bool = True) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "blint-output.html").write_text("<html>rich console</html>", encoding="utf-8")
    if findings:
        (directory / "findings.json").write_text(json.dumps(BLINT_FINDINGS), encoding="utf-8")
    if metadata:
        (directory / "case083-metadata.json").write_text(json.dumps(BLINT_METADATA), encoding="utf-8")
    return directory


# --- 1. blint ---------------------------------------------------------------------------------

def test_blint_report_reads_findings_json_and_per_binary_metadata(tmp_path: Path) -> None:
    report = blint_report.assemble(_blint_reports(tmp_path / "reports"))
    assert [item["id"] for item in report["findings"]] == ["CHECK_NX", "CHECK_PIE", "CHECK_ABI_FLOOR"]
    assert report["finding_count"] == 3 and report["analyzed_count"] == 1
    assert report["analyzed"][0]["has_nx"] is False and "strings" not in report["analyzed"][0]
    # A clean binary has metadata but no findings.json: analyzed, zero findings.
    clean = blint_report.assemble(_blint_reports(tmp_path / "clean", findings=False))
    assert clean["finding_count"] == 0 and clean["analyzed_count"] == 1
    # Nothing analyzed: no metadata at all.
    assert blint_report.assemble(_blint_reports(tmp_path / "none", findings=False, metadata=False))[
        "analyzed"] == []


def test_artifact_blint_findings_parse_and_unanalyzed_binary_is_a_gap(tmp_path: Path) -> None:
    for name, analyzed in (("found", True), ("missing", False)):
        case = tmp_path / name
        case.mkdir()
        config, run_id, run_root, target, fingerprint, _ = asa_tests._fixture(case, payload=ELF)
        payload = json.dumps(blint_report.assemble(_blint_reports(
            case / "reports", findings=analyzed, metadata=analyzed))).encode()

        def scanner(capability, path, artifact, timeout, limit, payload=payload):
            return {"stdout": "╔══ BLint Findings ══╗".encode(), "stderr": b"", "exit_code": 0,
                    "payload": payload if capability == "blint" else b"{}",
                    "tool_identity": {"scanner": capability, "image": "fixture", "rules": "fixture"}}

        GraphRunner(config, [build_artifact_security(scanner_runner=scanner)]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
        blint = load_accepted_artifact_security_analysis(run_root)["capabilities"]["blint"]
        assert not any("could not be parsed" in gap for gap in blint["gaps"]), blint["gaps"]
        assert (blint["gaps"] == []) is analyzed, blint["gaps"]


def test_evidence_blint_invocation_and_parser_match_blint_340(tmp_path: Path) -> None:
    adapter = adapter_registry()["tool-blint"]
    argv = adapter.argv("/opt/tool/bin/blint", Applicability(True, "x", ("out/a.so", "out/b.exe"), "built_binary"))
    assert "--format" not in argv and "--output" not in argv  # not blint 3.4.0 options
    assert argv[argv.index("--reports") + 1] == "/scratch"
    assert argv[argv.index("--src") + 1:] == ("/target/out/a.so", "/target/out/b.exe")
    _blint_reports(tmp_path)
    adapter.collector(tmp_path)
    records = adapter.parse((tmp_path / "blint-report.json").read_bytes())
    assert {item["rule_id"] for item in records} == {"CHECK_NX", "CHECK_PIE", "CHECK_ABI_FLOOR"}
    (tmp_path / "absent").mkdir()
    empty = adapter.parse(json.dumps(blint_report.assemble(tmp_path / "absent")).encode())
    assert empty == [{"gap_only": True,
                      "coverage_gap": "blint produced no per-binary analysis report for the selected binaries"}]


def test_blint_artifact_support_is_native_binaries_only() -> None:
    items = [("elf", "a", "elf"), ("jar", "b.jar", "jvm-archive"), ("class", "C.class", "jvm-class"),
             ("wheel", "c.whl", "python-wheel"), ("ar", "libx.a", "ar-archive")]
    partition = partition_artifacts("artifact:tool-blint", items)
    assert partition.supported == ("elf",)


# --- 2. osv-scanner ---------------------------------------------------------------------------

def test_osv_inputs_are_lockfiles_mapped_to_their_ecosystems() -> None:
    expected = {"svc/Cargo.lock": "crates.io", "web/package-lock.json": "npm", "ui/yarn.lock": "npm",
                "ui/pnpm-lock.yaml": "npm", "cmd/go.mod": "Go", "java/pom.xml": "Maven",
                "kt/gradle.lockfile": "Maven", "php/composer.lock": "Packagist",
                "net/packages.lock.json": "NuGet", "rb/Gemfile.lock": "RubyGems",
                "py/requirements.txt": "PyPI", "py/dev-requirements.txt": "PyPI", "py/poetry.lock": "PyPI",
                "py/Pipfile.lock": "PyPI"}
    assert {path: osv_ecosystem(path) for path in expected} == expected
    # osv-scanner 1.9.2 has no extractor for these when handed the file (verified: exit 127/128).
    for path in ("app.jar", "demo-1.0-py3-none-any.whl", "case083", "lib.rlib", "libx.a", "PKG-INFO",
                 "composer.json", "package.json", "Cargo.toml", "go.sum", "x.o", "build.d", "Main.class"):
        assert osv_ecosystem(path) is None, path
    partition = partition_artifacts("artifact:tool-osv-scanner",
                                    [("lock", "Cargo.lock", "unknown"), ("jar", "app.jar", "jvm-archive"),
                                     ("bin", "server", "elf")])
    assert partition.supported == ("lock",)
    assert {item.reason_code.value for item in partition.not_applicable} == {"INPUT_FORMAT_UNSUPPORTED"}


def test_osv_missing_offline_database_is_parsed_from_stderr() -> None:
    stderr = (b"Scanned /target/Cargo.lock file and found 1 package\n"
              b"could not find local databases for ecosystems: crates.io, Go\n")
    assert osv_missing_ecosystems(stderr) == ("crates.io", "Go")
    assert osv_missing_ecosystems(b"No package sources found") == ()


def test_artifact_osv_missing_ecosystem_gap_names_the_data_coverage(tmp_path: Path) -> None:
    config, run_id, run_root, target, fingerprint, _ = asa_tests._fixture(
        tmp_path, payload=b'version = 3\n', name="Cargo.lock", kind="generated-output")

    def scanner(capability, path, artifact, timeout, limit):
        stderr = (b"Scanned /target/Cargo.lock file and found 1 package\n"
                  b"could not find local databases for ecosystems: crates.io\n") if capability == "osv" else b""
        return {"stdout": b"", "stderr": stderr, "exit_code": 127 if capability == "osv" else 0,
                "payload": b"{}", "tool_identity": {"scanner": capability, "image": "f", "rules": "f"}}

    GraphRunner(config, [build_artifact_security(scanner_runner=scanner)]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    gaps = load_accepted_artifact_security_analysis(run_root)["capabilities"]["osv"]["gaps"]
    assert len(gaps) == 1 and "offline OSV snapshot lacks ecosystem crates.io" in gaps[0], gaps
    assert "exited 127" not in gaps[0]


def _osv_snapshot(root: Path, ecosystems: tuple[str, ...]) -> Path:
    work = root / "work"
    work.mkdir(parents=True, exist_ok=True)
    files = {}
    for name in ecosystems:
        archive = work / f"{name}.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr(f"OSV-{name}.json", json.dumps({"id": f"OSV-{name}"}))
        files[f"sources/{name}.zip"] = archive
    publish_snapshot(root / "data" / "feeds" / "osv", feed_id="osv", schema="appsec-review/osv-snapshot/1",
                     files=files, manifest_fields={"ecosystems": list(ecosystems)})
    return root / "data" / "feeds" / "osv"


def test_offline_database_mounts_expose_every_synchronized_ecosystem(tmp_path: Path) -> None:
    feed = _osv_snapshot(tmp_path, ("PyPI", "crates.io", "npm"))
    snapshot = next((feed / "snapshots").iterdir())
    ecosystems = snapshot_ecosystems(snapshot)
    assert set(ecosystems) == {"PyPI", "crates.io", "npm"}
    assert {mount.target for mount in offline_database_mounts(ecosystems)} == {
        "/database/osv-scanner/PyPI/all.zip", "/database/osv-scanner/crates.io/all.zip",
        "/database/osv-scanner/npm/all.zip"}
    assert all(mount.read_only for mount in offline_database_mounts(ecosystems))


def test_artifact_runner_withholds_lockfile_whose_ecosystem_is_not_synchronized(tmp_path: Path) -> None:
    runner = object.__new__(ContainerScannerRunner)
    runner.scratch_root = tmp_path / "scratch"
    runner._identities = {"osv": {"scanner": "tool-osv-scanner", "adapter": "fixture"}}
    runner._osv_ecosystems = {"PyPI": tmp_path / "PyPI.zip"}

    class Unlaunchable:
        def execute(self, request):  # pragma: no cover - reaching this is the failure
            raise AssertionError("osv-scanner must not be launched without the ecosystem database")

    runner.executor = Unlaunchable()
    lockfile = tmp_path / "Cargo.lock"
    lockfile.write_text("version = 3\n", encoding="utf-8")
    raw = runner("osv", lockfile, {"canonical_identity": "asr:x:1", "sha256": "a" * 64}, 60, 1024)
    assert "offline OSV snapshot lacks ecosystem crates.io" in raw["precondition_gap"]


class RecordingExecutor(evidence_tests.FakeExecutor):
    def __init__(self, repository: Path, run_root: Path, calls: list[str], requests: dict):
        super().__init__(repository, run_root, calls)
        self.requests = requests

    def execute(self, request):
        self.requests[request.tool_id] = request
        result = super().execute(request)
        if request.tool_id == "tool-osv-scanner":
            (request.scratch_root / "output.json").write_text('{"results": []}', encoding="utf-8")
        return result


def test_evidence_osv_selects_every_lockfile_in_any_root_and_names_unsynchronized_ecosystems(
        tmp_path: Path) -> None:
    config, target = evidence_tests.fixture(tmp_path)
    lockfiles = {"services/billing/Cargo.lock": 'version = 3\n', "web/package-lock.json": "{}",
                 "web/admin/yarn.lock": "# yarn\n", "tools/requirements.txt": "requests==2.19.0\n",
                 "cmd/agent/go.mod": "module x\n", "java/api/pom.xml": "<project/>",
                 "php/site/composer.lock": "{}", "ruby/app/Gemfile.lock": "GEM\n",
                 "dotnet/svc/packages.lock.json": "{}"}
    for relative, text in lockfiles.items():
        (target / relative).parent.mkdir(parents=True, exist_ok=True)
        (target / relative).write_text(text, encoding="utf-8")
    for relative in ("services/billing/Cargo.toml", "web/package.json", "java/api/app.jar"):
        (target / relative).write_text("not a lockfile", encoding="utf-8")
    _osv_snapshot(tmp_path, ("PyPI", "crates.io", "npm"))
    fingerprint = source_fingerprint(target)
    calls: list[str] = []
    requests: dict = {}
    factory = lambda unit: RecordingExecutor(unit.job.repository_root, unit.job.run_root, calls, requests)
    outcome = GraphRunner(config, [build_intake(), build_catalog(), build_analysis_plan(),
                                   build_evidence(executor_factory=factory)]).run(
        target_root=target, source_fingerprint=fingerprint)
    request = requests["tool-osv-scanner"]
    argv = request.argv
    launched = {argv[index + 1] for index, value in enumerate(argv) if value == "--lockfile"}
    assert launched == {"/target/services/billing/Cargo.lock", "/target/web/package-lock.json",
                        "/target/web/admin/yarn.lock", "/target/tools/requirements.txt",
                        "/target/package-lock.json"}  # the shared fixture's root lockfile
    assert "--recursive" not in argv
    assert {mount.target for mount in request.extra_mounts} >= {
        "/database/osv-scanner/PyPI/all.zip", "/database/osv-scanner/crates.io/all.zip",
        "/database/osv-scanner/npm/all.zip"}
    dispositions = outcome["jobs"]["job_evidence_collection"]["result"]["outputs"][
        "evidence_publication.publish_handoff"]["dispositions"]
    osv = next(item for item in dispositions if item["tool_id"] == "tool-osv-scanner")
    missing = [gap for gap in osv["gaps"] if "offline OSV snapshot lacks ecosystem" in gap]
    assert len(missing) == 1, osv["gaps"]
    for name in ("Go", "Maven", "NuGet", "Packagist", "RubyGems"):
        assert name in missing[0]
    for path in ("cmd/agent/go.mod", "java/api/pom.xml", "dotnet/svc/packages.lock.json"):
        assert path in missing[0]


def test_osv_split_blocks_when_no_selected_lockfile_has_a_synchronized_ecosystem() -> None:
    selection = Applicability(True, "x", ("a/Cargo.lock", "b/go.mod"), "dependency_lockfiles")
    split, gap = _osv_split_by_snapshot(selection, {"PyPI": Path("PyPI.zip")})
    assert split.files == () and "crates.io, Go" in gap
    kept, gap = _osv_split_by_snapshot(selection, {"crates.io": Path("c.zip")})
    assert kept.files == ("a/Cargo.lock",) and "lacks ecosystem Go" in gap and gap in kept.gaps
    unchanged, none = _osv_split_by_snapshot(selection, {"crates.io": Path("c"), "Go": Path("g")})
    assert unchanged is selection and none is None


# --- 3. gosec ---------------------------------------------------------------------------------

def test_gosec_receives_package_directories_never_files() -> None:
    adapter = adapter_registry()["tool-gosec"]
    files = ("svc/a/main.go", "svc/a/util.go", "svc/b/cmd/run.go", "main.go")
    argv = adapter.argv("/opt/tool/bin/gosec", Applicability(True, "x", files, "source_files"))
    targets = [item for item in argv if item.startswith("/target")]
    assert targets == ["/target", "/target/svc/a", "/target/svc/b/cmd"]
    assert not any(item.endswith(".go") for item in argv)


# --- 4. SpotBugs input classification ---------------------------------------------------------

def _zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path


def test_dex_and_classless_jars_are_not_spotbugs_inputs(tmp_path: Path) -> None:
    dex = classify(_zip(tmp_path / "dexBuilder_0.jar", {"classes.dex": b"dex\n035\0"}), {"kind": "jar"})
    resources = classify(_zip(tmp_path / "case-0.1.0.jar", {
        "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n", "META-INF/maven/g/a/pom.xml": b"<project/>"}),
        {"kind": "jar"})
    bytecode = classify(_zip(tmp_path / "app.jar", {
        "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n", "Main.class": b"\xca\xfe\xba\xbe"}), {"kind": "jar"})
    assert (dex["format"], resources["format"], bytecode["format"]) == (
        "dex-archive", "jvm-resource-archive", "jvm-archive")
    partition = partition_formats("artifact:tool-spotbugs", [
        ("dex", dex["format"]), ("resources", resources["format"]), ("bytecode", bytecode["format"])])
    assert partition.supported == ("bytecode",)
    assert all("artifact format is" in item.reason for item in partition.not_applicable)


# --- 5. Semgrep dropped inputs ----------------------------------------------------------------

def test_semgrep_inputs_given_but_not_scanned_are_recorded() -> None:
    rule_files = [ROOT / "rules" / "semgrep" / "security.yml", ROOT / "rules" / "semgrep" / "review-signals.yml"]
    languages = semgrep_rule_languages(rule_files)
    assert languages is not None and "python" in languages and "rust" not in languages
    payload = json.dumps({"results": [], "paths": {"scanned": ["/target/app.py", "/target/run.sh"]}}).encode()
    given = ("app.py", "run.sh", "crates/a/src/lib.rs", "android/Main.kt", "svc/handler.py")
    gaps, skipped = semgrep_unscanned_inputs(payload, given, languages, _container_relative)
    assert {path for path, _ in skipped} == {"crates/a/src/lib.rs", "android/Main.kt"}
    assert any("no rules for language rust" in reason for _, reason in skipped)
    assert len(gaps) == 1 and "svc/handler.py" in gaps[0]  # Python has rules: a dropped file is a gap
    # No language attribution possible: every dropped file stays a gap.
    gaps, skipped = semgrep_unscanned_inputs(payload, given, None, _container_relative)
    assert skipped == [] and "3 given input(s)" in gaps[0]
    assert semgrep_unscanned_inputs(b'{"results": []}', given, languages, _container_relative)[0] == [
        "engine did not report scanned paths; per-file Semgrep coverage is unverified"]


# --- 6. ShellCheck ----------------------------------------------------------------------------

def test_shellcheck_json1_sc2086_is_an_observation() -> None:
    # ShellCheck 0.11.0 `--format json1` for: rm -rf $1 (exit 1, accepted).
    payload = json.dumps({"comments": [{
        "file": "/target/scripts/clean.sh", "line": 2, "endLine": 2, "column": 8, "endColumn": 10,
        "level": "info", "code": 2086, "message": "Double quote to prevent globbing and word splitting.",
        "fix": {"replacements": []}}]}).encode()
    adapter = adapter_registry()["tool-shellcheck"]
    assert 1 in adapter.accepted_exit_codes
    argv = adapter.argv("/opt/tool/bin/shellcheck", Applicability(True, "x", ("scripts/clean.sh",), "source_files"))
    assert argv == ("/opt/tool/bin/shellcheck", "--format", "json1", "/target/scripts/clean.sh")
    records = adapter.parse(payload)
    assert [(item["rule_id"], item["path"], item["start_line"]) for item in records] == [
        (2086, "/target/scripts/clean.sh", 2)]


# --- 7. Trivy ---------------------------------------------------------------------------------

def test_trivy_is_offline_deterministic_and_names_a_bundle_fallback() -> None:
    adapter = adapter_registry()["tool-trivy"]
    argv = adapter.argv("/opt/tool/bin/trivy", Applicability(True, "x", ("Dockerfile",), "configuration_files"))
    assert "--skip-check-update" in argv
    assert any("embedded in the pinned Trivy binary" in item for item in adapter.limitations)
    fallback = (b'ERROR [misconfig] Falling back to embedded checks err="failed to download checks bundle: '
                b'download error: OCI repository error"')
    assert adapter.stderr_gaps(fallback)
    assert adapter.stderr_gaps(b'ERROR [misconfig] Falling back to embedded checks err="failed to check cache: '
                               b'cache does not exist"') == []


# --- 8. ar archives ---------------------------------------------------------------------------

def _ar(members: list[tuple[str, bytes]], *, gnu_long: bool = True) -> bytes:
    def header(name: str, size: int) -> bytes:
        return (name.ljust(16) + "0".ljust(12) + "0".ljust(6) + "0".ljust(6) + "644".ljust(8) +
                str(size).ljust(10)).encode() + b"`\n"
    body = b"!<arch>\n"
    table = b""
    names = []
    for name, _ in members:
        if gnu_long and len(name) > 15:
            names.append(f"/{len(table)}")
            table += name.encode() + b"/\n"
        else:
            names.append(name + "/")
    if table:
        body += header("//", len(table)) + table + (b"\n" if len(table) % 2 else b"")
    body += header("/", 4) + b"\0\0\0\0"
    for (_, data), name in zip(members, names):
        body += header(name, len(data)) + data + (b"\n" if len(data) % 2 else b"")
    return body


def test_rlib_and_static_library_ar_archives_list_members(tmp_path: Path) -> None:
    rlib = tmp_path / "libfoundation-0123456789abcdef.rlib"
    rlib.write_bytes(_ar([("lib.rmeta", b"rust-meta"), ("foundation-0123456789abcdef.foundation.o", b"\x7fELF")]))
    classification = classify(rlib, {"kind": "static-library"})
    assert classification["format"] == "ar-archive" and classification["container"]
    listing = inspect_archive(rlib, ArchiveLimits())
    assert listing["gaps"] == [] and listing["safe"]
    assert [item["path"] for item in listing["members"]] == [
        "lib.rmeta", "foundation-0123456789abcdef.foundation.o"]
    truncated = tmp_path / "libbroken.a"
    truncated.write_bytes(rlib.read_bytes()[:-3])
    assert "ar archive member data is truncated" in inspect_archive(truncated, ArchiveLimits())["gaps"]


# --- 9. Infer ---------------------------------------------------------------------------------

def test_infer_image_carries_system_headers_for_its_clang() -> None:
    dockerfile = (ROOT / "containers" / "tools" / "infer" / "Dockerfile").read_text(encoding="utf-8")
    final_from = [line for line in dockerfile.splitlines() if line.startswith("FROM ")][-1]
    assert final_from == "FROM appsec-review/tool-native-cpp:1.0.0"
    assert "test -f /usr/include/stdio.h" in dockerfile
    catalog = (ROOT / "containers" / "catalog.toml").read_text(encoding="utf-8")
    block = catalog.split('id = "tool-infer"', 1)[1].split("[[images]]", 1)[0]
    assert 'dependencies = ["tool-native-cpp"]' in block
