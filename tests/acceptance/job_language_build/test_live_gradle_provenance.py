"""The live Gradle check from the pre-walk suite, moved to the acceptance tier by T-113.

It runs a real Gradle distribution offline and needs a Gradle home (APPSEC_GRADLE_HOME) and a JDK.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from appsec_review.jobs.job_language_build import gradle_provenance
from appsec_review.jobs.job_language_build.jvm import _instrumentation, _mapped, _remove_jdk_mirrors, _trace_rows
from tests.unit.job_language_build.test_gradle_provenance import PARENT, _settings, _synthetic_project


def _java_feature_version() -> str:
    output = subprocess.run(["java", "-XshowSettings:properties", "-version"], capture_output=True,
                            text=True, check=True).stderr
    return re.search(r"java\.specification\.version = (\d+)", output).group(1)


@pytest.mark.skipif(not os.environ.get("APPSEC_GRADLE_HOME") or shutil.which("java") is None,
                    reason="set APPSEC_GRADLE_HOME to a Gradle distribution (offline; JDK required)")
@pytest.mark.parametrize("parallel", [False, True])
def test_live_gradle_forks_every_java_compilation_through_the_instrumented_mirror(
        tmp_path: Path, parallel: bool) -> None:
    """A real Gradle build of the synthetic java-library + application project, offline. The lib
    module also pins an explicit toolchain, so the mirror must satisfy toolchain validation. Two
    more modules configure their JavaCompile late, the Android Gradle Plugin way (see
    _LATE_CONFIGURED_MODULE): `droid` must still fork through the mirror despite its finalizing
    read and its fork resets; `pinned` cannot, and stays a declared record with a named gap."""
    gradle = Path(os.environ["APPSEC_GRADLE_HOME"]) / "bin" / "gradle"
    workspace = tmp_path / "workspace"
    project = workspace / "multi"
    _synthetic_project(project, kotlin=False, toolchain=_java_feature_version(), late=True)
    supplied = tmp_path / "supplied"
    trace, _logical = _instrumentation(supplied, tmp_path / "evidence", _settings())
    root = trace.parent
    argv, _facts = gradle_provenance.instrument_argv(
        ["gradle", "--offline", *(["--parallel"] if parallel else []), "assemble"], str(supplied))
    environment = {**os.environ, "APPSEC_JVM_INSTRUMENTATION": str(supplied), "APPSEC_JVM_EVIDENCE": str(root),
                   "APPSEC_JVM_TRACE_DIR": str(root / "invocations.d"),
                   "APPSEC_JVM_PARENT_COMMAND": PARENT, "GRADLE_USER_HOME": str(tmp_path / "gradle-home")}
    completed = subprocess.run([str(gradle), *argv[1:]], cwd=project, env=environment,
                               capture_output=True, text=True, timeout=600)
    assert completed.returncode == 0, completed.stdout[-4000:] + completed.stderr[-4000:]
    assert (project / "lib" / "build" / "classes" / "java" / "main" / "lib" / "Greeter.class").is_file()
    assert (project / "app" / "build" / "classes" / "java" / "main" / "app" / "Main.class").is_file()
    late_classes = "build/intermediates/javac/debug/classes"
    assert (project / "droid" / late_classes / "droid" / "Activity.class").is_file()

    # The build container sees the run-owned workspace at /workspace; this host run sees it at
    # tmp_path. Translate the recorded paths to the container view the parser resolves.
    for record in [*(root / "invocations.d").iterdir(), root / "gradle-tasks.jsonl"]:
        record.write_bytes(record.read_bytes().replace(str(workspace).encode(), b"/workspace"))
    rows, trace_gaps = _trace_rows(trace, workspace, 1000, 1 << 24, "multi")
    assert trace_gaps == []
    compilations = [row for row in rows if row["tool"] == "javac"]
    assert len(compilations) == 3
    inputs = {item["workspace_path"] for row in compilations for item in row["inputs"]}
    assert {"multi/lib/src/main/java/lib/Greeter.java", "multi/app/src/main/java/app/Main.java",
            "multi/droid/src/main/java/droid/Activity.java"} == inputs
    outputs = {item["workspace_path"] for row in compilations for item in row["outputs"]}
    assert {"multi/lib/build/classes/java/main", "multi/app/build/classes/java/main",
            f"multi/droid/{late_classes}"} <= outputs
    assert all(row["argfiles"] and row["parent_command_id"] == PARENT for row in compilations)
    # javac rows carry hash-resolved class outputs, nested and anonymous classes included.
    classes = {item["workspace_path"] for row in compilations for item in row["outputs"]
               if item.get("mapping") == "javac-derived-class" and item.get("sha256")}
    assert classes == {"multi/lib/build/classes/java/main/lib/Greeter.class",
                       f"multi/droid/{late_classes}/droid/Activity.class",
                       "multi/app/build/classes/java/main/app/Main.class",
                       "multi/app/build/classes/java/main/app/Main$Inner.class",
                       "multi/app/build/classes/java/main/app/Main$1.class"}
    assert not any(row.get("class_mapping_gaps") for row in compilations)

    records, record_gaps = gradle_provenance.read_task_records(root / "gradle-tasks.jsonl", 1 << 24, 1000)
    assert record_gaps == []
    declared, gaps = gradle_provenance.declared_compilations(
        records, rows, lambda values: _mapped(workspace, "multi", values))
    pinned_task = ":pinned:compileDebugJavaWithJavac"
    assert gaps == [f"Gradle task {pinned_task} ran javac without an observed compiler exec; "
                    "only build-tool-declared provenance is available"]
    by_task = {row["task_path"]: row for row in declared}
    pinned = by_task.pop(pinned_task)
    observed = list(by_task.values())
    assert set(by_task) == {":lib:compileJava", ":app:compileJava", ":droid:compileDebugJavaWithJavac"}
    assert all(row["observed_invocation_ordinals"] and row["did_work"] and
               row["instrumentation"]["observation"] == "fork-requested" and
               row["instrumentation"]["pre_compile_hook"] == "before-task-action" for row in observed)
    assert all(row["instrumentation"]["toolchain_replacement"] == "mirror" for row in observed)
    # The late task's own configure action finalized javaCompiler before projectsEvaluated, so only
    # the replacement made when java-base applied could take effect.
    droid = by_task[":droid:compileDebugJavaWithJavac"]["instrumentation"]
    assert droid["replacement_phases"] == ["java-base-applied"]
    assert droid["replacement_errors"] == ["projects-evaluated: java.lang.IllegalStateException"]
    # The explicit lib toolchain and the app's default both resolve to the real JDK behind the mirror.
    assert {row["declared_settings"]["toolchain_home"] for row in observed} == {
        row["instrumentation"]["toolchain_home"] for row in observed}
    # A toolchain set and read inside the same configure action can never be replaced: the
    # compilation ran in-process and is recorded as declared, with the reason.
    assert pinned["observed_invocation_ordinals"] == [] and pinned["did_work"]
    assert pinned["instrumentation"]["observation"] == "fork-unavailable"
    assert pinned["instrumentation"]["reason"] == "the task javaCompiler toolchain was final before it could be replaced"
    assert pinned["declared_settings"]["fork"] is False
    assert [item["workspace_path"] for item in pinned["inputs"]] == ["multi/pinned/src/main/java/pinned/Activity.java"]
    gaps = []
    _remove_jdk_mirrors(root, gaps)
    assert gaps == [] and not (root / "jdk").exists()

