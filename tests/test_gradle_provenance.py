"""Gradle and Android compiler provenance for the JVM language build.

Every project here is synthetic (a java-library, an application, and a Kotlin module); nothing is
keyed to a benchmark case. The live test runs a real Gradle distribution offline when
APPSEC_GRADLE_HOME names one (for example the hash-locked Gradle 8.9 from
containers/buildenv/java/assets.lock.json).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.build_discovery import jvm_build_command_errors
from appsec_review.jobs.job_language_build import gradle_provenance
from appsec_review.jobs.job_language_build.jvm import (
    _argfile_arguments, _artifact_kind, _environment, _instrumentation, _mapped, _remove_jdk_mirrors, _trace_rows,
)


ROOT = Path(__file__).parents[1]
PARENT = "c" * 64


def _settings() -> dict:
    return dict(load_config(ROOT / "appsec-review.toml").job("job_language_build").settings["jvm"])


# The Android Gradle Plugin pattern without the Android Gradle Plugin (which needs the network). A
# JavaCompile is registered lazily from an afterEvaluate (variant API) callback, so its own configure
# action runs when the task is realized during task-graph calculation, after projectsEvaluated.
# Like AGP's JavaCompileCreationAction, that action reads the task's javaCompiler (AGP does so to
# pick the JDK whose jlink builds its JDK image), which finalizes the property because JavaCompile
# declares it finalizeValueOnRead. It also resets the fork options, and a build-owned doFirst
# action resets them again just before compilation. With `pinned`, the action first sets
# javaCompiler explicitly and then reads it, which leaves no point at which an init script can
# replace it: that compilation must stay a declared record with a named gap.
_LATE_CONFIGURED_MODULE = """plugins { id 'java-base' }
def toolchains = extensions.getByType(JavaToolchainService)
afterEvaluate {
  def compile = tasks.register('compileDebugJavaWithJavac', JavaCompile) { task ->
    if (@PINNED@) task.javaCompiler.set(toolchains.compilerFor { })
    def jdkImageHome = task.javaCompiler.get().metadata.installationPath
    task.source = fileTree('src/main/java')
    task.classpath = files()
    task.destinationDirectory = layout.buildDirectory.dir('intermediates/javac/debug/classes')
    task.options.fork = false
    task.options.forkOptions.executable = null
    task.doFirst { task.options.fork = false; task.options.forkOptions.executable = null }
  }
  tasks.named('assemble') { dependsOn compile }
}
"""


def _synthetic_project(root: Path, *, kotlin: bool = True, toolchain: str | None = None,
                       late: bool = False) -> None:
    """A dependency-free multi-module build: java-library, application, optionally Kotlin, and
    optionally a module whose JavaCompile is configured late, the way the Android Gradle Plugin
    configures its variant compile tasks."""
    modules = ["lib", "app"] + (["kt"] if kotlin else []) + (["droid", "pinned"] if late else [])
    root.mkdir(parents=True, exist_ok=True)
    (root / "settings.gradle").write_text(
        "rootProject.name = 'synthetic'\ninclude " + ", ".join(f"'{name}'" for name in modules) + "\n",
        encoding="utf-8")
    library = root / "lib" / "src" / "main" / "java" / "lib"
    library.mkdir(parents=True)
    (library / "Greeter.java").write_text(
        'package lib; public class Greeter { public static String hi() { return "hi"; } }\n',
        encoding="utf-8")
    (root / "lib" / "build.gradle").write_text(
        "plugins { id 'java-library' }\n" +
        (f"java {{ toolchain {{ languageVersion = JavaLanguageVersion.of({toolchain}) }} }}\n"
         if toolchain else ""), encoding="utf-8")
    application = root / "app" / "src" / "main" / "java" / "app"
    application.mkdir(parents=True)
    (application / "Main.java").write_text(
        "package app; public class Main { static class Inner {}\n"
        " public static void main(String[] a) { Runnable r = new Runnable() { public void run() {} };\n"
        " System.out.println(lib.Greeter.hi()); } }\n", encoding="utf-8")
    (root / "app" / "build.gradle").write_text(
        "plugins { id 'application' }\ndependencies { implementation project(':lib') }\n"
        "application { mainClass = 'app.Main' }\n", encoding="utf-8")
    for name in ("droid", "pinned") if late else ():
        sources = root / name / "src" / "main" / "java" / name
        sources.mkdir(parents=True)
        (sources / "Activity.java").write_text(f"package {name}; public class Activity {{}}\n", encoding="utf-8")
        (root / name / "build.gradle").write_text(
            _LATE_CONFIGURED_MODULE.replace("@PINNED@", str(name == "pinned").lower()), encoding="utf-8")
    if kotlin:
        sources = root / "kt" / "src" / "main" / "kotlin" / "kt"
        sources.mkdir(parents=True)
        (sources / "Tool.kt").write_text("package kt\nclass Tool\n", encoding="utf-8")
        (root / "kt" / "build.gradle.kts").write_text(
            'plugins { kotlin("jvm") version "2.0.21" }\n', encoding="utf-8")


def _record(trace_dir: Path, name: str, tool: str, argv: list[str], argfiles: dict[str, str] | None = None):
    """Write one per-invocation record exactly as the instrumented wrapper does."""
    fields = [tool, PARENT, str(len(argv)), *argv]
    for path, text in (argfiles or {}).items():
        fields.extend(("@argfile", PARENT, "3", path, "/workspace/multi", text))
    (trace_dir / name).write_bytes(b"\0".join(item.encode() for item in fields) + b"\0")


def _task_records(root: Path, records: list[dict]) -> None:
    lines = [json.dumps({"schema": gradle_provenance.TASK_RECORD_SCHEMA, "parent_command_id": PARENT,
                         **record}) for record in records]
    (root / "gradle-tasks.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_gradle_instrumentation_writes_the_init_script_and_mirror_templates(tmp_path: Path) -> None:
    settings = _settings()
    _synthetic_project(tmp_path / "multi")
    environment, trace = _environment(
        {"image_profile": "java", "source_dir": "multi", "build_system": "gradle", "environment": {}},
        tmp_path, settings)
    root = tmp_path / "multi" / ".appsec-review-jvm"
    assert trace == root / "invocations.bin" and (root / "invocations.d").is_dir()
    assert environment["APPSEC_JVM_INSTRUMENTATION"] == "/workspace/multi/.appsec-review-jvm"
    assert environment["APPSEC_JVM_TRACE_DIR"] == "/workspace/multi/.appsec-review-jvm/invocations.d"
    script = (root / "gradle" / gradle_provenance.INIT_SCRIPT_NAME).read_text(encoding="utf-8")
    assert script == gradle_provenance.INIT_SCRIPT
    # The script forks every JavaCompile (plain and AGP) through the mirror's command-line javac,
    # moves Kotlin out of process, and records dex tasks; it selects no tasks of its own.
    for fragment in ("org.gradle.api.tasks.compile.JavaCompile", "options.fork = true",
                     "forkOptions.executable", "org.jetbrains.kotlin.gradle.tasks.KotlinCompile",
                     "OUT_OF_PROCESS", "kotlinJavaToolchain", "com.android.build.", "R8",
                     "gradle.taskGraph.whenReady", "APPSEC_JVM_INSTRUMENTATION"):
        assert fragment in script
    assert not re.search(r"case-\d+|multivuln", script, re.I)
    assert "tasks.register" not in script and "dependsOn" not in script
    for tool in gradle_provenance.MIRRORED_TOOLS:
        template = (root / "gradle" / f"{tool}.template").read_text(encoding="utf-8")
        assert f"exec {gradle_provenance.TEMPLATE_PLACEHOLDER} \"$@\"" in template
        assert f"'{tool}'" in template and "@argfile" in template
    # The PATH wrappers used by Maven share the same recording body.
    assert "@argfile" in (root / "bin" / "javac").read_text(encoding="utf-8")


def test_gradle_argv_is_instrumented_without_changing_the_accepted_tasks() -> None:
    accepted = ["gradle", "--daemon", "--build-cache", ":lib:assemble", ":app:assemble",
                ":kt:assemble", "-x", "test"]
    assert jvm_build_command_errors("java", accepted) == ()
    argv, facts = gradle_provenance.instrument_argv(accepted, "/workspace/multi/.appsec-review-jvm")
    assert [value for value in argv if not value.startswith("-")][:4] == [
        "gradle", ":lib:assemble", ":app:assemble", ":kt:assemble"]
    assert facts["removed_arguments"] == ["--daemon", "--build-cache"]
    assert argv[-2:] == ("--init-script",
                         "/workspace/multi/.appsec-review-jvm/gradle/appsec-provenance.init.gradle")
    for flag in ("--no-daemon", "--no-build-cache", "--no-configuration-cache",
                 "-Pkotlin.compiler.execution.strategy=out-of-process"):
        assert argv.count(flag) == 1
    assert facts["gradle_init_script"]["sha256"] == gradle_provenance.INIT_SCRIPT_SHA256
    again, _facts = gradle_provenance.instrument_argv(["gradle", "--no-daemon", "assemble"], "/x")
    assert again.count("--no-daemon") == 1


@pytest.mark.parametrize(("text", "expected"), [
    ('-d\n/w/build/classes\n-sourcepath\n""\n/w/A.java\n', ["-d", "/w/build/classes", "-sourcepath", "", "/w/A.java"]),
    ('"-classpath" "/w/a b.jar:/w/c.jar"\n# comment\n"C:\\\\x\\\\y.java"', ["-classpath", "/w/a b.jar:/w/c.jar", "C:\\x\\y.java"]),
    ("'single quoted' plain", ["single quoted", "plain"]),
])
def test_argfiles_are_tokenized_like_javac(text: str, expected: list[str]) -> None:
    assert _argfile_arguments(text) == expected


def test_instrumented_wrapper_retains_deleted_argfiles_and_parses_into_provenance(tmp_path: Path) -> None:
    """Run the generated wrapper with /bin/sh: the build tool deletes its argfile after the
    compiler exits, yet the record keeps its content, so the compilation's inputs and outputs
    resolve from the observed exec."""
    workspace = tmp_path / "workspace"
    _synthetic_project(workspace / "multi", kotlin=False)
    trace, _logical = _instrumentation(workspace, "multi", _settings())
    root = trace.parent
    real = tmp_path / "real-javac"
    real.write_text("#!/bin/sh\necho compiled \"$@\"\n", encoding="utf-8")
    real.chmod(0o755)
    template = (root / "gradle" / "javac.template").read_text(encoding="utf-8")
    wrapper = tmp_path / "jdk" / "bin" / "javac"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text(template.replace(gradle_provenance.TEMPLATE_PLACEHOLDER, f"'{real}'"), encoding="utf-8")
    wrapper.chmod(0o755)
    project = workspace / "multi"
    argfile = project / "lib" / "build" / "tmp" / "compileJava" / "java-compiler-args.txt"
    argfile.parent.mkdir(parents=True)
    source = project / "lib" / "src" / "main" / "java" / "lib" / "Greeter.java"
    argfile.write_text(f"-d\n{project}/lib/build/classes/java/main\n-sourcepath\n\"\"\n{source}\n",
                       encoding="utf-8")
    environment = {**os.environ, "APPSEC_JVM_TRACE_DIR": str(root / "invocations.d"),
                   "APPSEC_JVM_PARENT_COMMAND": PARENT}
    completed = subprocess.run([str(wrapper), f"@{argfile}"], env=environment, capture_output=True,
                               check=True, cwd=tmp_path)
    assert completed.stdout.decode().strip() == f"compiled @{argfile}"
    argfile.unlink()
    rows, gaps = _trace_rows(trace, workspace, 100, 1 << 20)
    assert gaps == []
    (row,) = rows
    assert row["tool"] == "javac" and row["evidence_kind"] == "observed-exec"
    assert row["argv"] == ["javac", f"@{argfile}"]
    assert row["expanded_argv"][1:3] == ["-d", f"{project}/lib/build/classes/java/main"]
    assert row["argfiles"][0]["reference"] == str(argfile)
    assert row["argfiles"][0]["working_directory"] == str(tmp_path)
    assert [item["workspace_path"] for item in row["inputs"]] == ["multi/lib/src/main/java/lib/Greeter.java"]
    assert row["inputs"][0]["mapping"] == "exact-workspace-path"
    assert [item["workspace_path"] for item in row["outputs"]] == ["multi/lib/build/classes/java/main"]


def test_multi_module_records_separate_observed_execs_from_declared_tasks(tmp_path: Path) -> None:
    """Fake Gradle run over java-library + application + Kotlin: observed javac and out-of-process
    kotlinc execs carry full provenance; declared task records are typed apart, matched by
    destination, and every compilation without an observed exec is a named gap."""
    workspace = tmp_path / "workspace"
    _synthetic_project(workspace / "multi")
    trace, _logical = _instrumentation(workspace, "multi", _settings())
    root, trace_dir = trace.parent, trace.with_name("invocations.d")
    base = "/workspace/multi"
    lib_args = f"-d\n{base}/lib/build/classes/java/main\n{base}/lib/src/main/java/lib/Greeter.java\n"
    _record(trace_dir, "0001-1", "javac", [f"@{base}/lib/build/tmp/compileJava/java-compiler-args.txt"],
            {f"{base}/lib/build/tmp/compileJava/java-compiler-args.txt": lib_args})
    kotlin_args = (f'"-d"\n"{base}/kt/build/classes/kotlin/main"\n'
                   f'"{base}/kt/src/main/kotlin/kt/Tool.kt"\n')
    _record(trace_dir, "0002-2", "java", ["-Xmx1g", "-cp", "/opt/kotlin/kotlin-compiler-embeddable.jar",
            gradle_provenance.KOTLIN_COMPILER_MAIN, f"@{base}/kt/build/tmp/compiler-arguments"],
            {f"{base}/kt/build/tmp/compiler-arguments": kotlin_args})
    _record(trace_dir, "0003-3", "java", ["-Xmx32m", "-cp", ".", "JavaProbe"])
    _task_records(root, [
        {"record_kind": "session", "gradle_version": "8.9"},
        {"record_kind": "configured", "task_path": ":lib:compileJava", "compiler": "javac",
         "task_type": "org.gradle.api.tasks.compile.JavaCompile", "observation": "fork-requested"},
        {"record_kind": "before-compile", "task_path": ":lib:compileJava", "compiler": "javac",
         "compiler_args": ["-parameters", "-Asecret=value"], "source_files": [f"{base}/lib/src/main/java/lib/Greeter.java"],
         "destination_directory": f"{base}/lib/build/classes/java/main", "release": 17,
         "classpath": []},
        {"record_kind": "completed", "task_path": ":lib:compileJava", "compiler": "javac", "did_work": True},
        # :app:compileJava compiled in-process (fork was unavailable): declared only, a gap.
        {"record_kind": "configured", "task_path": ":app:compileJava", "compiler": "javac",
         "observation": "fork-unavailable", "error": "org.gradle.api.GradleException"},
        {"record_kind": "before-compile", "task_path": ":app:compileJava", "compiler": "javac",
         "compiler_args": [], "source_files": [f"{base}/app/src/main/java/app/Main.java"],
         "destination_directory": f"{base}/app/build/classes/java/main",
         "classpath": [f"{base}/lib/build/classes/java/main"]},
        {"record_kind": "completed", "task_path": ":app:compileJava", "compiler": "javac", "did_work": True},
        {"record_kind": "configured", "task_path": ":kt:compileKotlin", "compiler": "kotlinc",
         "observation": "out-of-process-requested", "execution_strategy": "out-of-process"},
        {"record_kind": "before-compile", "task_path": ":kt:compileKotlin", "compiler": "kotlinc",
         "compiler_args": [], "source_files": [f"{base}/kt/src/main/kotlin/kt/Tool.kt"],
         "destination_directory": f"{base}/kt/build/classes/kotlin/main", "jvm_target": "17"},
        {"record_kind": "completed", "task_path": ":kt:compileKotlin", "compiler": "kotlinc", "did_work": True},
        # A NO-SOURCE javac task never compiled, so its missing exec is not a gap.
        {"record_kind": "completed", "task_path": ":kt:compileJava", "compiler": "javac", "did_work": False},
    ])

    rows, trace_gaps = _trace_rows(trace, workspace, 100, 1 << 20)
    assert trace_gaps == []
    assert [(row["tool"], row["launcher"]) for row in rows] == [
        ("javac", None), ("kotlinc", "java"), ("java", None)]
    kotlin = rows[1]
    assert kotlin["tool_kind"] == "compiler"
    assert kotlin["expanded_argv"][:3] == ["kotlinc", "-d", f"{base}/kt/build/classes/kotlin/main"]
    assert [item["workspace_path"] for item in kotlin["inputs"]] == ["multi/kt/src/main/kotlin/kt/Tool.kt"]

    records, record_gaps = gradle_provenance.read_task_records(root / "gradle-tasks.jsonl", 1 << 20, 100)
    assert record_gaps == []
    declared, gaps = gradle_provenance.declared_compilations(
        records, rows, lambda values: _mapped(workspace, "multi", values))
    by_task = {row["task_path"]: row for row in declared}
    assert all(row["evidence_kind"] == "build-tool-declared" and
               row["mapping_confidence"] < 1.0 for row in declared)
    assert by_task[":lib:compileJava"]["observed_invocation_ordinals"] == [1]
    assert by_task[":kt:compileKotlin"]["observed_invocation_ordinals"] == [2]
    assert by_task[":app:compileJava"]["observed_invocation_ordinals"] == []
    assert by_task[":app:compileJava"]["instrumentation"]["observation"] == "fork-unavailable"
    assert by_task[":lib:compileJava"]["declared_arguments"] == ["-parameters", "-Asecret=value"]
    assert by_task[":lib:compileJava"]["declared_settings"]["release"] == 17
    assert [item["workspace_path"] for item in by_task[":app:compileJava"]["inputs"]] == [
        "multi/app/src/main/java/app/Main.java"]
    assert gaps == ["Gradle task :app:compileJava ran javac without an observed compiler exec; "
                    "only build-tool-declared provenance is available"]


def test_late_configured_compile_tasks_keep_the_mirror_fork(tmp_path: Path) -> None:
    """The Android Gradle Plugin configures its JavaCompile when the task is realized, after
    projectsEvaluated, and reads javaCompiler there, which finalizes it. The init script therefore
    replaces the toolchain as soon as java-base has applied its convention (before any later
    configure action), again after evaluation, and applies the fork immediately before the task's
    own compile action, after every build-owned doFirst action."""
    script = gradle_provenance.INIT_SCRIPT
    early = script.index("appsecReplaceJavaToolchain(task, 'java-base-applied')")
    late = script.index("appsecReplaceJavaToolchain(task, 'projects-evaluated')")
    assert script.rindex("gradle.beforeProject", 0, early) < script.rindex("plugins.withId('java-base')", 0, early)
    assert early < script.index("gradle.projectsEvaluated") < late < script.index("gradle.taskGraph.whenReady")
    # whenReady is too late to replace a toolchain: the task graph has already read it.
    assert "appsecReplaceJavaToolchain" not in script[script.index("gradle.taskGraph.whenReady"):]
    assert "if (appsecIsMirror(home)) return compiler" in script
    assert "task.actions.add(index, action)" in script and "task.doFirst(action)" in script

    # Records of a fake run: the late task forked through the mirror replaced at java-base time
    # (the post-evaluation replacement found it final) and was observed; a task whose plugin set
    # and read its toolchain in one configure action could not be, and is a named gap.
    workspace = tmp_path / "workspace"
    (workspace / "mobile").mkdir(parents=True)
    trace, _logical = _instrumentation(workspace, "mobile", _settings())
    base = "/workspace/mobile"
    classes = f"{base}/app/build/intermediates/javac/debug/compileDebugJavaWithJavac/classes"
    _record(trace.with_name("invocations.d"), "0001-1", "javac", [f"@{base}/app/build/tmp/args.txt"],
            {f"{base}/app/build/tmp/args.txt": f"-d\n{classes}\n{base}/app/src/main/java/a/A.java\n"})
    late = {"task_type": "org.gradle.api.tasks.compile.JavaCompile", "compiler": "javac"}
    _task_records(trace.parent, [
        {"record_kind": "configured", "task_path": ":app:compileDebugJavaWithJavac", **late,
         "toolchain_replacement": "mirror", "replacement_phases": ["java-base-applied"],
         "replacement_errors": ["projects-evaluated: java.lang.IllegalStateException"],
         "pre_compile_hook": "before-task-action", "observation": "fork-requested"},
        {"record_kind": "before-compile", "task_path": ":app:compileDebugJavaWithJavac", **late,
         "destination_directory": classes, "source_files": [f"{base}/app/src/main/java/a/A.java"],
         "fork": True},
        {"record_kind": "completed", "task_path": ":app:compileDebugJavaWithJavac", **late, "did_work": True},
        {"record_kind": "configured", "task_path": ":lib:compileDebugJavaWithJavac", **late,
         "replacement_errors": ["java-base-applied: java.lang.IllegalStateException"],
         "observation": "fork-unavailable",
         "reason": "the task javaCompiler toolchain was final before it could be replaced"},
        {"record_kind": "before-compile", "task_path": ":lib:compileDebugJavaWithJavac", **late,
         "destination_directory": f"{base}/lib/build/classes", "fork": False},
        {"record_kind": "completed", "task_path": ":lib:compileDebugJavaWithJavac", **late, "did_work": True},
    ])
    rows, _trace_gaps = _trace_rows(trace, workspace, 100, 1 << 20)
    records, _gaps = gradle_provenance.read_task_records(trace.parent / "gradle-tasks.jsonl", 1 << 20, 100)
    declared, gaps = gradle_provenance.declared_compilations(
        records, rows, lambda values: _mapped(workspace, "mobile", values))
    by_task = {row["task_path"]: row for row in declared}
    app, lib = by_task[":app:compileDebugJavaWithJavac"], by_task[":lib:compileDebugJavaWithJavac"]
    assert app["observed_invocation_ordinals"] == [1]
    assert app["instrumentation"]["replacement_phases"] == ["java-base-applied"]
    assert app["instrumentation"]["pre_compile_hook"] == "before-task-action"
    assert lib["instrumentation"]["reason"].startswith("the task javaCompiler toolchain was final")
    assert gaps == ["Gradle task :lib:compileDebugJavaWithJavac ran javac without an observed compiler "
                    "exec; only build-tool-declared provenance is available"]


def test_android_dex_tasks_are_declared_gaps_and_dex_outputs_are_cataloged(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "mobile").mkdir(parents=True)
    trace, _logical = _instrumentation(workspace, "mobile", _settings())
    base = "/workspace/mobile/app/build"
    _task_records(trace.parent, [
        {"record_kind": "session"},
        {"record_kind": "dex-task", "task_path": ":app:mergeDexDebug", "compiler": "d8",
         "task_type": "com.android.build.gradle.internal.tasks.DexMergingTask",
         "output_files": [f"{base}/intermediates/dex/debug/mergeDexDebug"], "input_file_count": 4},
        {"record_kind": "completed", "task_path": ":app:mergeDexDebug", "compiler": "d8", "did_work": True},
    ])
    records, _gaps = gradle_provenance.read_task_records(trace.parent / "gradle-tasks.jsonl", 1 << 20, 100)
    declared, gaps = gradle_provenance.declared_compilations(records, [], lambda values: _mapped(workspace, "multi", values))
    (row,) = declared
    assert row["tool"] == "d8" and row["tool_kind"] == "dexer"
    assert row["evidence_kind"] == "build-tool-declared"
    assert row["declared_settings"] == {"input_file_count": 4}
    assert [item["workspace_path"] for item in row["outputs"]] == [
        "mobile/app/build/intermediates/dex/debug/mergeDexDebug"]
    assert len(gaps) == 1 and gaps[0].startswith("Android dex task :app:mergeDexDebug ran D8 in-process")
    assert _artifact_kind(Path("app/build/intermediates/dex/debug/classes.dex")) == "dex"
    assert _artifact_kind(Path("app/build/outputs/apk/debug/app-debug.apk")) == "android-apk"


def test_task_records_are_bounded_and_reject_foreign_records(tmp_path: Path) -> None:
    path = tmp_path / "gradle-tasks.jsonl"
    path.write_text(json.dumps({"schema": "other"}) + "\n", encoding="utf-8")
    assert gradle_provenance.read_task_records(path, 1 << 20, 10) == (
        [], ["Gradle task provenance records contain an invalid record"])
    row = json.dumps({"schema": gradle_provenance.TASK_RECORD_SCHEMA, "record_kind": "session"})
    path.write_text((row + "\n") * 3, encoding="utf-8")
    records, gaps = gradle_provenance.read_task_records(path, 1 << 20, 2)
    assert len(records) == 2 and gaps == ["Gradle task provenance records exceeded their configured count bound"]


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
    trace, _logical = _instrumentation(workspace, "multi", _settings())
    root = trace.parent
    argv, _facts = gradle_provenance.instrument_argv(
        ["gradle", "--offline", *(["--parallel"] if parallel else []), "assemble"], str(root))
    environment = {**os.environ, "APPSEC_JVM_INSTRUMENTATION": str(root),
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
