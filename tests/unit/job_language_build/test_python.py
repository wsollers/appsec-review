from __future__ import annotations

import hashlib
import io
from pathlib import Path
import tarfile
import zipfile

from appsec_review.jobs.job_language_build import python as python_adapter
from appsec_review.storage import canonical_json, file_sha256


def test_python_recipe_validation_is_package_only_and_allows_dependency_download(tmp_path: Path) -> None:
    setup = tmp_path / "setup.py"
    setup.write_text("from setuptools import setup\nsetup(name='sample')\n", encoding="utf-8")
    base = {"family": "python", "recipe": {"dependency_files": ["setup.py"],
        "network_required": False, "configure_commands": [],
        "build_commands": [["python", "setup.py", "sdist", "bdist_wheel"]]}}
    assert python_adapter.validate_dispatch(base, tmp_path) == []
    unsafe = {"family": "python", "recipe": {**base["recipe"],
        "build_commands": [["python", "-m", "pytest"]]}}
    assert any("allowlist" in gap for gap in python_adapter.validate_dispatch(unsafe, tmp_path))
    unlocked = {"family": "python", "recipe": {**base["recipe"], "network_required": True}}
    assert python_adapter.validate_dispatch(unlocked, tmp_path) == []
    assert python_adapter.validate_dispatch({"family": "node", "recipe": {}}) == [
        "Python execution requires an accepted Python recipe"
    ]
    missing_meta = {"family": "python", "recipe": {
        "dependency_files": ["README.md"],
        "configure_commands": ["not-a-list", [], ["pip3", "wheel", "--no-deps", "."], ["pip", "list"], ["pip", "--quiet"]],
        "build_commands": [
            ["python3", "-m", "build"],
            ["python", "setup.py", "test"],
            ["python", "setup.py", "--verbose"],
            ["python", "run_arbitrary.py"],
            ["cmake", "--build", "build"],
        ],
    }}
    errors = python_adapter.validate_dispatch(missing_meta, tmp_path)
    assert "Python package metadata is unavailable" in errors
    assert "pip subcommand is outside the package-build allowlist: list" in errors
    assert "pip subcommand is outside the package-build allowlist: <missing>" in errors
    assert "setup.py may perform only bounded package-build commands" in errors
    assert "Python may execute only approved package-builder modules or setup.py" in errors


def test_python_environment_and_artifact_kind_classification(tmp_path: Path) -> None:
    assert python_adapter.environment({}) == {
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PYTHONDONTWRITEBYTECODE": "0",
        "PYTHONHASHSEED": "0",
        "SOURCE_DATE_EPOCH": "0",
    }
    gen_c = tmp_path / "pkg" / "_ext.c"
    gen_c.parent.mkdir(parents=True)
    gen_c.write_text("int f(void) { return 1; }\n", encoding="utf-8")
    unchanged_c = tmp_path / "pkg" / "orig.c"
    unchanged_c.write_text("int g(void) { return 2; }\n", encoding="utf-8")
    before = {"pkg/orig.c": file_sha256(unchanged_c)}

    assert python_adapter.artifact_kind(Path("dist/pkg-1.0.whl"), "dist/pkg-1.0.whl", before) == "wheel"
    assert python_adapter.artifact_kind(Path("dist/pkg-1.0.tar.gz"), "dist/pkg-1.0.tar.gz", before) == "source-distribution"
    assert python_adapter.artifact_kind(Path("pkg/__pycache__/mod.pyc"), "pkg/__pycache__/mod.pyc", before) == "bytecode"
    assert python_adapter.artifact_kind(Path("pkg/_ext.so"), "pkg/_ext.so", before) == "native-extension"
    assert python_adapter.artifact_kind(Path("pkg-1.0.dist-info/METADATA"), "pkg-1.0.dist-info/METADATA", before) == "package-metadata"
    assert python_adapter.artifact_kind(gen_c, "pkg/_ext.c", before) == "generated-source"
    assert python_adapter.artifact_kind(unchanged_c, "pkg/orig.c", before) is None
    assert python_adapter.artifact_kind(Path("build/temp/_ext.o"), "build/temp/_ext.o", before) == "native-intermediate"
    assert python_adapter.artifact_kind(Path("README.txt"), "README.txt", before) is None


def test_python_project_metadata_parses_pyproject_poetry_uv_legacy_and_bad_toml(tmp_path: Path) -> None:
    ws_pyproject = tmp_path / "ws1"
    pkg = ws_pyproject / "sub"
    pkg.mkdir(parents=True)
    (pkg / "pyproject.toml").write_text(
        '[build-system]\nbuild-backend = "setuptools.build_meta"\n'
        '[project]\nname = "demo"\ndependencies = ["requests>=2.0", "click[extra]; python_version>=\'3.11\'"]\n'
        '[tool.uv.workspace]\nmembers = ["packages/a", "packages/b"]\n',
        encoding="utf-8",
    )
    projects, rels, gaps = python_adapter.project_metadata(ws_pyproject, "sub")
    assert gaps == []
    assert len(projects) == 1 and projects[0]["name"] == "demo"
    assert projects[0]["build_backend"] == "setuptools.build_meta"
    assert {(r["to"], r["kind"]) for r in rels} == {
        ("requests", "requires"), ("click", "requires"),
        ("packages/a", "workspace-member"), ("packages/b", "workspace-member"),
    }

    # Poetry fallback + non-list dependencies
    ws_poetry = tmp_path / "ws_poetry"
    ws_poetry.mkdir()
    (ws_poetry / "pyproject.toml").write_text(
        '[project]\ndependencies = "invalid"\n[tool.poetry]\nname = "poetry-pkg"\n',
        encoding="utf-8",
    )
    p2, r2, g2 = python_adapter.project_metadata(ws_poetry, ".")
    assert g2 == [] and p2[0]["name"] == "poetry-pkg" and p2[0]["requires"] == [] and r2 == []

    # Invalid TOML produces a gap
    ws_bad = tmp_path / "ws_bad"
    ws_bad.mkdir()
    (ws_bad / "pyproject.toml").write_text("[project\nbroken =", encoding="utf-8")
    p3, r3, g3 = python_adapter.project_metadata(ws_bad, ".")
    assert p3 == [] and r3 == [] and len(g3) == 1 and "TOMLDecodeError" in g3[0]

    # Legacy setup.cfg fallback
    ws_cfg = tmp_path / "ws_cfg"
    ws_cfg.mkdir()
    (ws_cfg / "setup.cfg").write_text("[metadata]\nname = legacy\n", encoding="utf-8")
    p4, r4, g4 = python_adapter.project_metadata(ws_cfg, ".")
    assert g4 == [] and r4 == [] and p4[0]["build_backend"] == "setuptools-legacy"


def test_python_package_contents_and_tool_invocations(tmp_path: Path) -> None:
    whl = tmp_path / "dist" / "demo-1.0-py3-none-any.whl"
    whl.parent.mkdir(parents=True)
    with zipfile.ZipFile(whl, "w") as zf:
        zf.writestr("demo/", "")
        zf.writestr("demo/__init__.py", "x = 1\n")
    rows, gaps = python_adapter.package_contents(whl, tmp_path)
    assert gaps == [] and rows == [
        {"package_path": "dist/demo-1.0-py3-none-any.whl", "member": "demo/__init__.py", "size_bytes": 6}
    ]

    sdist = tmp_path / "dist" / "demo-1.0.tar.gz"
    with tarfile.open(sdist, "w:gz") as tf:
        data = b"print('hi')\n"
        info = tarfile.TarInfo("demo-1.0/mod.py")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
        dir_info = tarfile.TarInfo("demo-1.0")
        dir_info.type = tarfile.DIRTYPE
        tf.addfile(dir_info)
    t_rows, t_gaps = python_adapter.package_contents(sdist, tmp_path)
    assert t_gaps == [] and t_rows == [
        {"package_path": "dist/demo-1.0.tar.gz", "member": "demo-1.0/mod.py", "size_bytes": len(data)}
    ]

    bad_whl = tmp_path / "dist" / "corrupt.whl"
    bad_whl.write_bytes(b"not a zip archive")
    b_rows, b_gaps = python_adapter.package_contents(bad_whl, tmp_path)
    assert b_rows == [] and b_gaps == ["corrupt.whl: package archive could not be inspected"]

    commands = [
        {"tool": "python3", "module": "build", "argv_sha256": "1" * 64, "working_directory": "."},
        {"tool": "python3", "module": "compileall", "argv_sha256": "2" * 64, "working_directory": "."},
    ]
    streams = [
        b"unclosed 'quote\n/usr/bin/gcc -c ext.c -o ext.o\necho ignored\n",
        b"cython -3 ext.pyx -o ext.c\n",
    ]
    invocations = python_adapter.tool_invocations(
        commands, streams, tmp_path, [{"path": "pyproject.toml", "build_backend": "setuptools.build_meta"}]
    )
    assert [row["tool_kind"] for row in invocations] == [
        "package-builder", "bytecode-compiler", "build-backend", "compiler-driver", "transpiler"
    ]
    assert invocations[3]["origin"] == {"stream": "stdout", "line": 2}
    assert invocations[4]["origin"] == {"stream": "stderr", "line": 1}
    assert invocations[2]["argv_sha256"] == hashlib.sha256(canonical_json(["setuptools.build_meta"])).hexdigest()
