"""A job's release identity follows the shared modules it imports, not every shared file."""
from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review.runtime.release import build_release, module_imports, module_name, resolve_module

MANIFEST = {
    "schema": "appsec-review/release-dependencies/1",
    "common": ["src/appsec_review/**/*", "pyproject.toml"],
    "exclude_common": ["src/appsec_review/jobs/job_*/**"],
    "job_pattern": "src/appsec_review/jobs/{job_id}/**/*",
    "validators": ["schemas/*.json"],
    "scripts": ["scripts/*.sh"],
    "environment_requirements": ["APPSEC_REVIEW_TARGET"],
}
JOB = "from appsec_review.storage import atomic_json\nfrom .helpers import run\n"


def write(root: Path, files: dict[str, str]) -> None:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def tree(root: Path, job: str = JOB) -> None:
    write(root, {
        "pyproject.toml": "[project]\nname = 'fixture'\n",
        "schemas/result.json": "{}\n",
        "scripts/run.sh": "echo fixture\n",
        "src/appsec_review/__init__.py": "",
        "src/appsec_review/storage/__init__.py": "from appsec_review.storage.files import atomic_json\n",
        "src/appsec_review/storage/files.py": "def atomic_json(path, value):\n    return path\n",
        "src/appsec_review/retrieval/__init__.py": "",
        "src/appsec_review/retrieval/index.py": "INDEX = 1\n",
        "src/appsec_review/operator.py": "import appsec_review.retrieval.index\n",
        "src/appsec_review/jobs/__init__.py": "",
        "src/appsec_review/jobs/job_alpha/__init__.py": "",
        "src/appsec_review/jobs/job_alpha/job.py": job,
        "src/appsec_review/jobs/job_alpha/helpers.py": "def run():\n    return 1\n",
        "src/appsec_review/jobs/job_beta/__init__.py": "",
        "src/appsec_review/jobs/job_beta/job.py": "from appsec_review.retrieval.index import INDEX\n",
    })


def identities(root: Path) -> dict[str, dict[str, str]]:
    return build_release(root, MANIFEST, ("job_alpha", "job_beta"))["jobs"]


def bump(root: Path, name: str) -> None:
    path = root / name
    path.write_text(path.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")


def test_a_shared_module_no_job_imports_leaves_every_job_identity_unchanged(tmp_path: Path) -> None:
    tree(tmp_path)
    before = build_release(tmp_path, MANIFEST, ("job_alpha", "job_beta"))
    bump(tmp_path, "src/appsec_review/operator.py")
    after = build_release(tmp_path, MANIFEST, ("job_alpha", "job_beta"))
    assert after["jobs"] == before["jobs"]
    assert after["files"] != before["files"] and after["sha256"] != before["sha256"]


def test_a_shared_module_a_job_imports_changes_only_that_job(tmp_path: Path) -> None:
    tree(tmp_path)
    before = identities(tmp_path)
    bump(tmp_path, "src/appsec_review/retrieval/index.py")
    after = identities(tmp_path)
    assert after["job_alpha"] == before["job_alpha"]
    assert after["job_beta"] != before["job_beta"]


@pytest.mark.parametrize("name", [
    "src/appsec_review/storage/files.py", "src/appsec_review/storage/__init__.py", "src/appsec_review/__init__.py",
    "src/appsec_review/jobs/job_alpha/helpers.py", "pyproject.toml", "schemas/result.json", "scripts/run.sh",
])
def test_every_file_in_the_job_closure_changes_its_identity(tmp_path: Path, name: str) -> None:
    tree(tmp_path)
    before = identities(tmp_path)
    bump(tmp_path, name)
    assert identities(tmp_path)["job_alpha"] != before["job_alpha"]


@pytest.mark.parametrize("job", [
    "import importlib\nNAME = 'appsec_review.operator'\nMODULE = importlib.import_module(NAME)\n",
    "from importlib import import_module\nMODULE = import_module('appsec_review.' + 'operator')\n",
    "MODULE = __import__('appsec_review' + '.operator')\n",
    "from appsec_review.nowhere import thing\n",
], ids=["import_module-name", "import_module-expression", "__import__", "unresolvable"])
def test_an_import_the_walk_cannot_follow_keeps_the_whole_shared_closure(tmp_path: Path, job: str) -> None:
    tree(tmp_path, job=job)
    before = identities(tmp_path)
    bump(tmp_path, "src/appsec_review/operator.py")
    after = identities(tmp_path)
    assert after["job_alpha"] != before["job_alpha"]
    assert after["job_beta"] == before["job_beta"]


@pytest.mark.parametrize("job", [
    "import importlib\nMODULE = importlib.import_module('appsec_review.operator')\n",
    "from importlib import import_module\nMODULE = import_module('appsec_review.operator')\n",
    "MODULE = __import__('appsec_review.operator')\n",
], ids=["import_module", "bare-import_module", "__import__"])
def test_a_literal_dynamic_import_is_followed_like_a_static_one(tmp_path: Path, job: str) -> None:
    tree(tmp_path, job=job)
    before = identities(tmp_path)
    bump(tmp_path, "src/appsec_review/operator.py")
    assert identities(tmp_path)["job_alpha"] != before["job_alpha"]
    bump(tmp_path, "src/appsec_review/storage/files.py")  # not reached: no fallback happened
    assert identities(tmp_path)["job_alpha"] == identities(tmp_path)["job_alpha"]
    after = identities(tmp_path)
    tree_before = before["job_alpha"]
    assert after["job_alpha"] != tree_before


def test_a_namespace_package_module_is_reached_without_an_init(tmp_path: Path) -> None:
    tree(tmp_path, job="from appsec_review.ns.mod import VALUE\n")
    write(tmp_path, {"src/appsec_review/ns/mod.py": "VALUE = 1\n", "src/appsec_review/ns/other.py": "OTHER = 1\n"})
    before = identities(tmp_path)
    bump(tmp_path, "src/appsec_review/ns/other.py")
    assert identities(tmp_path)["job_alpha"] == before["job_alpha"]
    bump(tmp_path, "src/appsec_review/ns/mod.py")
    assert identities(tmp_path)["job_alpha"] != before["job_alpha"]


def test_a_cross_job_import_still_pulls_in_the_other_job_package(tmp_path: Path) -> None:
    tree(tmp_path, job="from appsec_review.jobs.job_beta.job import INDEX\n")
    before = identities(tmp_path)
    bump(tmp_path, "src/appsec_review/jobs/job_beta/job.py")
    assert identities(tmp_path)["job_alpha"] != before["job_alpha"]
    bump(tmp_path, "src/appsec_review/retrieval/index.py")  # reached through job_beta
    assert identities(tmp_path)["job_alpha"] != before["job_alpha"]


def test_a_shared_module_importing_job_packages_does_not_chain_every_job(tmp_path: Path) -> None:
    tree(tmp_path, job="from appsec_review.registry import JOBS\n")
    write(tmp_path, {"src/appsec_review/registry.py": "from appsec_review.jobs.job_beta.job import INDEX\nJOBS = (INDEX,)\n"})
    before = identities(tmp_path)
    bump(tmp_path, "src/appsec_review/jobs/job_beta/job.py")
    after = identities(tmp_path)
    assert after["job_alpha"] == before["job_alpha"] and after["job_beta"] != before["job_beta"]
    bump(tmp_path, "src/appsec_review/registry.py")
    assert identities(tmp_path)["job_alpha"] != before["job_alpha"]


REPOSITORY = Path(__file__).resolve().parents[3]


def test_no_shipped_module_defeats_the_walk_with_a_computed_dynamic_import() -> None:
    """One computed ``import_module`` in a module every job reaches sends every job back to the
    whole shared closure (``jobs/bound_artifacts.py`` and ``review/slicing/registry.py`` did)."""
    offenders = []
    for path in sorted((REPOSITORY / "src/appsec_review").rglob("*.py")):
        if "development" in path.parts or "__pycache__" in path.parts:
            continue
        source = path.read_bytes()
        if b"import_module" not in source and b"__import__" not in source:
            continue  # only a candidate needs the AST walk, which keeps this under the unit budget
        if module_imports(path.relative_to(REPOSITORY).as_posix(), source)[1]:
            offenders.append(path.relative_to(REPOSITORY).as_posix())
    assert offenders == []


def test_module_names_and_resolution() -> None:
    assert module_name("src/appsec_review/storage/__init__.py") == "appsec_review.storage"
    assert module_name("src/appsec_review/storage/files.py") == "appsec_review.storage.files"
    assert module_name("src/appsec_review/__init__.py") == "appsec_review"
    assert module_name("pyproject.toml") is None and module_name("release-src/shared.py") is None
    modules = {"appsec_review": "src/appsec_review/__init__.py",
               "appsec_review.storage": "src/appsec_review/storage/__init__.py",
               "appsec_review.storage.files": "src/appsec_review/storage/files.py"}
    assert resolve_module("appsec_review.storage.files", modules) == [
        "src/appsec_review/__init__.py", "src/appsec_review/storage/__init__.py", "src/appsec_review/storage/files.py"]
    assert resolve_module("appsec_review.storage.atomic_json", modules, exact=False) == [
        "src/appsec_review/__init__.py", "src/appsec_review/storage/__init__.py"]
    assert resolve_module("appsec_review.storage.atomic_json", modules) is None
    assert resolve_module("appsec_review.nowhere", modules) is None
    assert resolve_module("appsec_review.nowhere.thing", modules, exact=False) is None
    assert resolve_module("other.package", modules) is None
    namespace = {**modules, "appsec_review.ns.mod": "src/appsec_review/ns/mod.py"}
    assert resolve_module("appsec_review.ns", namespace) == ["src/appsec_review/__init__.py"]
    assert resolve_module("appsec_review.ns.mod", namespace) == [
        "src/appsec_review/__init__.py", "src/appsec_review/ns/mod.py"]
    assert resolve_module("appsec_review.ns.mod.VALUE", namespace, exact=False) == [
        "src/appsec_review/__init__.py", "src/appsec_review/ns/mod.py"]


def test_relative_imports_resolve_against_the_module_package() -> None:
    imported, dynamic = module_imports(
        "src/appsec_review/jobs/job_alpha/job.py",
        b"from . import helpers\nfrom ..cataloging import fingerprint\nimport json\n")
    assert imported == {"appsec_review.jobs.job_alpha": True, "appsec_review.jobs.job_alpha.helpers": False,
                        "appsec_review.jobs.cataloging": True, "appsec_review.jobs.cataloging.fingerprint": False}
    assert dynamic is False
    imported, dynamic = module_imports("src/appsec_review/storage/__init__.py", b"from .files import atomic_json\n")
    assert imported == {"appsec_review.storage.files": True, "appsec_review.storage.files.atomic_json": False}
    assert module_imports("src/appsec_review/x.py", b"import appsec_review.retrieval.index\n") == (
        {"appsec_review.retrieval.index": True}, False)
    assert module_imports("release-src/job_fixture/job.py", b"from . import x\n") == ({}, True)
    assert module_imports("src/appsec_review/x.py", b"import importlib\nimportlib.import_module('appsec_review.a')\n") == (
        {"appsec_review.a": True}, False)
    assert module_imports("src/appsec_review/x.py", b"__import__('hashlib')\n") == ({}, False)
    assert module_imports("src/appsec_review/x.py", b"import importlib\nimportlib.import_module(NAME)\n") == ({}, True)
