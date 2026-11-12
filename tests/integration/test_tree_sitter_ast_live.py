"""The locked Tree-sitter image parses the multi-project fixture and the real graph is queryable.

Skips, naming the gap, when Docker or the image is missing. ``APPSEC_TREE_SITTER_TEST_IMAGE`` may
name a candidate image for the container test; the graph test runs only with the cataloged one.
The routing, normalization and fake-engine checks stay in ``tests/test_tree_sitter_ast.py``.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tomllib

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime.identity import application_runtime_user
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_tree_sitter_ast import build_job
from appsec_review.jobs.job_tree_sitter_ast.normalize import NORMALIZER_SCHEMA
from appsec_review.jobs.job_tree_sitter_ast.scope_execution import _write_container_request
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner
from tests.test_tree_sitter_ast import FIXTURE, ROOT

DEFAULT_IMAGE = "appsec-review/tool-tree-sitter:1.0.0"
IMAGE = os.environ.get("APPSEC_TREE_SITTER_TEST_IMAGE", DEFAULT_IMAGE)


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        if subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True,
                          timeout=15).returncode != 0:
            return False
        lock = json.loads((ROOT / "containers" / "tools" / "tree-sitter" /
                           "assets.lock.json").read_text(encoding="utf-8"))
        expected = sorted(item["artifact"] for item in lock["grammars"])
        probe = subprocess.run(["docker", "run", "--rm", "--entrypoint", "python", IMAGE,
            "-c", "from pathlib import Path; print('\\n'.join(sorted(p.name for p in "
                  "Path('/opt/grammars').glob('*.so'))))"], capture_output=True, text=True,
            timeout=15)
        return probe.returncode == 0 and probe.stdout.splitlines() == expected
    except (OSError, subprocess.TimeoutExpired):
        return False


def _cataloged_docker_available() -> bool:
    return IMAGE == DEFAULT_IMAGE and _docker_available()


def test_live_container_parses_mult_project_multilanguage_fixture_and_proves_identity(tmp_path: Path) -> None:
    if not _docker_available():
        pytest.skip("locked Tree-sitter image is not locally available")
    catalog = tomllib.loads((ROOT / "containers" / "catalog.toml").read_text(encoding="utf-8"))
    cataloged = next(item for item in catalog["images"] if item["id"] == "tool-tree-sitter")
    inspected = subprocess.run(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"],
                               capture_output=True, text=True, check=True).stdout.strip()
    if IMAGE == DEFAULT_IMAGE:
        assert inspected == cataloged["image_id"]
    cases = [("C", "native/main.c"), ("C++", "native/main.cpp"),
             ("Rust", "rust/src/main.rs"), ("Go", "go/main.go"),
             ("Java", "java/Main.java"), ("JavaScript", "web/src/index.js"),
             ("TypeScript", "web/src/index.ts"), ("TSX", "web/src/view.tsx"),
             ("C#", "dotnet/Program.cs"),
             ("Python", "python/app.py"), ("PHP", "php/index.php"),
             ("Kotlin", "kotlin/Main.kt"), ("PowerShell", "powershell/main.ps1"),
             ("Ruby", "ruby/main.rb"), ("Shell", "shell/main.sh")]
    for language, relative in cases:
        payload = (FIXTURE / relative).read_bytes()
        request = {"schema": "appsec-review/tree-sitter-request/1", "scope_id": language.lower(),
                   "language": language, "max_nodes": 1000, "max_scope_nodes": 1000,
                   "max_file_bytes": 1024 * 1024,
                   "files": [{"path": relative, "sha256": hashlib.sha256(payload).hexdigest()}]}
        scratch = tmp_path / language.lower()
        _write_container_request(scratch, request)
        subprocess.run(["docker", "run", "--rm", "--network", "none", "--read-only",
            "--user", application_runtime_user("10001:10001"), "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--cpus", "2", "--memory", "1g", "--pids-limit", "256",
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=128m",
            "--mount", f"type=bind,src={FIXTURE},dst=/target,readonly",
            "--mount", f"type=bind,src={scratch},dst=/scratch", "--workdir", "/scratch", IMAGE,
            "parse", "--request", "/scratch/request.json", "--output", "/scratch/output.json"],
            capture_output=True, check=True, timeout=60)
        output = json.loads((scratch / "output.json").read_text(encoding="utf-8"))
        assert output["tool"] == {"architecture": "x86_64", "id": "tool-tree-sitter",
            "language_pack": "1.12.5", "normalizer_schema": NORMALIZER_SCHEMA,
            "tree_sitter": "0.26.0", "version": "1.0.0"}
        assert output["records"][0]["status"] == "SUCCEEDED"
        assert output["records"][0]["node_count"] > 1

    payload = (FIXTURE / "python/app.py").read_bytes()
    bounded = tmp_path / "bounded"
    _write_container_request(bounded, {
        "schema": "appsec-review/tree-sitter-request/1", "scope_id": "bounded",
        "language": "Python", "max_nodes": 1000, "max_scope_nodes": 1,
        "max_file_bytes": 1024 * 1024,
        "files": [{"path": "python/app.py", "sha256": hashlib.sha256(payload).hexdigest()}],
    })
    subprocess.run(["docker", "run", "--rm", "--network", "none", "--read-only",
        "--user", application_runtime_user("10001:10001"), "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--cpus", "2", "--memory", "1g", "--pids-limit", "256",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=128m",
        "--mount", f"type=bind,src={FIXTURE},dst=/target,readonly",
        "--mount", f"type=bind,src={bounded},dst=/scratch", "--workdir", "/scratch", IMAGE,
        "parse", "--request", "/scratch/request.json", "--output", "/scratch/output.json"],
        capture_output=True, check=True, timeout=60)
    bounded_output = json.loads((bounded / "output.json").read_text(encoding="utf-8"))
    assert bounded_output["records"][0]["status"] == "PARTIAL"
    assert bounded_output["records"][0]["node_count"] == 1


def test_real_graph_is_parallel_queryable_complete_and_resumable(tmp_path: Path) -> None:
    if not _cataloged_docker_available():
        pytest.skip("cataloged Tree-sitter image is not locally available")
    base = load_config(ROOT / "appsec-review.toml")
    runtime = replace(base.runtime, runs_dir=tmp_path / "runs", data_dir=tmp_path / "data",
                      metadata_dir=tmp_path / "metadata")
    config = replace(base, runtime=runtime)
    fingerprint = source_fingerprint(FIXTURE)
    jobs = (build_intake(), build_catalog(), build_job())
    outcome = GraphRunner(config, jobs).run(target_root=FIXTURE, source_fingerprint=fingerprint)
    published = outcome["jobs"]["job_tree_sitter_ast"]["result"]["outputs"][
        "acceptance.publish_handoff"]
    # Catalog gaps (including the explicit Bundler execution gap) keep the aggregate partial,
    # while Ruby's grammar scope itself must be successful.
    assert published["terminal_status"] == "PARTIAL"
    assert any(value.get("language") == "Ruby" and value.get("terminal_status") == "SUCCEEDED"
               for value in published["dispositions"])
    successful = [value for value in published["dispositions"] if "execution" in value]
    intervals = [(value["execution"]["started_at"], value["execution"]["completed_at"])
                 for value in successful if not value.get("index_reused")]
    assert any(start_a < end_b and start_b < end_a
               for index, (start_a, end_a) in enumerate(intervals)
               for start_b, end_b in intervals[index + 1:])
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    assert core.search(query="identifier", indexes=("analysis",), kinds=("ast_node",))["results"]
    assert not any("grammar unavailable" in gap
                   for gap in core.coverage(indexes=("analysis",))["coverage_gaps"])
    resumed = GraphRunner(config, jobs).run(target_root=FIXTURE, source_fingerprint=fingerprint,
                                            run_id=outcome["run_id"])
    assert [item["action"] for item in resumed["decisions"]] == ["REUSE", "REUSE", "REUSE"]
