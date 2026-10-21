"""Record the reduced clang ASTs under ``ast/`` from the local build image (run by hand, committed once).

    cd ~/projects/appsec-review-pocjob
    PYTHONPATH=src:. ~/projects/appsec-review/.venv/bin/python tests/fixtures/poc_generation/record_ast.py [name ...]

For each variant of ``relay.VARIANTS`` this writes the PoC file the job would generate, runs the job's own
AST step (``buildcheck.ast_step``: the in-image reducer around ``clang++ -fsyntax-only -Xclang
-ast-dump=json``) through the production ``BuildContainerExecutor`` and stores the ``poc-ast/1`` document.
The workspace is a copy of ``targets/cpp-multivuln`` under ``test/tmp/``. The documents are small (the
reducer drops every header node) and contain no host paths beyond ``/workspace``.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys

from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile
from appsec_review.jobs.job_poc_generation import buildcheck
from appsec_review.jobs.job_poc_generation.source import WriterAnswer, assemble
from tests import poc_support
from tests.fixtures.poc_generation import relay

TAG = "audit-buildenv-cpp:local"
EXTRA_INCLUDES = {"ifstream": ("fstream",), "system_call": ("cstdlib",), "getenv_call": ("cstdlib",),
                  "unlisted_call": ("cstdlib",), "huge_vector": ("vector",)}
OUT = Path(__file__).parent / "ast"


def image_id() -> str:
    return subprocess.run(["docker", "image", "inspect", TAG, "--format", "{{.Id}}"], check=True,
                          capture_output=True, text=True, timeout=60).stdout.strip()


def main(names: list[str]) -> int:
    root = Path("test") / "tmp" / "poc-record"
    root.mkdir(parents=True, exist_ok=True)
    workspace, manifest = poc_support.relay_workspace(root / "workspace", with_objects=False)
    settings = poc_support.settings()
    identity = image_id()
    unit = poc_support.relay_unit(workspace, manifest, image_id=identity, tag=TAG)
    executor = BuildContainerExecutor(BuildProfile("native", TAG, identity, "10001:10001"), timeout_seconds=300,
                                      output_bytes=8 * 1024 * 1024, network="none")
    executor.resolve()
    builds = poc_support.builds(unit)
    OUT.mkdir(exist_ok=True)
    for name, (test, control, _rule) in relay.VARIANTS.items():
        if names and name not in names:
            continue
        includes = (*relay.INCLUDES, *EXTRA_INCLUDES.get(name, ()))
        answer = WriterAnswer.from_result(relay.answer(test, control, includes=includes)["result"])
        text = assemble(answer, settings, claim_id="claim-" + "0" * 64, package_id="finding_lead-" + "0" * 64)
        scratch = buildcheck.prepare(builds, unit, root / "scratch", name=name, poc_text=text, settings=settings)
        try:
            step = buildcheck.ast_step(executor, unit, scratch, settings)
            document, why = buildcheck.reduced_ast(step)
        finally:
            shutil.rmtree(scratch.root, ignore_errors=True)
        if document is None:
            print(f"{name}: no document ({why})")
            continue
        # The recorded source path is the in-image path of the generated file; keep it as the policy sees it.
        (OUT / f"{name}.json").write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        print(f"{name}: exit {document['compiler_exit_code']}, {len(document['nodes'])} nodes, "
              f"{len(json.dumps(document))} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
