"""Known-binary efficacy comparison for the Ghidra decompilation path.

A repository-owned fixture source is compiled into several variants with the pinned native
toolchain image, each variant is decompiled, and the publication is scored against what the
source is known to contain. The fixture is small, so one iteration takes seconds.

    python -m appsec_review.binary_decompilation.efficacy
    python -m appsec_review.binary_decompilation.efficacy --variant stripped --force
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import replace
import json
from pathlib import Path
import re
import sys
import time
import uuid
from typing import Any

from appsec_review.config import load_config
from appsec_review.config.binary_decompilation import BinaryRequest
from appsec_review.container_runtime import load_catalog
from appsec_review.container_runtime.executor import Runner, _default_runner
from appsec_review.storage import atomic_json, file_sha256

from .publication import load_table, verify_publication
from .runner import decompile_binary


EXPECTATIONS_SCHEMA = "appsec-review/binary-decompilation-expectations/1"
REPORT_SCHEMA = "appsec-review/binary-decompilation-efficacy/1"
EXPECTATIONS = Path("containers/fixtures/ghidra/expectations.json")
CHECK_KINDS = {"function", "import", "call", "string", "pseudo_c", "pcode_call", "decompile_coverage"}
_VARIANT = re.compile(r"[a-z][a-z0-9-]{0,31}")
_FLAG = re.compile(r"-[A-Za-z0-9][A-Za-z0-9_=,./+-]*")


def load_expectations(repository_root: Path) -> dict[str, Any]:
    document = json.loads((repository_root / EXPECTATIONS).read_text(encoding="utf-8"))
    if document.get("schema") != EXPECTATIONS_SCHEMA:
        raise ValueError("unsupported binary decompilation expectations schema")
    variants = document.get("variants")
    if not isinstance(variants, dict) or not variants:
        raise ValueError("expectations declare no variants")
    for name, variant in variants.items():
        if not _VARIANT.fullmatch(name):
            raise ValueError(f"invalid variant name: {name!r}")
        flags = [*document["build"]["common_flags"], *variant["flags"]]
        if any(not isinstance(flag, str) or not _FLAG.fullmatch(flag) for flag in flags):
            raise ValueError(f"variant {name} has an unsafe compiler flag")
        identifiers = [check.get("id") for check in variant["checks"]]
        if len(identifiers) != len(set(identifiers)) or not all(identifiers):
            raise ValueError(f"variant {name} needs unique check ids")
        for check in variant["checks"]:
            if check.get("kind") not in CHECK_KINDS:
                raise ValueError(f"variant {name} has an unknown check kind: {check.get('kind')!r}")
    return document


def fixture_argv(repository_root: Path, expectations: Mapping[str, Any], variant: str,
                 output_root: Path, image_id: str) -> tuple[list[str], str]:
    """The exact compile command for one variant, under the catalog runtime boundary."""
    catalog = load_catalog(repository_root)
    build = expectations["build"]
    tool = catalog.tool(build["tool_id"])
    source = (repository_root / expectations["source"]["fixture_path"]).resolve(strict=True)
    name = f"{expectations['fixture']}-{variant}"
    argv = [
        "docker", "run", "--rm", "--name", f"appsec-review-efficacy-{uuid.uuid4().hex}",
        "--network", "none", "--read-only", "--user", tool.user,
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--cpus", tool.cpus,
        "--memory", tool.memory, "--pids-limit", str(tool.pids_limit),
        "--tmpfs", str(catalog.policy["tmpfs"][0]), "--workdir", "/scratch",
        "--mount", f"type=bind,src={source.parent},dst=/target,readonly",
        "--mount", f"type=bind,src={output_root.resolve()},dst=/scratch",
        "--entrypoint", build["compiler"], image_id,
        *build["common_flags"], *expectations["variants"][variant]["flags"],
        "-o", f"/scratch/{name}", f"/target/{source.name}",
    ]
    return argv, name


def build_fixture(repository_root: Path, expectations: Mapping[str, Any], variant: str,
                  output_root: Path, *, runner: Runner | None = None) -> Path:
    """Compile one fixture variant offline and return the produced binary."""
    run = runner or _default_runner
    source = repository_root / expectations["source"]["fixture_path"]
    if file_sha256(source) != expectations["source"]["sha256"]:
        raise ValueError("fixture source does not match the hash recorded in the expectations")
    tool = load_catalog(repository_root).tool(expectations["build"]["tool_id"])
    inspected = run(("docker", "image", "inspect", tool.tag, "--format", "{{.Id}}"), 60)
    image_id = inspected.stdout.decode("utf-8", "replace").strip()
    if inspected.exit_code != 0 or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise RuntimeError(f"cataloged image is not locally available: {tool.tool_id}")
    output_root.mkdir(parents=True, exist_ok=True)
    output_root.chmod(0o777)  # the compiler runs as the fixed non-root container user
    argv, name = fixture_argv(repository_root, expectations, variant, output_root, image_id)
    binary = output_root / name
    binary.unlink(missing_ok=True)
    outcome = run(argv, tool.timeout_seconds)
    if outcome.timed_out:
        # Killing the docker client leaves the container running; remove it by name.
        run(("docker", "rm", "--force", argv[argv.index("--name") + 1]), 60)
    if outcome.exit_code != 0 or not binary.is_file():
        raise RuntimeError(f"fixture variant {variant} did not compile: "
                           + outcome.stderr.decode("utf-8", "replace")[-2000:])
    return binary


def _base(name: object) -> str:
    return str(name or "").rsplit("::", 1)[-1]


class Publication:
    """Read-only lookup helpers over one verified publication."""

    def __init__(self, root: Path):
        self.root = root
        self.manifest = verify_publication(root)
        self.functions = {row["address"]: row for row in load_table(root, "functions")}
        self.calls = load_table(root, "calls")
        self.imports = load_table(root, "imports")
        self.strings = load_table(root, "strings")

    def select(self, selector: Mapping[str, Any] | None) -> set[str]:
        """Function addresses matching ``{"name": ...}`` or ``{"calls": ...}``; ``None`` is all."""
        if selector is None:
            return set(self.functions)
        if "name" in selector:
            return {address for address, row in self.functions.items()
                    if _base(row.get("name")) == selector["name"] and not row.get("is_thunk")}
        if "calls" in selector:
            return {edge["from_function"] for edge in self.calls
                    if _base(edge.get("resolved_name")) == selector["calls"]
                    and not self.functions.get(edge["from_function"], {}).get("is_thunk")}
        raise ValueError(f"unknown function selector: {dict(selector)!r}")

    def names(self, addresses: set[str]) -> list[str]:
        return sorted(str(self.functions[address].get("name")) for address in addresses
                      if address in self.functions)

    def pseudo_c(self, address: str) -> str:
        entry = self.functions[address].get("pseudo_c")
        return (self.root / entry["path"]).read_text(encoding="utf-8") if entry else ""

    def pcode_callees(self, address: str) -> set[str]:
        entry = self.functions[address].get("pcode")
        if not entry:
            return set()
        with (self.root / entry["path"]).open(encoding="utf-8") as stream:
            operations = [json.loads(line) for line in stream]
        return {_base(item.get("callee")) for item in operations if item.get("mnemonic") == "CALL"}


def _evaluate_check(publication: Publication, check: Mapping[str, Any]) -> tuple[bool, Any]:
    kind = check["kind"]
    if kind == "function":
        found = publication.select({"name": check["name"]})
        return bool(found), sorted(found)
    if kind == "import":
        found = [row["name"] for row in publication.imports if row.get("name") == check["name"]]
        return bool(found), found
    if kind == "call":
        callers = publication.select(check.get("caller"))
        # An import stub "calls" its own import; only real functions count as callers.
        found = {edge["from_function"] for edge in publication.calls
                 if edge["from_function"] in callers and _base(edge.get("resolved_name")) == check["callee"]
                 and not publication.functions.get(edge["from_function"], {}).get("is_thunk")}
        return bool(found), publication.names(found)
    if kind == "string":
        functions = publication.select(check.get("referenced_by"))
        found: set[str] = set()
        present = False
        for row in publication.strings:
            if row.get("value") != check["value"]:
                continue
            present = True
            found |= {xref["function"] for xref in row.get("xrefs", []) if xref.get("function") in functions}
        passed = present and (bool(found) or "referenced_by" not in check)
        return passed, publication.names(found)
    if kind == "pseudo_c":
        found = {address for address in publication.select(check.get("function"))
                 if all(text in publication.pseudo_c(address) for text in check["contains"])}
        return bool(found), publication.names(found)
    if kind == "pcode_call":
        found = {address for address in publication.select(check.get("function"))
                 if check["callee"] in publication.pcode_callees(address)}
        return bool(found), publication.names(found)
    coverage = publication.manifest["coverage"]
    ratio = coverage["decompiled_functions"] / max(coverage["decompilable_functions"], 1)
    return ratio >= float(check["minimum"]), round(ratio, 4)


def evaluate(publication_root: Path, checks: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Score one verified publication. Optional checks are reported but do not affect the score."""
    publication = Publication(publication_root)
    results = []
    for check in checks:
        passed, observed = _evaluate_check(publication, check)
        results.append({"id": check["id"], "kind": check["kind"],
                        "required": check.get("required", True), "passed": passed, "observed": observed})
    required = [item for item in results if item["required"]]
    passed_count = sum(item["passed"] for item in required)
    return {
        "score": round(passed_count / max(len(required), 1), 4),
        "required_passed": passed_count, "required_total": len(required),
        "optional_passed": sum(item["passed"] for item in results if not item["required"]),
        "optional_total": len(results) - len(required),
        "checks": results,
        "coverage": publication.manifest["coverage"], "gaps": publication.manifest["gaps"],
    }


def run_efficacy(*, repository_root: Path, config_path: Path, work_root: Path,
                 variants: Sequence[str] | None = None, force: bool = False,
                 runner: Runner | None = None) -> dict[str, Any]:
    config = load_config(config_path)
    expectations = load_expectations(repository_root)
    selected = list(variants or expectations["variants"])
    unknown = sorted(set(selected) - set(expectations["variants"]))
    if unknown:
        raise ValueError("unknown fixture variants: " + ", ".join(unknown))
    settings = replace(config.binary_decompilation, binaries=())
    report: dict[str, Any] = {"schema": REPORT_SCHEMA, "fixture": expectations["fixture"],
                              "source": expectations["source"], "variants": {}}
    for variant in selected:
        started = time.monotonic()
        binary = build_fixture(repository_root, expectations, variant, work_root / "binaries", runner=runner)
        request = BinaryRequest(
            binary_id=f"{expectations['fixture']}-{variant}", path=binary, sha256=file_sha256(binary),
            authorization="repository-owned fixture compiled from " + expectations["source"]["fixture_path"])
        published = decompile_binary(repository_root=repository_root, data_dir=work_root,
                                     settings=settings, request=request, runner=runner, force=force)
        outcome = evaluate(Path(published["path"]), expectations["variants"][variant]["checks"])
        minimum = float(expectations["variants"][variant]["minimum_score"])
        report["variants"][variant] = {
            "binary_sha256": request.sha256, "identity": published["identity"],
            "publication": published["path"], "reused": published["reused"],
            "minimum_score": minimum, "accepted": outcome["score"] >= minimum,
            "elapsed_seconds": round(time.monotonic() - started, 3), **outcome,
        }
    report["accepted"] = all(item["accepted"] for item in report["variants"].values())
    atomic_json(work_root / "report.json", report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m appsec_review.binary_decompilation.efficacy",
                                     description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", default="appsec-review.toml")
    parser.add_argument("--variant", action="append", dest="variants",
                        help="fixture variant to run; repeatable; default is every variant")
    parser.add_argument("--force", action="store_true",
                        help="decompile again even when a verified publication exists")
    parser.add_argument("--work", type=Path,
                        help="work directory; default is <runs_dir>/binary-decompilation-efficacy")
    args = parser.parse_args(argv)
    config = load_config(args.config)
    work_root = (args.work or config.runtime.runs_dir / "binary-decompilation-efficacy").resolve()
    report = run_efficacy(repository_root=config.runtime.repository_root, config_path=Path(args.config),
                          work_root=work_root, variants=args.variants, force=args.force)
    for variant, outcome in report["variants"].items():
        print(f"{variant}: score={outcome['score']:.2f} required={outcome['required_passed']}/"
              f"{outcome['required_total']} optional={outcome['optional_passed']}/"
              f"{outcome['optional_total']} reused={outcome['reused']} "
              f"seconds={outcome['elapsed_seconds']}")
        for check in outcome["checks"]:
            mark = "PASS" if check["passed"] else ("FAIL" if check["required"] else "miss")
            print(f"  {mark:4} {check['id']} -> {json.dumps(check['observed'])}")
    print(f"report={work_root / 'report.json'}")
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    sys.exit(main())
