"""An offline review -> gate -> PoC job -> report chain for the job_poc_generation tests.

The scripted inference review runs over the fixture accepted index set (no model, container or network);
``poc_candidates`` is then written into the accepted review handoff exactly where the judge work will
produce it, the gate is run over that handoff, and ``job_poc_generation`` runs with injected edges: a
scripted writer, a recording fake build executor, an accepted-build lookup over a copy of cpp-multivuln
and a stub package view. The report then reads the PoC handoff when it exists.
"""
from __future__ import annotations

from copy import deepcopy
import dataclasses
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from types import SimpleNamespace
from typing import Any, Callable, Mapping, Sequence

from appsec_review.inference import ModelResult
from appsec_review.jobs.job_poc_generation import build_job as build_poc_job
from appsec_review.jobs.job_poc_generation.source import WriterAnswer, assemble
from appsec_review.storage import canonical_json
from tests import poc_support
from tests.final_report_support import (
    GATE, REPORT, job_tables, report_job, review_job, run_job,
)
from tests.fixtures.inference_review.acceptance import JOB, ROOT, write_config, write_overlay, write_scenario
from tests.fixtures.inference_review.builder import FixtureRun, build_accepted_index_set
from tests.fixtures.poc_generation import relay

POC = "job_poc_generation"
BASIS = {"entry": ["E1"], "path": ["F1", "F2"], "trigger": [relay.TRIGGER],
         "input_format": "4-byte header, then name bytes", "preconditions": ["attacker_controls_file_content"],
         "expected_observation": "a stack-buffer-overflow write in memcpy under a sanitizer", "unknowns": []}


def poc_tables(**overrides: int) -> str:
    """The repository configuration's ``[jobs.job_poc_generation...]`` tables, verbatim (comments included)."""
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    start = text.index("[jobs.job_poc_generation]\n")
    end = text.index("# Final report publication (docs/operations/final-report.md)")
    block = text[start:end]
    for key, value in overrides.items():
        assert f"\n{key} = " in block, key
        block = re.sub(rf"(?m)^{key} = .*$", f"{key} = {value}", block, count=1)
    return block


def stub_view(package, core, limits):
    """The labelled view a package would give the writer: the entry point and the call path the basis names."""
    return SimpleNamespace(document={
        "schema": "appsec-review/review-package-view/1",
        "neighborhood": {"chain": {"entries": [{"label": "E1", "ref": "asr:entry_point:" + "1" * 64,
                                                  "summary": "relay::main handles file input"}],
                                   "hops": [{"label": "F1", "ref": "asr:call_site:" + "2" * 64,
                                             "summary": "relay::main -> relay::parse_header (L12)"},
                                            {"label": "F2", "ref": "asr:call_site:" + "3" * 64,
                                             "summary": "relay::parse_header -> memcpy (L16)"}]}},
        "source": [{"label": "S1", "path": "src/packet.cpp", "lines": "7-18", "text": ["16|   std::memcpy(out.name...)"]}]},
        labels={"E1": "asr:entry_point:" + "1" * 64})


def sink_of(package):
    return {"name": relay.SINK, "path": "src/packet.cpp", "line": 7, "symbol": "asr:symbol:" + "4" * 64}


class Writer:
    """A scripted model keyed by claim: ``scripts[claim_id]`` is that claim's list of turns."""

    def __init__(self, scripts: Mapping[str, Sequence[Any]]) -> None:
        self.scripts = {claim: list(turns) for claim, turns in scripts.items()}
        self.requests: list[Any] = []

    def __call__(self, request, *, timeout_seconds):
        self.requests.append(request)
        claim = request.cell_id.removeprefix("poc-writer:")
        turn = self.scripts[claim].pop(0)
        if isinstance(turn, BaseException):
            raise turn
        return ModelResult(proposal=turn, input_tokens=120, output_tokens=40, raw_response=json.dumps(turn))


def ast_by_source(text: str) -> Mapping[str, Any]:
    """The recorded reduced AST that matches the generated file (the fake build image's clang)."""
    for name, (test, control, _rule) in relay.VARIANTS.items():
        if name != "syntax_error" and f"{test.strip()}\n\n{control.strip()}" in text:
            return poc_support.ast_document(name)
    raise AssertionError("no recorded AST matches the generated PoC file")


@dataclass
class PocChain:
    base: Path
    fixture: FixtureRun
    config: Path
    env: Mapping[str, str]
    snapshot: Path
    findings: list[dict[str, Any]]
    packages: list[str]
    schema_root: Path | None = None
    built: dict[str, Any] = field(default_factory=dict)

    @property
    def run_root(self) -> Path:
        return self.fixture.run_root

    @property
    def workspace(self) -> Path:
        return self.base.parent / f"{self.base.name}-accepted-workspace"

    def restore(self) -> None:
        shutil.rmtree(self.base)
        shutil.copytree(self.snapshot, self.base)

    def pointer(self, job_id: str) -> dict[str, str]:
        return json.loads((self.run_root / "data" / "jobs" / job_id / "latest.json").read_text(encoding="utf-8"))

    def handoff(self, job_id: str) -> dict[str, Any]:
        return json.loads((self.run_root / self.pointer(job_id)["handoff_path"]).read_text(encoding="utf-8"))

    def upstream(self, job_id: str) -> dict[str, str]:
        return {job_id: self.pointer(job_id)["handoff_sha256"]} if (
            self.run_root / "data" / "jobs" / job_id / "latest.json").exists() else {}

    def unit_file(self, job_id: str, unit: str, name: str) -> Path:
        attempts = self.run_root / "data" / "jobs" / job_id / "attempts"
        step, task = unit.split(".")
        return sorted(attempts.iterdir())[-1] / "steps" / step / "tasks" / task / name

    def read(self, job_id: str, unit: str, name: str) -> Any:
        return json.loads(self.unit_file(job_id, unit, name).read_text(encoding="utf-8"))

    # -- the candidates --------------------------------------------------------------------------------
    def candidate(self, index: int, *, state: str | None = None, verdict: str = "red_correct",
                  basis: Mapping[str, Any] | None = None, **changes: Any) -> dict[str, Any]:
        finding = self.findings[index]
        value = deepcopy(dict(basis if basis is not None else BASIS))
        entry = {"claim_id": finding["claim_id"], "package_id": self.packages[index % len(self.packages)],
                 "state": state or finding["state"], "judge_verdict": verdict,
                 "poc_basis": {"sha256": hashlib.sha256(canonical_json(value)).hexdigest(), "value": value},
                 "finding_package": {"finding_package_id": finding["finding_package_id"],
                                     "sha256": finding["sha256"]},
                 "evidence_refs": ["asr:sink_site:" + f"{index + 1}" * 64]}
        entry.update(changes)
        return entry

    def prepare(self, candidates: Sequence[Mapping[str, Any]] | None) -> None:
        """Restore the accepted review, write ``poc_candidates`` into its handoff and run the gate over it."""
        self.restore()
        if candidates is not None:
            self.inject(candidates)
        from appsec_review.jobs.job_final_publication_gate import build_job as build_gate

        run_job(self.config, build_gate(repository_root=self.schema_root), self.fixture.run_id,
                self.upstream(JOB), self.env)

    def inject(self, candidates: Sequence[Mapping[str, Any]]) -> None:
        pointer_path = self.run_root / "data" / "jobs" / JOB / "latest.json"
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        handoff_path = self.run_root / pointer["handoff_path"]
        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        artifact = handoff["outputs"]["publication.publish_handoff"]["artifact"]
        review_path = self.run_root / artifact["path"]
        review = json.loads(review_path.read_text(encoding="utf-8"))
        review["poc_candidates"] = [dict(item) for item in candidates]
        payload = canonical_json(review)
        review_path.write_bytes(payload)
        artifact["sha256"], artifact["size_bytes"] = hashlib.sha256(payload).hexdigest(), len(payload)
        handoff_path.write_bytes(canonical_json(handoff))
        pointer["handoff_sha256"] = hashlib.sha256(handoff_path.read_bytes()).hexdigest()
        pointer_path.write_text(json.dumps(pointer, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    # -- the job -----------------------------------------------------------------------------------------
    def job(self, writer: Callable[..., Any] | None = None, executor: Any = None, *, unit_kwargs=None,
            infer: Callable[..., Any] | None = None, **edges: Any):
        executor = executor or poc_support.FakeExecutor(ast_by_source)
        workspace, manifest = self.built.get("workspace") or poc_support.relay_workspace(self.workspace)
        self.built["workspace"] = (workspace, manifest)
        unit = poc_support.relay_unit(workspace, manifest, **(unit_kwargs or {}))
        self.built.update(executor=executor, unit=unit)
        return build_poc_job(infer=infer or writer, executor_factory=lambda _unit, _profile: executor,
                             builds_factory=lambda _root: poc_support.builds(unit), view_factory=stub_view,
                             sink_resolver=sink_of, repository_root=ROOT, **edges)

    def run_poc(self, writer, executor=None, *, env: Mapping[str, str] | None = None, **kwargs):
        job = self.job(writer, executor, **kwargs)
        return run_job(self.config, job, self.fixture.run_id, self.upstream(GATE), {**self.env, **dict(env or {})})

    def run_report(self):
        upstream = self.upstream(POC) or self.upstream(GATE)
        return run_job(self.config, report_job(), self.fixture.run_id, upstream, self.env)

    def summary(self) -> dict[str, Any]:
        return self.read(POC, "publish.publish_handoff", "poc-generation.json")

    def rows(self) -> dict[str, dict[str, Any]]:
        return {row["claim_id"]: row for row in self.summary()["candidates"]}


def schema_root_with_candidates(directory: Path, exist_ok: bool = False) -> Path:
    """A repository root whose review handoff schema already allows ``poc_candidates``.

    The handoff schema belongs to the judge work; until it adds the property the gate would refuse a handoff
    that carries it, so the tests give the gate a copy of the schemas that has it. The PoC job itself runs
    against the repository's own schemas and does not need this.
    """
    target = directory / "docs" / "schemas"
    if exist_ok and target.exists():
        return directory
    shutil.copytree(ROOT / "docs" / "schemas" / "inference-security-review", target / "inference-security-review")
    shutil.copytree(ROOT / "docs" / "schemas" / "final-report", target / "final-report")
    path = target / "inference-security-review" / "handoff.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    schema["properties"]["poc_candidates"] = {"type": "array", "maxItems": 10000}
    path.write_text(json.dumps(schema, indent=2), encoding="utf-8")
    return directory


def build_chain(base: Path, logs: Path, **settings: int) -> PocChain:
    """The scripted inference review over the fixture index; its accepted state is the snapshot.

    ``POC_TEST_CHAIN`` names a fixed directory that keeps the finished review between runs of the test
    suite (a development convenience: the review takes minutes); without it every call builds afresh.
    """
    kept = os.environ.get("POC_TEST_CHAIN")
    if kept:
        base, logs = Path(kept) / "review", Path(kept) / "logs"
        meta = Path(kept) / "meta.json"
        if meta.is_file() and json.loads(meta.read_text(encoding="utf-8")).get("settings") == settings:
            return load_chain(base, meta)
    chain = _build_chain(base, logs, **settings)
    if kept:
        record = {"fixture": {item.name: (str(getattr(chain.fixture, item.name)) if isinstance(
            getattr(chain.fixture, item.name), Path) else getattr(chain.fixture, item.name))
            for item in dataclasses.fields(chain.fixture)},
                  "settings": settings, "config": str(chain.config), "env": dict(chain.env),
                  "findings": chain.findings,
                  "packages": chain.packages}
        (Path(kept) / "meta.json").write_text(json.dumps(record), encoding="utf-8")
    return chain


def load_chain(base: Path, meta: Path) -> PocChain:
    record = json.loads(meta.read_text(encoding="utf-8"))
    types = {item.name: item.type for item in dataclasses.fields(FixtureRun)}
    fixture = FixtureRun(**{name: (Path(value) if "Path" in str(types[name]) else value)
                            for name, value in record["fixture"].items()})
    chain = PocChain(base, fixture, Path(record["config"]), record["env"], base.parent / f"{base.name}-snapshot",
                     record["findings"], record["packages"],
                     schema_root_with_candidates(base.parent / f"{base.name}-repository", exist_ok=True))
    chain.restore()
    return chain


def _build_chain(base: Path, logs: Path, **settings: int) -> PocChain:
    shutil.rmtree(base, ignore_errors=True)
    base.mkdir(parents=True)
    logs.mkdir(parents=True, exist_ok=True)
    fixture = build_accepted_index_set(base)
    config = write_config(base, fixture.runs_dir, extra=job_tables(GATE) + job_tables(REPORT) + poc_tables(**settings))
    env = {"APPSEC_REVIEW_CONFIG_OVERLAY": str(write_overlay(base, 1)), "APPSEC_C7_CONFIG": str(config),
           "APPSEC_C7_SCENARIO": str(write_scenario(logs, fixture.ids, calls=str(logs / "calls.jsonl"),
                                                    captures=str(logs / "captures")))}
    run_job(config, review_job(), fixture.run_id, env=env)
    chain = PocChain(base, fixture, config, env, base.parent / f"{base.name}-snapshot", [], [],
                     schema_root_with_candidates(base.parent / f"{base.name}-repository"))
    handoff = chain.handoff(JOB)
    review = json.loads((fixture.run_root / handoff["outputs"]["publication.publish_handoff"]["artifact"]["path"]
                         ).read_text(encoding="utf-8"))
    findings = []
    for item in review["finding_packages"]:
        path = (fixture.run_root / handoff["outputs"]["publication.publish_handoff"]["artifact"]["path"]).parent / \
            "findings" / f"{item['finding_package_id']}.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        findings.append({"finding_package_id": item["finding_package_id"], "sha256": item["sha256"],
                         "claim_id": document["claim_id"], "state": document["state"]})
    chain.findings = sorted(findings, key=lambda item: (item["state"] != "confirmed", item["claim_id"]))
    packages = []
    for lane in ("lead", "hunt"):
        document = json.loads((fixture.run_root / handoff["outputs"][f"packages.assemble_{lane}_packages"][
            "artifact"]["path"]).read_text(encoding="utf-8"))
        packages.extend(record["package_id"] for record in document["packages"])
    chain.packages = sorted(packages)
    shutil.copytree(base, chain.snapshot)
    return chain


def good_turns() -> list[Any]:
    return [relay.answer()]


def answer_for(claim_id: str, test: str, control: str, **kwargs: Any) -> tuple[str, dict[str, Any]]:
    return claim_id, relay.answer(test, control, **kwargs)


def generated_text(claim_id: str, package_id: str, test: str, control: str, settings=None) -> str:
    answer = WriterAnswer.from_result(relay.answer(test, control)["result"])
    return assemble(answer, settings or poc_support.settings(), claim_id=claim_id, package_id=package_id)
