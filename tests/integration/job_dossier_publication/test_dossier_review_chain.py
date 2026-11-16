from __future__ import annotations

from types import SimpleNamespace

import pytest

from appsec_review.jobs.accepted_review import load_accepted_review
from appsec_review.jobs.bound_artifacts import read_bound_json
from appsec_review.jobs.job_dossier_publication import JOB_ID, build_job, inputs
from appsec_review.jobs.job_dossier_publication.job import TOPOLOGY
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.observability import EventLog
from appsec_review.runtime import JobContext
from tests.dossier_fixture import ROOT, settings
from tests.final_report_support import run_review_chain

pytestmark = pytest.mark.integration


def _context(fixture, name="a", **overrides):
    config = SimpleNamespace(
        settings=settings(**{"render_pdf": False, **overrides}).identity(),
        steps=TOPOLOGY,
        step=lambda key: SimpleNamespace(tasks=TOPOLOGY[key]),
    )
    attempt = fixture.root / "data" / "jobs" / JOB_ID / "attempts" / name
    attempt.mkdir(parents=True, exist_ok=True)
    return JobContext(
        run_id=fixture.root.name,
        attempt_id=name,
        trigger="test",
        repository_root=ROOT,
        run_root=fixture.root,
        attempt_root=attempt,
        metadata_root=attempt,
        orchestration={},
        config=config,
        events=EventLog(attempt / "events.jsonl"),
    )


def test_real_accepted_review_reader_to_dossier_models(tmp_path):
    chain = run_review_chain(tmp_path / "c", tmp_path / "l")
    verified = load_accepted_review(chain.run_root, SchemaSet(ROOT / SCHEMA_DIRECTORY), max_packages=10000)
    document = inputs.load_inputs(chain.run_root, verified.document, settings())
    assert document["run_id"] == chain.fixture.run_id
    assert document["source_manifest"]["sha256"] == verified.document["review"]["accepted_manifest_sha256"]
    fixture = SimpleNamespace(root=chain.run_root, verified=verified.document)
    result = build_job(repository_root=ROOT).execute(_context(fixture))
    assert not result["failed_units"], result
    publication = result["outputs"]["acceptance.publish_handoff"]
    summary = read_bound_json(fixture.root, publication["artifact"])
    confirmed = sum(row["state"] == "confirmed" for row in verified.document["packages"])
    assert summary["counts"]["items"] == confirmed
    assert all(item["kind"] == "confirmed_finding" for item in summary["items"])
