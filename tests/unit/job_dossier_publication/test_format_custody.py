"""Private receipt custody across actual dossier and report producers; no external execution."""
from types import SimpleNamespace

import pytest

from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound, read_bound_json
from appsec_review.jobs.job_dossier_publication.job import build_job as dossier_job, verify_publication
from appsec_review.jobs.job_final_publication_gate.attachments import _dossiers
from appsec_review.jobs.job_final_report_publication import build_job as report_job
from appsec_review.jobs.job_final_report_publication.pdf import bind_dossiers
from appsec_review.jobs.job_final_report_publication.report import build_report
from appsec_review.reporting.dossier_render import render_dossier
from appsec_review.review.models import IntegrityError
from appsec_review.storage import atomic_bytes, atomic_json
from tests.unit.job_dossier_publication.test_coverage_edges import _ctx, _seed_env
from tests.unit.job_final_report_publication.test_job_units import EXCERPT, _setup_run, run_units
from tests.unit.job_final_report_publication.test_report_and_render import _validator
from tests.dossier_fixture import ROOT, make_model, settings

CURRENT = "appsec-review/dossier-rendering-receipt/2"
LEGACY = "appsec-review/dossier-rendering-receipt/1"
PUBLIC_FILES = {"json", "latex", "pdf", "receipt"}


def _summary(fx):
    return read_bound_json(fx.root, fx.verified["capabilities"]["dossiers"]["summary"])


def _gate_rows(fx, summary, bindings):
    return _dossiers(fx.root, summary, {row["finding_package_id"]: row for row in fx.verified["packages"]},
                     [], bindings)


def _repin_receipt(fx, item, receipt):
    path = fx.root / item["files"]["receipt"]["path"]
    atomic_json(path, receipt)
    item["files"]["receipt"] = artifact_ref(fx.root, path)


def test_real_dossier_publication_retains_private_formats_without_public_map_expansion(tmp_path, monkeypatch):
    env = _seed_env(tmp_path, monkeypatch)
    core = SimpleNamespace(read_excerpt=lambda **_: {
        "results": env.source["excerpts"], "coverage_gaps": [], "truncated": False,
    })
    built = dossier_job(review_loader=lambda *_a, **_kw: SimpleNamespace(document=env.verified),
                        core_factory=lambda *_: core)
    result = built.execute(_ctx(env.root))
    assert not result["failed_units"]
    summary = read_bound_json(env.root, result["outputs"]["acceptance.publish_handoff"]["artifact"])
    assert len(summary["items"]) == 2
    verify_publication(env.root, summary)
    bindings = []
    _dossiers(env.root, summary, {env.binding["finding_package_id"]: env.source["finding"]},
              [env.source["poc"]], bindings)
    for item in summary["items"]:
        assert set(item["files"]) == PUBLIC_FILES
        receipt = read_bound_json(env.root, item["files"]["receipt"])
        assert receipt["schema"] == CURRENT
        assert set(receipt["additional_formats"]) == {"markdown", "html"}
        for ref in receipt["additional_formats"].values():
            assert ref in bindings
            assert read_bound(env.root, ref)


def test_report_lists_only_receipt_certified_format_refs_and_preserves_legacy_public_schemas(tmp_path, monkeypatch):
    fx = _setup_run(tmp_path, monkeypatch, dossier=True, render_pdf=False)
    outputs = run_units(fx, report_job(executor_factory=lambda *_: pytest.fail("PDF disabled")))
    publication = outputs["acceptance.publish_handoff"]
    report = read_bound_json(fx.root, publication["artifact"])
    _validator("final-publication-gate").validate(fx.gate)
    _validator("final-report-v4").validate(report)
    item, = report["dossiers"]["items"]
    assert set(item["files"]) == PUBLIC_FILES
    receipt = read_bound_json(fx.root, item["files"]["receipt"])
    assert "SECRET_EXCERPT" in read_bound(fx.root, receipt["additional_formats"]["html"]).decode()
    markdown = read_bound(fx.root, publication["markdown"]).decode()
    html = read_bound(fx.root, publication["html"]).decode()
    for ref in receipt["additional_formats"].values():
        assert ref in fx.gate["bindings"]
        assert ref["path"] in markdown and ref["sha256"] in markdown
        assert ref["path"] in html and ref["sha256"] in html
    assert EXCERPT not in markdown and EXCERPT not in html


@pytest.mark.parametrize("key,filename", [("artifact", "final-report.md"), ("html", "final-report.html")])
def test_report_publication_reproves_receipt_linked_listings(tmp_path, monkeypatch, key, filename):
    fx = _setup_run(tmp_path, monkeypatch, dossier=True, render_pdf=False)
    built = report_job(executor_factory=lambda *_: pytest.fail("PDF disabled"))
    outputs = run_units(fx, built)
    item, = fx.gate["attachments"]["dossiers"]
    receipt = read_bound_json(fx.root, item["files"]["receipt"])
    digest = receipt["additional_formats"]["markdown"]["sha256"].encode()
    rendered = outputs["report.render"]
    path = fx.root / rendered[key]["path"]
    data = read_bound(fx.root, rendered[key])
    assert digest in data
    atomic_bytes(path, data.replace(digest, b"0" * 64))
    rendered[key] = artifact_ref(fx.root, path)
    with pytest.raises(IntegrityError, match=filename.replace(".", r"\.") + " is not the rendering"):
        built.units[-1].handler(fx.unit("acceptance.publish_handoff", outputs))


@pytest.mark.parametrize("format", ["markdown", "html"])
@pytest.mark.parametrize("damage", ["changed", "missing"])
def test_claimed_sidecars_fail_at_publication_gate_and_report(tmp_path, monkeypatch, format, damage):
    fx = _setup_run(tmp_path, monkeypatch, dossier=True, render_pdf=False)
    summary = _summary(fx)
    item, = summary["items"]
    receipt = read_bound_json(fx.root, item["files"]["receipt"])
    ref = receipt["additional_formats"][format]
    path = fx.root / ref["path"]
    if damage == "changed":
        atomic_bytes(path, b"tampered")
    else:
        path.unlink()
    with pytest.raises(IntegrityError, match="changed after acceptance|missing"):
        verify_publication(fx.root, summary)
    with pytest.raises(IntegrityError, match="changed after acceptance|missing"):
        _gate_rows(fx, summary, [])
    report = build_report(fx.gate, gate_handoff={"path": fx.accepted.path, "sha256": fx.accepted.sha256},
                          gate_document=fx.gate_ref)
    with pytest.raises(IntegrityError, match="changed after acceptance|missing"):
        bind_dossiers(fx.root, report, fx.gate["bindings"])


@pytest.mark.parametrize("format", ["markdown", "html"])
def test_rehashed_wrong_format_is_not_a_valid_rendering(tmp_path, monkeypatch, format):
    fx = _setup_run(tmp_path, monkeypatch, dossier=True, render_pdf=False)
    summary = _summary(fx)
    item, = summary["items"]
    receipt = read_bound_json(fx.root, item["files"]["receipt"])
    path = fx.root / receipt["additional_formats"][format]["path"]
    atomic_bytes(path, b"not the rendering of the published dossier")
    receipt["additional_formats"][format] = artifact_ref(fx.root, path)
    _repin_receipt(fx, item, receipt)
    with pytest.raises(IntegrityError, match="not the.*rendering"):
        verify_publication(fx.root, summary)
    with pytest.raises(IntegrityError, match="not the.*rendering"):
        _gate_rows(fx, summary, [])


@pytest.mark.parametrize("damage", ["missing", "null", "extra", "root-extra", "unknown-version", "downgrade"])
def test_private_receipt_version_and_complete_closed_format_map_are_enforced(tmp_path, monkeypatch, damage):
    fx = _setup_run(tmp_path, monkeypatch, dossier=True, render_pdf=False)
    summary = _summary(fx)
    item, = summary["items"]
    receipt = read_bound_json(fx.root, item["files"]["receipt"])
    if damage == "missing":
        del receipt["additional_formats"]["html"]
    elif damage == "null":
        receipt["additional_formats"]["html"] = None
    elif damage == "extra":
        receipt["additional_formats"]["other"] = receipt["additional_formats"]["html"]
    elif damage == "root-extra":
        receipt["unexpected"] = True
    else:
        receipt["schema"] = LEGACY if damage == "downgrade" else "unsupported/1"
    _repin_receipt(fx, item, receipt)
    with pytest.raises(IntegrityError, match="receipt"):
        verify_publication(fx.root, summary)
    with pytest.raises(IntegrityError, match="receipt"):
        _gate_rows(fx, summary, [])


@pytest.mark.parametrize("removed", ["receipt", "markdown", "html"])
def test_report_requires_receipt_and_additional_format_gate_membership(tmp_path, monkeypatch, removed):
    fx = _setup_run(tmp_path, monkeypatch, dossier=True, render_pdf=False)
    item, = fx.gate["attachments"]["dossiers"]
    receipt = read_bound_json(fx.root, item["files"]["receipt"])
    ref = item["files"]["receipt"] if removed == "receipt" else receipt["additional_formats"][removed]
    bindings = [row for row in fx.gate["bindings"] if row != ref]
    report = build_report(fx.gate, gate_handoff={"path": fx.accepted.path, "sha256": fx.accepted.sha256},
                          gate_document=fx.gate_ref)
    with pytest.raises(IntegrityError, match="not bound"):
        bind_dossiers(fx.root, report, bindings)


def test_legacy_receipt_never_discovers_or_certifies_unclaimed_sidecars(tmp_path, monkeypatch):
    fx = _setup_run(tmp_path, monkeypatch, dossier=True, render_pdf=False)
    summary = _summary(fx)
    item, = summary["items"]
    receipt = read_bound_json(fx.root, item["files"]["receipt"])
    unclaimed = receipt.pop("additional_formats")
    receipt["schema"] = LEGACY
    _repin_receipt(fx, item, receipt)
    for ref in unclaimed.values():
        atomic_bytes(fx.root / ref["path"], b"unclaimed bytes must not be discovered")
    verify_publication(fx.root, summary)
    bindings = [ref for ref in fx.verified["inputs"].values()]
    rows = _gate_rows(fx, summary, bindings)
    assert not any(ref in bindings for ref in unclaimed.values())
    report = build_report(fx.gate, gate_handoff={"path": fx.accepted.path, "sha256": fx.accepted.sha256},
                          gate_document=fx.gate_ref)
    report["dossiers"]["items"] = rows
    dossiers = bind_dossiers(fx.root, report, bindings)
    from appsec_review.jobs.job_final_report_publication.render import render_markdown
    from appsec_review.reporting.executive_report import render_executive_html
    formats = {row.dossier_id: row.additional_formats for row in dossiers}
    markdown = render_markdown(report, evidence_ids=8, gap_ids=16, dossier_formats=formats)
    html = render_executive_html(report, dossiers)
    assert "legacy receipt" in markdown.lower() and "not certified" in markdown.lower()
    assert "legacy receipt" in html.lower() and "not certified" in html.lower()
    for ref in unclaimed.values():
        assert ref["path"] not in markdown and ref["path"] not in html
    assert "unclaimed bytes" not in markdown and "unclaimed bytes" not in html


@pytest.mark.parametrize("filename", ["dossier.md", "dossier.html"])
def test_writer_does_not_repin_formats_changed_during_external_rendering(tmp_path, filename):
    root = tmp_path / "run"
    model = make_model(root)
    output = root / "data" / "rendered"

    class Renderer:
        def execute(self, _request):
            atomic_bytes(output / filename, b"changed during renderer execution")
            return SimpleNamespace(receipt_path="data/no-execution.json", exit_code=1, timed_out=False,
                                   oom_killed=False, file_size_limit_reached=False, terminal_status="FAILED")

    with pytest.raises(IntegrityError, match="changed after acceptance"):
        render_dossier(root, output, model, settings=settings(), repository_root=ROOT,
                       executor_factory=lambda *_: Renderer())
