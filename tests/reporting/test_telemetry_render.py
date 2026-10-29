from __future__ import annotations

import json
from pathlib import Path
import tomllib

import pytest

from appsec_review.config.telemetry_report import TelemetryReportSettings, parse_telemetry_report
from appsec_review.container_runtime.executor import CommandOutcome, ContainerExecutor
from appsec_review.reporting.telemetry_render import RECEIPT_SCHEMA, REPORT_PATH, render_telemetry_report
from appsec_review.storage import canonical_json

from .telemetry_fixture import build_telemetry_run

ROOT = Path(__file__).resolve().parents[2]
PDF = b"%PDF-1.5\n" + b"synthetic telemetry report " * 4 + b"\n%%EOF\n"
SETTINGS = TelemetryReportSettings()


def executor_factory(seen, *, status=0, pdf=PDF, timed_out=False, logs=True):
    class FixtureExecutor(ContainerExecutor):
        def _docker_bind_source(self, path):
            return path

    def factory(catalog, root):
        def runner(argv, timeout):
            if argv[1:3] == ("image", "inspect"):
                return CommandOutcome(0, SETTINGS.image_id.encode(), b"")
            if "run" in argv:
                seen.append(tuple(argv))
                mounts = [argv[i + 1] for i, value in enumerate(argv) if value == "--mount"]
                spec = next(item for item in mounts if "dst=/scratch" in item)
                scratch = Path(spec.split("src=", 1)[1].split(",dst=")[0])
                if pdf is not None:
                    (scratch / "report.pdf").write_bytes(pdf)
                if logs:
                    (scratch / "report.log").write_bytes(b"xelatex log\n")
                    (scratch / "report.pdfinfo.txt").write_bytes(b"Pages: 3\n")
            return CommandOutcome(status, b"out", b"err", timed_out=timed_out)
        return FixtureExecutor(catalog, root, runner=runner)
    return factory


def _evidence(run: Path) -> dict[str, bytes]:
    return {name: (run / name).read_bytes()
            for name in ("data/logs/pipeline.jsonl", "data/telemetry/summary.json")}


def _receipt(run: Path) -> dict:
    data = (run / REPORT_PATH / "receipt.json").read_bytes()
    assert data == canonical_json(json.loads(data))
    return json.loads(data)


def test_rendered_report_writes_all_files_hashes_pin_and_epoch(tmp_path):
    run = build_telemetry_run(tmp_path)
    before = _evidence(run)
    seen = []
    result = render_telemetry_report(run, SETTINGS, repository_root=ROOT, executor_factory=executor_factory(seen))
    report = run / REPORT_PATH
    assert result.status == "rendered" and result.report_dir == report
    assert sorted(p.name for p in report.iterdir()) == [
        "receipt.json", "report.log", "report.pdfinfo.txt", "telemetry-report.pdf", "telemetry-report.tex"]
    receipt = _receipt(run)
    assert receipt == dict(result.record)
    assert receipt["schema"] == RECEIPT_SCHEMA and receipt["run_id"] == run.name
    assert receipt["pdf_sha256"] == hashlib_sha256(report / "telemetry-report.pdf")
    assert receipt["tex_sha256"] == hashlib_sha256(report / "telemetry-report.tex")
    assert receipt["summary_source"] == "summary.json"
    assert receipt["summary_sha256"] == hashlib_sha256(run / "data/telemetry/summary.json")
    assert receipt["events_sha256"] == hashlib_sha256(run / "data/logs/pipeline.jsonl")
    assert receipt["tool"]["image_id"] == SETTINGS.image_id and receipt["tool"]["image_tag"] == SETTINGS.image_tag
    assert receipt["template"]["sha256"] and receipt["renderer"]
    assert not any(gap.startswith("telemetry_report_") for gap in receipt["named_gaps"])
    command = seen[0]
    epoch = receipt["source_date_epoch"]
    assert epoch > 0 and f"SOURCE_DATE_EPOCH={epoch}" in command
    assert command[command.index("--network") + 1] == "none"
    mounts = [command[i + 1] for i, arg in enumerate(command) if arg == "--mount"]
    assert any("dst=/template,readonly" in m for m in mounts) and any("dst=/input,readonly" in m for m in mounts)
    assert not [p for p in report.parent.iterdir() if p.name.startswith(".report-")]
    assert _evidence(run) == before


def hashlib_sha256(path: Path) -> str:
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("kwargs,gap", [
    ({"status": 1, "pdf": None}, "telemetry_report_render_failed"),
    ({"status": 0, "pdf": b"%PDF-1.7\n" + b"x" * 40}, "telemetry_report_pdf_invalid"),
    ({"status": 0, "pdf": b"not a pdf at all, but long enough to pass the size floor"}, "telemetry_report_pdf_invalid"),
    ({"status": None, "pdf": None, "timed_out": True}, "telemetry_report_render_timeout"),
])
def test_render_failures_are_named_gaps_and_run_evidence_is_untouched(tmp_path, kwargs, gap):
    run = build_telemetry_run(tmp_path, outcome="FAILED")
    before = _evidence(run)
    result = render_telemetry_report(run, SETTINGS, repository_root=ROOT,
                                     executor_factory=executor_factory([], **kwargs))
    assert result.status == "failed" and gap in result.named_gaps
    receipt = _receipt(run)
    assert receipt["pdf_sha256"] is None and receipt["tex_sha256"]
    assert not (run / REPORT_PATH / "telemetry-report.pdf").exists()
    assert (run / REPORT_PATH / "telemetry-report.tex").is_file()
    assert _evidence(run) == before


def test_missing_image_is_a_gap_not_an_exception(tmp_path):
    run = build_telemetry_run(tmp_path)

    def factory(catalog, root):
        return ContainerExecutor(catalog, root, runner=lambda argv, timeout: CommandOutcome(1, b"", b"no such image"))
    result = render_telemetry_report(run, SETTINGS, repository_root=ROOT, executor_factory=factory)
    assert result.status == "failed" and "telemetry_report_renderer_unavailable" in result.named_gaps


def test_disabled_and_tex_only_policies(tmp_path):
    run = build_telemetry_run(tmp_path)
    disabled = render_telemetry_report(run, TelemetryReportSettings(enabled=False), repository_root=ROOT,
                                       executor_factory=lambda *a: pytest.fail("disabled must not render"))
    assert disabled.status == "disabled" and disabled.report_dir is None
    assert not (run / REPORT_PATH).exists()
    tex_only = render_telemetry_report(run, TelemetryReportSettings(render_pdf=False), repository_root=ROOT,
                                       executor_factory=lambda *a: pytest.fail("tex_only must not render"))
    assert tex_only.status == "tex_only"
    assert sorted(p.name for p in (run / REPORT_PATH).iterdir()) == ["receipt.json", "telemetry-report.tex"]
    assert "telemetry_report_pdf_disabled_by_policy" in _receipt(run)["named_gaps"]


def test_oversized_tex_is_a_gap(tmp_path):
    run = build_telemetry_run(tmp_path)
    result = render_telemetry_report(run, TelemetryReportSettings(max_tex_bytes=1), repository_root=ROOT,
                                     executor_factory=lambda *a: pytest.fail("must not render"))
    assert result.status == "failed" and "telemetry_report_tex_too_large" in result.named_gaps
    assert sorted(p.name for p in (run / REPORT_PATH).iterdir()) == ["receipt.json"]


def test_rerender_atomically_replaces_and_is_deterministic(tmp_path):
    run = build_telemetry_run(tmp_path)
    render_telemetry_report(run, SETTINGS, repository_root=ROOT, executor_factory=executor_factory([]))
    first = _receipt(run)
    (run / REPORT_PATH / "stale.txt").write_text("old")
    render_telemetry_report(run, SETTINGS, repository_root=ROOT, executor_factory=executor_factory([]))
    assert _receipt(run) == first
    render_telemetry_report(run, SETTINGS, repository_root=ROOT,
                            executor_factory=executor_factory([], status=1, pdf=None, logs=False))
    names = sorted(p.name for p in (run / REPORT_PATH).iterdir())
    assert names == ["receipt.json", "telemetry-report.tex"]
    assert not [p for p in (run / REPORT_PATH).parent.iterdir() if p.name.startswith(".report-")]


def test_settings_parse_with_defaults_and_reject_invalid():
    assert parse_telemetry_report(None) == TelemetryReportSettings()
    parsed = parse_telemetry_report(tomllib.loads("enabled = false\ntimeout_seconds = 30\n"))
    assert parsed == TelemetryReportSettings(enabled=False, timeout_seconds=30)
    for bad in ({"render_pdf": "yes"}, {"timeout_seconds": 0}, {"image_id": "latest"},
                {"image_tag": "-x"}, {"unknown": 1}, {"max_pdf_bytes": True}):
        with pytest.raises(ValueError):
            parse_telemetry_report(bad)


def test_repository_configuration_pins_the_dossier_image():
    from appsec_review.config.loader import load_config
    config = load_config(ROOT / "appsec-review.toml", overlay="", profile="dev")
    assert config.telemetry_report == TelemetryReportSettings()
    assert json.loads(config.resolved_json)["reporting"]["telemetry_report"] == SETTINGS.view()
    document = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    telemetry = parse_telemetry_report(document["reporting"]["telemetry_report"])
    dossier = document["jobs"]["job_dossier_publication"]["settings"]
    assert (telemetry.image_tag, telemetry.image_id) == (dossier["image_tag"], dossier["image_id"])
    assert telemetry == TelemetryReportSettings()
