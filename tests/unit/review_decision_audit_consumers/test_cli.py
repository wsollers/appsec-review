import json

import pytest

from appsec_review.observability.findings.cli import main
from appsec_review.review.decision_audit import reader

from .helpers import Fixture


def test_operator_cli_runs_real_bounded_query(tmp_path, monkeypatch, capsys):
    fixture = Fixture(tmp_path)
    # The CLI's accepted-review loading boundary is tested independently; reader/query are real here.
    monkeypatch.setattr(reader, "load_decision_audit", lambda root: fixture.load())
    assert main(["decision-audit", "--run", str(fixture.root), "--template", "population", "--limit", "1"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["returned"] == 1 and result["total"] == 3 and result["next_cursor"]
    assert "literal-secret" not in json.dumps(result)


def test_cli_legacy_absence_is_named_not_clean(tmp_path, monkeypatch, capsys):
    fixture = Fixture(tmp_path)
    fixture.publish(legacy=True)
    monkeypatch.setattr(reader, "load_decision_audit", lambda root: fixture.load())
    assert main(["decision-audit", "--run", str(fixture.root), "--template", "population"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["unavailable_reason"] == "legacy_unrecorded" and result["total"] is None


@pytest.mark.parametrize("args", [["--template", "lead_trace"], ["--template", "population", "--claim-id", "claim"],
                                  ["--template", "population", "--limit", "201"],
                                  ["--template", "population", "--cursor", "not-base64"]])
def test_cli_invalid_inputs_exit_two(tmp_path, monkeypatch, capsys, args):
    fixture = Fixture(tmp_path)
    monkeypatch.setattr(reader, "load_decision_audit", lambda root: fixture.load())
    assert main(["decision-audit", "--run", str(fixture.root), *args]) == 2
    captured = capsys.readouterr()
    assert "finding-metrics:" in captured.err and captured.out == ""


def test_cli_tampered_audit_is_not_empty_success(tmp_path, monkeypatch, capsys):
    fixture = Fixture(tmp_path)
    monkeypatch.setattr(reader, "load_decision_audit", lambda root: fixture.load())
    (fixture.root / fixture.reference.path).write_text("{}")
    assert main(["decision-audit", "--run", str(fixture.root), "--template", "population"]) == 2
    assert "finding-metrics:" in capsys.readouterr().err


@pytest.mark.parametrize("extra", [["--role", "operator"], ["--manifest", "anything"], ["--sql", "select 1"],
                                   ["--template", "raw"]])
def test_cli_cannot_offer_role_authorization_raw_path_or_sql(tmp_path, extra):
    with pytest.raises(SystemExit) as exc:
        main(["decision-audit", "--run", str(tmp_path), "--template", "population", *extra])
    assert exc.value.code == 2
