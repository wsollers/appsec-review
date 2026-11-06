import json

import pytest

from appsec_review.mcp.configuration import client_configuration, main
from appsec_review.mcp.stdio import parser


@pytest.mark.parametrize("run_id", ["", "latest", "../2026-11-06-0001", "2026-11-06-0001/extra",
                                  "3daa98c3-6373-4565-a580-e0e012ad4347"])
def test_config_never_infers_an_application_run(run_id):
    with pytest.raises(ValueError):
        client_configuration(run_id=run_id)


def test_generated_config_is_valid_client_json_without_host_specific_defaults():
    config = client_configuration(run_id="2026-11-06-0001")
    assert json.loads(json.dumps(config)) == config
    entry = config["mcpServers"]["appsec-review"]
    assert entry == {"command": "appsec-review-mcp",
                     "args": ["--runs-dir", "runs", "--run-id", "2026-11-06-0001"]}
    assert "env" not in entry
    args = parser().parse_args(entry["args"])
    assert args.run_id == "2026-11-06-0001" and args.dagster_endpoint is None
    pinned = client_configuration(run_id=args.run_id, manifest_sha256="a" * 64)
    assert parser().parse_args(pinned["mcpServers"]["appsec-review"]["args"]).manifest_sha256 == "a" * 64


@pytest.mark.parametrize("pin", ["LATEST", "", "a" * 63, "A" * 64, "../manifest", 42])
def test_config_rejects_invalid_manifest_pins(pin):
    with pytest.raises(ValueError):
        client_configuration(run_id="2026-11-06-0001", manifest_sha256=pin)


def test_config_cli_prints_but_does_not_install(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        main([])
    assert not capsys.readouterr().out
    assert main(["--run-id", "2026-11-06-0001"]) == 0
    assert json.loads(capsys.readouterr().out)["mcpServers"]["appsec-review"]["args"][-1] == "2026-11-06-0001"
    assert not list(tmp_path.iterdir())
