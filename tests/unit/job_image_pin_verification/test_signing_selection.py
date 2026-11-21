"""Shared selection preserves bulk-signing policy without executing Docker or OpenSSL."""

import json
import subprocess
from unittest.mock import Mock

import pytest

from appsec_review import cli
from appsec_review.config import load_config
from appsec_review.config.host_pins import HostPins, serialize_host_pins
from appsec_review.signing import cli as signing_cli
from tests.host_pins_support import ROOT, fixture_bindings, fixture_preinstalled


@pytest.mark.parametrize(
    ("outcome", "expected_status", "expected_code"),
    [("build-absent", "skipped_absent", 0), ("runtime-absent", "skipped_absent", 0),
     ("daemon-error", "inspect_failed", 1), ("tag-absent", "inspect_failed", 1),
     ("id-mismatch", "mismatched", 1), ("matched", "signed", 0)],
    ids=["build-absent", "runtime-absent", "daemon-error", "tag-absent", "id-mismatch", "matched"],
)
def test_real_shared_selector_preserves_bulk_signing_id_only_policy(
        tmp_path, monkeypatch, capsys, outcome, expected_status, expected_code):
    images = fixture_bindings()
    declarations = fixture_preinstalled()
    host = HostPins(tmp_path / "host-pins.toml", serialize_host_pins(images, declarations))
    config = load_config(ROOT / "appsec-review.toml", profile="dev", overlay="", host_pins=host)
    key = tmp_path / "inert-private-key"
    key.write_bytes(b"never passed to a cryptographic implementation")
    signatures = tmp_path / "signatures"
    selected_id = declarations[1]["build_image_id"] if outcome == "build-absent" else declarations[0]["runtime_image_id"]
    selected_tag = "audit-codeql:custom-2.27.0"
    exact_ids = {row[field] for row in declarations
                 for field in ("source_image_id", "build_image_id", "runtime_image_id")}
    images.update({image_id: image_id for image_id in exact_ids})
    calls = []

    def inspect(command, **kwargs):
        assert command[:5] == ["docker", "image", "inspect", "--format", "{{.Id}}"]
        reference = command[-1]
        calls.append(reference)
        if reference == selected_tag and outcome == "tag-absent":
            return subprocess.CompletedProcess(command, 1, b"", b"No such image: tagged")
        if reference == selected_id:
            if outcome in {"build-absent", "runtime-absent"}:
                return subprocess.CompletedProcess(command, 1, b"", b"No such image: declared")
            if outcome == "daemon-error":
                return subprocess.CompletedProcess(command, 1, b"", b"daemon unavailable")
            if outcome == "id-mismatch":
                return subprocess.CompletedProcess(command, 0, ("sha256:" + "f" * 64).encode(), b"")
        return subprocess.CompletedProcess(command, 0, images[reference].encode(), b"")

    openssl = object()
    monkeypatch.setattr(signing_cli, "OpenSSL", Mock(return_value=openssl))
    monkeypatch.setattr(signing_cli, "_inspect_runner", inspect)
    sign = Mock(side_effect=lambda tool, private, image_id, directory: directory / (image_id[7:] + ".json"))
    monkeypatch.setattr(signing_cli, "sign_image", sign)
    args = cli.parser().parse_args([
        "signing", "sign-image", "--all-pinned", "--private-key", str(key),
        "--signatures-dir", str(signatures),
    ])
    code = signing_cli.run(args, lambda: config)
    report = json.loads(capsys.readouterr().out)
    declared = [row for row in report["images"] if ".preinstalled_runtimes[" in row["source"]]
    assert code == expected_code
    assert declared and all(row["tag"] is None for row in declared)
    affected = [row for row in report["images"]
                if (row["tag"] == selected_tag if outcome == "tag-absent"
                    else row["tag"] is None and row["image_id"] == selected_id)]
    assert affected and {row["status"] for row in affected} == {expected_status}
    assert all(row["status"] in {"signed", expected_status} for row in report["images"])
    if expected_status != "signed":
        assert all(row["envelope"] is None for row in affected)
    assert exact_ids <= set(calls) and len(calls) == len(set(calls))
    assert {call.args[2] for call in sign.call_args_list} == {
        row["image_id"] for row in report["images"] if row["status"] == "signed"}
    assert all(call.args[0] is openssl and call.args[1] == key for call in sign.call_args_list)
    assert not signatures.exists()
