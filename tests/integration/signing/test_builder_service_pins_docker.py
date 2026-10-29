"""``sign-image --all-pinned --builder-service-config`` against the real Docker daemon.

Builds two tiny local images and names their daemon-reported IDs as the BuildKit worker, egress
proxy and declared input images of an operator builder service configuration that
``load_image_builder_service`` accepts. The ``appsec-review signing`` command line runs in process
with real OpenSSL and the real ``docker image inspect``; only the application configuration is a
temporary repository root with an empty catalog and no jobs, so the host's own pins stay out of
the run. A configuration that names an image ID the daemon no longer has is refused and nothing
is signed for it.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest

from appsec_review import cli
from appsec_review.config.signing import SigningConfig
from appsec_review.signing import EnvelopeImageVerifier, SignatureVerificationError, image_envelope_path
from tests.signing.test_cli import _builder_service_config

from .test_image_signing_docker import _image_context


def _signing(capsys, *argv: str) -> tuple[int, dict]:
    code = cli.main(["signing", *argv])
    return code, json.loads(capsys.readouterr().out)


@pytest.fixture
def repository_config(tmp_path, signing_key, monkeypatch) -> SimpleNamespace:
    root = tmp_path / "repository"
    (root / "containers").mkdir(parents=True)
    (root / "containers" / "catalog.toml").write_text("", encoding="utf-8")
    loaded = SimpleNamespace(
        runtime=SimpleNamespace(repository_root=root),
        signing=SigningConfig(openssl=Path(signing_key.openssl.binary), trusted_keys_dir=signing_key.trusted_keys_dir,
                              image_signatures_dir=tmp_path / "image-signatures"),
        resolved_json=b"{}")
    monkeypatch.setattr(cli, "load_config", lambda *_args, **_kwargs: loaded)
    return loaded


def test_all_pinned_signs_builder_service_image_ids_and_refuses_an_absent_one(
        tmp_path, capsys, docker, signing_key, repository_config):
    _, worker = docker.build(_image_context(tmp_path / "context-worker", f"worker-{uuid.uuid4().hex}"),
                             "builder-worker")
    _, proxy = docker.build(_image_context(tmp_path / "context-proxy", f"proxy-{uuid.uuid4().hex}"),
                            "builder-proxy")
    assert worker != proxy
    signatures = repository_config.signing.image_signatures_dir
    private_key = str(signing_key.private_key)

    service = _builder_service_config(tmp_path / "service.toml", worker=worker, proxy=proxy,
                                      inputs={"base:release": worker, "tools:release": proxy})
    code, report = _signing(capsys, "sign-image", "--all-pinned", "--private-key", private_key,
                            "--builder-service-config", str(service))
    assert code == 0, report
    assert report["signatures_dir"] == str(signatures)
    rows = {row["source"]: row for row in report["images"]}
    assert {source: (row["image_id"], row["resolved_image_id"], row["status"]) for source, row in rows.items()} == {
        "builder-service:worker": (worker, worker, "signed"),
        "builder-service:proxy": (proxy, proxy, "signed"),
        "builder-service:input:base:release": (worker, worker, "signed"),
        "builder-service:input:tools:release": (proxy, proxy, "signed"),
    }
    assert {row["config"] for row in rows.values()} == {os.path.abspath(service)}
    assert sorted(path.name for path in signatures.iterdir()) == sorted(
        image_envelope_path(signatures, image_id).name for image_id in (worker, proxy))

    verifier = EnvelopeImageVerifier(signatures_dir=signatures, trusted_keys_dir=signing_key.trusted_keys_dir,
                                     openssl=signing_key.openssl)
    for image_id in (worker, proxy):
        verifier.verify(image_id)
    code, report = _signing(capsys, "verify-image", worker, proxy)
    assert code == 0, report
    assert [(row["image_id"], row["status"]) for row in report["images"]] == [
        (worker, "verified"), (proxy, "verified")]

    # The configuration still names an input image that has since been removed from the daemon.
    _, stale = docker.build(_image_context(tmp_path / "context-stale", f"stale-{uuid.uuid4().hex}"),
                            "builder-stale")
    docker.remove_image(stale)
    stale_service = _builder_service_config(tmp_path / "stale.toml", worker=worker,
                                            inputs={"base:release": stale})
    code, report = _signing(capsys, "sign-image", "--all-pinned", "--private-key", private_key,
                            "--builder-service-config", str(stale_service))
    assert code == 1, report
    rows = {row["source"]: row for row in report["images"]}
    assert rows["builder-service:worker"]["status"] == "signed"
    stale_row = rows["builder-service:input:base:release"]
    assert stale_row["status"] == "inspect_failed" and stale_row["envelope"] is None, stale_row
    assert stale_row["image_id"] == stale and stale_row["resolved_image_id"] is None
    assert not image_envelope_path(signatures, stale).exists()
    with pytest.raises(SignatureVerificationError, match="has no signature envelope"):
        verifier.verify(stale)
