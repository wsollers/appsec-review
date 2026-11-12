from __future__ import annotations

from dataclasses import replace
import shutil
import subprocess

import pytest

from appsec_review.config import load_config
from appsec_review.config.host_pins import host_pins_path, load_host_pins
from appsec_review.container_runtime import ContainerExecutor, load_catalog
from appsec_review.signing import EnvelopeImageVerifier, OpenSSL, SignatureVerificationError

from .support import ROOT


def require_image(reference: str, expected: str | None):
    if shutil.which("docker") is None:
        pytest.skip("missing Docker CLI for the pinned feed tool")
    if expected is None:
        pytest.skip(f"missing operator-owned exact image pin for {reference}")
    inspected = subprocess.run(
        ["docker", "image", "inspect", reference, "--format", "{{.Id}}"],
        capture_output=True, text=True, check=False, timeout=10,
    )
    if inspected.returncode:
        pytest.skip(f"pinned feed image unavailable: {reference}: {inspected.stderr.strip()}")
    observed = inspected.stdout.strip()
    if observed != expected:
        pytest.skip(f"pinned feed image mismatch: {reference}; expected {expected}, observed {observed}")
    signing = load_config(ROOT / "appsec-review.toml").signing
    verifier = EnvelopeImageVerifier(
        signatures_dir=signing.image_signatures_dir, trusted_keys_dir=signing.trusted_keys_dir,
        openssl=OpenSSL(str(signing.openssl)),
    )
    try:
        verifier.verify(observed, reference=reference)
    except SignatureVerificationError as error:
        pytest.skip(f"missing valid signature for {reference}: {error}")
    return verifier


@pytest.fixture
def grype_executor(tmp_path):
    if not host_pins_path(ROOT).is_file():
        pytest.skip("missing operator-owned deploy/dagster/host-pins.toml")
    pins = load_host_pins(ROOT)
    catalog = load_catalog(ROOT, resolved_config={"configuration_host_pins": pins.record()})
    tool = catalog.tool("tool-grype")
    verifier = require_image(tool.tag, tool.expected_image_id)
    bounded = replace(tool, timeout_seconds=30)
    catalog = replace(catalog, tools={**catalog.tools, tool.tool_id: bounded})
    return ContainerExecutor(catalog, tmp_path, image_verifier=verifier)


@pytest.fixture
def cve_settings(tmp_path):
    from appsec_review.jobs.job_third_party_data_sync.steps.cve_bin_tool_db_build.database import CveBinToolSettings
    values = load_config(ROOT / "appsec-review.toml").job(
        "job_third_party_data_sync").step("cve_bin_tool_db_build").settings
    settings = CveBinToolSettings.from_mapping(ROOT, values)
    verifier = require_image(settings.image, settings.image_id)
    return replace(settings, feed_root=tmp_path / "feeds/cve-bin-tool", run_timeout_seconds=30), verifier
