"""Integration tier: pinned release image identities resolve to their commissioned native images.

Operator-run against a commissioned broker (deploy/dagster/native/README.md, "Integration and
acceptance tests"), under the same gates as the mount tests. For every operator-attested
``image_sources`` entry in the published client contract, the public ``NativeClient`` must report
the release pin for ``docker image inspect <pin>`` and must run an allowlisted command created with
the pin as its image. Skipped, with the reason named, when the contract maps no pins.
"""

from __future__ import annotations

import shutil
import uuid

import pytest

from tests.native_live_support import INTEGRATION_ENV, new_name, open_session, skip_reason


_SKIP = skip_reason(INTEGRATION_ENV)
pytestmark = pytest.mark.skipif(_SKIP is not None, reason=_SKIP or "")


@pytest.fixture(scope="module")
def session(tmp_path_factory):
    return open_session(tmp_path_factory.mktemp("native-events") / "native-events.jsonl")


@pytest.fixture(scope="module")
def sources(session):
    if not session.contract.image_sources:
        pytest.skip("native client contract maps no image_sources (no pinned image was commissioned "
                    "with source_image_id)")
    return sorted(session.contract.image_sources.items())


def test_pinned_image_inspect_reports_the_release_pin(session, sources):
    for pin, private in sources:
        assert private in session.contract.image_ids
        code, out, err, timed = session.client.run(("docker", "image", "inspect", pin, "--format", "{{.Id}}"), 30)
        assert (code, out, err, timed) == (0, (pin + "\n").encode(), b"", False), (pin, private)


def test_allowed_command_created_with_pin_runs_and_is_removed(session, sources):
    for pin, private in sources:
        mounted = session.run_root / f"c4b-pin-{uuid.uuid4().hex[:12]}"
        mounted.mkdir(mode=0o700)
        try:
            name = new_name()
            argv = session.run_argv(name, "/bin/sh", ["-c", "printf plain > /scratch/plain.txt"],
                                    source=mounted, image=pin)
            assert argv[-3] == pin
            with session.reserved("pinned-image"):
                try:
                    code, out, err, timed = session.client.run(argv, 60)
                finally:
                    session.remove_if_owned(name)
            assert code == 0 and not timed, (pin, private, code, out, err)
            assert (mounted / "plain.txt").read_bytes() == b"plain"
            assert session.client.executions[name]["state"] == "REMOVED"
        finally:
            shutil.rmtree(mounted)
