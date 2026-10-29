"""Signed-module enforcement in a real container built like the Dagster runtime stage.

The image copies the exported standalone bootstrap to ``/opt/appsec-review/signing-bootstrap``,
installs ``sitecustomize_shim.py`` as the interpreter's ``sitecustomize.py``, installs a copy of
the repository's ``src/appsec_review`` into ``site-packages`` with its signed module envelope and
sets the same ``APPSEC_REVIEW_*`` variables as ``deploy/dagster/Dockerfile``. Trust anchors are
bind-mounted read-only at run time, as in the deployment.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.signing.modules import sign_modules

from .conftest import BASE_IMAGE, PACKAGE_SOURCE, SigningKey, copy_package, export_bootstrap, make_signing_key


BOOTSTRAP_DIR = "/opt/appsec-review/signing-bootstrap"
SITE_PACKAGES = "/usr/local/lib/python3.12/site-packages"
MODULE_ROOT = f"{SITE_PACKAGES}/appsec_review"
TRUSTED_KEYS = "/etc/appsec-review/signing/trusted-keys"
ENVELOPE = "/opt/appsec-review/signing/python-modules.json"
MARKER = "SIGNED-MODULES-LOADED"
EXIT_VERIFICATION_FAILED = 78

DOCKERFILE = f"""\
FROM {BASE_IMAGE}
USER 0:0
COPY --chown=0:0 bootstrap/bootstrap.py bootstrap/core.py bootstrap/modules.py bootstrap/import_hook.py \\
    bootstrap/sitecustomize_shim.py {BOOTSTRAP_DIR}/
COPY --chown=0:0 bootstrap/sitecustomize_shim.py /usr/local/lib/python3.12/sitecustomize.py
COPY --chown=0:0 site/appsec_review {MODULE_ROOT}
COPY --chown=0:0 python-modules.json {ENVELOPE}
RUN chmod -R u=rwX,go=rX /opt/appsec-review /usr/local/lib/python3.12/sitecustomize.py {MODULE_ROOT}
ENV APPSEC_REVIEW_SIGNING_BOOTSTRAP_DIR={BOOTSTRAP_DIR} \\
    APPSEC_REVIEW_MODULE_ROOT={MODULE_ROOT} \\
    APPSEC_REVIEW_TRUSTED_KEYS_DIR={TRUSTED_KEYS} \\
    APPSEC_REVIEW_OPENSSL=/usr/bin/openssl \\
    APPSEC_REVIEW_MODULE_SIGNATURE={ENVELOPE} \\
    APPSEC_REVIEW_REQUIRE_SIGNED_MODULES=1
USER 10001:10001
"""

PROBE = f"""\
import sys
import appsec_review.signing.core as core
finders = [type(finder).__name__ for finder in sys.meta_path]
print("{MARKER}", core.__file__, sys.modules["sitecustomize"].__file__, "VerifiedFinder" in finders)
"""

CHILD = f"""\
import json, subprocess, sys
probe = [sys.executable, "-c", "import appsec_review.signing.core; print('CHILD-{MARKER}')"]
before = subprocess.run(probe, capture_output=True, text=True)
with open("{MODULE_ROOT}/signing/policy.py", "a", encoding="utf-8") as handle:
    handle.write("\\n# changed after the parent process verified the tree\\n")
after = subprocess.run(probe, capture_output=True, text=True)
print(json.dumps({{"before": [before.returncode, before.stdout, before.stderr],
                  "after": [after.returncode, after.stdout, after.stderr]}}))
"""


def _keys_mount(directory: Path) -> tuple[str, ...]:
    return ("--mount", f"type=bind,src={directory},dst={TRUSTED_KEYS},readonly")


@pytest.fixture
def module_image(tmp_path, docker, signing_key: SigningKey) -> str:
    context = tmp_path / "context"
    context.mkdir()
    export_bootstrap(context / "bootstrap")
    root = copy_package(context / "site" / "appsec_review")
    sign_modules(signing_key.openssl, signing_key.private_key, root, context / "python-modules.json")
    (context / "Dockerfile").write_text(DOCKERFILE, encoding="utf-8")
    _, image_id = docker.build(context, "modules")
    return image_id


def test_container_interpreters_run_only_verified_modules(tmp_path, docker, module_image, signing_key, openssl):
    available = docker.run(module_image, "/usr/bin/openssl", "version")
    if available.returncode != 0:
        pytest.skip(f"{BASE_IMAGE} has no usable /usr/bin/openssl: {available.stderr.strip()[:200]}")
    trusted = _keys_mount(signing_key.trusted_keys_dir)

    verified = docker.run(module_image, "python", "-c", PROBE, options=trusted)
    assert verified.returncode == 0, verified.stderr
    marker, module_file, sitecustomize, hooked = verified.stdout.split()
    assert marker == MARKER and hooked == "True"
    assert module_file == f"{MODULE_ROOT}/signing/core.py"
    assert sitecustomize == "/usr/local/lib/python3.12/sitecustomize.py"

    # Without trust anchors, or with only an unrelated key, no interpreter starts.
    untrusted = make_signing_key(openssl, tmp_path / "untrusted-key")
    for options in ((), _keys_mount(untrusted.trusted_keys_dir)):
        refused = docker.run(module_image, "python", "-c", PROBE, options=options)
        assert refused.returncode == EXIT_VERIFICATION_FAILED, refused
        assert MARKER not in refused.stdout
        assert "signed module verification failed" in refused.stderr

    # A changed module, whether or not the program imports it, fails the whole tree at startup.
    for relpath in ("signing/core.py", "signing/policy.py"):
        changed = tmp_path / "changed" / relpath
        changed.parent.mkdir(parents=True, exist_ok=True)
        changed.write_bytes((PACKAGE_SOURCE / relpath).read_bytes() + b"\n# tampered\n")
        changed.chmod(0o644)
        mount = ("--mount", f"type=bind,src={changed},dst={MODULE_ROOT}/{relpath},readonly")
        refused = docker.run(module_image, "python", "-c", PROBE, options=(*trusted, *mount))
        assert refused.returncode == EXIT_VERIFICATION_FAILED, refused
        assert MARKER not in refused.stdout
        assert "signed module verification failed" in refused.stderr


def test_child_interpreters_are_enforced_too(docker, module_image, signing_key):
    completed = docker.run(module_image, "python", "-c", CHILD,
                           options=(*_keys_mount(signing_key.trusted_keys_dir), "--user", "0:0"))
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    before_code, before_stdout, before_stderr = report["before"]
    assert before_code == 0, before_stderr
    assert before_stdout.strip() == f"CHILD-{MARKER}"
    after_code, after_stdout, after_stderr = report["after"]
    assert after_code == EXIT_VERIFICATION_FAILED
    assert MARKER not in after_stdout
    assert "signed module verification failed" in after_stderr
