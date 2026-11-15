"""The original mapped code-level configuration and path-safety checks."""

from pathlib import Path

import pytest

from appsec_review.config import parse_target_acquisition
from appsec_review.target_acquisition.safety import AcquisitionError, check_git_url, safe_relative, scrub


@pytest.mark.parametrize("target, message", [
    ({"id": "a", "kind": "git", "url": "https://user:pass@example.com/r.git", "commit": "a" * 40}, "credentials"),
    ({"id": "a", "kind": "git", "url": "https://tok@example.com/r.git", "commit": "a" * 40}, "credentials"),
    ({"id": "a", "kind": "git", "url": "ext::sh -c id", "commit": "a" * 40}, "transport"),
    ({"id": "a", "kind": "git", "url": "http://example.com/r.git", "commit": "a" * 40}, "refused"),
    ({"id": "a", "kind": "git", "url": "-uhttps://example.com", "commit": "a" * 40}, "transport"),
    ({"id": "a", "kind": "git", "url": "https://example.com/r.git", "commit": "main"}, "commit"),
    ({"id": "a", "kind": "git", "url": "https://example.com/r.git", "commit": "a" * 40, "token": "x"}, "unknown"),
    ({"id": "../a", "kind": "git", "url": "https://example.com/r.git", "commit": "a" * 40}, "id"),
    ({"id": "a", "kind": "perforce", "port": "ssl:p4:1666", "depot_path": "//depot/x/...", "changelist": 1,
      "user_env": "P4USER"}, "trust_fingerprint"),
    ({"id": "a", "kind": "perforce", "port": "p4:1666", "depot_path": "//depot/../x/...", "changelist": 1,
      "user_env": "P4USER"}, "depot_path"),
    ({"id": "a", "kind": "perforce", "port": "p4:1666", "depot_path": "//depot/x/...", "changelist": 1,
      "user_env": "P4USER", "password": "x"}, "unknown"),
    ({"id": "a", "kind": "review_export", "provider": "gerrit", "api_url": "https://g.example.com", "change": 1,
      "revision": "a" * 40, "clone_url": "https://g.example.com/r"}, "patchset"),
    ({"id": "a", "kind": "review_export", "provider": "gitlab", "api_url": "https://g.example.com", "project": "p",
      "change": 1, "revision": "a" * 40, "clone_url": "https://g.example.com/r", "iteration": 2}, "iteration"),
    ({"id": "a", "kind": "review_export", "provider": "azure_devops", "api_url": "https://dev.azure.com/o",
      "project": "p", "change": 1, "iteration": 1, "revision": "a" * 40,
      "clone_url": "https://dev.azure.com/o/p/_git/r"}, "repository"),
    ({"id": "a", "kind": "review_export", "provider": "gitlab", "source": "bundle", "project": "p", "change": 1,
      "revision": "a" * 40, "clone_url": "https://g.example.com/r", "bundle_path": "b.json"}, "bundle_sha256"),
], ids=["password-url", "token-url", "external-transport", "http", "option-url", "unpinned-commit",
        "inline-token", "escaping-id", "missing-trust", "escaping-depot", "inline-password",
        "missing-patchset", "wrong-iteration", "missing-repository", "unpinned-bundle"])
def test_configuration_refuses_unsafe_or_incomplete_targets(tmp_path: Path, target: dict, message: str) -> None:
    with pytest.raises(ValueError, match=message) as caught:
        parse_target_acquisition({"systems": [{"id": "s", "components": [target]}]}, tmp_path)
    assert "target_acquisition.systems[0].components[0]" in str(caught.value)


def test_configuration_refuses_duplicate_ids_and_escaping_directories(tmp_path: Path) -> None:
    item = {"id": "a", "kind": "git", "url": "https://example.com/r.git", "commit": "a" * 40}
    with pytest.raises(ValueError, match="target_acquisition system s component ids must be unique"):
        parse_target_acquisition({"systems": [{"id": "s", "components": [item, item]}]}, tmp_path)
    with pytest.raises(ValueError, match=r"target_acquisition.targets_dir must be a relative path"):
        parse_target_acquisition({"targets_dir": "../elsewhere"}, tmp_path)
    with pytest.raises(ValueError, match="target_acquisition.*unknown.*target_dir"):
        parse_target_acquisition({"target_dir": "targets"}, tmp_path)


def test_url_and_path_safety_primitives() -> None:
    assert check_git_url("https://example.com/r.git", allow_local=False) == "https"
    assert check_git_url("ssh://git@example.com/r.git", allow_local=False) == "ssh"
    assert check_git_url("git@example.com:team/r.git", allow_local=False) == "ssh"
    for url in ("file:///fixture/r", "/fixture/r", "ext::sh", "fd::3", "git://example.com/r", "git@host:../r"):
        with pytest.raises(AcquisitionError, match="fixture.source"):
            check_git_url(url, allow_local=False, field_name="fixture.source")
    assert check_git_url("file:///fixture/r", allow_local=True) == "file"
    for path in ("../x", "a/../../x", "/abs", "a\\b", "a/.git/config", ".GIT/hooks/x", "c:/x", "a//b", ""):
        with pytest.raises(AcquisitionError, match="path"):
            safe_relative(path, max_bytes=4096)
    assert safe_relative("src/a b.c", max_bytes=4096).as_posix() == "src/a b.c"
    assert scrub("token s3cr3t-value at https://user:pass@host/x", ["s3cr3t-value"]) == \
        "token [REDACTED] at https://[REDACTED]@host/x"
