"""Windows ACL custody: the pure DACL evaluator and parser everywhere, the advapi32 reader on Windows."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from appsec_review.signing import cli as signing_cli
from appsec_review.signing import core, images, modules
from appsec_review.signing.core import SignatureVerificationError, WindowsAce
from tests.signing._host import OPENSSL_BINARY

USER = "S-1-5-21-1004336348-1177238915-682003330-1001"
SYSTEM = "S-1-5-18"
ADMINISTRATORS = "S-1-5-32-544"
EVERYONE = "S-1-1-0"
USERS = "S-1-5-32-545"
AUTHENTICATED_USERS = "S-1-5-11"
FULL = 0x001F01FF
READ_EXECUTE = 0x001200A9
GENERIC_READ, GENERIC_WRITE, GENERIC_EXECUTE, GENERIC_ALL = 0x80000000, 0x40000000, 0x20000000, 0x10000000
OI_CI_IO = 0x01 | 0x02 | 0x08
PATH = r"C:\Users\operator\.config\appsec-review\signing\private"

windows_only = pytest.mark.skipif(os.name != "nt", reason="reads real NTFS ACLs through advapi32")


def _owner_only() -> list[WindowsAce]:
    return [WindowsAce(0, 0x10, FULL, sid) for sid in (USER, SYSTEM, ADMINISTRATORS)]


def _evaluate(aces, kind="private", *, directory=True, owner=USER) -> None:
    core.evaluate_windows_dacl(PATH, aces, kind=kind, what="object", directory=directory, owner_sid=owner)


def test_owner_only_dacl_passes_both_rules() -> None:
    for kind in ("private", "anchor"):
        _evaluate(_owner_only(), kind)


def test_everyone_read_on_a_private_key_is_refused_with_the_icacls_fix() -> None:
    with pytest.raises(SignatureVerificationError) as raised:
        _evaluate(_owner_only() + [WindowsAce(0, 0x10, 0x00120089, EVERYONE)], directory=False)
    message = str(raised.value)
    assert PATH in message and "Everyone (S-1-1-0)" in message
    assert "FILE_READ_DATA" in message and "FILE_READ_EA" in message
    assert f'icacls "{PATH}" /inheritance:r /remove:g *S-1-1-0 /grant:r "%USERNAME%:F" "*S-1-5-18:F"' in message


def test_users_write_on_an_anchor_directory_is_refused() -> None:
    with pytest.raises(SignatureVerificationError, match=r"BUILTIN\\Users \(S-1-5-32-545\) FILE_WRITE_DATA") as raised:
        _evaluate(_owner_only() + [WindowsAce(0, 0x12, 0x00000002, USERS)], "anchor")
    assert '"*S-1-5-32-545:(OI)(CI)RX"' in str(raised.value)


def test_users_read_passes_an_anchor_but_not_a_private_key() -> None:
    aces = _owner_only() + [WindowsAce(0, 0x13, READ_EXECUTE, USERS)]
    _evaluate(aces, "anchor")
    with pytest.raises(SignatureVerificationError, match="FILE_READ_DATA"):
        _evaluate(aces, "private")


def test_inherit_only_entries_are_ignored() -> None:
    _evaluate(_owner_only() + [WindowsAce(0, OI_CI_IO, GENERIC_ALL, EVERYONE)], "private")


def test_deny_entries_never_trigger_and_do_not_excuse_an_allow() -> None:
    _evaluate(_owner_only() + [WindowsAce(1, 0, FULL, EVERYONE)])
    with pytest.raises(SignatureVerificationError, match="Everyone"):
        _evaluate([WindowsAce(1, 0, FULL, EVERYONE), *_owner_only(), WindowsAce(0, 0, 0x1, EVERYONE)])


def test_null_dacl_is_refused() -> None:
    for kind in ("private", "anchor"):
        with pytest.raises(SignatureVerificationError, match="NULL DACL"):
            _evaluate(None, kind)


@pytest.mark.parametrize("kind, sid, mask, refused", [
    ("private", EVERYONE, GENERIC_READ, "FILE_READ_DATA"),
    ("private", USERS, GENERIC_EXECUTE, None),
    ("anchor", USERS, GENERIC_READ | GENERIC_EXECUTE, None),
    ("anchor", USERS, GENERIC_WRITE, "FILE_WRITE_DATA"),
    ("anchor", AUTHENTICATED_USERS, GENERIC_ALL, "WRITE_DAC"),
    ("anchor", "S-1-5-7", 0x02000000, "DELETE"),
])
def test_generic_rights_are_mapped_to_file_rights(kind, sid, mask, refused) -> None:
    aces = _owner_only() + [WindowsAce(0, 0, mask, sid)]
    if refused is None:
        _evaluate(aces, kind)
    else:
        with pytest.raises(SignatureVerificationError, match=refused):
            _evaluate(aces, kind)


@pytest.mark.parametrize("sid", ["S-1-5-2", "S-1-5-4", "S-1-5-32-546", "S-1-5-21-1-2-3-513", "S-1-15-2-1"])
def test_every_broad_principal_is_refused_write_on_an_anchor(sid) -> None:
    with pytest.raises(SignatureVerificationError, match=sid):
        _evaluate(_owner_only() + [WindowsAce(0, 0, 0x00010000, sid)], "anchor")


def test_named_non_broad_principals_may_hold_rights() -> None:
    _evaluate(_owner_only() + [WindowsAce(0, 0, FULL, "S-1-5-21-1-2-3-1002"),
                               WindowsAce(0, 0, FULL, "S-1-5-21-1-2-3-512")])


def test_callback_object_and_unparseable_entries_are_refused_conservatively() -> None:
    with pytest.raises(SignatureVerificationError, match="callback or object"):
        _evaluate(_owner_only() + [WindowsAce(9, 0, 0x00000080, EVERYONE)], "anchor")
    with pytest.raises(SignatureVerificationError, match="cannot be checked"):
        _evaluate(_owner_only() + [WindowsAce(4, 0, 0x1, None)], "anchor")
    _evaluate(_owner_only() + [WindowsAce(5, 0, FULL, USER)], "anchor")


def test_a_broad_owner_is_refused() -> None:
    with pytest.raises(SignatureVerificationError, match=r"owned by BUILTIN\\Users .*/setowner \*S-1-5-32-544"):
        _evaluate(_owner_only(), "anchor", owner=USERS)


def _sid(text: str) -> bytes:
    parts = [int(part) for part in text.split("-")[1:]]
    return (bytes([parts[0], len(parts) - 2]) + parts[1].to_bytes(6, "big")
            + b"".join(part.to_bytes(4, "little") for part in parts[2:]))


def _ace(ace_type: int, flags: int, mask: int, body: bytes) -> bytes:
    data = mask.to_bytes(4, "little") + body
    return bytes([ace_type, flags]) + (len(data) + 4).to_bytes(2, "little") + data


def _acl(*aces: bytes) -> bytes:
    body = b"".join(aces)
    return bytes([2, 0]) + (len(body) + 8).to_bytes(2, "little") + len(aces).to_bytes(2, "little") + b"\0\0" + body


def test_binary_acls_parse_into_entries() -> None:
    guid = bytes(range(16))
    data = _acl(_ace(0, 0x10, FULL, _sid(USER)),
                _ace(1, 0, 0x2, _sid(EVERYONE)),
                _ace(5, 0, 0x2, (0x1 | 0x2).to_bytes(4, "little") + guid + guid + _sid(USERS)),
                _ace(9, 0, 0x1, _sid(AUTHENTICATED_USERS) + b"artx"),
                _ace(4, 0, 0x1, b"\0" * 8)) + b"slack"
    assert core.parse_windows_acl(data) == [
        WindowsAce(0, 0x10, FULL, USER), WindowsAce(1, 0, 0x2, EVERYONE), WindowsAce(5, 0, 0x2, USERS),
        WindowsAce(9, 0, 0x1, AUTHENTICATED_USERS), WindowsAce(4, 0, 0x1, None)]
    assert core.windows_sid_string(_sid("S-1-5-21-1-2-3-513")) == "S-1-5-21-1-2-3-513"


@pytest.mark.parametrize("data", [b"", bytes([9, 0, 8, 0, 0, 0, 0, 0]), _acl(_ace(0, 0, 1, _sid(USER)))[:-4],
                                  bytes([2, 0, 8, 0, 1, 0, 0, 0])])
def test_malformed_binary_acls_are_refused(data) -> None:
    with pytest.raises(SignatureVerificationError, match="Windows ACL"):
        core.parse_windows_acl(data)


def test_the_reader_fails_closed_off_windows(tmp_path) -> None:
    if os.name == "nt":
        pytest.skip("the reader works on Windows")
    with pytest.raises(SignatureVerificationError, match="cannot read the Windows ACL"):
        core.read_windows_security(tmp_path)
    with pytest.raises(SignatureVerificationError, match="cannot set the Windows ACL"):
        core.apply_windows_acl(tmp_path, "private", directory=True)


@pytest.fixture
def simulated(monkeypatch) -> SimpleNamespace:
    """A Windows host whose ACL reader and writer are replaced; ``acls`` maps paths to entries."""
    state = SimpleNamespace(acls={}, calls=[])

    def read(path):
        state.calls.append(("check", Path(path)))
        return USER, state.acls.get(Path(path), _owner_only())

    def apply(path, kind, *, directory):
        state.calls.append(("apply", Path(path), kind, directory))

    monkeypatch.setattr(core, "windows_host", lambda: True)
    monkeypatch.setattr(core, "read_windows_security", read)
    monkeypatch.setattr(core, "apply_windows_acl", apply)
    return state


@pytest.mark.skipif(not os.path.isfile(OPENSSL_BINARY), reason="system OpenSSL is required")
def test_trusted_keys_load_checks_the_anchor_directory_and_every_anchor(simulated, monkeypatch, tmp_path) -> None:
    if os.name != "nt":
        monkeypatch.setattr(core, "windows_host", lambda: False)
    openssl = core.OpenSSL(OPENSSL_BINARY)
    private = openssl.generate_private_key(tmp_path / "private" / "operator.pem")
    pem = openssl.public_key_pem(private)
    identity = core.key_id(openssl.public_key_der(pem))
    anchors = tmp_path / "trusted"
    anchors.mkdir()
    anchor = anchors / f"{identity.removeprefix('sha256:')}.pem"
    anchor.write_bytes(pem)
    monkeypatch.setattr(core, "windows_host", lambda: True)
    assert list(core.TrustedKeys.load(anchors, openssl)) == [identity]
    assert simulated.calls == [("check", anchors), ("check", anchor)]
    simulated.acls[anchor] = _owner_only() + [WindowsAce(0, 0, 0x2, USERS)]
    with pytest.raises(SignatureVerificationError, match="trusted key can be modified"):
        core.TrustedKeys.load(anchors, openssl)
    simulated.acls[anchors] = _owner_only() + [WindowsAce(0, 0x2, 0x40, EVERYONE)]
    with pytest.raises(SignatureVerificationError, match="trusted keys directory .*FILE_DELETE_CHILD"):
        core.TrustedKeys.load(anchors, openssl)


def test_private_key_directory_gets_an_acl_when_created_and_is_always_checked(simulated, tmp_path) -> None:
    signing_cli._private_parent(tmp_path / "new" / "operator.pem")
    assert simulated.calls == [("apply", tmp_path / "new", "private", True), ("check", tmp_path / "new")]
    existing = tmp_path / "existing"
    existing.mkdir()
    simulated.calls.clear()
    simulated.acls[existing] = _owner_only() + [WindowsAce(0, 0x13, READ_EXECUTE, USERS)]
    with pytest.raises(SignatureVerificationError, match="private key directory is not private"):
        signing_cli._private_parent(existing / "operator.pem")
    assert simulated.calls == [("check", existing)]


@pytest.fixture
def signing_key(simulated, monkeypatch, tmp_path) -> SimpleNamespace:
    """A real key and OpenSSL on a simulated Windows host; ``signed`` records every OpenSSL sign call."""
    if not os.path.isfile(OPENSSL_BINARY):
        pytest.skip("system OpenSSL is required")
    monkeypatch.setattr(core, "windows_host", lambda: os.name == "nt")
    openssl = core.OpenSSL(OPENSSL_BINARY, temp_dir=str(tmp_path))
    key = openssl.generate_private_key(tmp_path / "private" / "operator.pem")
    monkeypatch.setattr(core, "windows_host", lambda: True)
    state = SimpleNamespace(openssl=openssl, key=key, signed=[])
    real_sign = openssl.sign
    monkeypatch.setattr(openssl, "sign", lambda path, message: state.signed.append(path) or real_sign(path, message))
    return state


def _sign_paths(openssl, key: Path, root: Path) -> dict:
    package = root / "pkg"
    package.mkdir(exist_ok=True)
    (package / "__init__.py").write_bytes(b"")
    return {
        "statement": lambda: core.sign_statement(openssl, key, core.make_statement("test", {"value": 1})),
        "image": lambda: images.sign_image(openssl, key, "sha256:" + "a" * 64, root / "images"),
        "modules": lambda: modules.sign_modules(openssl, key, package, root / "modules.json"),
    }


@pytest.mark.parametrize("path", ["statement", "image", "modules"])
@pytest.mark.parametrize("target", ["key", "directory"])
def test_signing_refuses_a_broadly_readable_private_key_before_openssl_runs(
        signing_key, simulated, tmp_path, path, target) -> None:
    broad = signing_key.key if target == "key" else signing_key.key.parent
    simulated.acls[broad] = _owner_only() + [WindowsAce(0, 0, 0x00120089, EVERYONE)]
    with pytest.raises(SignatureVerificationError, match=r"Everyone \(S-1-1-0\) FILE_READ_DATA"):
        _sign_paths(signing_key.openssl, signing_key.key, tmp_path)[path]()
    assert signing_key.signed == []
    assert not (tmp_path / "images").exists() and not (tmp_path / "modules.json").exists()


@pytest.mark.parametrize("path", ["statement", "image", "modules"])
def test_signing_with_a_private_key_checks_its_directory_and_file(signing_key, simulated, tmp_path, path) -> None:
    simulated.calls.clear()
    _sign_paths(signing_key.openssl, signing_key.key, tmp_path)[path]()
    assert simulated.calls == [("check", signing_key.key.parent), ("check", signing_key.key)]
    assert signing_key.signed == [signing_key.key]


@pytest.mark.skipif(not os.path.isfile(OPENSSL_BINARY), reason="system OpenSSL is required")
def test_posix_signing_reads_no_windows_acl(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(core, "windows_host", lambda: False)
    monkeypatch.setattr(core, "read_windows_security", lambda path: pytest.fail("Windows ACL read on POSIX"))
    openssl = core.OpenSSL(OPENSSL_BINARY, temp_dir=str(tmp_path))
    key = openssl.generate_private_key(tmp_path / "private" / "operator.pem")
    core.sign_statement(openssl, key, core.make_statement("test", {"value": 1}))


@pytest.mark.skipif(not os.path.isfile(OPENSSL_BINARY), reason="system OpenSSL is required")
def test_keygen_restricts_and_checks_the_new_key_and_anchor_directory(simulated, monkeypatch, tmp_path) -> None:
    if os.name != "nt":
        monkeypatch.setattr(core, "windows_host", lambda: False)
    openssl = core.OpenSSL(OPENSSL_BINARY)
    monkeypatch.setattr(core, "windows_host", lambda: True)
    monkeypatch.setattr(signing_cli, "_openssl", lambda args, config: openssl)
    private_key, anchors = tmp_path / "private" / "operator.pem", tmp_path / "anchors"
    report, ok = signing_cli._keygen(SimpleNamespace(private_key=private_key, trusted_keys_dir=anchors), None)
    assert ok and Path(report["trusted_key"]).parent == anchors
    assert simulated.calls == [("apply", private_key.parent, "private", True), ("check", private_key.parent),
                               ("apply", private_key, "private", False), ("check", private_key),
                               ("apply", anchors, "anchor", True)]


def _icacls(*arguments: str) -> None:
    icacls = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "icacls.exe")
    subprocess.run([icacls, *arguments], check=True, capture_output=True)


@windows_only
def test_real_acls_are_read_and_judged(tmp_path) -> None:
    secret = tmp_path / "secret.pem"
    secret.write_bytes(b"secret")
    core.apply_windows_acl(secret, "private", directory=False)
    core.check_windows_custody(secret, "private", "private key", directory=False)
    _icacls(str(secret), "/grant", "*S-1-1-0:R")
    with pytest.raises(SignatureVerificationError, match=r"Everyone \(S-1-1-0\) FILE_READ_DATA"):
        core.check_windows_custody(secret, "private", "private key", directory=False)
    _icacls(str(secret), "/remove:g", "*S-1-1-0")
    core.check_windows_custody(secret, "private", "private key", directory=False)

    anchors = tmp_path / "anchors"
    anchors.mkdir()
    core.apply_windows_acl(anchors, "anchor", directory=True)
    _icacls(str(anchors), "/grant", "*S-1-5-32-545:(OI)(CI)RX")
    core.check_windows_custody(anchors, "anchor", "trusted keys directory", directory=True)
    _icacls(str(anchors), "/grant", "*S-1-5-32-545:(OI)(CI)M")
    with pytest.raises(SignatureVerificationError, match=r"BUILTIN\\Users"):
        core.check_windows_custody(anchors, "anchor", "trusted keys directory", directory=True)


@windows_only
@pytest.mark.skipif(not os.path.isfile(OPENSSL_BINARY), reason="system OpenSSL is required")
def test_real_keygen_output_passes_the_custody_checks(tmp_path) -> None:
    private_key, anchors = tmp_path / "private" / "operator.pem", tmp_path / "anchors"
    report, ok = signing_cli._keygen(
        SimpleNamespace(private_key=private_key, trusted_keys_dir=anchors, openssl=Path(OPENSSL_BINARY)), None)
    assert ok
    core.check_windows_custody(private_key.parent, "private", "private key directory", directory=True)
    core.check_windows_custody(private_key, "private", "private key", directory=False)
    assert list(core.TrustedKeys.load(anchors, core.OpenSSL(OPENSSL_BINARY))) == [report["key_id"]]
