"""Stdlib-only Ed25519 signing primitives over the system OpenSSL command line.

This module must stay loadable by file path under ``python -I -S``: it imports only the standard
library and nothing from ``appsec_review``. Every failure to establish a valid signature raises
``SignatureVerificationError``; nothing here reports an unverifiable object as trusted.
"""
from __future__ import annotations

import base64
import binascii
from collections.abc import Iterator, Mapping, Sequence
import contextlib
import hashlib
import json
import ntpath
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Any, NamedTuple


STATEMENT_SCHEMA = "appsec-review.signed-statement/v1"
ALGORITHM = "ed25519"
DEFAULT_OPENSSL = "/usr/bin/openssl"
DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_ENVELOPE_BYTES = 64 * 1024 * 1024
MAX_PUBLIC_KEY_BYTES = 16 * 1024
MAX_SIGNATURES = 16
SIGNATURE_BYTES = 64

ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_ED25519_SPKI_BYTES = len(ED25519_SPKI_PREFIX) + 32
WINDOWS_GIT_OPENSSL = r"C:\Program Files\Git\mingw64\bin\openssl.exe"
_SANITIZED_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "OPENSSL_CONF": "/dev/null"}
_WINDOWS_ENV_NAMES = ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATHEXT", "COMSPEC")
_KEY_ID = re.compile(r"sha256:[0-9a-f]{64}")
_KEY_FILE = re.compile(r"([0-9a-f]{64})\.pem")
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

# RFC 8032 section 7.1, TEST 2. OpenSSL 3.0 cannot sign or verify an empty -rawin message (TEST 1).
_KAT_PUBLIC_KEY = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
_KAT_MESSAGE = bytes.fromhex("72")
_KAT_SIGNATURE = bytes.fromhex(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")


class SignatureVerificationError(Exception):
    """A signature, trust anchor, or envelope could not be verified; callers must fail closed."""


def windows_host() -> bool:
    """True on a native Windows interpreter; tests replace this to exercise the Windows paths."""
    return os.name == "nt"


def is_absolute_path(value: str | os.PathLike[str]) -> bool:
    """Absolute on this host: on Windows a drive-qualified or UNC path, never a bare ``/rooted`` one."""
    text = os.fspath(value)
    if not isinstance(text, str) or not text or "\x00" in text:
        return False
    if windows_host():
        path = PureWindowsPath(text)
        return bool(path.drive and path.root)
    return os.path.isabs(text)


def default_openssl() -> str:
    """``/usr/bin/openssl`` on POSIX; on Windows the Git for Windows OpenSSL, preferring an existing one."""
    if not windows_host():
        return DEFAULT_OPENSSL
    candidates = [ntpath.join(root, "Git", "mingw64", "bin", "openssl.exe")
                  for root in (os.environ.get("ProgramW6432"), os.environ.get("ProgramFiles")) if root]
    candidates.append(WINDOWS_GIT_OPENSSL)
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return WINDOWS_GIT_OPENSSL


def is_link_or_reparse_point(info: os.stat_result) -> bool:
    """A symbolic link, or on Windows any reparse point (junction, mount point, symlink)."""
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def windows_openssl_environment(binary: str, config_path: str,
                                environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Minimal Windows environment: system variables, the binary's directory (its DLLs) and System32.

    ``OPENSSL_CONF`` names an empty private file; ``OPENSSL_MODULES``/``OPENSSL_ENGINES`` and every
    other inherited variable are dropped.
    """
    source = {name.upper(): value for name, value in (os.environ if environ is None else environ).items()}
    environment = {name: source[name] for name in _WINDOWS_ENV_NAMES if source.get(name)}
    system_root = environment.get("SYSTEMROOT") or environment.get("WINDIR") or r"C:\Windows"
    environment["PATH"] = ";".join((ntpath.dirname(binary), ntpath.join(system_root, "System32")))
    environment["OPENSSL_CONF"] = config_path
    return environment


# Windows custody. NTFS DACLs stand in for POSIX owner and mode bits: a private key and its directory
# must grant no broad principal a read or write right, and trust anchors no broad principal a right to
# modify them. Deny entries are ignored (an allow entry is refused even when a deny entry masks it),
# and inherit-only entries are ignored because they do not apply to the object itself.
WINDOWS_BROAD_PRINCIPALS = {
    "S-1-1-0": "Everyone",
    "S-1-2-0": "LOCAL",
    "S-1-5-1": "DIALUP",
    "S-1-5-2": "NETWORK",
    "S-1-5-4": "INTERACTIVE",
    "S-1-5-7": "ANONYMOUS LOGON",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-13": "TERMINAL SERVER USER",
    "S-1-5-14": "REMOTE INTERACTIVE LOGON",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-15-2-1": "ALL APPLICATION PACKAGES",
    "S-1-15-2-2": "ALL RESTRICTED APPLICATION PACKAGES",
}
# Relative IDs under any S-1-5-21-<domain or machine> authority: Domain Users (the local "None" group on
# a workgroup host) and Domain Guests.
_WINDOWS_DOMAIN_BROAD_RIDS = {"513": "Domain Users", "514": "Domain Guests"}
WINDOWS_FILE_RIGHTS = (
    (0x00000001, "FILE_READ_DATA"), (0x00000002, "FILE_WRITE_DATA"), (0x00000004, "FILE_APPEND_DATA"),
    (0x00000008, "FILE_READ_EA"), (0x00000010, "FILE_WRITE_EA"), (0x00000040, "FILE_DELETE_CHILD"),
    (0x00000100, "FILE_WRITE_ATTRIBUTES"), (0x00010000, "DELETE"), (0x00040000, "WRITE_DAC"),
    (0x00080000, "WRITE_OWNER"))
# Every right above. Traverse/execute, FILE_READ_ATTRIBUTES, READ_CONTROL and SYNCHRONIZE stay allowed.
WINDOWS_PRIVATE_FORBIDDEN = 0x000D015F
# The write and modify rights above (on a directory FILE_WRITE_DATA is FILE_ADD_FILE and
# FILE_APPEND_DATA is FILE_ADD_SUBDIRECTORY); reading an anchor is allowed.
WINDOWS_ANCHOR_FORBIDDEN = 0x000D0156
_WINDOWS_GENERIC_RIGHTS = (
    (0x80000000, 0x00120089),  # GENERIC_READ -> FILE_GENERIC_READ
    (0x40000000, 0x00120116),  # GENERIC_WRITE -> FILE_GENERIC_WRITE
    (0x20000000, 0x001200A0),  # GENERIC_EXECUTE -> FILE_GENERIC_EXECUTE
    (0x10000000, 0x001F01FF),  # GENERIC_ALL -> FILE_ALL_ACCESS
    (0x02000000, 0x001F01FF),  # MAXIMUM_ALLOWED, conservatively everything
)
WINDOWS_ACCESS_ALLOWED_ACE = 0
WINDOWS_ACCESS_DENIED_ACE = 1
WINDOWS_INHERIT_ONLY_ACE = 0x08
_WINDOWS_DENIED_ACES = frozenset({1, 6, 10})  # denied, denied object, denied callback
_WINDOWS_OBJECT_ACES = frozenset({5, 6, 11})  # allowed object, denied object, allowed callback object
_WINDOWS_SIMPLE_SID_ACES = frozenset({0, 1, 9, 10})  # allowed, denied, allowed/denied callback
_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1


class WindowsAce(NamedTuple):
    """One DACL entry; ``sid`` is ``None`` when the entry carries no SID this module can parse."""

    ace_type: int
    flags: int
    mask: int
    sid: str | None


class _WindowsCustody(NamedTuple):
    forbidden: int
    failure: str
    owner: str
    full_control: tuple[str, ...]
    read_execute: tuple[str, ...]


_WINDOWS_CUSTODY = {
    "private": _WindowsCustody(WINDOWS_PRIVATE_FORBIDDEN, "is not private", '"%USERNAME%"',
                               ("%USERNAME%", "*S-1-5-18", "*S-1-5-32-544"), ()),
    "anchor": _WindowsCustody(WINDOWS_ANCHOR_FORBIDDEN, "can be modified by a broad principal", "*S-1-5-32-544",
                              ("*S-1-5-18", "*S-1-5-32-544"), ("*S-1-5-32-545",)),
}


def windows_broad_principal(sid: str) -> str | None:
    """The name of ``sid`` when it is a broad principal (see ``WINDOWS_BROAD_PRINCIPALS``), else ``None``."""
    if sid in WINDOWS_BROAD_PRINCIPALS:
        return WINDOWS_BROAD_PRINCIPALS[sid]
    parts = sid.split("-")
    if len(parts) == 8 and sid.startswith("S-1-5-21-") and parts[-1] in _WINDOWS_DOMAIN_BROAD_RIDS:
        return _WINDOWS_DOMAIN_BROAD_RIDS[parts[-1]]
    return None


def windows_file_rights(mask: int) -> int:
    """``mask`` with its generic rights (and MAXIMUM_ALLOWED) mapped to the specific file rights."""
    for generic, specific in _WINDOWS_GENERIC_RIGHTS:
        if mask & generic:
            mask |= specific
    return mask


def windows_sid_string(data: bytes) -> str:
    """Render a binary SID as ``S-1-...``."""
    if len(data) < 8 or data[0] != 1 or len(data) != 8 + 4 * data[1]:
        raise SignatureVerificationError("malformed Windows SID")
    authority = int.from_bytes(data[2:8], "big")
    parts = [f"S-1-{authority}" if authority < 1 << 32 else f"S-1-0x{authority:012X}"]
    parts.extend(str(int.from_bytes(data[index:index + 4], "little")) for index in range(8, len(data), 4))
    return "-".join(parts)


def _windows_ace_sid(ace_type: int, body: bytes) -> str | None:
    start = 8
    if ace_type in _WINDOWS_OBJECT_ACES:
        if len(body) < 12:
            return None
        object_flags = int.from_bytes(body[8:12], "little")
        start = 12 + 16 * bool(object_flags & 0x1) + 16 * bool(object_flags & 0x2)
    elif ace_type not in _WINDOWS_SIMPLE_SID_ACES:
        return None
    if len(body) < start + 8:
        return None
    end = start + 8 + 4 * body[start + 1]
    if end > len(body):
        return None
    try:
        return windows_sid_string(body[start:end])
    except SignatureVerificationError:
        return None


def parse_windows_acl(data: bytes) -> list[WindowsAce]:
    """Parse a self-relative binary ACL into its entries; a malformed ACL raises."""
    if len(data) < 8 or data[0] not in (2, 4):
        raise SignatureVerificationError("malformed Windows ACL header")
    size = int.from_bytes(data[2:4], "little")
    count = int.from_bytes(data[4:6], "little")
    if size < 8 or size > len(data):
        raise SignatureVerificationError("malformed Windows ACL size")
    aces: list[WindowsAce] = []
    offset = 8
    for _ in range(count):
        if offset + 8 > size:
            raise SignatureVerificationError("truncated Windows ACL")
        ace_size = int.from_bytes(data[offset + 2:offset + 4], "little")
        if ace_size < 8 or offset + ace_size > size:
            raise SignatureVerificationError("malformed Windows ACL entry")
        body = data[offset:offset + ace_size]
        aces.append(WindowsAce(body[0], body[1], int.from_bytes(body[4:8], "little"),
                               _windows_ace_sid(body[0], body)))
        offset += ace_size
    return aces


def windows_custody_fix(path: str, kind: str, *, directory: bool, remove: str | None = None) -> str:
    """The ``icacls`` command that gives ``path`` the custody ``kind`` requires."""
    custody = _WINDOWS_CUSTODY[kind]
    inherit = "(OI)(CI)" if directory else ""
    grants = [f'"{who}:{inherit}F"' for who in custody.full_control]
    grants.extend(f'"{who}:{inherit}RX"' for who in custody.read_execute)
    removal = f" /remove:g *{remove}" if remove else ""
    return f'icacls "{path}" /inheritance:r{removal} /grant:r {" ".join(grants)}'


def evaluate_windows_dacl(path: str, aces: Sequence[WindowsAce] | None, *, kind: str, what: str,
                          directory: bool, owner_sid: str | None = None) -> None:
    """Refuse a DACL (``None`` is a NULL DACL) that breaks the ``kind`` custody rule for ``path``.

    ``kind`` is ``"private"`` (a private key or its directory: no broad principal may hold any right in
    ``WINDOWS_PRIVATE_FORBIDDEN``) or ``"anchor"`` (a trust-anchor directory or file: no broad principal
    may hold any right in ``WINDOWS_ANCHOR_FORBIDDEN``). A broad owner, an allow entry whose SID cannot be
    parsed, and a callback or object allow entry naming a broad principal are refused too.
    """
    custody = _WINDOWS_CUSTODY[kind]

    def refuse(reason: str, remove: str | None = None) -> None:
        raise SignatureVerificationError(
            f"{what} {custody.failure} on Windows: {path} {reason}; fix it with: "
            f"{windows_custody_fix(path, kind, directory=directory, remove=remove)}")

    owner = windows_broad_principal(owner_sid) if owner_sid is not None else None
    if owner is not None:
        raise SignatureVerificationError(
            f"{what} {custody.failure} on Windows: {path} is owned by {owner} ({owner_sid}); fix it with: "
            f'icacls "{path}" /setowner {custody.owner}')
    if aces is None:
        refuse("has a NULL DACL, which grants Everyone full access")
        return
    for ace in aces:
        if ace.ace_type in _WINDOWS_DENIED_ACES or ace.flags & WINDOWS_INHERIT_ONLY_ACE:
            continue
        if ace.sid is None:
            refuse(f"has an access entry of type {ace.ace_type} that cannot be checked")
            continue
        principal = windows_broad_principal(ace.sid)
        if principal is None:
            continue
        if ace.ace_type != WINDOWS_ACCESS_ALLOWED_ACE:
            refuse(f"grants {principal} ({ace.sid}) a callback or object access entry (type {ace.ace_type})",
                   ace.sid)
        rights = windows_file_rights(ace.mask) & custody.forbidden
        if rights:
            names = "|".join(name for bit, name in WINDOWS_FILE_RIGHTS if rights & bit)
            refuse(f"grants {principal} ({ace.sid}) {names}", ace.sid)


def _windows_api() -> tuple[Any, Any, Any]:
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    out = ctypes.POINTER(ctypes.c_void_p)
    void = ctypes.c_void_p
    for function, argtypes, restype in (
            (advapi32.GetNamedSecurityInfoW,
             [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, out, out, out, out, out], wintypes.DWORD),
            (advapi32.SetNamedSecurityInfoW,
             [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, void, void, void, void], wintypes.DWORD),
            (advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW,
             [wintypes.LPCWSTR, wintypes.DWORD, out, ctypes.POINTER(wintypes.ULONG)], wintypes.BOOL),
            (advapi32.GetSecurityDescriptorDacl,
             [void, ctypes.POINTER(wintypes.BOOL), out, ctypes.POINTER(wintypes.BOOL)], wintypes.BOOL),
            (advapi32.OpenProcessToken, [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)],
             wintypes.BOOL),
            (advapi32.GetTokenInformation,
             [wintypes.HANDLE, ctypes.c_int, void, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            (advapi32.IsValidSid, [void], wintypes.BOOL),
            (advapi32.GetLengthSid, [void], wintypes.DWORD),
            (advapi32.IsValidAcl, [void], wintypes.BOOL),
            (kernel32.GetCurrentProcess, [], wintypes.HANDLE),
            (kernel32.CloseHandle, [wintypes.HANDLE], wintypes.BOOL),
            (kernel32.LocalFree, [void], void)):
        function.argtypes = argtypes
        function.restype = restype
    return ctypes, advapi32, kernel32


def _windows_sid_at(ctypes: Any, advapi32: Any, sid: int | None) -> str:
    if not sid or not advapi32.IsValidSid(sid):
        raise OSError("missing or invalid SID")
    return windows_sid_string(ctypes.string_at(sid, advapi32.GetLengthSid(sid)))


def read_windows_security(path: str | os.PathLike[str]) -> tuple[str, list[WindowsAce] | None]:
    """The owner SID and DACL entries of ``path`` (``None`` for a NULL DACL); any failure raises.

    Reads the security descriptor with ``GetNamedSecurityInfoW`` and parses the returned ACL bytes;
    Windows only. Tests replace this to exercise the Windows custody paths on POSIX.
    """
    target = os.fspath(path)
    try:
        ctypes, advapi32, kernel32 = _windows_api()
        owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        status = advapi32.GetNamedSecurityInfoW(
            target, _SE_FILE_OBJECT, _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
        if status != 0:
            raise OSError(status, ctypes.FormatError(status))
        try:
            owner_sid = _windows_sid_at(ctypes, advapi32, owner.value)
            if not dacl.value:
                return owner_sid, None
            if not advapi32.IsValidAcl(dacl.value):
                raise OSError("invalid DACL")
            size = int.from_bytes(ctypes.string_at(dacl.value + 2, 2), "little")
            return owner_sid, parse_windows_acl(ctypes.string_at(dacl.value, size))
        finally:
            kernel32.LocalFree(descriptor.value)
    except Exception as error:  # fail closed on any ctypes, API or parsing failure
        raise SignatureVerificationError(f"cannot read the Windows ACL of {target}: {error}") from error


def check_windows_custody(path: str | os.PathLike[str], kind: str, what: str, *, directory: bool) -> None:
    """Read ``path``'s owner and DACL and refuse them unless they meet the ``kind`` custody rule."""
    owner_sid, aces = read_windows_security(path)
    evaluate_windows_dacl(os.fspath(path), aces, kind=kind, what=what, directory=directory,
                          owner_sid=owner_sid)


def apply_windows_acl(path: str | os.PathLike[str], kind: str, *, directory: bool) -> None:
    """Replace ``path``'s DACL with a protected one that meets the ``kind`` custody rule.

    The current user, SYSTEM and Administrators get full control (inherited by new children of a
    directory); for ``"anchor"`` BUILTIN\\Users may also read and traverse. SIDs are used throughout,
    so localized account names do not matter. Windows only; any failure raises.
    """
    target = os.fspath(path)
    try:
        ctypes, advapi32, kernel32 = _windows_api()
        from ctypes import wintypes

        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            needed = wintypes.DWORD()
            advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(needed))
            buffer = ctypes.create_string_buffer(needed.value)
            if not advapi32.GetTokenInformation(token, _TOKEN_USER, buffer, needed, ctypes.byref(needed)):
                raise ctypes.WinError(ctypes.get_last_error())
            user = _windows_sid_at(ctypes, advapi32, ctypes.c_void_p.from_buffer(buffer).value)
        finally:
            kernel32.CloseHandle(token)
        inherit = "OICI" if directory else ""
        entries = [f"(A;{inherit};FA;;;{sid})" for sid in (user, "S-1-5-18", "S-1-5-32-544")]
        if kind == "anchor":
            entries.append(f"(A;{inherit};0x1200a9;;;S-1-5-32-545)")
        elif kind != "private":
            raise ValueError(f"unknown Windows custody kind: {kind!r}")
        descriptor = ctypes.c_void_p()
        if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                "D:P" + "".join(entries), 1, ctypes.byref(descriptor), None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            present, defaulted, dacl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
            if not advapi32.GetSecurityDescriptorDacl(descriptor.value, ctypes.byref(present), ctypes.byref(dacl),
                                                      ctypes.byref(defaulted)):
                raise ctypes.WinError(ctypes.get_last_error())
            if not present.value or not dacl.value:
                raise OSError("the constructed security descriptor has no DACL")
            status = advapi32.SetNamedSecurityInfoW(
                target, _SE_FILE_OBJECT, _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
                None, None, dacl.value, None)
            if status != 0:
                raise OSError(status, ctypes.FormatError(status))
        finally:
            kernel32.LocalFree(descriptor.value)
    except Exception as error:  # fail closed on any ctypes or API failure
        raise SignatureVerificationError(f"cannot set the Windows ACL of {target}: {error}") from error


def key_id(public_key_der: bytes) -> str:
    if not isinstance(public_key_der, (bytes, bytearray)) or not public_key_der:
        raise SignatureVerificationError("public key DER must be non-empty bytes")
    return "sha256:" + hashlib.sha256(bytes(public_key_der)).hexdigest()


def ed25519_public_key_pem(raw_public_key: bytes) -> bytes:
    """Wrap a raw 32-byte Ed25519 public key as an SPKI PEM document."""
    if len(raw_public_key) != 32:
        raise SignatureVerificationError("raw Ed25519 public key must be 32 bytes")
    return _der_to_pem(ED25519_SPKI_PREFIX + bytes(raw_public_key))


def _der_to_pem(der: bytes) -> bytes:
    body = base64.b64encode(der)
    lines = [body[index:index + 64] for index in range(0, len(body), 64)]
    return b"-----BEGIN PUBLIC KEY-----\n" + b"\n".join(lines) + b"\n-----END PUBLIC KEY-----\n"


def _check_canonical_value(value: Any) -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        raise ValueError("canonical JSON rejects floating-point values")
    if isinstance(value, (list, tuple)):
        for item in value:
            _check_canonical_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("canonical JSON object keys must be strings")
            _check_canonical_value(item)
        return
    raise ValueError(f"canonical JSON rejects values of type {type(value).__name__}")


def canonical_json(obj: Any) -> bytes:
    """Deterministic UTF-8 JSON: sorted keys, no whitespace, no floats, string keys only."""
    try:
        _check_canonical_value(obj)
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")
    except RecursionError as error:
        raise ValueError("canonical JSON value is nested too deeply") from error
    except UnicodeEncodeError as error:
        raise ValueError("canonical JSON strings must be valid Unicode") from error


def make_statement(kind: str, subject: dict) -> dict:
    if not isinstance(kind, str) or not kind:
        raise ValueError("statement kind must be a non-empty string")
    if not isinstance(subject, dict):
        raise ValueError("statement subject must be an object")
    return {"schema": STATEMENT_SCHEMA, "kind": kind, "subject": json.loads(canonical_json(subject))}


@contextlib.contextmanager
def _private_directory(parent: str | None) -> Iterator[Path]:
    directory = tempfile.mkdtemp(prefix="appsec-review-openssl-", dir=parent)
    try:
        os.chmod(directory, 0o700)
        yield Path(directory)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _write_new_file(path: Path, data: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC | _O_BINARY,
                         mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            if hasattr(os, "fchmod"):
                os.fchmod(handle.fileno(), mode)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        if descriptor != -1:
            os.close(descriptor)
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise


def _read_regular_file(path: Path, limit: int, what: str) -> bytes:
    try:
        info = os.lstat(path)
    except FileNotFoundError as error:
        raise SignatureVerificationError(f"{what} is missing: {path}") from error
    except OSError as error:
        raise SignatureVerificationError(f"{what} cannot be inspected: {path}: {error}") from error
    if is_link_or_reparse_point(info):
        raise SignatureVerificationError(f"{what} must not be a symbolic link: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise SignatureVerificationError(f"{what} must be a regular file: {path}")
    try:
        descriptor = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | _O_BINARY)
    except OSError as error:
        raise SignatureVerificationError(f"{what} cannot be opened: {path}: {error}") from error
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise SignatureVerificationError(f"{what} changed while it was opened: {path}")
        if opened.st_size > limit:
            raise SignatureVerificationError(f"{what} exceeds {limit} bytes: {path}")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise SignatureVerificationError(f"{what} exceeds {limit} bytes: {path}")
    return data


class OpenSSL:
    """Absolute-path OpenSSL 3 CLI run without a shell and with a fixed, minimal environment."""

    def __init__(self, binary: str | None = None, *, timeout: float = DEFAULT_TIMEOUT_SECONDS,
                 temp_dir: str | None = None) -> None:
        binary = default_openssl() if binary is None else os.fspath(binary)
        if not isinstance(binary, str) or not is_absolute_path(binary):
            raise SignatureVerificationError(f"OpenSSL binary must be an absolute path: {binary!r}")
        if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
            raise SignatureVerificationError(f"OpenSSL binary is not an executable file: {binary}")
        self.binary = binary
        self.timeout = float(timeout)
        self.temp_dir = temp_dir

    def _run(self, arguments: list[str], *, stdin: bytes | None = None,
             check: bool = True) -> subprocess.CompletedProcess[bytes]:
        if not windows_host():
            return self._execute(arguments, stdin, check, dict(_SANITIZED_ENV), "/")
        # Windows has no /dev/null file and OPENSSL_CONF=NUL is not portable across builds; an empty
        # private configuration file loads nothing on every OpenSSL 3 build.
        with _private_directory(self.temp_dir) as directory:
            config = directory / "openssl.cnf"
            _write_new_file(config, b"", 0o600)
            return self._execute(arguments, stdin, check,
                                 windows_openssl_environment(self.binary, str(config)), str(directory))

    def _execute(self, arguments: list[str], stdin: bytes | None, check: bool, environment: dict[str, str],
                 cwd: str) -> subprocess.CompletedProcess[bytes]:
        try:
            completed = subprocess.run(
                [self.binary, *arguments], input=stdin,
                stdin=subprocess.DEVNULL if stdin is None else None,
                capture_output=True, env=environment, cwd=cwd, shell=False,
                close_fds=True, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as error:
            raise SignatureVerificationError(f"openssl {arguments[0]} timed out") from error
        except OSError as error:
            raise SignatureVerificationError(f"openssl {arguments[0]} could not run: {error}") from error
        if check and completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", "replace").strip()[:500]
            raise SignatureVerificationError(
                f"openssl {arguments[0]} failed with exit code {completed.returncode}: {detail}")
        return completed

    def generate_private_key(self, path: str | os.PathLike[str]) -> Path:
        target = Path(os.path.abspath(path))
        if not target.parent.exists():
            target.parent.mkdir(mode=0o700, parents=True)
            os.chmod(target.parent, 0o700)
        if os.path.lexists(target):
            raise FileExistsError(f"private key already exists: {target}")
        pem = self._run(["genpkey", "-algorithm", "ed25519"]).stdout
        if not pem.startswith(b"-----BEGIN PRIVATE KEY-----"):
            raise SignatureVerificationError("openssl genpkey did not produce a PEM private key")
        _write_new_file(target, pem, 0o600)
        return target

    def public_key_pem(self, private_key_path: str | os.PathLike[str]) -> bytes:
        pem = self._run(["pkey", "-in", os.path.abspath(private_key_path), "-pubout"]).stdout
        return _der_to_pem(self.public_key_der(pem))

    def public_key_der(self, public_key_pem: bytes) -> bytes:
        if not isinstance(public_key_pem, (bytes, bytearray)) or not public_key_pem:
            raise SignatureVerificationError("public key PEM must be non-empty bytes")
        der = self._run(["pkey", "-pubin", "-inform", "PEM", "-outform", "DER"],
                        stdin=bytes(public_key_pem)).stdout
        if len(der) != _ED25519_SPKI_BYTES or not der.startswith(ED25519_SPKI_PREFIX):
            raise SignatureVerificationError("public key is not an Ed25519 SubjectPublicKeyInfo")
        return der

    def sign(self, private_key_path: str | os.PathLike[str], message: bytes) -> bytes:
        if not isinstance(message, (bytes, bytearray)) or not message:
            raise SignatureVerificationError("message to sign must be non-empty bytes")
        with _private_directory(self.temp_dir) as directory:
            message_path = directory / "message"
            _write_new_file(message_path, bytes(message), 0o600)
            signature = self._run(["pkeyutl", "-sign", "-inkey", os.path.abspath(private_key_path),
                                   "-rawin", "-in", str(message_path)]).stdout
        if len(signature) != SIGNATURE_BYTES:
            raise SignatureVerificationError("openssl did not produce a 64-byte Ed25519 signature")
        return signature

    def verify(self, public_key_pem: bytes, message: bytes, signature: bytes) -> bool:
        if not isinstance(message, (bytes, bytearray)) or not message:
            return False
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != SIGNATURE_BYTES:
            return False
        if not isinstance(public_key_pem, (bytes, bytearray)) or not public_key_pem:
            raise SignatureVerificationError("public key PEM must be non-empty bytes")
        with _private_directory(self.temp_dir) as directory:
            key_path, message_path, signature_path = (
                directory / "key.pem", directory / "message", directory / "signature")
            _write_new_file(key_path, bytes(public_key_pem), 0o600)
            _write_new_file(message_path, bytes(message), 0o600)
            _write_new_file(signature_path, bytes(signature), 0o600)
            completed = self._run(["pkeyutl", "-verify", "-pubin", "-inkey", str(key_path), "-rawin",
                                   "-in", str(message_path), "-sigfile", str(signature_path)],
                                  check=False)
        if completed.returncode == 0 and b"Signature Verified Successfully" in completed.stdout:
            return True
        if completed.returncode == 1 and b"Signature Verification Failure" in completed.stdout:
            return False
        detail = completed.stderr.decode("utf-8", "replace").strip()[:500]
        raise SignatureVerificationError(
            f"openssl pkeyutl -verify failed with exit code {completed.returncode}: {detail}")

    def self_test(self) -> bool:
        """Verify the RFC 8032 known answer and reject a one-bit corruption of it."""
        public_key_pem = ed25519_public_key_pem(_KAT_PUBLIC_KEY)
        if self.public_key_der(public_key_pem) != ED25519_SPKI_PREFIX + _KAT_PUBLIC_KEY:
            raise SignatureVerificationError("OpenSSL self-test failed: Ed25519 key round trip")
        if not self.verify(public_key_pem, _KAT_MESSAGE, _KAT_SIGNATURE):
            raise SignatureVerificationError("OpenSSL self-test failed: known-answer signature rejected")
        corrupted = bytes([_KAT_SIGNATURE[0] ^ 0x01]) + _KAT_SIGNATURE[1:]
        if self.verify(public_key_pem, _KAT_MESSAGE, corrupted):
            raise SignatureVerificationError("OpenSSL self-test failed: corrupted signature accepted")
        return True


class TrustedKeys(Mapping[str, bytes]):
    """Trust anchors keyed by recomputed key ID; values are normalized Ed25519 public-key PEM."""

    def __init__(self, keys: Mapping[str, bytes] | None = None) -> None:
        self._keys = dict(keys or {})

    def __getitem__(self, key: str) -> bytes:
        return self._keys[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._keys)

    def __len__(self) -> int:
        return len(self._keys)

    @classmethod
    def load(cls, directory: str | os.PathLike[str], openssl: OpenSSL) -> TrustedKeys:
        """Load ``<hex>.pem`` anchors; a missing or empty directory loads no keys and verifies nothing."""
        root = Path(directory)
        if not root.exists():
            return cls()
        if not root.is_dir():
            raise SignatureVerificationError(f"trusted keys path is not a directory: {root}")
        windows = windows_host()
        if windows:
            check_windows_custody(root, "anchor", "trusted keys directory", directory=True)
        keys: dict[str, bytes] = {}
        with os.scandir(root) as entries:
            names = sorted(entry.name for entry in entries if entry.name.endswith(".pem"))
        for name in names:
            path = root / name
            match = _KEY_FILE.fullmatch(name)
            if match is None:
                raise SignatureVerificationError(f"trusted key file name is not <sha256-hex>.pem: {path}")
            if windows:
                check_windows_custody(path, "anchor", "trusted key", directory=False)
            der = openssl.public_key_der(_read_regular_file(path, MAX_PUBLIC_KEY_BYTES, "trusted key"))
            identity = key_id(der)
            if identity != "sha256:" + match.group(1):
                raise SignatureVerificationError(
                    f"trusted key file name does not match its key ID {identity}: {path}")
            keys[identity] = _der_to_pem(der)
        return cls(keys)


def _check_statement(statement: Any, kind: str | None = None) -> None:
    if not isinstance(statement, dict) or set(statement) != {"schema", "kind", "subject"}:
        raise SignatureVerificationError("statement must have exactly schema, kind, and subject")
    if statement["schema"] != STATEMENT_SCHEMA:
        raise SignatureVerificationError(f"unsupported statement schema: {statement['schema']!r}")
    if not isinstance(statement["kind"], str) or not statement["kind"]:
        raise SignatureVerificationError("statement kind must be a non-empty string")
    if kind is not None and statement["kind"] != kind:
        raise SignatureVerificationError(
            f"statement kind {statement['kind']!r} does not match expected {kind!r}")
    if not isinstance(statement["subject"], dict):
        raise SignatureVerificationError("statement subject must be an object")


def _canonical_statement(statement: Any, kind: str | None = None) -> bytes:
    _check_statement(statement, kind)
    try:
        return canonical_json(statement)
    except ValueError as error:
        raise SignatureVerificationError(f"statement is not canonical JSON: {error}") from error


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str):
        raise SignatureVerificationError("signature must be a base64 string")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as error:
        raise SignatureVerificationError("signature is not strict base64") from error
    if base64.b64encode(raw).decode("ascii") != value:
        raise SignatureVerificationError("signature is not canonical base64")
    if len(raw) != SIGNATURE_BYTES:
        raise SignatureVerificationError(f"signature must decode to {SIGNATURE_BYTES} bytes")
    return raw


def _parsed_signatures(signatures: Any) -> list[tuple[str, bytes]]:
    if not isinstance(signatures, list) or not signatures:
        raise SignatureVerificationError("envelope signatures must be a non-empty list")
    if len(signatures) > MAX_SIGNATURES:
        raise SignatureVerificationError(f"envelope carries more than {MAX_SIGNATURES} signatures")
    parsed: list[tuple[str, bytes]] = []
    for entry in signatures:
        if not isinstance(entry, dict) or set(entry) != {"key_id", "algorithm", "signature"}:
            raise SignatureVerificationError(
                "signature entry must have exactly key_id, algorithm, and signature")
        if entry["algorithm"] != ALGORITHM:
            raise SignatureVerificationError(f"unsupported signature algorithm: {entry['algorithm']!r}")
        if not isinstance(entry["key_id"], str) or not _KEY_ID.fullmatch(entry["key_id"]):
            raise SignatureVerificationError("signature key_id must be sha256:<64 lowercase hex>")
        if any(entry["key_id"] == seen for seen, _ in parsed):
            raise SignatureVerificationError(f"duplicate signature for key {entry['key_id']}")
        parsed.append((entry["key_id"], _decode_signature(entry["signature"])))
    return parsed


def _check_envelope(envelope: Any) -> None:
    if not isinstance(envelope, dict) or set(envelope) != {"statement", "signatures"}:
        raise SignatureVerificationError("envelope must have exactly statement and signatures")


def check_private_key_custody(private_key_path: str | os.PathLike[str]) -> None:
    """On Windows, refuse a private key whose directory or file ACL lets a broad principal in.

    POSIX hosts are unchanged: there only keygen checks the private key directory's mode.
    """
    if not windows_host():
        return
    key = Path(os.path.abspath(private_key_path))
    check_windows_custody(key.parent, "private", "private key directory", directory=True)
    check_windows_custody(key, "private", "private key", directory=False)


def sign_statement(openssl: OpenSSL, private_key_path: str | os.PathLike[str], statement: dict) -> dict:
    message = _canonical_statement(statement)
    check_private_key_custody(private_key_path)
    signature = openssl.sign(private_key_path, message)
    public_key_pem = openssl.public_key_pem(private_key_path)
    if not openssl.verify(public_key_pem, message, signature):
        raise SignatureVerificationError("freshly produced signature does not verify")
    return {
        "statement": json.loads(message),
        "signatures": [{
            "key_id": key_id(openssl.public_key_der(public_key_pem)),
            "algorithm": ALGORITHM,
            "signature": base64.b64encode(signature).decode("ascii"),
        }],
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise ValueError(f"JSON constant {name} is not allowed")


def _reject_float(text: str) -> Any:
    raise ValueError("JSON floating-point numbers are not allowed")


def parse_envelope(data: bytes) -> dict:
    """Strictly parse envelope bytes without verifying any signature."""
    if not isinstance(data, (bytes, bytearray)):
        raise SignatureVerificationError("envelope bytes are required")
    if len(data) > MAX_ENVELOPE_BYTES:
        raise SignatureVerificationError(f"envelope exceeds {MAX_ENVELOPE_BYTES} bytes")
    try:
        value = json.loads(bytes(data).decode("utf-8"), object_pairs_hook=_reject_duplicate_keys,
                           parse_constant=_reject_constant, parse_float=_reject_float)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise SignatureVerificationError(f"envelope is not strict JSON: {error}") from error
    _check_envelope(value)
    return value


def verify_envelope(envelope: dict | bytes, trusted: TrustedKeys, openssl: OpenSSL, *, kind: str) -> dict:
    """Return the statement only if at least one trusted key signed it and no trusted signature fails.

    Signatures by keys outside ``trusted`` are ignored, so they never suffice on their own.
    """
    if isinstance(envelope, (bytes, bytearray)):
        envelope = parse_envelope(envelope)
    _check_envelope(envelope)
    message = _canonical_statement(envelope["statement"], kind)
    signatures = _parsed_signatures(envelope["signatures"])
    if not trusted:
        raise SignatureVerificationError("no trusted signing keys are configured")
    verified = 0
    for identity, signature in signatures:
        public_key_pem = trusted.get(identity)
        if public_key_pem is None:
            continue
        if not openssl.verify(public_key_pem, message, signature):
            raise SignatureVerificationError(f"signature by trusted key {identity} does not verify")
        verified += 1
    if not verified:
        raise SignatureVerificationError("envelope has no signature from a trusted key")
    return json.loads(message)


def write_envelope(path: str | os.PathLike[str], envelope: dict) -> None:
    """Atomically write a structurally valid envelope as canonical JSON plus a newline."""
    _check_envelope(envelope)
    _canonical_statement(envelope["statement"])
    _parsed_signatures(envelope["signatures"])
    try:
        data = canonical_json(envelope) + b"\n"
    except ValueError as error:
        raise SignatureVerificationError(f"envelope is not canonical JSON: {error}") from error
    target = Path(os.path.abspath(path))
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            if hasattr(os, "fchmod"):
                os.fchmod(handle.fileno(), 0o644)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise
    if hasattr(os, "O_DIRECTORY"):
        with contextlib.suppress(OSError):
            directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)


def read_envelope(path: str | os.PathLike[str]) -> dict:
    """Read and strictly parse an envelope file (no symlinks, size-capped); signatures are unchecked."""
    return parse_envelope(_read_regular_file(Path(path), MAX_ENVELOPE_BYTES, "signature envelope"))
