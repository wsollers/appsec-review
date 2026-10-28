"""Safety primitives shared by every acquisition source.

Nothing here trusts the source: URLs come from configuration or from untrusted ``.gitmodules``,
paths come from the depot or the repository, and process output may echo secrets back. Every check
fails closed.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import ipaddress
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any
from urllib.parse import urlsplit


class AcquisitionError(RuntimeError):
    """A refusal or failure that publishes nothing. ``status`` is REFUSED or FAILED."""

    def __init__(self, message: str, *, status: str = "FAILED") -> None:
        super().__init__(message)
        self.status = status


_SCP_LIKE = re.compile(r"[A-Za-z0-9._-]{1,64}@[A-Za-z0-9.\-]{1,255}:[A-Za-z0-9._~/-][A-Za-z0-9._~/ -]{0,1023}")
_HOST = re.compile(r"[A-Za-z0-9.\-]{1,255}|[0-9A-Fa-f:.]{2,45}")
_USER = re.compile(r"[A-Za-z0-9._-]{1,64}")
_PRINTABLE = re.compile(r"[^\x00-\x1f\x7f]*")


def is_loopback(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def check_git_url(url: str, *, allow_local: bool, field_name: str = "url") -> str:
    """Return the URL's transport, or refuse a URL that could carry credentials or run commands.

    Allowed: ``https://host/...`` with no user information, ``ssh://[user@]host[:port]/...``, the
    scp-like ``user@host:path``, and, only with ``allow_local``, ``file://`` URLs and absolute paths.
    """
    if (not isinstance(url, str) or not url or len(url) > 2048 or not _PRINTABLE.fullmatch(url)
            or url != url.strip()):
        raise AcquisitionError(f"{field_name} is not a valid Git URL", status="REFUSED")
    if url.startswith("-") or "::" in url.split("/", 1)[0]:
        raise AcquisitionError(f"{field_name} uses a refused Git transport", status="REFUSED")
    if "://" not in url:
        if _SCP_LIKE.fullmatch(url) and ".." not in url.split(":", 1)[1].split("/"):
            return "ssh"
        if allow_local and (Path(url).is_absolute() or PurePosixPath(url).is_absolute()):
            return "file"
        raise AcquisitionError(f"{field_name} is not an allowed Git URL", status="REFUSED")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme == "file":
        if not allow_local:
            raise AcquisitionError(f"{field_name}: file:// sources need allow_local_sources", status="REFUSED")
        return "file"
    if scheme not in {"https", "ssh"}:
        raise AcquisitionError(f"{field_name}: Git transport {scheme!r} is refused", status="REFUSED")
    try:
        parts.port
    except ValueError as exc:
        raise AcquisitionError(f"{field_name} has an invalid port", status="REFUSED") from exc
    if parts.query or parts.fragment or not parts.hostname or not _HOST.fullmatch(parts.hostname):
        raise AcquisitionError(f"{field_name} is not a valid Git URL", status="REFUSED")
    if parts.password is not None or (scheme == "https" and parts.username is not None):
        raise AcquisitionError(
            f"{field_name} embeds credentials; use a Git credential helper or ssh agent instead", status="REFUSED")
    if parts.username is not None and not _USER.fullmatch(parts.username):
        raise AcquisitionError(f"{field_name} has an invalid user name", status="REFUSED")
    if ".." in PurePosixPath(parts.path).parts:
        raise AcquisitionError(f"{field_name} path is invalid", status="REFUSED")
    return scheme


def check_http_url(url: str, *, allow_local: bool) -> None:
    parts = urlsplit(url)
    if parts.username is not None or parts.password is not None:
        raise AcquisitionError("review API URL embeds credentials", status="REFUSED")
    if parts.scheme == "https" and parts.hostname:
        return
    if parts.scheme == "http" and allow_local and is_loopback(parts.hostname):
        return
    raise AcquisitionError("review API URL must use https (plain http only for loopback with allow_local_sources)",
                           status="REFUSED")


def safe_relative(path: str, *, max_bytes: int) -> PurePosixPath:
    """Validate one source-supplied relative path before anything is written for it."""
    if (not path or "\x00" in path or "\\" in path or path.startswith("/") or
            len(path.encode("utf-8", "surrogateescape")) > max_bytes or not _PRINTABLE.fullmatch(path)):
        raise AcquisitionError(f"unsafe source path: {path[:200]!r}")
    pure = PurePosixPath(path)
    if any(part in {"", ".", ".."} for part in path.split("/")) or pure.parts[0].endswith(":"):
        raise AcquisitionError(f"unsafe source path: {path[:200]!r}")
    if any(part.lower() == ".git" for part in pure.parts):
        raise AcquisitionError(f"source path enters a .git directory: {path[:200]!r}")
    return pure


def scrub(text: str, secrets: Iterable[str]) -> str:
    """Remove every secret value (and URL user information) from process output kept in a record."""
    for secret in sorted((item for item in secrets if item and len(item) >= 4), key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    return re.sub(r"(https?://)[^/@\s]+@", r"\1[REDACTED]@", text)


def tail(data: bytes | str, limit: int = 2000) -> str:
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
    return text[-limit:]


def run_command(argv: Sequence[str], *, env: Mapping[str, str], cwd: Path | None, timeout: int,
                secrets: Sequence[str] = (), check: bool = True,
                stdout_limit: int | None = None) -> subprocess.CompletedProcess[bytes]:
    """Run one tool with an explicit environment, no shell, no stdin, and a hard timeout."""
    try:
        result = subprocess.run(list(argv), cwd=cwd, env=dict(env), stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise AcquisitionError(f"tool is not installed: {argv[0]}", status="REFUSED") from exc
    except subprocess.TimeoutExpired as exc:
        raise AcquisitionError(f"{Path(argv[0]).name} {argv[1] if len(argv) > 1 else ''} "
                               f"timed out after {timeout}s") from exc
    if stdout_limit is not None and len(result.stdout) > stdout_limit:
        raise AcquisitionError(f"{Path(argv[0]).name} output exceeded {stdout_limit} bytes")
    if check and result.returncode != 0:
        raise AcquisitionError(f"{Path(argv[0]).name} {describe(argv)} exited {result.returncode}: "
                               + scrub(tail(result.stderr or result.stdout), secrets))
    return result


def describe(argv: Sequence[str]) -> str:
    """A short, secret-free rendering of a command's subcommand (no option values beyond -c keys)."""
    words = [item for item in argv[1:] if not item.startswith("-") and "=" not in item][:3]
    return " ".join(item if len(item) <= 80 else item[:77] + "..." for item in words)


def inspect_tree(root: Path, *, max_files: int, max_total_bytes: int, max_file_bytes: int,
                 max_path_bytes: int) -> dict[str, Any]:
    """Verify a materialized tree: no symbolic links, no special files, everything inside bounds.

    ``.git`` directories and submodule ``.git`` files are repository metadata and are skipped, as
    the review's own source fingerprint skips them.
    """
    root = root.resolve(strict=True)
    count = total = 0
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        for name in dirnames:
            candidate = base / name
            if candidate.is_symlink():
                raise AcquisitionError(f"materialized tree contains a symbolic link: {candidate.relative_to(root)}")
        dirnames[:] = sorted(name for name in dirnames if name != ".git")
        for name in sorted(filenames):
            candidate = base / name
            relative = candidate.relative_to(root).as_posix()
            if candidate.is_symlink():
                raise AcquisitionError(f"materialized tree contains a symbolic link: {relative}")
            if name == ".git":
                continue
            if not candidate.is_file():
                raise AcquisitionError(f"materialized tree contains a special file: {relative}")
            if len(relative.encode("utf-8", "surrogateescape")) > max_path_bytes:
                raise AcquisitionError(f"materialized path exceeds max_path_bytes: {relative[:200]}")
            size = candidate.stat().st_size
            if size > max_file_bytes:
                raise AcquisitionError(f"file exceeds max_file_bytes: {relative}")
            count += 1
            total += size
            if count > max_files:
                raise AcquisitionError("materialized tree exceeds max_files")
            if total > max_total_bytes:
                raise AcquisitionError("materialized tree exceeds max_total_bytes")
    return {"file_count": count, "total_bytes": total}


def base_environment() -> dict[str, str]:
    """The minimal inherited environment tools need (locale, home, path, temp, ssh agent, CA bundle)."""
    keep = ("PATH", "HOME", "USERPROFILE", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT",
            "SystemRoot", "COMSPEC", "PATHEXT", "WINDIR", "APPDATA", "LOCALAPPDATA", "SSH_AUTH_SOCK",
            "XDG_CONFIG_HOME", "GIT_SSH_COMMAND", "SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO")
    return {key: os.environ[key] for key in keep if key in os.environ}
