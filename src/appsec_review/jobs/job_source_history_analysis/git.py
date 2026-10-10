"""Hardened Git execution in the pinned ``tool-git`` image and parsers for its byte output.

The container sees the target read-only at ``/target``, run-owned scratch at ``/scratch``, and a
read-only ``/gitdir``: an application-written directory containing only a minimal ``config`` and a
detached ``HEAD`` that serves as ``GIT_DIR``; ``GIT_OBJECT_DIRECTORY`` points at the target's read-only object store.  The
target's config, hooks, attributes drivers, refs, mailmap, and replace refs are never consulted.

History output is target-controlled and unbounded in principle, so it is never held in memory as a
whole: ``log`` and ``messages`` write to run-owned files under an execution-level ``RLIMIT_FSIZE``
taken from central configuration, and the parsers read those files in fixed-size chunks with a bound
on every individual record. Reaching any bound is a named gap; partial output is never history.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import asdict, dataclass
import io
from pathlib import Path
import re
from typing import Any, BinaryIO

from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, Mount
from appsec_review.container_runtime.executor import FILE_SIZE_SIGNAL_EXIT

from .sources import GitSource


TOOL_ID = "tool-git"
ARGV_VERSION = "appsec-review/git-argv/1"
PARSER_IDENTITY = "appsec-review/git-history-stream-parser/2"
CHUNK_BYTES = 64 * 1024
LIMIT_RANGES: Mapping[str, tuple[int, int]] = {
    "max_output_bytes": (1, 64 * 1024 * 1024 * 1024), "max_record_bytes": (64, 16 * 1024 * 1024),
    "max_message_bytes": (1, 64 * 1024 * 1024), "max_changed_paths": (1, 100_000_000),
}
_PROTECTED_CONFIG = (
    "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null",
    "-c", "core.pager=cat", "-c", "log.showSignature=false", "-c", "safe.directory=*",
    "-c", "diff.renames=true", "-c", "core.quotePath=false",
)
_HEADER = re.compile(rb"\x01([0-9a-f]{40}|[0-9a-f]{64})\x1f([0-9a-f ]*)\x1f(-?[0-9]+)\x1f(-?[0-9]+)\x1f(.*)", re.S)


class HistoryBoundError(ValueError):
    """A configured history bound was reached; the history is incomplete and must not be used."""

    def __init__(self, gap: str):
        super().__init__(gap)
        self.gap = gap


@dataclass(frozen=True, slots=True)
class GitLimits:
    """Typed execution and parsing bounds for Git history, from central configuration."""

    max_output_bytes: int
    max_record_bytes: int
    max_message_bytes: int
    max_changed_paths: int

    def __post_init__(self) -> None:
        for key, (low, high) in LIMIT_RANGES.items():
            value = getattr(self, key)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"source history git limit is invalid: {key}")

    @classmethod
    def from_settings(cls, git: Mapping[str, Any]) -> "GitLimits":
        return cls(**{key: git.get(key) for key in LIMIT_RANGES})

    def as_dict(self) -> dict[str, int]:
        return {key: getattr(self, key) for key in LIMIT_RANGES}


@dataclass(frozen=True, slots=True)
class GitRun:
    stdout: bytes
    output: Path | None
    exit_code: int | None
    timed_out: bool
    truncated: bool
    execution: dict[str, Any]
    output_limit_reached: bool = False


class GitRunner:
    """Run one fixed Git subcommand per container execution against a sanitized repository view."""

    def __init__(self, executor: ContainerExecutor, target_root: Path, scratch_root: Path, source: GitSource,
                 limits: GitLimits):
        if source.decision != "SUCCEEDED" or source.git_dir is None or source.snapshot_commit is None:
            raise ValueError("git runner requires a resolved history source")
        self.executor = executor
        self.target_root = target_root
        self.scratch_root = scratch_root
        self.source = source
        self.limits = limits
        self.tool = executor.catalog.tool(TOOL_ID)
        self._prepare()

    def _prepare(self) -> None:
        git_dir = self.scratch_root / "gitdir"
        (git_dir / "refs").mkdir(parents=True, exist_ok=True)
        version = 1 if self.source.object_format == "sha256" else 0
        config = ["[core]", f"\trepositoryformatversion = {version}", "\tbare = true"]
        if self.source.object_format == "sha256":
            config += ["[extensions]", "\tobjectformat = sha256"]
        (git_dir / "config").write_text("\n".join(config) + "\n", encoding="utf-8")
        (git_dir / "HEAD").write_text(f"{self.source.snapshot_commit}\n", encoding="ascii")
        if self.source.shallow:
            (git_dir / "shallow").write_text("".join(f"{item}\n" for item in self.source.shallow), encoding="ascii")
        for path in (git_dir, git_dir / "refs", *git_dir.iterdir()):
            path.chmod(0o755 if path.is_dir() else 0o644)

    def environment(self) -> dict[str, str]:
        return {
            "GIT_DIR": "/gitdir",
            "GIT_OBJECT_DIRECTORY": f"/target/{self.source.git_dir}/objects",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ATTR_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat", "HOME": "/tmp", "XDG_CONFIG_HOME": "/dev/null", "LC_ALL": "C",
        }

    def run(self, name: str, arguments: tuple[str, ...], *, output_file: bool = False) -> GitRun:
        if not re.fullmatch(r"[a-z0-9_-]{1,64}", name):
            raise ValueError("git execution name is unsafe")
        scratch = self.scratch_root / "executions" / name
        output_name = f"{name}.bin"
        argv = (self.tool.executable, *_PROTECTED_CONFIG, "--no-pager", *arguments)
        if output_file:
            argv = (*argv[:-1], f"--output=/scratch/{output_name}", argv[-1])
        output_path = scratch / output_name
        if output_path.exists() or output_path.is_symlink():
            output_path.unlink()
        # One byte above the retention bound: a file that reaches it proves the producer was stopped.
        result = self.executor.execute(ExecutionRequest(
            tool_id=TOOL_ID, argv=argv, target_root=self.target_root, scratch_root=scratch,
            extra_mounts=(Mount(self.scratch_root / "gitdir", "/gitdir", True),),
            environment=self.environment(), working_directory="/scratch",
            file_size_limit_bytes=self.limits.max_output_bytes + 1,
        ))
        # stdout is already bounded and truncated by the executor's per-tool output limit.
        stdout = (self.executor.run_root / result.stdout_path).read_bytes()
        output: Path | None = None
        limited = result.file_size_limit_reached or result.exit_code == FILE_SIZE_SIGNAL_EXIT
        if output_file and output_path.is_file() and not output_path.is_symlink():
            output = output_path
            limited = limited or output_path.stat().st_size > self.limits.max_output_bytes
        execution = asdict(result)
        execution["output_limit_reached"] = limited
        return GitRun(stdout, output, result.exit_code, result.timed_out,
                      result.stdout_truncated, execution, limited)

    def log(self, max_count: int) -> GitRun:
        return self.run("log", (
            "log", "--first-parent", "--diff-merges=first-parent", "-M", "--numstat", "-z",
            "--no-ext-diff", "--no-textconv", "--no-mailmap", "--no-color", "--no-abbrev",
            f"--max-count={max_count}", "--format=%x01%H%x1f%P%x1f%at%x1f%ct%x1f%ae", "HEAD",
        ), output_file=True)

    def messages(self, max_count: int) -> GitRun:
        return self.run("messages", (
            "log", "--first-parent", "-z", "--no-mailmap", "--no-color",
            f"--max-count={max_count}", "--format=%H%x00%B", "HEAD",
        ), output_file=True)

    def tree(self) -> GitRun:
        return self.run("tree", ("ls-tree", "-r", "-z", "--full-tree", "HEAD"))

    def blame(self, index: int, path: str) -> GitRun:
        return self.run(f"blame-{index:05d}", (
            "blame", "--porcelain", "-w", "--no-progress", "HEAD", "--", path))


def iter_tokens(stream: BinaryIO, max_record_bytes: int) -> Iterator[bytes]:
    """Yield NUL-terminated tokens read in fixed chunks; no token may exceed ``max_record_bytes``."""
    pending = bytearray()
    while True:
        chunk = stream.read(CHUNK_BYTES)
        if not chunk:
            break
        start = 0
        while True:
            end = chunk.find(b"\0", start)
            piece = chunk[start:] if end < 0 else chunk[start:end]
            if len(pending) + len(piece) > max_record_bytes:
                raise HistoryBoundError("git_record_bound_reached")
            pending += piece
            if end < 0:
                break
            yield bytes(pending)
            pending.clear()
            start = end + 1
    if pending:
        yield bytes(pending)


def parse_log_stream(stream: BinaryIO, *, max_record_bytes: int, max_changed_paths: int) -> list[dict[str, Any]]:
    """Parse ``\\x01`` headers and ``-z --numstat`` records incrementally; paths may contain any byte.

    Raises :class:`HistoryBoundError` when a record or the retained changed-path count exceeds its
    bound; the caller must then treat the whole history as unavailable.
    """
    tokens = iter_tokens(stream, max_record_bytes)
    commits: list[dict[str, Any]] = []
    changed_paths = 0
    for raw in tokens:
        token = raw.lstrip(b"\n")
        if not token:
            continue
        header = _HEADER.fullmatch(token)
        if header is not None:
            parents = header.group(2).decode().split()
            commits.append({
                "commit": header.group(1).decode(), "parents": parents,
                "author_time": int(header.group(3)), "commit_time": int(header.group(4)),
                "author_key": header.group(5).strip().lower().decode("utf-8", "replace"),
                "files": [],
            })
            continue
        if not commits:
            raise ValueError("git log output does not begin with a commit header")
        fields = token.split(b"\t", 2)
        if len(fields) != 3 or not re.fullmatch(rb"[0-9]+|-", fields[0]) or not re.fullmatch(rb"[0-9]+|-", fields[1]):
            raise ValueError("git numstat record is malformed")
        binary = fields[0] == b"-" or fields[1] == b"-"
        added = 0 if binary else int(fields[0])
        deleted = 0 if binary else int(fields[1])
        if fields[2]:
            old, new = None, fields[2]
        else:
            old, new = next(tokens, None), next(tokens, None)
            if old is None or new is None:
                raise ValueError("git rename record is truncated")
        changed_paths += 1
        if changed_paths > max_changed_paths:
            raise HistoryBoundError("git_changed_path_bound_reached")
        commits[-1]["files"].append({
            "path": new.decode("utf-8", "surrogateescape"),
            "renamed_from": old.decode("utf-8", "surrogateescape") if old is not None else None,
            "added": added, "deleted": deleted, "binary": binary,
        })
    return commits


def parse_log(data: bytes, *, max_record_bytes: int = 1 << 24, max_changed_paths: int = 1 << 30) -> list[dict[str, Any]]:
    return parse_log_stream(io.BytesIO(data), max_record_bytes=max_record_bytes, max_changed_paths=max_changed_paths)


class _Buffer:
    """A sliding window over a stream; it never holds more than one chunk beyond what is consumed."""

    def __init__(self, stream: BinaryIO):
        self.stream = stream
        self.data = bytearray()
        self.eof = False

    def fill(self) -> bool:
        if self.eof:
            return False
        chunk = self.stream.read(CHUNK_BYTES)
        if not chunk:
            self.eof = True
            return False
        self.data += chunk
        return True

    def ensure(self, size: int) -> bool:
        while len(self.data) < size and self.fill():
            pass
        return len(self.data) >= size


def parse_messages_stream(stream: BinaryIO, ordered_commits: list[str], *, max_message_bytes: int
                          ) -> tuple[dict[str, bytes], list[str], list[str]]:
    """Split ``%H\\0%B\\0`` records by the known commit order so NUL bytes in bodies cannot misalign.

    At most ``max_message_bytes`` of each body is retained; longer bodies are streamed past and
    reported, so their classification is explicitly incomplete. Returns messages, gaps, and the
    commits whose bodies exceeded the bound.
    """
    messages: dict[str, bytes] = {}
    gaps: list[str] = []
    oversized: list[str] = []
    buffer = _Buffer(stream)
    for offset, commit in enumerate(ordered_commits):
        marker = commit.encode() + b"\0"
        if not buffer.ensure(len(marker)) or not buffer.data.startswith(marker):
            gaps.append("message_stream_misaligned")
            break
        del buffer.data[:len(marker)]
        retained = bytearray()
        total = 0

        def keep(part: bytes | bytearray) -> None:
            nonlocal total
            room = max_message_bytes - len(retained)
            if room > 0:
                retained.extend(part[:room])
            total += len(part)

        if offset + 1 < len(ordered_commits):
            separator = b"\0" + ordered_commits[offset + 1].encode() + b"\0"
            found = False
            while True:
                index = buffer.data.find(separator)
                if index >= 0:
                    keep(buffer.data[:index])
                    del buffer.data[:index + 1]
                    found = True
                    break
                safe = max(0, len(buffer.data) - len(separator) + 1)
                keep(buffer.data[:safe])
                del buffer.data[:safe]
                if not buffer.fill():
                    break
            if not found:
                gaps.append("message_stream_misaligned")
                break
        else:
            # Trailing NULs end the stream, but only EOF proves they are trailing; hold them back.
            while buffer.fill():
                body = buffer.data.rstrip(b"\0")
                keep(body)
                del buffer.data[:len(body)]
            keep(buffer.data.rstrip(b"\0"))
            buffer.data.clear()
        messages[commit] = bytes(retained)
        if total > max_message_bytes:
            oversized.append(commit)
    if oversized:
        gaps.append("commit_message_bound_reached")
    return messages, gaps, oversized


def parse_messages(data: bytes, ordered_commits: list[str], *, max_message_bytes: int = 1 << 30
                   ) -> tuple[dict[str, bytes], list[str]]:
    messages, gaps, _ = parse_messages_stream(io.BytesIO(data), ordered_commits, max_message_bytes=max_message_bytes)
    return messages, gaps


def parse_tree(data: bytes) -> dict[str, dict[str, str]]:
    entries: dict[str, dict[str, str]] = {}
    for record in data.split(b"\0"):
        if not record:
            continue
        meta, _, path = record.partition(b"\t")
        parts = meta.split(b" ")
        if len(parts) != 3 or not path:
            raise ValueError("git tree record is malformed")
        entries[path.decode("utf-8", "surrogateescape")] = {
            "mode": parts[0].decode(), "type": parts[1].decode(), "oid": parts[2].decode()}
    return entries


def parse_blame(data: bytes) -> list[int]:
    """Return the committer time of every blamed line from ``--porcelain`` output."""
    times: dict[str, int] = {}
    lines: list[int] = []
    current: str | None = None
    for raw in data.split(b"\n"):
        if raw.startswith(b"\t"):
            if current is None:
                raise ValueError("blame line precedes its header")
            lines.append(times.get(current, 0))
            continue
        header = re.fullmatch(rb"([0-9a-f]{40}|[0-9a-f]{64}) \d+ \d+(?: \d+)?", raw)
        if header is not None:
            current = header.group(1).decode()
        elif raw.startswith(b"committer-time ") and current is not None:
            times[current] = int(raw.split(b" ", 1)[1])
    return lines


ExecutorFactory = Callable[[Any], ContainerExecutor]
