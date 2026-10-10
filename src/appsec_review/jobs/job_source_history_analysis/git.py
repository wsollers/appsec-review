"""Hardened Git execution in the pinned ``tool-git`` image and parsers for its byte output.

The container sees the target read-only at ``/target``, run-owned scratch at ``/scratch``, and a
read-only ``/gitdir``: an application-written directory containing only a minimal ``config`` and a
detached ``HEAD`` that serves as ``GIT_DIR``; ``GIT_OBJECT_DIRECTORY`` points at the target's read-only object store.  The
target's config, hooks, attributes drivers, refs, mailmap, and replace refs are never consulted.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
import re
from typing import Any

from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, Mount

from .sources import GitSource


TOOL_ID = "tool-git"
ARGV_VERSION = "appsec-review/git-argv/1"
_PROTECTED_CONFIG = (
    "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null",
    "-c", "core.pager=cat", "-c", "log.showSignature=false", "-c", "safe.directory=*",
    "-c", "diff.renames=true", "-c", "core.quotePath=false",
)
_HEADER = re.compile(rb"\x01([0-9a-f]{40}|[0-9a-f]{64})\x1f([0-9a-f ]*)\x1f(-?[0-9]+)\x1f(-?[0-9]+)\x1f(.*)", re.S)


@dataclass(frozen=True, slots=True)
class GitRun:
    stdout: bytes
    output: bytes | None
    exit_code: int | None
    timed_out: bool
    truncated: bool
    execution: dict[str, Any]


class GitRunner:
    """Run one fixed Git subcommand per container execution against a sanitized repository view."""

    def __init__(self, executor: ContainerExecutor, target_root: Path, scratch_root: Path, source: GitSource):
        if source.decision != "SUCCEEDED" or source.git_dir is None or source.snapshot_commit is None:
            raise ValueError("git runner requires a resolved history source")
        self.executor = executor
        self.target_root = target_root
        self.scratch_root = scratch_root
        self.source = source
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
        result = self.executor.execute(ExecutionRequest(
            tool_id=TOOL_ID, argv=argv, target_root=self.target_root, scratch_root=scratch,
            extra_mounts=(Mount(self.scratch_root / "gitdir", "/gitdir", True),),
            environment=self.environment(), working_directory="/scratch",
        ))
        stdout = (self.executor.run_root / result.stdout_path).read_bytes()
        output_path = scratch / output_name
        output = output_path.read_bytes() if output_file and output_path.is_file() else None
        return GitRun(stdout, output, result.exit_code, result.timed_out,
                      result.stdout_truncated, asdict(result))

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


def parse_log(data: bytes) -> list[dict[str, Any]]:
    """Parse ``\\x01`` headers and ``-z --numstat`` records sequentially; paths may contain any byte."""
    tokens = data.split(b"\0")
    commits: list[dict[str, Any]] = []
    index = 0
    while index < len(tokens):
        token = tokens[index].lstrip(b"\n")
        index += 1
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
            if index + 1 >= len(tokens):
                raise ValueError("git rename record is truncated")
            old, new = tokens[index], tokens[index + 1]
            index += 2
        commits[-1]["files"].append({
            "path": new.decode("utf-8", "surrogateescape"),
            "renamed_from": old.decode("utf-8", "surrogateescape") if old is not None else None,
            "added": added, "deleted": deleted, "binary": binary,
        })
    return commits


def parse_messages(data: bytes, ordered_commits: list[str]) -> tuple[dict[str, bytes], list[str]]:
    """Split ``%H\\0%B\\0`` records by the known commit order so NUL bytes in bodies cannot misalign."""
    messages: dict[str, bytes] = {}
    gaps: list[str] = []
    position = 0
    for offset, commit in enumerate(ordered_commits):
        marker = commit.encode() + b"\0"
        if not data.startswith(marker, position):
            gaps.append("message_stream_misaligned")
            break
        start = position + len(marker)
        if offset + 1 < len(ordered_commits):
            end = data.find(b"\0" + ordered_commits[offset + 1].encode() + b"\0", start)
            if end < 0:
                gaps.append("message_stream_misaligned")
                break
            messages[commit] = data[start:end]
            position = end + 1
        else:
            messages[commit] = data[start:].rstrip(b"\0")
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
