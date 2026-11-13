from __future__ import annotations

from dataclasses import dataclass
import io
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_source_history_analysis import git
from appsec_review.jobs.job_source_history_analysis.sources import GitSource
from .support import HEAD, PARENT, header


def test_log_parser_preserves_paths_binary_renames_and_authors():
    first = header().replace(b"\x1f\x1f", b"\x1f" + PARENT.encode() + b"\x1f").replace(
        b"person@example.test", b"x\x1f@evil")
    raw = first + b"\n2\t3\ta\tb\nc\0-\t-\tbin\0" + b"1\t0\t\0old\0new\xff\0" + header(PARENT)
    parsed = git.parse_log(raw)
    assert parsed[0]["commit"] == HEAD and parsed[0]["author_key"] == "x\x1f@evil"
    assert parsed[0]["parents"] == [PARENT]
    assert parsed[0]["files"] == [
        {"path": "a\tb\nc", "renamed_from": None, "added": 2, "deleted": 3, "binary": False},
        {"path": "bin", "renamed_from": None, "added": 0, "deleted": 0, "binary": True},
        {"path": "new\udcff", "renamed_from": "old", "added": 1, "deleted": 0, "binary": False}]
    assert parsed[1]["files"] == [] and parsed[1]["parents"] == []


@pytest.mark.parametrize("data,message", [
    (b"1\t1\tx\0", "does not begin"),
    (header() + b"1\tx\tx\0", "malformed"),
    (header() + b"1\t1\t\0old\0", "truncated"),
], ids=["header", "numstat", "rename"])
def test_log_parser_refuses_malformed_records(data, message):
    with pytest.raises(ValueError, match=message):
        git.parse_log(data)


@pytest.mark.parametrize("bound", ["record", "paths"])
def test_log_parser_enforces_bounds_exactly(bound):
    data = header() + b"1\t1\tx\0"
    assert len(git.parse_log_stream(io.BytesIO(data), max_record_bytes=256, max_changed_paths=1)) == 1
    with pytest.raises(git.HistoryBoundError) as error:
        git.parse_log_stream(io.BytesIO(data), max_record_bytes=10 if bound == "record" else 256,
                             max_changed_paths=0 if bound == "paths" else 1)
    assert error.value.gap == ("git_record_bound_reached" if bound == "record" else "git_changed_path_bound_reached")


def test_tokens_cross_chunk_boundaries_and_keep_unterminated_tail(monkeypatch):
    monkeypatch.setattr(git, "CHUNK_BYTES", 3)
    assert list(git.iter_tokens(io.BytesIO(b"abc\0d\0\0tail"), 4)) == [b"abc", b"d", b"", b"tail"]


def test_messages_keep_embedded_nuls_and_mark_truncation(monkeypatch):
    monkeypatch.setattr(git, "CHUNK_BYTES", 7)
    body = b"fix\0stuff " + PARENT.encode() + b"\0 remains"
    raw = HEAD.encode() + b"\0" + body + b"\0" + PARENT.encode() + b"\0last\0\0"
    messages, gaps, oversized = git.parse_messages_stream(io.BytesIO(raw), [HEAD, PARENT], max_message_bytes=4)
    assert messages == {HEAD: b"fix\0", PARENT: b"last"}
    assert gaps == ["commit_message_bound_reached"] and oversized == [HEAD]
    assert git.parse_messages(raw, [HEAD, PARENT]) == ({HEAD: body, PARENT: b"last"}, [])


@pytest.mark.parametrize("raw", [b"", HEAD.encode() + b"\0without-next"], ids=["missing-first", "missing-next"])
def test_messages_reject_misalignment(raw):
    assert git.parse_messages_stream(io.BytesIO(raw), [HEAD, PARENT], max_message_bytes=10) == (
        {}, ["message_stream_misaligned"], [])


def test_tree_and_blame_parsers():
    assert git.parse_tree(f"100644 blob {HEAD}\tx.py\0".encode()) == {
        "x.py": {"mode": "100644", "type": "blob", "oid": HEAD}}
    with pytest.raises(ValueError, match="tree record is malformed"):
        git.parse_tree(b"broken\0")
    assert git.parse_blame(f"{HEAD} 1 1 2\ncommitter-time 10\n\ta\n{HEAD} 2 2\n\tb\n"
                           f"{PARENT} 3 3\n\tc\n".encode()) == [10, 10, 0]
    with pytest.raises(ValueError, match="precedes its header"):
        git.parse_blame(b"\torphan")


@pytest.mark.parametrize("key", sorted(git.LIMIT_RANGES))
def test_limits_reject_booleans_and_outside_values_and_accept_endpoints(key):
    base = {"max_output_bytes": 1000, "max_record_bytes": 128, "max_message_bytes": 50, "max_changed_paths": 10}
    low, high = git.LIMIT_RANGES[key]
    for bad in (True, low - 1, high + 1):
        with pytest.raises(ValueError, match=key):
            git.GitLimits.from_settings({**base, key: bad})
    for good in (low, high):
        assert git.GitLimits.from_settings({**base, key: good}).as_dict()[key] == good


@dataclass
class Result:
    stdout_path: str
    exit_code: int = 0
    timed_out: bool = False
    stdout_truncated: bool = False
    file_size_limit_reached: bool = False


class Executor:
    def __init__(self, root, *, size=0, signal=False):
        self.run_root, self.size, self.signal = root, size, signal
        self.catalog = SimpleNamespace(tool=lambda name: SimpleNamespace(executable="git"))
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        request.scratch_root.mkdir(parents=True, exist_ok=True)
        (self.run_root / "stdout").write_bytes(b"output")
        for arg in request.argv:
            if arg.startswith("--output="):
                (request.scratch_root / arg.rsplit("/", 1)[1]).write_bytes(b"x" * self.size)
        return Result("stdout", exit_code=153 if self.signal else 0)


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
def test_runner_uses_sanitized_metadata_and_fixed_argv(tmp_path, object_format):
    source = GitSource("SUCCEEDED", "resolved", ".git", object_format=object_format,
                       snapshot_commit=HEAD, shallow=(PARENT,))
    executor = Executor(tmp_path)
    runner = git.GitRunner(executor, tmp_path / "target", tmp_path / "scratch", source,
                           git.GitLimits(100, 128, 50, 10), path_prefix="component")
    config = (tmp_path / "scratch/gitdir/config").read_text()
    assert f"repositoryformatversion = {1 if object_format == 'sha256' else 0}" in config
    assert ("objectformat = sha256" in config) == (object_format == "sha256")
    assert (tmp_path / "scratch/gitdir/HEAD").read_text() == HEAD + "\n"
    assert (tmp_path / "scratch/gitdir/shallow").read_text() == PARENT + "\n"
    assert runner.environment()["GIT_OBJECT_DIRECTORY"] == "/target/.git/objects"
    assert runner.environment()["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert runner.log(3).stdout == b"output"
    runner.messages(4)
    runner.tree()
    runner.file_history(2, "component/a.py", 5)
    runner.blame(3, "component/a.py")
    runner.run("ancestor", ("merge-base", "--is-ancestor", HEAD, PARENT))
    args = [request.argv for request in executor.requests]
    assert "--max-count=3" in args[0] and "--numstat" in args[0] and "--first-parent" in args[0]
    assert "--max-count=4" in args[1] and "--format=%H%x00%B" in args[1]
    assert args[2][-5:] == ("ls-tree", "-r", "-z", "--full-tree", "HEAD")
    assert args[3][-2:] == ("--", "a.py") and "--follow" in args[3]
    assert args[4][-7:] == ("blame", "--porcelain", "-w", "--no-progress", "HEAD", "--", "a.py")
    assert executor.requests[-1].accepted_exit_codes == frozenset({0, 1})
    assert all(request.file_size_limit_bytes == 101 for request in executor.requests)
    assert all(request.extra_mounts[0].read_only for request in executor.requests)
    for name, argv, error in (("bad/name", (), "name is unsafe"),
                               ("outside", ("blame", "--", "elsewhere/a"), "outside its source")):
        with pytest.raises(ValueError, match=error):
            runner.run(name, argv)


@pytest.mark.parametrize("size,signal,limited", [(100, False, False), (101, False, True), (0, True, True)])
def test_runner_reports_output_limit_and_removes_stale_output(tmp_path, size, signal, limited):
    executor = Executor(tmp_path, size=size, signal=signal)
    source = GitSource("SUCCEEDED", "resolved", ".git", snapshot_commit=HEAD)
    runner = git.GitRunner(executor, tmp_path / "target", tmp_path / "scratch", source, git.GitLimits(100, 128, 50, 10))
    stale = tmp_path / "scratch/executions/log/log.bin"
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b"old")
    result = runner.log(2)
    assert result.output_limit_reached is limited and result.execution["output_limit_reached"] is limited
    assert result.output.read_bytes() == b"x" * size
    with pytest.raises(ValueError, match="resolved history source"):
        git.GitRunner(executor, tmp_path, tmp_path, GitSource("GAP", "missing"), runner.limits)


def test_stream_parsers_never_request_unbounded_reads():
    class Reader(io.BytesIO):
        def read(self, size=-1):
            assert 0 < size <= git.CHUNK_BYTES
            return super().read(size)

    raw = header() + b"1\t1\ta.py\0" * 15000
    result = git.parse_log_stream(Reader(raw), max_record_bytes=256, max_changed_paths=15000)
    assert len(result[0]["files"]) == 15000
    with pytest.raises(git.HistoryBoundError, match="git_changed_path_bound_reached"):
        git.parse_log_stream(Reader(raw), max_record_bytes=256, max_changed_paths=14999)
    long_path = header() + b"1\t1\t" + b"x" * (3 * git.CHUNK_BYTES) + b"\0"
    with pytest.raises(git.HistoryBoundError, match="git_record_bound_reached"):
        git.parse_log_stream(Reader(long_path), max_record_bytes=4096, max_changed_paths=10)
    body = b"fix: " + b"x\0y" * git.CHUNK_BYTES
    raw = HEAD.encode() + b"\0" + body + b"\0" + PARENT.encode() + b"\0last\n\0"
    messages, gaps, oversized = git.parse_messages_stream(Reader(raw), [HEAD, PARENT], max_message_bytes=1024)
    assert messages == {HEAD: body[:1024], PARENT: b"last\n"}
    assert gaps == ["commit_message_bound_reached"] and oversized == [HEAD]
    assert git.parse_messages_stream(Reader(raw), [HEAD, PARENT], max_message_bytes=len(body))[0][HEAD] == body
