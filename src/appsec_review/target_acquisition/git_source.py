"""Materialize a Git repository at a pinned commit, following submodule gitlinks recursively.

The repository and every ``.gitmodules`` file are untrusted. Each Git process runs with an
explicit environment: no system configuration, no terminal prompt, no repository hooks, no LFS
smudge, fsck on transfer, symbolic links written as plain files, and a transport allow-list that
refuses everything except https and ssh (and ``file`` only when local sources are allowed).
Credentials come from the operator's own Git credential helpers or ssh agent, never from here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .safety import (AcquisitionError, base_environment, check_git_url, run_command, safe_relative,
                     scrub, tail)


LFS_POINTER_PREFIX = b"version https://git-lfs.github.com/spec/"
MAX_LISTED_GAPS = 1000


@dataclass(slots=True)
class GitResult:
    commit: str
    tree: str
    object_format: str
    submodules: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[dict[str, str]] = field(default_factory=list)
    version: str = ""


class Git:
    def __init__(self, executable: str, *, scratch: Path, allow_local: bool, timeout: int) -> None:
        hooks = scratch / "empty-hooks"
        template = scratch / "empty-template"
        hooks.mkdir(parents=True, exist_ok=True)
        template.mkdir(parents=True, exist_ok=True)
        pairs = [
            ("core.symlinks", "false"), ("core.hooksPath", str(hooks)), ("core.fsmonitor", "false"),
            ("core.autocrlf", "false"), ("core.eol", "lf"), ("init.templateDir", str(template)),
            ("init.defaultBranch", "appsec-review"), ("advice.detachedHead", "false"),
            ("transfer.fsckObjects", "true"), ("fetch.fsckObjects", "true"), ("submodule.recurse", "false"),
            ("fetch.recurseSubmodules", "false"), ("protocol.allow", "never"),
            ("protocol.https.allow", "always"), ("protocol.ssh.allow", "always"),
            ("protocol.file.allow", "always" if allow_local else "never"),
            ("filter.lfs.smudge", ""), ("filter.lfs.process", ""), ("filter.lfs.required", "false"),
            ("gc.auto", "0"), ("maintenance.auto", "false"), ("credential.interactive", "false"),
        ]
        self.env = base_environment()
        self.env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_LFS_SKIP_SMUDGE": "1",
                         "GCM_INTERACTIVE": "never", "GIT_PROTOCOL_FROM_USER": "0",
                         "GIT_CONFIG_COUNT": str(len(pairs))})
        for index, (key, value) in enumerate(pairs):
            self.env[f"GIT_CONFIG_KEY_{index}"] = key
            self.env[f"GIT_CONFIG_VALUE_{index}"] = value
        self.executable = executable
        self.allow_local = allow_local
        self.timeout = timeout

    def __call__(self, *args: str, cwd: Path | None = None, check: bool = True,
                 stdout_limit: int | None = None):
        return run_command([self.executable, *args], env=self.env, cwd=cwd, timeout=self.timeout,
                           check=check, stdout_limit=stdout_limit)

    def text(self, *args: str, cwd: Path | None = None) -> str:
        return self(*args, cwd=cwd).stdout.decode("utf-8", "surrogateescape").strip()

    def version(self) -> str:
        return self.text("--version")

    def has_commit(self, repo: Path, commit: str) -> bool:
        return self("cat-file", "-e", f"{commit}^{{commit}}", cwd=repo, check=False).returncode == 0

    def fetch_pinned(self, repo: Path, url: str, commit: str, refs: tuple[str, ...] = (),
                     extra_commits: tuple[str, ...] = ()) -> None:
        """Fetch branches, tags, and the named refs, then the pinned commit itself if still absent."""
        check_git_url(url, allow_local=self.allow_local)
        object_format = "sha256" if len(commit) == 64 else "sha1"
        repo.mkdir(parents=True, exist_ok=False)
        self("init", "--quiet", f"--object-format={object_format}", str(repo))
        self("remote", "add", "origin", "--", url, cwd=repo)
        refspecs = ["+refs/heads/*:refs/remotes/origin/*", "+refs/tags/*:refs/tags/*"]
        refspecs += [f"+{ref}:refs/appsec-review/fetched/{index}" for index, ref in enumerate(refs)]
        self("fetch", "--quiet", "--no-recurse-submodules", "--", "origin", *refspecs, cwd=repo)
        for wanted in (commit, *extra_commits):
            if not self.has_commit(repo, wanted):
                self("fetch", "--quiet", "--no-recurse-submodules", "--", "origin", wanted, cwd=repo, check=False)
        if not self.has_commit(repo, commit):
            raise AcquisitionError(f"pinned commit {commit} is not reachable from the configured repository")

    def checkout(self, repo: Path, commit: str) -> str:
        self("checkout", "--quiet", "--detach", commit, cwd=repo)
        head = self.text("rev-parse", "--verify", "HEAD^{commit}", cwd=repo)
        if head != commit:
            raise AcquisitionError(f"checked-out HEAD {head} does not match the pinned commit {commit}")
        return self.text("rev-parse", "--verify", "HEAD^{tree}", cwd=repo)

    def index_entries(self, repo: Path) -> list[tuple[str, str, str]]:
        """``(mode, object, path)`` for every index entry, NUL-separated so no path is ambiguous."""
        output = self("ls-files", "--stage", "-z", cwd=repo).stdout
        entries = []
        for record in output.split(b"\0"):
            if not record:
                continue
            meta, _, path = record.partition(b"\t")
            mode, obj, _stage = meta.decode("ascii").split(" ")
            entries.append((mode, obj, path.decode("utf-8", "surrogateescape")))
        return entries

    def submodule_names(self, repo: Path) -> dict[str, str]:
        """Map gitlink path to submodule name from the commit's ``.gitmodules`` (untrusted)."""
        if not (repo / ".gitmodules").is_file() or (repo / ".gitmodules").is_symlink():
            return {}
        result = self("config", "--file", ".gitmodules", "-z", "--get-regexp", r"^submodule\..*\.path$",
                      cwd=repo, check=False)
        names: dict[str, str] = {}
        for record in result.stdout.split(b"\0"):
            key, _, value = record.decode("utf-8", "surrogateescape").partition("\n")
            if key.startswith("submodule.") and key.endswith(".path") and value:
                names.setdefault(value, key[len("submodule."):-len(".path")])
        return names


def _gap(gaps: list[dict[str, str]], reason: str, path: str = ".", detail: str | None = None) -> None:
    if len(gaps) >= MAX_LISTED_GAPS:
        if not gaps or gaps[-1]["reason"] != "gap_list_truncated":
            gaps.append({"path": ".", "reason": "gap_list_truncated"})
        return
    item = {"path": path, "reason": reason}
    if detail:
        item["detail"] = detail[:500]
    gaps.append(item)


def materialize(git: Git, *, url: str, commit: str, dest: Path, refs: tuple[str, ...], submodules: str,
                max_depth: int, max_path_bytes: int, extra_commits: tuple[str, ...] = ()) -> GitResult:
    git.fetch_pinned(dest, url, commit, refs, extra_commits)
    tree = git.checkout(dest, commit)
    result = GitResult(commit=commit, tree=tree, object_format="sha256" if len(commit) == 64 else "sha1",
                       version=git.version())
    _inspect_repository(git, dest, "", 0, submodules, max_depth, max_path_bytes, result)
    result.submodules.sort(key=lambda item: item["path"])
    return result


def _inspect_repository(git: Git, repo: Path, prefix: str, depth: int, mode: str, max_depth: int,
                        max_path_bytes: int, result: GitResult) -> None:
    gitlinks = []
    for entry_mode, obj, path in git.index_entries(repo):
        safe_relative(prefix + path, max_bytes=max_path_bytes)
        if entry_mode == "120000":
            _gap(result.gaps, "symlink_materialized_as_text", prefix + path)
        elif entry_mode == "160000":
            gitlinks.append((path, obj))
    if not gitlinks:
        return
    if mode == "none":
        for path, obj in gitlinks:
            _gap(result.gaps, "submodule_not_materialized", prefix + path, f"submodules = \"none\"; gitlink {obj}")
        return
    names = git.submodule_names(repo)
    for path, obj in sorted(gitlinks):
        location = prefix + path
        if depth + 1 > max_depth:
            _gap(result.gaps, "submodule_depth_exceeded", location, f"gitlink {obj}")
            continue
        name = names.get(path)
        if name is None:
            _gap(result.gaps, "submodule_url_missing", location, f"gitlink {obj}")
            continue
        git("submodule", "init", "--", path, cwd=repo, check=False)
        configured = git("config", "--get", f"submodule.{name}.url", cwd=repo, check=False)
        sub_url = configured.stdout.decode("utf-8", "surrogateescape").strip()
        try:
            check_git_url(sub_url, allow_local=git.allow_local, field_name="submodule url")
        except AcquisitionError as exc:
            _gap(result.gaps, "submodule_url_refused", location, str(exc))
            continue
        update = git("submodule", "update", "--init", "--checkout", "--", path, cwd=repo, check=False)
        sub_repo = repo / path
        if update.returncode != 0:
            _gap(result.gaps, "submodule_checkout_failed", location, scrub(tail(update.stderr, 400), ()))
            continue
        head = git("rev-parse", "--verify", "HEAD^{commit}", cwd=sub_repo, check=False)
        actual = head.stdout.decode("ascii", "replace").strip()
        if head.returncode != 0 or actual != obj:
            _gap(result.gaps, "submodule_commit_mismatch", location, f"expected {obj}, found {actual or 'none'}")
            continue
        result.submodules.append({"path": location, "name": name, "url": sub_url, "commit": obj,
                                  "tree": git.text("rev-parse", "--verify", "HEAD^{tree}", cwd=sub_repo),
                                  "depth": depth + 1})
        _inspect_repository(git, sub_repo, location + "/", depth + 1, mode, max_depth, max_path_bytes, result)


def lfs_pointer_gaps(root: Path, gaps: list[dict[str, str]]) -> None:
    """Large-file pointers are not fetched (LFS smudge is disabled); each one is a named gap."""
    for path in sorted(root.rglob("*")):
        if ".git" in path.relative_to(root).parts or path.is_symlink() or not path.is_file():
            continue
        if path.stat().st_size <= 1024:
            with path.open("rb") as handle:
                if handle.read(len(LFS_POINTER_PREFIX)) == LFS_POINTER_PREFIX:
                    _gap(gaps, "git_lfs_object_not_fetched", path.relative_to(root).as_posix())


def change_diff(git: Git, repo: Path, base: str, head: str, max_bytes: int) -> tuple[bytes | None, list[dict[str, Any]], list[dict[str, str]]]:
    """The base-to-head patch and changed paths for a review revision, or named gaps."""
    gaps: list[dict[str, str]] = []
    if not git.has_commit(repo, base):
        _gap(gaps, "change_base_unavailable", ".", f"base {base} was not fetched")
        return None, [], gaps
    names = git("diff", "--no-color", "--no-ext-diff", "--no-textconv", "--name-status", "-z", "-M",
                base, head, "--", cwd=repo).stdout.split(b"\0")
    changed: list[dict[str, Any]] = []
    index = 0
    while index < len(names) and names[index]:
        status = names[index].decode("ascii", "replace")
        count = 2 if status[:1] in {"R", "C"} else 1
        paths = [item.decode("utf-8", "surrogateescape") for item in names[index + 1:index + 1 + count]]
        changed.append({"status": status[:1], "score": status[1:] or None, "paths": paths})
        index += 1 + count
    patch = git("diff", "--no-color", "--no-ext-diff", "--no-textconv", "--binary", "--full-index", "-M",
                base, head, "--", cwd=repo, check=False)
    if patch.returncode != 0:
        _gap(gaps, "change_diff_failed", ".", scrub(tail(patch.stderr, 400), ()))
        return None, changed, gaps
    if len(patch.stdout) > max_bytes:
        _gap(gaps, "change_diff_too_large", ".", f"{len(patch.stdout)} bytes exceeds max_diff_bytes")
        return None, changed, gaps
    return patch.stdout, changed, gaps
