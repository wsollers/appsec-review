"""Trusted provisioning roles, separate from target-controlled file names."""
from __future__ import annotations

from pathlib import PurePosixPath
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
import re

from appsec_review.config.assurance import ScopeRole


_CODEQL_SUPPLIED = re.compile(
    r"data/codeql/scopes/[^/]+/export/(?:pack(?:/.*)?|columns\.json|assets\.lock\.json)")
_JVM_SUPPLIED = re.compile(
    r"data/build/jvm/units/[^/]+/(?:instrumentation(?:/.*)?|instrumentation-evidence/jdk(?:/.*)?)")
_ACTIVE: ContextVar[tuple[Path, Path, Path | None] | None] = ContextVar("customer_review_scope", default=None)


@contextmanager
def review_scope(repository_root: Path, run_root: Path, target_root: Path | None):
    token = _ACTIVE.set((repository_root.resolve(), run_root.resolve(),
                         target_root.resolve() if target_root is not None else None))
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def require_hashable_evidence(path: Path) -> None:
    scope = _ACTIVE.get()
    if scope is None:
        return
    repository, run, target = scope
    candidate = path.resolve()
    if candidate.is_relative_to(run):
        if supplied_run_path(candidate.relative_to(run).as_posix()):
            raise ValueError("supplied platform payload hashing is excluded from customer review")
        return
    if target is not None and candidate.is_relative_to(target):
        return
    if any(candidate.is_relative_to(repository / name) for name in ("src", "containers", "rules")):
        raise ValueError("supplied platform payload hashing is excluded from customer review")


def supplied_run_path(relative: str) -> bool:
    """Only application-reserved run layouts; never apply this to target-relative paths."""
    return (_CODEQL_SUPPLIED.fullmatch(relative) is not None
            or _JVM_SUPPLIED.fullmatch(relative) is not None)


def target_role(relative: str) -> ScopeRole:
    path = PurePosixPath(relative)
    if (path.parts[:1] in ((".github",), (".gitlab",)) or path.name in {
            "Dockerfile", "Makefile", "CMakeLists.txt", "package.json", "package-lock.json",
            "pnpm-lock.yaml", "yarn.lock", "pyproject.toml", "setup.py", "Cargo.toml", "Cargo.lock",
            "go.mod", "go.sum", "build.gradle", "pom.xml"}):
        return ScopeRole.BUILD_CHAIN
    return ScopeRole.TARGET_SOURCE
