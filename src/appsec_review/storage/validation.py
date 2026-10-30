"""Explicit, bounded-lifetime verification state, never proof of immutable custody."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Iterator, ParamSpec, TypeVar

from .atomic import file_sha256

AliasKey = tuple[int, int, int, int]


def _alias_key(path: Path) -> AliasKey:
    status = path.stat()
    return status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns


@dataclass
class ValidationContext:
    run_root: Path
    target_snapshot: str = "unknown"
    policy_identity: str = "strict-legacy"
    hashes: dict[tuple[Path, str], str] = field(default_factory=dict)
    # Hard-link alias digests: one inode published under several run paths is hashed once per
    # validation context. Never shared across contexts or attempts.
    aliases: dict[AliasKey, str] = field(default_factory=dict)
    records: dict[tuple[str, str, str], Any] = field(default_factory=dict)
    admitted: dict[tuple[str, str], int] = field(default_factory=dict)
    admitted_receipts: dict[str, Any] = field(default_factory=dict)
    admitted_manifests: dict[str, Any] = field(default_factory=dict)
    lock: Any = field(default_factory=RLock)

    def _resolved(self, path: Path) -> Path:
        resolved = path.resolve()
        if self.run_root not in resolved.parents:
            raise ValueError("validation object escapes its run")
        return resolved

    def remember(self, path: Path, digest: str) -> None:
        """Record bytes this context wrote and hashed itself, keyed by inode alias."""
        self._resolved(path)
        with self.lock:
            self.aliases[_alias_key(path)] = digest

    def observe(self, path: Path) -> str:
        """Return the digest of ``path``, hashing an inode at most once per context."""
        self._resolved(path)
        with self.lock:
            before = _alias_key(path)
            cached = self.aliases.get(before)
            if cached is not None:
                return cached
            actual = file_sha256(path)
            if _alias_key(path) == before:
                self.aliases[before] = actual
            return actual

    def digest(self, path: Path, expected: str) -> str:
        resolved = self._resolved(path)
        key = (resolved, expected)
        with self.lock:
            admitted = self.admitted.get((resolved.relative_to(self.run_root).as_posix(), expected))
            if admitted is not None and path.stat().st_size == admitted:
                return expected
            if key not in self.hashes:
                actual = self.observe(path)
                if actual != expected:
                    raise ValueError("target evidence integrity mismatch")
                self.hashes[key] = actual
            return self.hashes[key]


_ACTIVE: ContextVar[ValidationContext | None] = ContextVar("validation_operation", default=None)


def current_validation(root: Path) -> ValidationContext | None:
    current = _ACTIVE.get()
    if current is None:
        return None
    if current.run_root == root:
        return current
    return current if current.run_root == root.resolve() else None


@contextmanager
def validation_scope(root: Path, *, target_snapshot: str | None = None,
                     policy_identity: str | None = None) -> Iterator[ValidationContext]:
    existing = current_validation(root)
    if existing is not None:
        if ((target_snapshot is not None and target_snapshot != existing.target_snapshot)
                or (policy_identity is not None and policy_identity != existing.policy_identity)):
            raise ValueError("nested validation target or policy identity changed")
        yield existing
        return
    context = ValidationContext(root.resolve(), target_snapshot or "unknown", policy_identity or "strict-legacy")
    token = _ACTIVE.set(context)
    try:
        yield context
    finally:
        _ACTIVE.reset(token)


def verified_digest(root: Path, path: Path, expected: str) -> str:
    context = current_validation(root)
    if context is None:
        with validation_scope(root) as context:
            return context.digest(path, expected)
    return context.digest(path, expected)


def remember_digest(root: Path, path: Path, digest: str) -> None:
    """Let the active context reuse a digest the caller computed from bytes it just wrote."""
    context = current_validation(root)
    if context is not None:
        context.remember(path, digest)


def observed_digest(root: Path, path: Path) -> str:
    context = current_validation(root)
    return file_sha256(path) if context is None else context.observe(path)


P = ParamSpec("P")
T = TypeVar("T")


def validation_operation(function: Callable[P, T]) -> Callable[P, T]:
    @wraps(function)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> T:
        root = args[0] if args else kwargs.get("run_root", kwargs.get("root"))
        if not isinstance(root, Path):
            raise TypeError("validation operation requires an explicit run root")
        with validation_scope(root):
            return function(*args, **kwargs)
    return wrapped
