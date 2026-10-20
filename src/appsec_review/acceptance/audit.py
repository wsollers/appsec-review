"""Permission and filesystem audit of what one job wrote into an application run.

The audit runs on the operator's host against the bind-mounted ``runs/`` and ``data/`` trees, so
it sees exactly what the code-location container left behind for the operator.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat as stat_module

SCRATCH_NAMES = re.compile(
    r"^(\.appsec-review-build-scratch\..+|\.tmp-.+|.+\.tmp|.+\.partial|tmp|scratch|\.scratch)$")


def _tool_owned(path: Path) -> bool:
    """Whether ``path`` is inside a tree a build or analysis tool owns.

    That is a copied build workspace, the C/C++ analysis job's copy of a build tree
    (``cpp/projects/<unit>/build``) and an Infer output directory (``infer-out``), where tools
    create their own ``tmp`` directories.
    """

    parts = path.parts
    if "workspace" in parts or "infer-out" in parts:
        return True
    return any(parts[i:i + 2] == ("cpp", "projects") and "build" in parts[i + 3:] for i in range(len(parts) - 1))


TERMINAL_STATUSES = {"SUCCEEDED", "COMPLETED_WITH_GAPS", "FAILED"}
ACCEPTED_STATUSES = {"SUCCEEDED", "COMPLETED_WITH_GAPS"}


@dataclass(frozen=True, order=True)
class AuditFinding:
    kind: str
    path: str
    detail: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "path": self.path, "detail": self.detail}


def _within(path: Path, roots: Iterable[Path]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def audit_tree(
    roots: Iterable[Path], *, expected_uid: int, expected_gid: int, since: float | None = None,
    allowed_link_roots: Iterable[Path] = (), exclude: Iterable[Path] = (),
    retained: Iterable[Path] = (),
    lstat: Callable[[str], os.stat_result] = os.lstat,
    access: Callable[[str, int], bool] = os.access,
) -> list[AuditFinding]:
    """Audit entries under ``roots`` changed at or after ``since`` (every entry when ``None``).

    ``retained`` names scratch-named directories that the job's own records reference as evidence;
    they are not leftovers.
    """

    findings: list[AuditFinding] = []
    kept = {str(Path(item)) for item in retained}
    link_roots = tuple(Path(os.path.realpath(root)) for root in allowed_link_roots)
    excluded = tuple(Path(item) for item in exclude)

    def changed(info: os.stat_result) -> bool:
        return since is None or max(info.st_mtime, info.st_ctime) >= since

    def check(path: Path, *, in_scratch: bool) -> None:
        try:
            info = lstat(str(path))
        except OSError as exc:
            findings.append(AuditFinding("unreadable", str(path), f"lstat failed: {exc.strerror}"))
            return
        if not changed(info):
            return
        if info.st_uid == 0 or info.st_gid == 0:
            findings.append(AuditFinding("root-owned", str(path), f"uid={info.st_uid} gid={info.st_gid}"))
        elif info.st_uid != expected_uid or info.st_gid != expected_gid:
            findings.append(AuditFinding(
                "owner", str(path),
                f"uid={info.st_uid} gid={info.st_gid} expected {expected_uid}:{expected_gid}"))
        if stat_module.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            resolved = Path(os.path.normpath(path.parent / target))
            if not os.path.exists(resolved):
                findings.append(AuditFinding("dangling-symlink", str(path), f"-> {target}"))
            elif link_roots and not _within(Path(os.path.realpath(resolved)), link_roots):
                findings.append(AuditFinding("escaping-symlink", str(path), f"-> {target}"))
            return
        if info.st_mode & stat_module.S_IWOTH:
            findings.append(AuditFinding("world-writable", str(path), f"mode={stat_module.filemode(info.st_mode)}"))
        needed = os.R_OK | os.X_OK if stat_module.S_ISDIR(info.st_mode) else os.R_OK
        if not access(str(path), needed):
            findings.append(AuditFinding("unreadable", str(path), f"mode={stat_module.filemode(info.st_mode)}"))
        # Inside a copied build workspace, tmp-like names belong to the target's own toolchain
        # (CMake, Gradle); only the capture driver's scratch is the pipeline's to clean up.
        target_owned = _tool_owned(path) and not path.name.startswith(".appsec-review-build-scratch.")
        if not in_scratch and not target_owned and SCRATCH_NAMES.match(path.name) and str(path) not in kept:
            findings.append(AuditFinding("scratch-leftover", str(path), "scratch or temporary entry persisted"))

    for root in roots:
        root = Path(root)
        if not root.exists():
            continue
        scratch_directories: set[str] = set()
        excluded_names = {str(item) for item in excluded}
        check(root, in_scratch=False)

        def on_error(error: OSError) -> None:
            findings.append(AuditFinding("unreadable", str(error.filename), f"cannot list: {error.strerror}"))

        for current, directories, files in os.walk(root, onerror=on_error):
            base = Path(current)
            in_scratch = current in scratch_directories
            directories[:] = [name for name in directories
                              if os.path.join(current, name) not in excluded_names]
            for name in directories:
                if in_scratch or SCRATCH_NAMES.match(name):
                    scratch_directories.add(os.path.join(current, name))
            for name in [*directories, *files]:
                check(base / name, in_scratch=in_scratch)
    return sorted(set(findings))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_attempt(run_root: Path, job_id: str, attempt_root: Path | None, *,
                  dagster_status: str | None = None, verify_hashes: bool = True) -> list[AuditFinding]:
    """Check the receipts and accepted handoff a finished job attempt must leave."""

    run_root = Path(run_root)
    if attempt_root is None:
        return [AuditFinding("missing-expected", str(run_root / "data" / "jobs" / job_id),
                             "job produced no attempt")]
    findings: list[AuditFinding] = []
    for name in ("claim.json", "status.json"):
        if not (attempt_root / name).is_file():
            findings.append(AuditFinding("missing-expected", str(attempt_root / name)))
    try:
        status = json.loads((attempt_root / "status.json").read_text(encoding="utf-8")).get("status")
    except (OSError, ValueError):
        status = None
    if dagster_status in {"SUCCESS", "FAILURE", "CANCELED"} and status not in TERMINAL_STATUSES:
        findings.append(AuditFinding("stale-status", str(attempt_root / "status.json"),
                                     f"attempt status {status} after Dagster {dagster_status}"))
    if status in TERMINAL_STATUSES and status != "FAILED" and not (attempt_root / "result.json").is_file():
        findings.append(AuditFinding("missing-expected", str(attempt_root / "result.json")))
    if status not in ACCEPTED_STATUSES:
        return findings
    handoff_path = attempt_root / "handoff.json"
    if not handoff_path.is_file():
        return [*findings, AuditFinding("missing-expected", str(handoff_path))]
    pointer_path = run_root / "data" / "jobs" / job_id / "latest.json"
    try:
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [*findings, AuditFinding("missing-expected", str(pointer_path), "accepted pointer unreadable")]
    if (run_root / str(pointer.get("handoff_path", ""))).resolve() != handoff_path.resolve():
        findings.append(AuditFinding("missing-expected", str(pointer_path), "pointer names another attempt"))
    elif pointer.get("handoff_sha256") != _sha256(handoff_path):
        findings.append(AuditFinding("artifact-mismatch", str(handoff_path), "handoff digest differs from pointer"))
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    for artifact in handoff.get("artifacts", ()):
        path = (run_root / str(artifact.get("path", ""))).resolve()
        if run_root.resolve() not in path.parents:
            findings.append(AuditFinding("artifact-mismatch", str(path), "artifact escapes the run"))
        elif not path.is_file():
            findings.append(AuditFinding("missing-expected", str(path), "handoff artifact missing"))
        elif not os.access(path, os.R_OK):
            continue  # reported by the tree audit as unreadable
        elif artifact.get("size_bytes") is not None and path.stat().st_size != artifact["size_bytes"]:
            findings.append(AuditFinding("artifact-mismatch", str(path), "size differs from handoff"))
        elif verify_hashes and _sha256(path) != artifact.get("sha256"):
            findings.append(AuditFinding("artifact-mismatch", str(path), "sha256 differs from handoff"))
    return findings


def retained_directories(run_root: Path, attempt_root: Path) -> set[Path]:
    """Every directory on the path to a run-relative file the attempt's JSON records reference."""

    run_root = Path(run_root)
    referenced: set[Path] = set()

    def visit(value: object) -> None:
        if isinstance(value, Mapping):
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
        elif isinstance(value, str) and "/" in value and not value.startswith(("/", "sha256:")):
            candidate = run_root / value
            if candidate.exists():
                referenced.update(parent for parent in candidate.parents if run_root in parent.parents)

    for record in Path(attempt_root).rglob("*.json"):
        try:
            visit(json.loads(record.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return referenced


def audit_job_writes(run_root: Path, job_id: str, attempt_root: Path | None, *, expected_uid: int,
                     expected_gid: int, since: float | None, extra_roots: Iterable[Path] = (),
                     exclude: Iterable[Path] = (), dagster_status: str | None = None,
                     **options) -> list[AuditFinding]:
    """Tree audit of the run (and any shared roots) plus the attempt's receipt checks."""

    run_root = Path(run_root)
    retained = retained_directories(run_root, attempt_root) if attempt_root is not None else set()
    tree = audit_tree([run_root, *extra_roots], expected_uid=expected_uid, expected_gid=expected_gid,
                      since=since, allowed_link_roots=[run_root], exclude=exclude, retained=retained,
                      **options)
    if attempt_root is not None and since is not None:
        # The attempt is always audited in full, whatever its timestamps say.
        tree = sorted(set(tree) | set(audit_tree([attempt_root], expected_uid=expected_uid,
                                                  expected_gid=expected_gid, since=None,
                                                  allowed_link_roots=[run_root], retained=retained,
                                                  **options)))
    return [*tree, *audit_attempt(run_root, job_id, attempt_root, dagster_status=dagster_status)]


def summarize(findings: Iterable[AuditFinding]) -> Mapping[str, int]:
    return dict(sorted(Counter(item.kind for item in findings).items()))
