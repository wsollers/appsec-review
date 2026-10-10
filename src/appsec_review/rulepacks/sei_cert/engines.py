"""Execute the SEI CERT rule pack under Semgrep CE and OpenGrep and normalize the results.

Both engines are invoked with an argv array, explicit target files (so built-in default ignore
lists cannot silently drop a fixture or target file), and no network-dependent features. Raw
stdout and stderr are preserved with their SHA-256 identities. Engine errors, skipped targets,
nonzero exits, timeouts, and unparsable output are returned as explicit coverage gaps; they are
never interpreted as an absence of findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Iterable, Mapping, Sequence

ENGINES = ("semgrep", "opengrep")
RULE_ID_PREFIX = "appsec-review.sei-cert."
_ENV_OVERRIDES = {"semgrep": "APPSEC_REVIEW_SEMGREP", "opengrep": "APPSEC_REVIEW_OPENGREP"}


@dataclass(frozen=True, slots=True)
class Finding:
    engine: str
    rule_id: str
    path: str
    start_line: int
    end_line: int
    message: str
    severity: str
    cert: str | None

    def key(self) -> tuple[str, str, int]:
        return (self.rule_id, self.path, self.start_line)

    def as_dict(self) -> dict[str, Any]:
        return {"engine": self.engine, "rule_id": self.rule_id, "path": self.path,
                "start_line": self.start_line, "end_line": self.end_line,
                "message": self.message, "severity": self.severity, "cert": self.cert}


@dataclass(slots=True)
class EngineRun:
    engine: str
    executable: str | None
    version: str | None
    argv: tuple[str, ...] = ()
    exit_code: int | None = None
    timed_out: bool = False
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    findings: list[Finding] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    scanned: list[str] = field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.gaps

    def as_dict(self) -> dict[str, Any]:
        return {"engine": self.engine, "executable": self.executable, "version": self.version,
                "argv": list(self.argv), "exit_code": self.exit_code, "timed_out": self.timed_out,
                "stdout": {"path": self.stdout_path, "sha256": self.stdout_sha256},
                "stderr": {"path": self.stderr_path, "sha256": self.stderr_sha256},
                "scanned": self.scanned, "gaps": self.gaps,
                "findings": [finding.as_dict() for finding in self.findings]}


def locate(engine: str) -> str | None:
    """Return the configured executable: an explicit environment override, else PATH."""
    override = os.environ.get(_ENV_OVERRIDES[engine])
    if override:
        return override if Path(override).is_file() else None
    return shutil.which(engine)


def _environment(home: Path) -> dict[str, str]:
    home = home.resolve()
    # OpenGrep aborts at start-up when XDG_CONFIG_HOME does not exist.
    for directory in (home, home / ".config", home / ".cache"):
        directory.mkdir(parents=True, exist_ok=True)
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"), "XDG_CACHE_HOME": str(home / ".cache"),
            "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def engine_version(engine: str, executable: str, home: Path) -> str | None:
    try:
        result = subprocess.run([executable, "--version"], capture_output=True, text=True,
                                timeout=120, check=False, env=_environment(home))
    except (OSError, subprocess.SubprocessError):
        return None
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return lines[-1] if result.returncode == 0 and lines else None


def scan_argv(engine: str, executable: str, configs: Sequence[Path], targets: Sequence[str],
              *, timeout_seconds: int = 30) -> tuple[str, ...]:
    argv = [executable, "scan", "--json", "--disable-version-check", "--timeout", str(timeout_seconds)]
    if engine == "semgrep":
        argv += ["--metrics", "off"]
    for config in configs:
        argv += ["--config", str(config)]
    argv += ["--", *targets]
    return tuple(argv)


def canonical_rule_id(check_id: str) -> str:
    """Engines may prefix rule IDs with the config path; keep the pack-owned identifier."""
    index = check_id.find(RULE_ID_PREFIX)
    return check_id[index:] if index >= 0 else check_id


def normalize(engine: str, document: Mapping[str, Any], root: Path) -> tuple[list[Finding], list[str], list[str]]:
    findings: list[Finding] = []
    gaps: list[str] = []
    for item in document.get("results", []):
        extra = item.get("extra", {}) if isinstance(item.get("extra"), Mapping) else {}
        metadata = extra.get("metadata", {}) if isinstance(extra.get("metadata"), Mapping) else {}
        findings.append(Finding(
            engine=engine, rule_id=canonical_rule_id(str(item.get("check_id", ""))),
            path=_relative(str(item.get("path", "")), root),
            start_line=int(item.get("start", {}).get("line", 0)),
            end_line=int(item.get("end", {}).get("line", 0)),
            # Messages are compared after interpolation; source excerpts ("lines") are never used
            # because Semgrep CE withholds them while OpenGrep returns them.
            message=" ".join(str(extra.get("message", "")).split()),
            severity=str(extra.get("severity", "")),
            cert=str(metadata["cert"]) if "cert" in metadata else None,
        ))
    for error in document.get("errors", []):
        if isinstance(error, Mapping):
            location = error.get("path") or error.get("rule_id") or "engine"
            text = " ".join(str(error.get("message", error.get("type", "error"))).split())[:300]
            gaps.append(f"{engine} reported {error.get('level', 'error')} for {location}: {text}")
    paths = document.get("paths", {}) if isinstance(document.get("paths"), Mapping) else {}
    for skipped in paths.get("skipped", []) or []:
        if isinstance(skipped, Mapping):
            gaps.append(f"{engine} skipped {_relative(str(skipped.get('path')), root)}: {skipped.get('reason')}")
    scanned = sorted(_relative(str(path), root) for path in paths.get("scanned", []) or [])
    findings.sort(key=lambda finding: (finding.path, finding.start_line, finding.rule_id))
    return findings, gaps, scanned


def _relative(path: str, root: Path) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            return candidate.relative_to(root).as_posix()
        except ValueError:
            return candidate.as_posix()
    return candidate.as_posix()


def run_engine(engine: str, configs: Sequence[Path], targets: Iterable[str], *, cwd: Path,
               output_dir: Path, expected_version: str | None = None,
               timeout_seconds: int = 600) -> EngineRun:
    """Run one engine over explicit targets relative to ``cwd`` and preserve its raw streams."""
    target_list = sorted(set(targets))
    executable = locate(engine)
    home = output_dir / f"{engine}-home"
    if executable is None:
        return EngineRun(engine, None, None, gaps=[f"{engine} executable is not available"])
    version = engine_version(engine, executable, home)
    run = EngineRun(engine, executable, version)
    if version is None:
        run.gaps.append(f"{engine} version could not be determined")
        return run
    if expected_version is not None and version != expected_version:
        run.gaps.append(f"{engine} {version} does not match the pinned version {expected_version}")
        return run
    if not target_list:
        run.gaps.append("no targets were supplied")
        return run
    run.argv = scan_argv(engine, executable, configs, target_list)
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_path, stderr_path = output_dir / f"{engine}.stdout.json", output_dir / f"{engine}.stderr.txt"
    try:
        result = subprocess.run(run.argv, cwd=cwd, capture_output=True, timeout=timeout_seconds,
                                check=False, env=_environment(home))
        stdout, stderr, run.exit_code = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as exc:
        stdout, stderr, run.timed_out = exc.stdout or b"", exc.stderr or b"", True
        run.gaps.append(f"{engine} timed out after {timeout_seconds} seconds")
    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(stderr)
    run.stdout_path, run.stderr_path = stdout_path.as_posix(), stderr_path.as_posix()
    run.stdout_sha256 = hashlib.sha256(stdout).hexdigest()
    run.stderr_sha256 = hashlib.sha256(stderr).hexdigest()
    if run.exit_code not in (0, None):
        run.gaps.append(f"{engine} exited with status {run.exit_code}")
    try:
        document = json.loads(stdout.decode("utf-8")) if stdout.strip() else None
    except (UnicodeError, json.JSONDecodeError):
        document = None
    if not isinstance(document, Mapping):
        run.gaps.append(f"{engine} produced no parsable JSON document")
        return run
    run.findings, gaps, run.scanned = normalize(engine, document, cwd)
    run.gaps.extend(gaps)
    missing = sorted(set(target_list) - set(run.scanned))
    if missing:
        run.gaps.append(f"{engine} did not report scanning {len(missing)} target(s): {', '.join(missing[:5])}")
    return run
