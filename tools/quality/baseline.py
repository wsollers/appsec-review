from __future__ import annotations

import ast
from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path

from .config import GateError, checked_file, relative_path, table


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    rule: str
    message: str
    fingerprint: str
    line: int

    @property
    def key(self) -> tuple[str, str, str]:
        return self.path, self.rule, self.fingerprint


def finding(root: Path, path: str, rule: str, message: str, line: int) -> Finding:
    source = checked_file(root, path).read_text(encoding="utf-8")
    lines = source.splitlines()
    if type(line) is not int or not 1 <= line <= len(lines):
        raise GateError("tool-output", f"invalid diagnostic line: {path}:{line}")
    anchor = lines[line - 1].strip()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        pass  # Ruff syntax diagnostics still have a resolving source line.
    else:
        statements = [
            node for node in ast.walk(tree) if isinstance(node, ast.stmt)
            and node.lineno <= line <= (node.end_lineno or node.lineno)
        ]
        if statements:
            node = min(statements, key=lambda item: (item.end_lineno or item.lineno) - item.lineno)
            anchor = ast.dump(node, include_attributes=False)
        if rule.startswith("bandit:"):
            scopes = [node for node in statements if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
            scope = min(scopes, key=lambda item: (item.end_lineno or item.lineno) - item.lineno) if scopes else tree
            anchor = ast.dump(scope, include_attributes=False)
    identity = json.dumps([rule, message, anchor], ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return Finding(path, rule, message, hashlib.sha256(identity).hexdigest(), line)


def decode_baseline(text: str) -> tuple[Finding, ...]:
    try:
        document = table(json.loads(text), "baseline")
    except json.JSONDecodeError as error:
        raise GateError("configuration", f"invalid baseline JSON: {error}") from error
    if (set(document) != {"version", "reason", "findings"}
            or type(document["version"]) is not int or document["version"] != 1):
        raise GateError("configuration", "unsupported baseline schema")
    if not isinstance(document["reason"], str) or not document["reason"].strip():
        raise GateError("configuration", "baseline requires a review reason")
    values = document["findings"]
    if not isinstance(values, list):
        raise GateError("configuration", "baseline findings must be a list")
    result: list[Finding] = []
    for value in values:
        entry = table(value, "baseline entry")
        if set(entry) != {"path", "rule", "message", "fingerprint", "line"}:
            raise GateError("configuration", "unknown or missing baseline finding fields")
        path, rule, message, fingerprint = (entry[name] for name in ("path", "rule", "message", "fingerprint"))
        line = entry["line"]
        if (not isinstance(path, str) or not isinstance(rule, str) or not isinstance(message, str)
                or not isinstance(fingerprint, str) or len(fingerprint) != 64
                or any(char not in "0123456789abcdef" for char in fingerprint)
                or type(line) is not int or line < 1):
            raise GateError("configuration", "invalid baseline finding")
        relative_path(path)
        if not path.startswith("src/appsec_review/"):
            raise GateError("configuration", "new development tooling cannot have legacy baseline entries")
        if rule.startswith("ARCH:bootstrap"):
            raise GateError("configuration", "bootstrap isolation cannot be baselined")
        result.append(Finding(path, rule, message, fingerprint, line))
    return tuple(sorted(result))


def baseline_json(findings: tuple[Finding, ...], reason: str) -> str:
    return json.dumps(
        {"version": 1, "reason": reason, "findings": [asdict(value) for value in sorted(findings)]},
        indent=2, ensure_ascii=True,
    ) + "\n"


def compare(findings: tuple[Finding, ...], baseline: tuple[Finding, ...]) -> tuple[str, ...]:
    actual = Counter(value.key for value in findings)
    expected = Counter(value.key for value in baseline)
    messages: list[str] = []
    for key, count in sorted((actual - expected).items()):
        item = next(value for value in findings if value.key == key)
        messages.append(f"NEW {item.path}:{item.line} {item.rule} {item.message} (count +{count})")
    for key, count in sorted((expected - actual).items()):
        messages.append(f"STALE {key[0]} {key[1]} {key[2]} (count -{count}); prune the baseline")
    return tuple(messages)


def require_shrink_only(current: tuple[Finding, ...], previous: tuple[Finding, ...]) -> None:
    if Counter(value.key for value in current) - Counter(value.key for value in previous):
        raise GateError("baseline-growth", "baseline additions or increased counts require a separate policy review")


def prune(findings: tuple[Finding, ...], baseline: tuple[Finding, ...]) -> tuple[Finding, ...]:
    remaining = Counter(value.key for value in baseline)
    result: list[Finding] = []
    for value in sorted(findings):
        if remaining[value.key] > 0:
            result.append(value)
            remaining[value.key] -= 1
    return tuple(result)
