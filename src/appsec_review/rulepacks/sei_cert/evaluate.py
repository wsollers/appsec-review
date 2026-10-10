"""Differential evaluation of the SEI CERT rule pack under Semgrep CE and OpenGrep.

An evaluation runs every rule against every focused fixture with both engines, compares the
normalized findings (rule, path, line range, interpolated message), scores each rule against the
fixture annotations, and, when the pinned multivuln target is present, checks the expected
findings, exclusions, and known false negatives there. Every raw stream and the normalized result
are written with SHA-256 identities into a manifest that :func:`verify_evaluation` re-checks.

The result describes rule-pack behavior. It is not a CERT conformance assessment of any target.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any, Mapping

from .engines import ENGINES, EngineRun, Finding, run_engine
from .fixtures import Expectation
from .pack import PACK_ROOT, REPOSITORY_ROOT, Pack, compute_lock, load_pack
from .validate import collect_expectations, validate

EVALUATION_SCHEMA = "appsec-review/sei-cert-evaluation/1"
MANIFEST_SCHEMA = "appsec-review/sei-cert-evaluation-manifest/1"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def score_rule(rule_id: str, expectations: list[Expectation], findings: list[Finding], engine: str) -> dict[str, Any]:
    applicable = [item for item in expectations if item.rule_id == rule_id and item.applies_to(engine)]
    found = {(finding.path, finding.start_line) for finding in findings if finding.rule_id == rule_id}
    positive_lines = {(item.path, item.line) for item in applicable if item.positive}
    metrics = {"true_positives": 0, "false_negatives": 0, "known_false_negatives": 0,
               "false_positives": 0, "known_false_positives": 0, "expected_exclusions": 0,
               "violated_exclusions": 0}
    failures: list[str] = []
    for item in applicable:
        hit = (item.path, item.line) in found
        if item.positive:
            if not hit:
                metrics["false_negatives"] += 1
                failures.append(f"missed {item.kind} at {item.path}:{item.line}")
            elif item.exception_id:
                metrics["known_false_positives"] += 1
            else:
                metrics["true_positives"] += 1
        elif item.kind == "known-false-negative":
            if hit:
                failures.append(f"known false negative at {item.path}:{item.line} is now detected; update the fixture")
            else:
                metrics["known_false_negatives"] += 1
        elif hit:
            metrics["violated_exclusions"] += 1
            failures.append(f"reported {item.kind} line {item.path}:{item.line}")
        else:
            metrics["expected_exclusions"] += 1
    for path, line in sorted(found - positive_lines):
        if not any(item.path == path and item.line == line for item in applicable):
            metrics["false_positives"] += 1
            failures.append(f"unannotated finding at {path}:{line}")
    return {"metrics": metrics, "failures": failures}


def _metadata_failures(pack: Pack, run: EngineRun) -> list[str]:
    rules = pack.rules_by_id()
    failures = []
    for finding in run.findings:
        rule = rules.get(finding.rule_id)
        if rule is None:
            failures.append(f"{run.engine} reported unknown rule {finding.rule_id}")
        elif finding.cert != rule.metadata.get("cert"):
            failures.append(f"{run.engine} emitted cert {finding.cert!r} for {finding.rule_id}; the rule declares "
                            f"{rule.metadata.get('cert')!r}")
    return failures


def _differential(runs: Mapping[str, EngineRun]) -> dict[str, Any]:
    normalized = {engine: {(f.rule_id, f.path, f.start_line, f.end_line, f.message) for f in run.findings}
                  for engine, run in runs.items()}
    engines = sorted(normalized)
    if len(engines) < 2:
        return {"compared": False, "only_in": {}, "agree": False}
    first, second = engines[:2]
    only = {first: sorted(normalized[first] - normalized[second]),
            second: sorted(normalized[second] - normalized[first])}
    return {"compared": True, "agree": not only[first] and not only[second],
            "only_in": {engine: [dict(zip(("rule_id", "path", "start_line", "end_line", "message"), item, strict=True))
                                 for item in items] for engine, items in only.items()}}


def _git_head(path: Path) -> str | None:
    try:
        result = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True,
                                text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _multivuln(pack: Pack, output: Path, target: Path | None) -> dict[str, Any]:
    spec = pack.multivuln
    target = target or (REPOSITORY_ROOT / spec["target"]["local_path"])
    expected_commit = spec["target"]["commit"]
    if not target.is_dir():
        return {"status": "NOT_RUN", "gap": f"multivuln target is not present at {target}"}
    head = _git_head(target)
    if head != expected_commit:
        return {"status": "NOT_RUN", "gap": f"multivuln target is at {head}, expected {expected_commit}"}
    suffixes = set(spec["scope"]["extensions"])
    files = sorted(path.relative_to(target).as_posix() for path in target.rglob("*")
                   if path.is_file() and path.suffix in suffixes and ".git" not in path.parts)
    runs = {engine: run_engine(engine, pack.rule_paths, files, cwd=target, output_dir=output / "multivuln" / engine,
                               expected_version=pack.manifest["engines"][engine]["version"])
            for engine in ENGINES}
    rules = pack.rules_by_id()
    expected = {(item["rule_id"], item["path"], item["line"]) for item in spec["expected_findings"]}
    failures: list[str] = []
    per_engine: dict[str, Any] = {}
    for engine, run in runs.items():
        got = {finding.key(): finding for finding in run.findings}
        missing = sorted(expected - set(got))
        unexpected = sorted(set(got) - expected)
        excluded_hits = [item for item in spec["expected_exclusions"]
                         if any(f.path == item["path"] and f.start_line == item["line"] and item["cert"] in rules[f.rule_id].certs
                                for f in run.findings if f.rule_id in rules)]
        resolved = []
        for finding in run.findings:
            source = target / finding.path
            lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
            in_range = 1 <= finding.start_line <= finding.end_line <= len(lines)
            resolved.append({**finding.as_dict(), "certs": list(rules[finding.rule_id].certs) if finding.rule_id in rules else [],
                             "source_sha256": _sha256(source),
                             "line_resolves": in_range,
                             "start_line_text": lines[finding.start_line - 1].strip() if in_range else None})
            if not in_range:
                failures.append(f"{engine} finding {finding.rule_id} at {finding.path}:{finding.start_line} does not resolve")
        failures += [f"{engine} missed expected {item[0]} at {item[1]}:{item[2]}" for item in missing]
        failures += [f"{engine} reported unexpected {item[0]} at {item[1]}:{item[2]}" for item in unexpected]
        failures += [f"{engine} reported an expected exclusion at {item['path']}:{item['line']}" for item in excluded_hits]
        failures += [f"{engine} gap: {gap}" for gap in run.gaps]
        failures += _metadata_failures(pack, run)
        per_engine[engine] = {"run": run.as_dict() | {"findings": resolved}, "missing": [list(item) for item in missing],
                              "unexpected": [list(item) for item in unexpected]}
    by_cert: dict[str, int] = defaultdict(int)
    for finding in runs["semgrep"].findings:
        for cert in rules[finding.rule_id].certs if finding.rule_id in rules else ():
            by_cert[cert] += 1
    differential = _differential(runs)
    if not differential["agree"]:
        failures.append("Semgrep and OpenGrep multivuln findings differ")
    return {"status": "PASSED" if not failures else "FAILED", "target": str(target), "commit": head,
            "scanned_files": files, "engines": per_engine, "differential": differential,
            "findings_by_cert": dict(sorted(by_cert.items())),
            "known_false_negatives": spec["known_false_negatives"], "failures": failures}


def evaluate(output: Path, *, root: Path = PACK_ROOT, multivuln_target: Path | None = None,
             include_multivuln: bool = True) -> dict[str, Any]:
    """Run the full evaluation and write ``evaluation.json`` and ``manifest.json`` under ``output``."""
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    validation_errors = validate(root)
    pack = load_pack(root)
    lock = compute_lock(root)
    expectations = collect_expectations(pack)
    fixture_root = pack.root / pack.manifest["fixture_root"]
    fixtures = sorted(path.relative_to(pack.root).as_posix() for path in fixture_root.rglob("*") if path.is_file())
    runs = {engine: run_engine(engine, pack.rule_paths, fixtures, cwd=pack.root, output_dir=output / "fixtures" / engine,
                               expected_version=pack.manifest["engines"][engine]["version"])
            for engine in ENGINES}
    failures = [f"validation: {error}" for error in validation_errors]
    rule_results: dict[str, Any] = {}
    for rule in pack.rules:
        per_engine = {}
        for engine, run in runs.items():
            scored = score_rule(rule.rule_id, expectations, run.findings, engine)
            per_engine[engine] = scored
            failures += [f"{engine} {rule.rule_id}: {item}" for item in scored["failures"]]
        rule_results[rule.rule_id] = {"certs": list(rule.certs), "file": rule.file, "engines": per_engine}
    for engine, run in runs.items():
        failures += [f"{engine} gap: {gap}" for gap in run.gaps]
        failures += _metadata_failures(pack, run)
    differential = _differential(runs)
    if not differential["agree"]:
        failures.append("Semgrep and OpenGrep fixture findings differ")
    multivuln = _multivuln(pack, output, multivuln_target) if include_multivuln else {"status": "NOT_RUN", "gap": "not requested"}
    if multivuln["status"] == "FAILED":
        failures += [f"multivuln: {item}" for item in multivuln["failures"]]
    result = {
        "schema": EVALUATION_SCHEMA,
        "pack": {"id": pack.manifest["id"], "version": pack.manifest["version"],
                 "tree_sha256": lock["tree_sha256"], "rule_files_sha256": lock["rule_files_sha256"]},
        "engines": {engine: {"version": run.version, "executable": run.executable, "succeeded": run.succeeded}
                    for engine, run in runs.items()},
        "fixtures": {"files": fixtures, "expectations": len(expectations),
                     "runs": {engine: run.as_dict() for engine, run in runs.items()}},
        "differential": differential,
        "rules": rule_results,
        "multivuln": multivuln,
        "failures": failures,
        "status": "PASSED" if not failures else "FAILED",
        "interpretation": ("Rule-pack behavior on focused fixtures and the pinned corpus only. Passing does not "
                           "establish CERT conformance of any target; see the mapping statuses for coverage."),
    }
    evaluation_path = output / "evaluation.json"
    evaluation_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # Engine home directories hold engine-private caches and logs, not evaluation evidence.
    artifacts = sorted(path for path in output.rglob("*")
                       if path.is_file() and path.relative_to(output).as_posix() != "manifest.json"
                       and not any(part.endswith("-home") for part in path.relative_to(output).parts))
    manifest = {"schema": MANIFEST_SCHEMA, "pack_tree_sha256": lock["tree_sha256"],
                "artifacts": {path.relative_to(output).as_posix(): _sha256(path) for path in artifacts}}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def verify_evaluation(output: Path) -> list[str]:
    """Re-hash every artifact recorded in an evaluation manifest."""
    manifest_path = output / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"manifest unreadable: {exc}"]
    errors = []
    if manifest.get("schema") != MANIFEST_SCHEMA:
        errors.append("unexpected manifest schema")
    for relative, digest in sorted(manifest.get("artifacts", {}).items()):
        path = output / relative
        if not path.is_file():
            errors.append(f"missing artifact {relative}")
        elif _sha256(path) != digest:
            errors.append(f"artifact changed: {relative}")
    if "evaluation.json" not in manifest.get("artifacts", {}):
        errors.append("manifest does not cover evaluation.json")
    return errors
