"""Immutable attempt-owned developer files of one compile-only candidate.

``poc_<name>.cpp`` (both functions and the generated includes), ``compile.json`` (policy verdict,
commands, exit codes, diagnostics and the symbol check), ``README.md`` (what it shows, where to add
it, the expected observation, breakpoints and limitations) and ``provenance.json`` (the hashes that
tie the files to the brief, the review package, the source tree, the image and the model). The
source is stored verbatim as data; nothing here executes it. Model text in the README is shown in
code spans or fenced blocks that cannot be closed from inside.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
from pathlib import Path
import re
from typing import Any

from appsec_review.jobs.bound_artifacts import artifact_ref
from appsec_review.jobs.completion_contracts import nonexecution_assurance
from appsec_review.review.models import IntegrityError
from appsec_review.jobs.job_final_report_publication.render import code, plain
from appsec_review.storage import atomic_bytes, atomic_json

from .candidates import PocCandidate
from .source import WriterAnswer
from .statuses import COMPILE_VERIFIED

PROVENANCE_SCHEMA = "appsec-review/poc-provenance/2"
POLICY_SCHEMA = "appsec-review/poc-policy/1"
DESCRIPTION_LIMIT = 300
STATUS_TEXT = {
    "compile_verified": "the functions compile against the project's own build flags and every symbol they need "
                        "resolves",
    "compile_failed": "the generated code does not build; this does not contradict the finding",
    "artifact_generated": "the functions were generated but could not be verified against a build (a named gap)",
    "policy_denied": "a deterministic validator refused the functions; they are kept as data and were not compiled",
}


def source_file_name(answer: WriterAnswer, language: str) -> str:
    return f"{answer.test_name}{'.c' if language == 'c' else '.cpp'}"


def describe(status: str, answer: WriterAnswer | None, reason: str) -> str:
    """The bounded description the handoff and the report carry."""
    if answer is None:
        return reason[:DESCRIPTION_LIMIT]
    head = f"{status}: {answer.test_name} (negative control {answer.control_name}). "
    return (head + (answer.expected_observation or reason))[:DESCRIPTION_LIMIT]


def fence(text: str) -> str:
    """A code fence longer than any backtick run in ``text``, so the content cannot close it."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def render_readme(*, candidate: PocCandidate, finding: Mapping[str, Any], answer: WriterAnswer, status: str,
                  reason: str, source_name: str, source_text: str, facts: Mapping[str, Any] | None,
                  violations: Sequence[Mapping[str, Any]]) -> str:
    marks = fence(source_text)
    lines = [
        f"# Proof of concept for {code(candidate.claim_id)}", "",
        f"- finding {code(finding.get('title', ''))} ({code(candidate.state)}, judge verdict "
        f"{code(candidate.judge_verdict)})",
        f"- status {code(status)}: {plain(STATUS_TEXT.get(status, reason))}",
        f"- detail: {plain(reason)}", "",
        "This is a unit-test function for developers, written by a model and checked by deterministic validators. "
        "The pipeline compiled it (when the status says so) and checked that its symbols resolve. "
        "It never ran it, and it has no `main`.", "",
        "## What it shows", "", plain(answer.expected_observation) or "No observation was stated.", "",
        f"- test function {code(answer.test_name)}",
        f"- negative control {code(answer.control_name)} (a safe input that must not trigger the condition)", ""]
    if answer.setup:
        lines += ["## Setup", ""] + [f"- {plain(item)}" for item in answer.setup] + [""]
    lines += ["## Where to add it", "",
              f"Add {code(source_name)} (or just the two functions) to the unit-test target of the project. The "
              "functions need the project's headers on the include path"]
    if facts:
        paths = ", ".join(code(item) for item in facts.get("include_paths", ())[:8]) or "none recorded"
        lines[-1] += f"; the sink's translation unit compiled with: include paths {paths}, standard " \
                     f"{code(facts.get('standard') or 'default')}."
    else:
        lines[-1] += "."
    lines += ["", "To observe the fault, build the test with `-fsanitize=address,undefined -g -O0` "
              "(`-fno-omit-frame-pointer` helps stack traces) and run it under a debugger yourself.", ""]
    if answer.breakpoints:
        lines += ["## Breakpoints", ""] + [
            f"- {code(item['function'])} line {item['line']}: {plain(item['why'])}" for item in answer.breakpoints] + [""]
    if answer.notes:
        lines += ["## Notes from the writer", "", plain(answer.notes), ""]
    if violations:
        lines += ["## Why a validator refused it", ""] + [
            f"- {code(item['rule'])}: {plain(item['message'])}" for item in violations[:20]] + [""]
    lines += ["## Limitations", "",
              "- The functions are untrusted model output. Read them before adding them to a test target.",
              "- A status other than `compile_verified` means the build check did not pass or did not run; "
              "`compile_failed` does not contradict the finding.",
              "- Nothing was linked into an executable and nothing was executed by the pipeline.", "",
              "## Source", "", f"{marks}cpp", source_text.rstrip("\n"), marks, ""]
    return "\n".join(lines).rstrip("\n") + "\n"


def write_candidate(run_root: Path, *, output_root: Path, candidate: PocCandidate, finding: Mapping[str, Any], answer: WriterAnswer,
                    status: str, reason: str, source_text: str, language: str, compile_record: Mapping[str, Any],
                    violations: Sequence[Mapping[str, Any]], policy_verdict: str, provenance: Mapping[str, Any],
                    facts: Mapping[str, Any] | None) -> dict[str, Any]:
    """Write the four files; the returned references are run-relative, hashed and ready for the handoff."""
    root = Path(output_root).resolve() / candidate.claim_id
    if not root.is_relative_to(Path(run_root).resolve() / "data" / "jobs" / "job_poc_generation" / "attempts"):
        raise IntegrityError("PoC files must be owned by a producer attempt")
    if root.exists():
        raise IntegrityError("PoC candidate artifacts are immutable; use a new attempt")
    source_name = source_file_name(answer, language)
    atomic_bytes(root / source_name, source_text.encode("utf-8"))
    atomic_json(root / "compile.json", {
        **compile_record, "policy": {"schema": POLICY_SCHEMA, "verdict": policy_verdict,
                                     "violations": list(violations)}})
    atomic_bytes(root / "README.md", render_readme(
        candidate=candidate, finding=finding, answer=answer, status=status, reason=reason, source_name=source_name,
        source_text=source_text, facts=facts, violations=violations).encode("utf-8"))
    atomic_json(root / "provenance.json", {
        "schema": PROVENANCE_SCHEMA, **provenance, **nonexecution_assurance(),
        "files": {"source": {"name": source_name, "sha256": hashlib.sha256(source_text.encode()).hexdigest()},
                  "compile": {"name": "compile.json"}, "readme": {"name": "README.md"}}})
    return {"source": artifact_ref(run_root, root / source_name), "compile": artifact_ref(run_root, root / "compile.json"),
            "readme": artifact_ref(run_root, root / "README.md"),
            "provenance": artifact_ref(run_root, root / "provenance.json")}


__all__ = ["COMPILE_VERIFIED", "DESCRIPTION_LIMIT", "describe", "render_readme", "source_file_name",
           "write_candidate"]
