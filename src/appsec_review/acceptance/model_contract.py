"""Assert the contract around model calls without asserting what the model said.

A model's answer varies from run to run, so a run is never compared with an accepted answer.
Instead, for every job that calls a model:

- **inputs match**: the first-attempt requests of the run, normalized the way output is, equal the
  accepted run's. Repair requests carry the previous failure and so depend on the model; they are
  not compared;
- **responses are complete**: every request ends with a response that passes the rules its consumer
  applies (the proposal names the right schema, validates against it where a schema file exists, and
  cites only the evidence it was given). A request whose every attempt failed is a violation.

A job whose valid responses differ from the accepted ones is *response-changed*; so is everything
downstream of it. Those jobs are checked by this contract, not compared with the baseline output.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
import glob
import json
from pathlib import Path
from typing import Any

from .normalize import Masks, canonical, normalize_value

SCHEMA = "appsec-review/model-contract/1"
DEFAULT_PROFILE = "dev"
RECORDINGS = Path("data") / "inference-recordings"
MAX_DEPENDENCY_CONFIDENCE = 0.95
SCHEMA_FILES = {
    "appsec-review/target-analysis-proposal/2": Path("docs") / "schemas" / "target-analysis-proposal.schema.json",
}
_REPAIR_FIELDS = ("repair_errors", "prior_response")


@dataclass(frozen=True)
class Call:
    job_id: str
    request: Mapping[str, Any]
    proposal: Mapping[str, Any] | None
    error: Mapping[str, Any] | None


def run_profile(run_root: Path) -> str:
    """The runtime profile a run was configured with (``dev`` for a run that predates profiles)."""

    try:
        resolved = json.loads((Path(run_root) / "data" / "configuration" / "resolved.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"the run's resolved configuration is unreadable: {run_root}") from error
    return str((resolved.get("configuration_profile") or {}).get("name") or DEFAULT_PROFILE)


def load_calls(directory: Path) -> list[Call]:
    """The recorded model calls under ``directory`` (``<job>/<key>.<sequence>.json``)."""

    calls = []
    for name in sorted(glob.glob(str(Path(directory) / "*" / "*.json"))):
        if "misses" in Path(name).parts:
            continue
        try:
            document = json.loads(Path(name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        result = document.get("result")
        calls.append(Call(str(document["job_id"]), document["request"],
                          dict(result.get("proposal") or {}) if isinstance(result, Mapping) else None,
                          document.get("error")))
    return calls


def _first_attempt(request: Mapping[str, Any]) -> bool:
    return not request.get("repair_errors") and not request.get("prior_response")


def _normalized(request: Mapping[str, Any], masks: Masks) -> Any:
    return normalize_value(request, masks)


def _chain(request: Mapping[str, Any], masks: Masks) -> str:
    return canonical(_normalized({**request, **{field: None for field in _REPAIR_FIELDS}}, masks))


def baseline_document(calls: Iterable[Call], masks: Masks, *, run_id: str,
                      profile: str = DEFAULT_PROFILE) -> dict[str, Any]:
    """The part of an accepted run that a later run is held to: its inputs, and its valid responses."""

    jobs: dict[str, dict[str, list]] = {}
    for call in calls:
        entry = jobs.setdefault(call.job_id, {"requests": [], "responses": []})
        if _first_attempt(call.request):
            entry["requests"].append(_normalized(call.request, masks))
        if call.proposal is not None:
            entry["responses"].append(_normalized(call.proposal, masks))
    for entry in jobs.values():
        entry["requests"].sort(key=canonical)
        entry["responses"].sort(key=canonical)
    return {"schema": SCHEMA, "accepted_run": run_id, "profile": profile, "jobs": dict(sorted(jobs.items()))}


@dataclass
class ContractReport:
    input_problems: list[str] = field(default_factory=list)
    response_problems: list[str] = field(default_factory=list)
    requests: dict[str, int] = field(default_factory=dict)
    failed_attempts: dict[str, int] = field(default_factory=dict)
    response_changed: set[str] = field(default_factory=set)

    @property
    def failed(self) -> bool:
        return bool(self.input_problems or self.response_problems)

    def as_dict(self) -> dict[str, Any]:
        return {"input_problems": self.input_problems, "response_problems": self.response_problems,
                "requests": self.requests, "failed_attempts": self.failed_attempts,
                "response_changed": sorted(self.response_changed)}


def _schema_errors(schema_root: Path, schema_file: Path, proposal: dict[str, Any]) -> list[str]:
    """Validation errors of ``proposal``; sibling ``$ref`` files are loaded by name from the schema directory."""

    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    directory = (Path(schema_root) / schema_file).parent

    def retrieve(uri: str) -> Resource:
        document = json.loads((directory / uri.rsplit("/", 1)[-1]).read_text(encoding="utf-8"))
        return Resource.from_contents(document, default_specification=DRAFT202012)

    document = json.loads((Path(schema_root) / schema_file).read_text(encoding="utf-8"))
    validator = Draft202012Validator(document, registry=Registry(retrieve=retrieve))
    return [f"{'.'.join(str(part) for part in error.path) or '<root>'}: {error.message[:100]}"
            for error in list(validator.iter_errors(proposal))[:3]]


def response_problems(request: Mapping[str, Any], proposal: Mapping[str, Any], schema_root: Path) -> list[str]:
    """Why ``proposal`` is not a complete answer to ``request`` (empty when it is)."""

    schema = str(request.get("schema", ""))
    if not isinstance(proposal, Mapping) or not proposal:
        return ["the response is empty"]
    problems = []
    if proposal.get("schema") != schema:
        problems.append(f"the response names schema {proposal.get('schema')!r}, not {schema!r}")
    schema_file = SCHEMA_FILES.get(schema)
    if schema_file is not None and (Path(schema_root) / schema_file).is_file():
        try:
            for error in _schema_errors(Path(schema_root), schema_file, dict(proposal)):
                problems.append(error)
        except Exception as error:  # an unreadable schema is a finding, not a crash
            problems.append(f"the response could not be checked against {schema_file.name}: {type(error).__name__}")
    if schema.startswith("appsec-review/native-dependency-resolution-proposal/"):
        summary = request.get("summary")
        allowed = set(summary.get("allowed_evidence_refs", ())) if isinstance(summary, Mapping) else set()
        refs = proposal.get("evidence_refs")
        confidence = proposal.get("confidence")
        if not isinstance(proposal.get("candidate_id"), str) or not proposal.get("candidate_id"):
            problems.append("candidate_id is missing")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) \
                or not 0 <= confidence <= MAX_DEPENDENCY_CONFIDENCE:
            problems.append(f"confidence must be a number from 0 to {MAX_DEPENDENCY_CONFIDENCE}")
        if not isinstance(refs, list) or not all(isinstance(item, str) for item in refs):
            problems.append("evidence_refs must be a list of references")
        elif allowed and not set(refs) <= allowed:
            problems.append("evidence_refs cite evidence the request did not supply")
        if not isinstance(proposal.get("rationale"), str) or not proposal.get("rationale", "").strip():
            problems.append("rationale is empty")
        repository = proposal.get("repository")
        if repository is not None and not (isinstance(repository, (str, Mapping)) and repository):
            problems.append("repository must be null or an identity")
    return problems


def check(baseline: Mapping[str, Any], calls: Sequence[Call], masks: Masks, schema_root: Path,
          profile: str = DEFAULT_PROFILE) -> ContractReport:
    """Hold ``calls`` to ``baseline``. A baseline is valid only for the runtime profile it was recorded under
    (a baseline without a ``profile`` was recorded under ``dev``); another profile is a named input problem."""

    report = ContractReport()
    recorded = str(baseline.get("profile") or DEFAULT_PROFILE)
    if recorded != profile:
        report.input_problems.append(
            f"profile mismatch: the model contract was recorded under profile {recorded!r} but this run used "
            f"{profile!r}; its models and limits differ, so record a contract for {profile!r} instead")
    expected_jobs = baseline.get("jobs", {})
    by_job: dict[str, list[Call]] = {}
    for call in calls:
        by_job.setdefault(call.job_id, []).append(call)
    for job in sorted(set(expected_jobs) | set(by_job)):
        run_calls = by_job.get(job, [])
        expected = expected_jobs.get(job, {"requests": [], "responses": []})
        firsts = Counter(canonical(_normalized(call.request, masks)) for call in run_calls
                         if _first_attempt(call.request))
        wanted = Counter(canonical(item) for item in expected["requests"])
        report.requests[job] = sum(firsts.values())
        if firsts != wanted:
            report.input_problems.append(
                f"{job}: {sum((wanted - firsts).values())} baseline request(s) not sent, "
                f"{sum((firsts - wanted).values())} request(s) not in the baseline")
        chains: dict[str, list[Call]] = {}
        for call in run_calls:
            chains.setdefault(_chain(call.request, masks), []).append(call)
        report.failed_attempts[job] = sum(1 for call in run_calls if call.proposal is None)
        for attempts in chains.values():
            valid = [call for call in attempts if call.proposal is not None
                     and not response_problems(call.request, call.proposal, schema_root)]
            if not valid:
                reasons = {problem for call in attempts if call.proposal is not None
                           for problem in response_problems(call.request, call.proposal, schema_root)}
                failures = {str(call.error.get("message", ""))[:80] for call in attempts if call.error}
                report.response_problems.append(
                    f"{job}: no complete response in {len(attempts)} attempt(s) "
                    f"({'; '.join(sorted(reasons | failures))[:200] or 'no response'})")
        got = Counter(canonical(_normalized(call.proposal, masks)) for call in run_calls
                      if call.proposal is not None
                      and not response_problems(call.request, call.proposal, schema_root))
        if got != Counter(canonical(item) for item in expected["responses"]):
            report.response_changed.add(job)
    return report


def tainted_jobs(response_changed: Iterable[str], topology: Sequence[Mapping[str, Any]]) -> set[str]:
    """Jobs whose output cannot be held to the baseline: the changed ones and all their downstream."""

    changed = set(response_changed)
    return {item["job_id"] for item in topology
            if item["job_id"] in changed or changed & set(item.get("upstream_handoffs", ()))}
