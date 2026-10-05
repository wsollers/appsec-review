"""Citable structural evidence (ADR-0035): code-query answers recorded by Python, cited by id.

A citable ``code_*`` answer is written once, by the input server and never by the model, to
``runs/<run>/data/tool-evidence/<job>/<attempt>/<hex>.json``: the tool, its normalized arguments, the
bound index (pinned summary ref + sha256, database sha256), the answer and its sha256, ``complete``,
the escapes, and the invoking job and attempt. ``citation_id`` (``tev:<32 hex>``) is the content hash
of that body. The model cites the id; Python resolves it to the record, re-runs the query against the
same re-hashed index, requires the same answer hash, and builds the canonical
``claim-lifecycle-citation`` (producer = the invoking job/attempt, artifact = the record,
``locator_json`` = the query, ``observed_fact`` = a summary built here). A record cannot be forged,
edited or borrowed from another invocation.

Only answers that are a deterministic function of a hash-bound index are citable: the code-index
tools below, ``code_calls_to`` without partition/component scope (those read the cell's own pinned
maps), and lsp answers served wholly from the precomputed ``02-lsp-xref`` rows (a live or recorded
server answer is not hermetic to re-run). Rows stay untrusted target data.
"""
from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from execution_state import atomic_json, data_path, digest, file_hash, now

SCHEMA = "appsec-review/tool-evidence/1.0"
PREFIX = "tev:"   # ':' keeps the id a bare digest-length hex run for the V06 redactor
FOLDER = "tool-evidence"
CODE_TOOLS = ("code_symbol", "code_locate", "code_callers", "code_callees", "code_path", "code_calls_to")
LSP_TOOLS = ("code_definition", "code_references", "code_call_hierarchy")
CITABLE = CODE_TOOLS + LSP_TOOLS
_ID = re.compile(r"^tev:([0-9a-f]{32})$")
_SEGMENT = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_BODY = ("tool", "arguments", "index", "answer_sha256", "complete", "reasons", "escapes", "job_id", "attempt_id")


def is_id(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def is_citation(citation: Any) -> bool:
    return (isinstance(citation, dict) and is_id(citation.get("citation_id")) and
            str(citation.get("artifact_path") or "").startswith(FOLDER + "/"))


def locator(citation: dict[str, Any]) -> dict[str, Any]:
    """The query a tool-evidence citation names (``{tool, arguments, complete}``)."""
    try:
        value = json.loads(citation.get("locator_json") or "")
    except (TypeError, ValueError):
        value = None
    return value if isinstance(value, dict) else {}


def complete(citation: dict[str, Any]) -> bool:
    return locator(citation).get("complete") is True


def not_citable(tool: str, answer: dict[str, Any]) -> str | None:
    """Why this answer gets no citation_id (None: it is citable)."""
    if tool not in CITABLE:
        return f"{tool} answers are locators only (ADR-0035); cite what you read, not this answer"
    if tool == "code_calls_to" and any((answer.get("query") or {}).get(key) for key in ("partition_id", "component_id")):
        return "code_calls_to with partition_id/component_id is not citable; repeat it with path_prefix or no scope"
    if tool in LSP_TOOLS and (answer.get("source") or {}).get("answered_from") != "precomputed":
        return "only language-server answers served wholly from the precomputed 02-lsp-xref rows are citable"
    return None


def _canonical(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))


def answer_sha256(answer: dict[str, Any]) -> str:
    return "sha256:" + digest({key: item for key, item in _canonical(answer).items()
                               if key not in ("note", "citation_id", "citation_gap")})


def _escapes(answer: dict[str, Any]) -> int:
    rows = sum(1 for row in answer.get("rows") or [] if isinstance(row, dict) and row.get("kind") == "escape")
    return rows + int(answer.get("escapes_total") or len(answer.get("escapes") or []))


def build(tool: str, answer: dict[str, Any], *, index: dict[str, Any], job_id: str, attempt_id: str,
          cell: str | None = None, recorded_at: str | None = None) -> dict[str, Any]:
    """The record of one citable answer (deterministic apart from ``cell`` and ``recorded_at``)."""
    answer = {key: item for key, item in _canonical(answer).items()
              if key not in ("note", "citation_id", "citation_gap")}
    body = {"tool": tool, "arguments": answer.get("query") or {}, "index": index,
            "answer_sha256": answer_sha256(answer),
            "complete": answer.get("complete") is True and not answer.get("truncated"),
            "reasons": list(answer.get("reasons") or []), "escapes": _escapes(answer),
            "job_id": job_id, "attempt_id": attempt_id}
    content = digest(body)
    return {"schema": SCHEMA, "citation_id": PREFIX + content[:32], "content_sha256": "sha256:" + content,
            "body": body, "answer": answer, "cell": cell, "recorded_at": recorded_at}


def relative_path(job_id: str, attempt_id: str, citation_id: str) -> str:
    match = _ID.match(citation_id or "")
    if not match or not _SEGMENT.match(job_id or "") or not _SEGMENT.match(attempt_id or "") or \
            job_id in (".", "..") or attempt_id in (".", ".."):
        raise ValueError(f"not a tool-evidence identity: {citation_id!r} of {job_id!r}/{attempt_id!r}")
    return f"{FOLDER}/{job_id}/{attempt_id}/{match.group(1)}.json"


def _data(run_id: str, root: Path | None, *parts: str) -> Path:
    """The run's ``data/`` (or an explicit data root, e.g. the report's ``jobs_root`` parent)."""
    return Path(root).joinpath(*parts) if root is not None else data_path(run_id, *parts)


def _path(run_id: str, relative: str, root: Path | None = None) -> Path:
    path = _data(run_id, root, *PurePosixPath(relative).parts)
    cursor = _data(run_id, root)
    for part in PurePosixPath(relative).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError(f"tool evidence {relative} traverses a symbolic link")
    return path


def check(record: Any, *, job_id: str | None = None, attempt_id: str | None = None,
          citation_id: str | None = None) -> dict[str, Any]:
    """Raise ValueError unless ``record`` is an untampered tool-evidence record (of that identity)."""
    if not isinstance(record, dict) or record.get("schema") != SCHEMA or not isinstance(record.get("body"), dict) \
            or set(record["body"]) != set(_BODY) or not isinstance(record.get("answer"), dict):
        raise ValueError("tool evidence record shape is invalid")
    body, content = record["body"], digest(record["body"])
    if (record.get("content_sha256") != "sha256:" + content or record.get("citation_id") != PREFIX + content[:32]
            or body["answer_sha256"] != answer_sha256(record["answer"]) or body["tool"] not in CITABLE):
        raise ValueError(f"tool evidence {record.get('citation_id')!r} was altered (content hash mismatch)")
    if not_citable(body["tool"], record["answer"]):
        raise ValueError(f"tool evidence {record['citation_id']!r} records an answer that is not citable")
    if (job_id, attempt_id, citation_id) != (None, None, None) and \
            (body["job_id"], body["attempt_id"], record["citation_id"]) != (job_id, attempt_id, citation_id):
        raise ValueError(f"tool evidence {record['citation_id']!r} belongs to another invocation")
    return record


def write(run_id: str, record: dict[str, Any]) -> Path:
    """Write ``record`` once; an existing record with the same id must hold the same content."""
    check(record)
    body = record["body"]
    path = _path(run_id, relative_path(body["job_id"], body["attempt_id"], record["citation_id"]))
    if path.is_file():
        check(json.loads(path.read_text(encoding="utf-8")), job_id=body["job_id"], attempt_id=body["attempt_id"],
              citation_id=record["citation_id"])
        return path
    atomic_json(path, record)
    return path


def _target(answer: dict[str, Any]) -> str:
    query = answer.get("query") or {}
    if answer.get("tool") == "code_path":
        return (f"{query.get('from')} -> " if query.get("from") else "") + str(query.get("to"))
    for key in ("function", "name", "family"):
        if query.get(key):
            return str(query[key])
    return f"{query.get('path')}:{query.get('line')}" if query.get("path") else ""


def observed_fact(record: dict[str, Any]) -> str:
    """Python's one-line summary of the answer: query -> locators [complete | incomplete: why]."""
    answer, body = record["answer"], record["body"]
    rows = [row for row in answer.get("rows") or [] if isinstance(row, dict)]
    if body["tool"] == "code_path":
        shown = []
        for row in rows:
            steps = [step for step in row.get("steps") or [] if isinstance(step, dict) and step.get("function")]
            shown.append(" -> ".join(str(step["function"]) for step in steps) +
                         (f" ({steps[-1]['cite']})" if steps and steps[-1].get("cite") else ""))
        found = f"{len(rows)} path(s): " + "; ".join(shown[:3]) if rows else "no path"
    else:
        cites = list(dict.fromkeys(str(row["cite"]) for row in rows if row.get("cite") and row.get("kind") != "escape"))
        found = ", ".join(cites[:8]) + (f" (+{len(cites) - 8} more)" if len(cites) > 8 else "") if cites else "no rows"
    state = "[complete]" if body["complete"] else (
        "[incomplete: " + "; ".join(str(reason)[:120] for reason in body["reasons"][:2]) +
        (f"; {body['escapes']} escape(s)" if body["escapes"] else "") + "]")
    return f"{body['tool']}({_target(answer)}) -> {found} {state}"[:900]


def citation(record: dict[str, Any], artifact_sha256: str) -> dict[str, Any]:
    body = record["body"]
    return {"citation_id": record["citation_id"], "producer_job_id": body["job_id"],
            "producer_attempt_id": body["attempt_id"],
            "artifact_path": relative_path(body["job_id"], body["attempt_id"], record["citation_id"]),
            "artifact_sha256": artifact_sha256,
            "locator_json": json.dumps({"tool": body["tool"], "arguments": body["arguments"],
                                        "complete": body["complete"]}, sort_keys=True, separators=(",", ":")),
            "observed_fact": observed_fact(record)}


# -- re-run ---------------------------------------------------------------------------------------
class _NoBroker:
    """A re-run never starts a language server: only precomputed rows can reproduce."""
    def query(self, *_args: Any, **_kwargs: Any) -> Any:
        raise ValueError("re-run needs a live language server; only precomputed answers are citable")


_INDEXES: dict[tuple, Any] = {}


def _summary(run_id: str, index: dict[str, Any], root: Path | None = None) -> tuple[Path, str, dict[str, Any]]:
    ref = index.get("ref")
    if not isinstance(ref, str) or ":" not in ref:
        raise ValueError("tool evidence names no pinned index summary")
    relative = ref.split(":", 1)[1]
    jobs = _data(run_id, root, "jobs")
    path = jobs.joinpath(*PurePosixPath(relative).parts)
    if path.is_symlink() or not path.is_file() or "sha256:" + file_hash(path) != index.get("summary_sha256"):
        raise ValueError(f"the index summary {relative} the record was bound to is missing or changed")
    return jobs, relative, json.loads(path.read_text(encoding="utf-8"))


def rerun(run_id: str, record: dict[str, Any], root: Path | None = None) -> dict[str, Any]:
    """The answer the recorded query gives now against the recorded, re-hashed index."""
    import code_query_mcp
    body = record["body"]
    jobs, relative, summary = _summary(run_id, body["index"], root)
    key = (str(jobs), json.dumps(body["index"], sort_keys=True))
    lsp = body["index"].get("kind") == "lsp-xref"
    if key not in _INDEXES:
        _INDEXES[key] = (code_query_mcp.LspIndex(run_id, jobs, relative, summary, broker=_NoBroker()) if lsp
                         else code_query_mcp.CodeIndex(jobs, relative, summary))
    index = _INDEXES[key]
    if index.source.get("sha256") != body["index"].get("database_sha256"):
        raise ValueError("the index database differs from the one the record was bound to")
    if lsp:
        index.calls = 0
        return code_query_mcp.call(None, body["tool"], dict(body["arguments"]), lsp=index)
    return code_query_mcp.call(index, body["tool"], dict(body["arguments"]))


def verify_citation(run_id: str, given: dict[str, Any], *, data_root: Path | None = None) -> dict[str, Any]:
    """Raise ValueError unless ``given`` is exactly the canonical citation of an untampered record whose
    query re-runs to the same answer; return the canonical citation. ``data_root``: the run's ``data/``
    when the caller holds it explicitly (report assembly, ledger)."""
    relative = relative_path(given.get("producer_job_id"), given.get("producer_attempt_id"), given.get("citation_id"))
    if given.get("artifact_path") != relative:
        raise ValueError(f"tool evidence {given.get('citation_id')!r} names another record path")
    path = _path(run_id, relative, data_root)
    if not path.is_file():
        raise ValueError(f"tool evidence {given['citation_id']!r} is not a record of {given['producer_job_id']}/"
                         f"{given['producer_attempt_id']}")
    record = check(json.loads(path.read_text(encoding="utf-8")), job_id=given["producer_job_id"],
                   attempt_id=given["producer_attempt_id"], citation_id=given["citation_id"])
    try:
        again = rerun(run_id, record, data_root)
    except ValueError as exc:
        raise ValueError(f"tool evidence {given['citation_id']!r} cannot be re-run: {exc}") from None
    if answer_sha256(again) != record["body"]["answer_sha256"]:
        raise ValueError(f"tool evidence {given['citation_id']!r}: re-running {record['body']['tool']} gives a "
                         "different answer than the record holds")
    expected = citation(record, "sha256:" + file_hash(path))
    if given != expected:
        raise ValueError(f"tool evidence {given['citation_id']!r}: citation differs from its record")
    return expected


class Resolver:
    """Resolve ``tev:`` ids against one invocation's own records (re-run checked, cached)."""

    def __init__(self, run_id: str | None, job_id: str | None, attempt_id: str | None):
        self.run_id, self.job_id, self.attempt_id = run_id, job_id, attempt_id
        self._done: dict[str, dict[str, Any] | ValueError] = {}

    def resolve(self, citation_id: str) -> dict[str, Any]:
        if citation_id not in self._done:
            try:
                if not (self.run_id and self.job_id and self.attempt_id):
                    raise ValueError("this invocation has no tool-evidence records")
                relative = relative_path(self.job_id, self.attempt_id, citation_id)
                path = _path(self.run_id, relative)
                if not path.is_file():
                    raise ValueError("not a citation_id any code_* answer of this invocation returned; cite only "
                                     "ids your own code_* answers carried")
                record = check(json.loads(path.read_text(encoding="utf-8")))
                self._done[citation_id] = verify_citation(self.run_id, citation(record, "sha256:" + file_hash(path)))
            except (ValueError, OSError) as exc:
                self._done[citation_id] = ValueError(str(exc))
        found = self._done[citation_id]
        if isinstance(found, ValueError):
            raise found
        return found


def verify_decisions(run_id: str, decisions: dict[str, Any]) -> int:
    """Re-verify every tool-evidence citation of merged stage decisions; return how many were checked."""
    seen: set[str] = set()
    for row in decisions.get("decisions") or []:
        items = list(row.get("citations") or [])
        for obligation in row.get("proof_obligations") or []:
            items += obligation.get("citations") or []
        for item in items:
            if is_id(item.get("citation_id")) and item["citation_id"] not in seen:
                verify_citation(run_id, item)
                seen.add(item["citation_id"])
    return len(seen)


# -- the input server's side ----------------------------------------------------------------------
def attach(run_id: str, inputs: Any, code_ref: str | None, context: dict[str, Any], tool: str,
           answer: Any) -> Any:
    """Record a citable code_* answer and return it with ``citation_id`` (or ``citation_gap`` why not).
    Never fails the query: a record that cannot be written is a gap on the answer."""
    if not tool.startswith("code_") or not isinstance(answer, dict):
        return answer
    reason = not_citable(tool, answer)
    if reason is None:
        try:
            job_id, attempt_id = (str(context.get(key) or "") for key in ("job_id", "attempt_id"))
            if job_id in ("", "None") or attempt_id in ("", "None"):
                raise ValueError("this server serves no job attempt")
            if inputs is None:
                raise ValueError("no pinned inputs bind an index to this answer")
            if tool in LSP_TOOLS:
                import code_query_mcp
                ref = code_query_mcp.lsp_summary_ref([entry["ref"] for entry in inputs.entries])
                kind = "lsp-xref"
            else:
                ref, kind = code_ref, "code-index"
            if not ref or ref not in inputs.by_ref:
                raise ValueError("no pinned index summary is bound to this answer")
            source = answer.get("source") or {}
            index = {"kind": kind, "ref": ref, "summary_sha256": inputs.by_ref[ref]["sha256"],
                     "producer_job": source.get("producer_job"), "producer_attempt": source.get("attempt_id"),
                     "database_sha256": source.get("sha256")}
            record = build(tool, answer, index=index, job_id=job_id, attempt_id=attempt_id,
                           cell=context.get("output_root"), recorded_at=now())
            write(run_id, record)
            return {**answer, "citation_id": record["citation_id"]}
        except (ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
            reason = f"not recorded: {exc}"[:300]
    return {**answer, "citation_gap": reason}
