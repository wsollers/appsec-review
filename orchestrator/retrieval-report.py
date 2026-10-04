#!/usr/bin/env python3
"""How model jobs used their lookup tools in a run, and whether it paid off.

usage: orchestrator/retrieval-report.py <run_id> [--job JOB] [--calls]
       orchestrator/retrieval-report.py <run_id> --summary [--json] [--compare OTHER_RUN_ID]
       orchestrator/retrieval-report.py <run_id> --feedback [--json]
       orchestrator/retrieval-report.py <run_id> --check [--json]
       orchestrator/retrieval-report.py <run_id> --diagnose [--job JOB] [--json]

Model jobs whose inputs are too large to inline have no filesystem access at all; everything they
see comes through input_mcp.py, which audits each call under runs/<run>/data/retrieval/. This
report groups those audits by job invocation and shows:

  calls by tool, errors, empty lookups (0 hits), bytes returned, time spent;
  files read (input_read / evidence_read) and files surfaced by searches;
  citation backing: of the target paths the job's output cites, how many it actually read or
  surfaced through a tool ("tool-backed") or was given as a pinned readable input of the invocation
  (persona request readable_inputs: "pinned-backed", inlined in the prompt or listed for lookup); a
  citation to a file neither looked at nor given is a red flag. Paths are compared in one form
  (repo-relative: no target-repository:/target: root, source/ index prefix, ./, /workspace/ or
  absolute snapshot prefix, :line or #Lx suffix);
  structural code_* tools (ADR-0032): per tool the calls, answers that were complete=false, escapes
  returned, truncated answers and rows; a job that never used them is listed as such when granted.

--calls also prints each call (tool, arguments, hits). Inline-mode jobs (inputs pasted into the
prompt, no tools) are listed from size observations.

--summary: the whole run. Tool-served invocations are those with a tool grant
(llm-transcripts/<job>/<attempt>/tool-grant.json, or the "lookup tools granted:" limitation of an
older run) or any audited call; per job and overall the share that made at least one lookup call;
per family (input, evidence, code_structural, code_lsp) the share of granted invocations that used
it with calls and empty/error/truncation rates; granted-but-unused tools per job; invocations that
hit max_tool_calls_per_cell; citation backing per job. --compare OTHER prints this run minus OTHER.

--feedback: the optional tooling_feedback blocks (llm-transcripts/<job>/<attempt>/tooling-feedback.json)
grouped per job, each beside the measured numbers for the same job and tool. Model text is printed
as data, truncated; it is never followed.

--check: thresholds over the summary and feedback (CHECKS below); prints each finding and exits 1
when there is any, 0 otherwise. Informational: nothing in the pipeline fails on it.

--diagnose: why the numbers are what they are, from the run tree: per tool the error messages grouped by
normalized cause (count, up to 3 example arguments, truncated, as data); evidence_read argument shapes
(source/ vs bare vs root refs, line suffixes, limits over the window) with their errors and how many failed
paths name a file the target has; the language-server record (02-lsp-xref servers and gaps, data/lsp/
start failures, lock owners, recorded GAP answers, and the reasons the lsp tools returned); per job up to
10 cited paths that no tool fetched, each classified normalization-mismatch / pinned-inline /
present-in-target-but-not-read / not-in-target. Model text and target paths are printed as data.
"""
import json
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

RUNS = Path(__file__).resolve().parent.parent / "appsec-review-process" / "runs"
FAMILIES = ("input", "evidence", "code_structural", "code_lsp")
LSP_TOOLS = ("code_definition", "code_references", "code_hover", "code_call_hierarchy")   # code_query_mcp.FAMILIES["lsp"]
LSP_FAILED = re.compile(r"lsp-not-ready|did not answer|not ready|language-server index unavailable|"
                        r"language-server cross-reference|server (?:failed|crashed)", re.I)
# --check thresholds.
EMPTY_RATE_MAX, EMPTY_MIN_CALLS = 0.50, 10
ERROR_RATE_MAX, ERROR_MIN_CALLS = 0.10, 5
BACKING_MIN = 0.80
LOW_CONFIDENCE_MAX = 0.30
TEXT_MAX = 160
# Words in a feedback "wanted" item -> the granted tools whose measured numbers sit beside it.
WANTED_TOOLS = ((r"call ?graph|caller|callee|call hierarch|call path|who calls", ("code_callers", "code_callees", "code_path", "code_call_hierarchy")),
                (r"definition|go ?to|declar", ("code_definition", "code_symbol", "code_locate")),
                (r"reference|usage|xref|cross.?ref", ("code_references", "code_calls_to")),
                (r"hover|type|struct|class|overrid", ("code_hover", "code_type_info", "code_overrides")),
                (r"symbol|function list|outline", ("code_symbol", "code_search", "code_file_outline")),
                (r"grep|regex|text search|full.?text|search", ("evidence_search", "input_grep")),
                (r"export|entry ?point|api surface", ("code_exports",)),
                (r"finding|scanner|tool output|derived", ("evidence_derived",)))


TARGET_ROOTS = ("target", "target-repository", "source")   # persona_dispatch.DEFAULT_READABLE_ROOT and aliases
_ROOT_REF = re.compile(r"^([a-z][a-z0-9-]*):(?!\d)(.+)$")
_LINE_SUFFIX = re.compile(r"(?:#L\d+(?:-L?\d+)?|:\d+(?:[-:]\d+)*)$")


def norm(ref: str) -> str:
    """One form for a cited or looked-at path: target files repo-relative (no target-repository:/target: root,
    source/ index prefix, ./, /workspace/ or absolute snapshot prefix, :line / #Lx suffix); other pinned roots
    as root:path (upstream-artifacts: as upstream:)."""
    ref = str(ref).strip().removeprefix("file://")
    root, match = None, _ROOT_REF.match(ref)
    if match:
        root, ref = match.group(1), match.group(2)
    ref = _LINE_SUFFIX.sub("", ref)
    if ref.startswith("/"):
        ref = ref.split("/source/", 1)[1] if "/source/" in ref else (
            ref[len("/workspace/"):] if ref.startswith("/workspace/") else ref)
    while ref.startswith("./"):
        ref = ref[2:]
    if root is None or root in TARGET_ROOTS:
        return ref.removeprefix("source/")
    return ("upstream" if root == "upstream-artifacts" else root) + ":" + ref


def _legacy(ref: str) -> str:
    """The form the report compared before paths were normalized (diagnose: normalization mismatches)."""
    ref = str(ref)
    ref = ref.split(":")[0] if ref.count(":") == 1 and not ref.startswith("target:") else ref
    head, sep, rest = ref.partition(":")
    if sep and head in ("target", "target-repository", "upstream-artifacts"):
        ref = rest if head != "upstream-artifacts" else "upstream:" + rest
    return ref[len("source/"):] if ref.startswith("source/") else ref


def cited(value, inside=False, found=None, ids=None) -> tuple[set, set]:
    """(raw cited path strings, citation ids) anywhere under a key containing 'citation' (or 'evidence').
    A citation object's own non-target ``root`` is kept as root:path."""
    found = set() if found is None else found
    ids = set() if ids is None else ids
    if isinstance(value, dict):
        root = value.get("root") if inside and isinstance(value.get("root"), str) else None
        for key, item in value.items():
            nested = inside or "citation" in key.lower() or key.lower() in ("evidence", "evidence_paths")
            if key.lower() in ("citation_id", "citation_ids", "citation_refs"):
                ids.update(str(i) for i in (item if isinstance(item, list) else [item]) if isinstance(i, (str, int)))
            elif nested and key in ("path", "file", "source_path") and isinstance(item, str):
                found.add(item if root is None or root in TARGET_ROOTS else f"{root}:{item}")
            else:
                cited(item, nested, found, ids)
    elif isinstance(value, list):
        for item in value:
            if inside and isinstance(item, str) and ("/" in item or "." in item):
                found.add(item)
            else:
                cited(item, inside, found, ids)
    return found, ids


def citations(value) -> set:
    """Target paths cited anywhere under a key containing 'citation' (or 'evidence'), normalized."""
    return {norm(item) for item in cited(value)[0]}


def family(tool: str) -> str:
    if tool in LSP_TOOLS:
        return "code_lsp"
    if tool.startswith("code_"):
        return "code_structural"
    return "evidence" if tool.startswith("evidence_") else "input"


def _json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def text(value, limit: int = TEXT_MAX) -> str:
    """Model text printed as data: one line, control characters removed, truncated."""
    value = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value)).strip()
    return value if len(value) <= limit else value[:limit - 3] + "..."


def _granted_from_output(root) -> list | None:
    """Older runs: the grant from the 'lookup tools granted:' limitation of the invocation's output."""
    record = _json(Path(root) / "invoker-output.json") if root else None
    for line in (record or {}).get("limitations") or []:
        if isinstance(line, str) and line.startswith("lookup tools granted: "):
            return [t.strip() for t in line[len("lookup tools granted: "):].split(";")[0].split(" (")[0].split(",") if t.strip()]
    return None


def load(run: str, only: str | None = None) -> dict:
    """{(job, attempt): {calls, granted, usage, feedback, output_root}} plus the inline-mode jobs."""
    data = RUNS / run / "data"
    invocations = defaultdict(lambda: {"calls": [], "granted": None, "usage": {}, "feedback": None, "output_root": None})
    for folder in sorted((data / "retrieval").glob("*")) if (data / "retrieval").is_dir() else []:
        request = _json(folder / "request.json")
        if not isinstance(request, dict) or not request.get("tool"):
            continue
        outcome = {}
        for name in ("result.json", "error.json"):
            if (folder / name).is_file():
                outcome = _json(folder / name) or {}; outcome["_kind"] = name[:-5]
        key = (request.get("job_id") or "(unattributed)", request.get("attempt_id") or "-")
        if only and key[0] != only:
            continue
        invocations[key]["calls"].append((request, outcome))
        invocations[key]["output_root"] = invocations[key]["output_root"] or request.get("output_root")
    transcripts = data / "llm-transcripts"
    for folder in sorted(transcripts.glob("*/*")) if transcripts.is_dir() else []:
        key = (folder.parent.name, folder.name)
        if not folder.is_dir() or only and key[0] != only:
            continue
        grant, usage, feedback = (_json(folder / n) for n in ("tool-grant.json", "tool-usage.json", "tooling-feedback.json"))
        if not (grant or usage or feedback) and key not in invocations:
            continue   # repair-log only: a model call without the input server
        row = invocations[key]
        if isinstance(grant, dict) and isinstance(grant.get("tools"), list):
            row["granted"] = [str(t) for t in grant["tools"]]
            row["cap"] = grant.get("max_tool_calls_per_cell")
            row["output_root"] = row["output_root"] or grant.get("output_root")
            row["input_mode"] = grant.get("input_mode")
        row["usage"] = {k: v for k, v in usage.items() if isinstance(v, int)} if isinstance(usage, dict) else {}
        row["feedback"] = feedback if isinstance(feedback, dict) else None
    for row in invocations.values():
        row["calls"].sort(key=lambda c: c[0].get("time", ""))
        if row["granted"] is None:
            row["granted"] = _granted_from_output(row["output_root"])
    inline = []
    for path in sorted((data / "size-observations").glob("*.prompt_input_mode.json")) if (data / "size-observations").is_dir() else []:
        record = _json(path) or {}
        if record.get("mode") == "inline" and (not only or record.get("job") == only):
            inline.append(record)
    return {"invocations": dict(invocations), "inline": inline}


READ_TOOLS = ("input_read", "evidence_read", "input_jq")


def _looked_raw(calls: list) -> tuple[set, set]:
    """(raw refs read, raw refs surfaced by searches) over an invocation's successful calls."""
    read, surfaced = set(), set()
    for request, outcome in calls:
        if outcome.get("_kind") != "result":
            continue
        refs = {str(r) for r in outcome.get("refs", []) or [] if r}
        if request["tool"] in READ_TOOLS:
            arguments = request.get("arguments") or {}
            read |= refs or {str(arguments.get("ref") or arguments.get("path", ""))}
        else:
            surfaced |= refs
    return read, surfaced


def looked(calls: list) -> tuple[set, set]:
    """(files read, files surfaced by searches) over an invocation's successful calls."""
    read, surfaced = _looked_raw(calls)
    return {norm(r) for r in read}, {norm(r) for r in surfaced}


def persona_request(output_root) -> dict | None:
    """The persona request (persona_invocation writes it to <attempt>/<log_path>/request.json) whose
    output_root is this invocation's: its readable_inputs are what the model was given."""
    out = Path(output_root)
    for ancestor in list(out.parents)[:4]:
        for candidate in sorted(ancestor.glob("*/request.json")) + sorted(ancestor.glob("*/*/request.json")):
            request = _json(candidate)
            if (isinstance(request, dict) and isinstance(request.get("readable_inputs"), list)
                    and isinstance(request.get("output_root"), str)
                    and ancestor.joinpath(*request["output_root"].split("/")) == out):
                return request
    return None


def pinned_paths(request: dict | None) -> set:
    """Normalized paths of a persona request's readable_inputs (target roots repo-relative, others root:path)."""
    out = set()
    for entry in (request or {}).get("readable_inputs") or []:
        if isinstance(entry, dict) and isinstance(entry.get("path"), str):
            root = str(entry.get("root") or "")
            out.add(norm(entry["path"]) if root in TARGET_ROOTS or not root else norm(f"{root}:{entry['path']}"))
    return out


def backing(row: dict) -> dict | None:
    """Cited target paths of the invocation's output and how they are backed (None: no output): tool-backed
    (read or surfaced by a call) or pinned-backed (a readable input of the invocation, never fetched)."""
    read, surfaced = looked(row["calls"])
    root = row["output_root"]
    if not root or not Path(root).is_dir():
        return None
    raw, ids = set(), set()
    for path in Path(root).glob("*.json"):
        if path.name != "invoker-output.json":
            cited(_json(path) or {}, found=raw, ids=ids)
    paths = {norm(item) for item in raw}
    request = persona_request(root)
    pinned = pinned_paths(request)
    seen = read | surfaced
    tool, given = paths & seen, (paths & pinned) - seen
    return {"read": read, "surfaced": surfaced, "cited": paths, "raw": raw, "ids": ids, "pinned": pinned,
            "request": request, "tool_backed": tool, "pinned_backed": given, "backed": tool | given,
            "unbacked": sorted(paths - seen - pinned)}


def lsp_failed(outcome: dict) -> bool:
    """An lsp call the server could not answer: an error, or an empty incomplete answer naming the server."""
    if outcome.get("_kind") == "error":
        return True
    reasons = " ".join(str(r) for r in outcome.get("reasons") or []) + " " + " ".join(str(g) for g in outcome.get("gaps") or [])
    return not outcome.get("hits") and outcome.get("complete") is False and bool(LSP_FAILED.search(reasons))


def _rate(part: int, whole: int):
    return round(part / whole, 4) if whole else None


def _tool_row(calls: list) -> dict:
    n = len(calls)
    errors = sum(1 for _, o in calls if o.get("_kind") == "error")
    empty = sum(1 for _, o in calls if o.get("_kind") == "result" and not o.get("hits"))
    truncated = sum(1 for _, o in calls if o.get("truncated"))
    return {"calls": n, "errors": errors, "empty": empty, "truncated": truncated,
            "error_rate": _rate(errors, n), "empty_rate": _rate(empty, n), "truncation_rate": _rate(truncated, n)}


def summarize(loaded: dict) -> dict:
    invocations = loaded["invocations"]
    served = {k: r for k, r in invocations.items() if r["granted"] or r["calls"] or r["usage"]}
    jobs = defaultdict(lambda: {"invocations": 0, "used": 0, "calls": 0, "unused": Counter(), "cited": 0,
                                "backed": 0, "tool_backed": 0, "pinned_backed": 0, "unbacked": 0, "ids": 0,
                                "with_output": 0, "with_request": 0})
    fam = {f: {"granted": 0, "used": 0, "calls": []} for f in FAMILIES}
    tools, cap_hits, lsp = defaultdict(list), [], {"granted": 0, "calls": 0, "failed": 0}
    for (job, attempt), row in sorted(served.items()):
        calls = row["calls"]
        used_tools = {r["tool"] for r, _ in calls} | {t for t, n in row["usage"].items() if n and not t.startswith("_")}
        j = jobs[job]
        j["invocations"] += 1
        j["used"] += 1 if used_tools else 0
        j["calls"] += len(calls)
        granted = set(row["granted"] or [])
        for tool in sorted(granted - used_tools):
            j["unused"][tool] += 1
        for f in FAMILIES:
            g = {t for t in granted if family(t) == f}
            if g:
                fam[f]["granted"] += 1
                fam[f]["used"] += 1 if g & used_tools else 0
        for request, outcome in calls:
            fam[family(request["tool"])]["calls"].append((request, outcome))
            tools[request["tool"]].append((request, outcome))
            if request["tool"] in LSP_TOOLS:
                lsp["calls"] += 1
                lsp["failed"] += 1 if lsp_failed(outcome) else 0
        lsp["granted"] += 1 if granted & set(LSP_TOOLS) else 0
        refused = row["usage"].get("_budget_exhausted", 0)
        if refused:
            cap_hits.append({"job": job, "attempt": attempt, "refused": refused, "cap": row.get("cap")})
        back = backing(row)
        if back is not None:
            j["with_output"] += 1
            j["with_request"] += 1 if back["request"] is not None else 0
            j["cited"] += len(back["cited"]); j["backed"] += len(back["backed"]); j["unbacked"] += len(back["unbacked"])
            j["tool_backed"] += len(back["tool_backed"]); j["pinned_backed"] += len(back["pinned_backed"])
            j["ids"] += len(back["ids"])
    used = sum(j["used"] for j in jobs.values())
    return {
        "served_invocations": len(served), "used_invocations": used, "used_rate": _rate(used, len(served)),
        "inline_jobs": sorted({r.get("job") for r in loaded["inline"] if r.get("job")}),
        "jobs": {job: {"invocations": j["invocations"], "used": j["used"], "used_rate": _rate(j["used"], j["invocations"]),
                       "calls": j["calls"], "granted_unused": dict(sorted(j["unused"].items())),
                       "citations": ({"cited": j["cited"], "backed": j["backed"], "unbacked": j["unbacked"],
                                      "backed_rate": _rate(j["backed"], j["cited"]),
                                      "tool_backed": j["tool_backed"], "tool_backed_rate": _rate(j["tool_backed"], j["cited"]),
                                      "pinned_backed": j["pinned_backed"], "cited_ids": j["ids"],
                                      "pinned_inputs_found": j["with_request"], "with_output": j["with_output"]}
                                     if j["with_output"] else None)}
                 for job, j in sorted(jobs.items())},
        "families": {f: {"granted_invocations": v["granted"], "used_invocations": v["used"],
                         "used_rate": _rate(v["used"], v["granted"]), **_tool_row(v["calls"])} for f, v in fam.items()},
        "tools": {t: {"family": family(t), **_tool_row(c)} for t, c in sorted(tools.items())},
        "cap_exhausted": cap_hits,
        "lsp": lsp,
    }


def _pct(value) -> str:
    return "-" if value is None else f"{100 * value:.0f}%"


def print_summary(run: str, s: dict) -> None:
    print(f"== {run}: {s['served_invocations']} tool-served invocation(s), {s['used_invocations']} made a lookup call "
          f"({_pct(s['used_rate'])}); inline jobs (no tools) {len(s['inline_jobs'])}")
    print("-- per job: invocations, used lookups, calls, citation backing")
    for job, j in s["jobs"].items():
        c = j["citations"]
        cites = "citations unavailable (output not found)" if c is None else (
            f"cited {c['cited']}, backed {_pct(c['backed_rate'])} (tool {c['tool_backed']}, pinned {c['pinned_backed']}"
            + ("" if c["pinned_inputs_found"] else ", pinned inputs not found") + f"), unbacked {c['unbacked']}"
            + (f", cited by id {c['cited_ids']} (not path-backed)" if c["cited_ids"] else ""))
        print(f"   {job:<45} {j['invocations']:>3}  used {_pct(j['used_rate']):>4}  calls {j['calls']:>4}  {cites}")
    print("-- per family: invocations granted, used, calls, empty, errors, truncated")
    for f, v in s["families"].items():
        print(f"   {f:<16} granted {v['granted_invocations']:>3}  used {_pct(v['used_rate']):>4}  calls {v['calls']:>5}  "
              f"empty {_pct(v['empty_rate']):>4}  errors {_pct(v['error_rate']):>4}  truncated {_pct(v['truncation_rate']):>4}")
    print("-- per tool")
    for t, v in s["tools"].items():
        print(f"   {t:<20} {v['family']:<16} calls {v['calls']:>5}  empty {_pct(v['empty_rate']):>4}  "
              f"errors {_pct(v['error_rate']):>4}  truncated {_pct(v['truncation_rate']):>4}")
    if s["lsp"]["granted"] or s["lsp"]["calls"]:
        print(f"-- lsp: granted in {s['lsp']['granted']} invocation(s), {s['lsp']['calls']} audited call(s), "
              f"{s['lsp']['failed']} server failed / not ready")
    unused = {job: j["granted_unused"] for job, j in s["jobs"].items() if j["granted_unused"]}
    if unused:
        print("-- granted but unused (tool: invocations that never called it)")
        for job, tools in unused.items():
            print(f"   {job}: " + ", ".join(f"{t} {n}" for t, n in tools.items()))
    for hit in s["cap_exhausted"]:
        print(f"-- cap exhausted: {hit['job']} attempt {hit['attempt']}: {hit['refused']} call(s) refused "
              f"(max_tool_calls_per_cell {hit['cap'] if hit['cap'] is not None else '?'})")


def compare(a: dict, b: dict) -> dict:
    """This run (a) minus the other (b): rates and counts that both carry."""
    def delta(x, y):
        return None if x is None or y is None else round(x - y, 4)
    out = {"used_rate": [a["used_rate"], b["used_rate"], delta(a["used_rate"], b["used_rate"])],
           "served_invocations": [a["served_invocations"], b["served_invocations"],
                                  a["served_invocations"] - b["served_invocations"]],
           "cap_exhausted": [len(a["cap_exhausted"]), len(b["cap_exhausted"]), len(a["cap_exhausted"]) - len(b["cap_exhausted"])],
           "families": {}, "jobs": {}}
    for f in FAMILIES:
        x, y = a["families"][f], b["families"][f]
        out["families"][f] = {k: [x[k], y[k], delta(x[k], y[k]) if k.endswith("rate") else x[k] - y[k]]
                              for k in ("used_rate", "calls", "empty_rate", "error_rate", "truncation_rate")}
    for job in sorted(set(a["jobs"]) | set(b["jobs"])):
        x, y = a["jobs"].get(job), b["jobs"].get(job)
        bx = ((x or {}).get("citations") or {}).get("backed_rate")
        by = ((y or {}).get("citations") or {}).get("backed_rate")
        ux, uy = (x or {}).get("used_rate"), (y or {}).get("used_rate")
        out["jobs"][job] = {"used_rate": [ux, uy, delta(ux, uy)], "backed_rate": [bx, by, delta(bx, by)],
                            "calls": [(x or {}).get("calls", 0), (y or {}).get("calls", 0),
                                      (x or {}).get("calls", 0) - (y or {}).get("calls", 0)]}
    return out


def print_compare(run: str, other: str, d: dict) -> None:
    def cell(v, rate=True):
        if rate:
            sign = "" if v[2] is None else f" ({'+' if v[2] >= 0 else ''}{100 * v[2]:.0f} pts)"
            return f"{_pct(v[0])} vs {_pct(v[1])}{sign}"
        return f"{v[0]} vs {v[1]} ({'+' if v[2] >= 0 else ''}{v[2]})"
    print(f"== compare {run} vs {other}")
    print(f"   invocations using lookups {cell(d['used_rate'])}; tool-served {cell(d['served_invocations'], False)}; "
          f"cap exhausted {cell(d['cap_exhausted'], False)}")
    for f, v in d["families"].items():
        print(f"   {f:<16} used {cell(v['used_rate'])}  calls {cell(v['calls'], False)}  empty {cell(v['empty_rate'])}  "
              f"errors {cell(v['error_rate'])}  truncated {cell(v['truncation_rate'])}")
    for job, v in d["jobs"].items():
        print(f"   {job:<45} used {cell(v['used_rate'])}  calls {cell(v['calls'], False)}  backed {cell(v['backed_rate'])}")


def _wanted_key(item: dict) -> tuple:
    what = re.sub(r"[^a-z0-9_+#./ -]+", " ", str(item.get("what", "")).lower())
    return str(item.get("kind", "other")), re.sub(r"\s+", " ", what).strip(" .,;:-")


def _measured(tool: str, job_tools: dict, granted: set) -> str:
    v = job_tools.get(tool)
    if v:
        return f"{tool}: {v['calls']} calls, {_pct(v['empty_rate'])} empty, {_pct(v['error_rate'])} errors"
    return f"{tool}: granted, 0 calls" if tool in granted else f"{tool}: not granted"


def feedback(loaded: dict) -> dict:
    """Per job: tooling_feedback grouped beside the measured numbers for the same job and tool."""
    per_job = defaultdict(lambda: {"invocations": 0, "with_feedback": 0, "confidence": Counter(), "wanted": Counter(),
                                   "wanted_sample": {}, "useful": Counter(), "unhelpful": Counter(),
                                   "unhelpful_reason": {}, "would_change": [], "granted": set(), "calls": defaultdict(list)})
    for (job, _attempt), row in sorted(loaded["invocations"].items()):
        if not (row["granted"] or row["calls"] or row["usage"]):
            continue
        j = per_job[job]
        j["invocations"] += 1
        j["granted"] |= set(row["granted"] or [])
        for request, outcome in row["calls"]:
            j["calls"][request["tool"]].append((request, outcome))
        fb = row["feedback"]
        if not fb:
            continue
        j["with_feedback"] += 1
        if fb.get("coverage_confidence"):
            j["confidence"][str(fb["coverage_confidence"])] += 1
        for item in fb.get("wanted") or []:
            if isinstance(item, dict):
                key = _wanted_key(item)
                j["wanted"][key] += 1
                j["wanted_sample"].setdefault(key, item)
        for tool in fb.get("useful_tools") or []:
            j["useful"][str(tool)] += 1
        for item in fb.get("unhelpful_tools") or []:
            if isinstance(item, dict):
                j["unhelpful"][str(item.get("tool"))] += 1
                j["unhelpful_reason"].setdefault(str(item.get("tool")), item.get("reason", ""))
        if fb.get("would_change"):
            j["would_change"].append(text(fb["would_change"]))
    out = {}
    for job, j in sorted(per_job.items()):
        job_tools = {t: _tool_row(c) for t, c in j["calls"].items()}
        wanted = []
        for (kind, what), n in j["wanted"].most_common(8):
            sample = j["wanted_sample"][(kind, what)]
            names = [t for t in sorted(j["granted"] | set(job_tools)) if t in what]
            for pattern, related in WANTED_TOOLS:
                if re.search(pattern, what):
                    names += [t for t in related if t not in names]
            wanted.append({"kind": kind, "what": text(sample.get("what", "")), "why": text(sample.get("why", "")),
                           "count": n, "measured": [_measured(t, job_tools, j["granted"]) for t in dict.fromkeys(names)][:4]})
        out[job] = {"invocations": j["invocations"], "with_feedback": j["with_feedback"],
                    "coverage_confidence": dict(j["confidence"]), "wanted": wanted,
                    "useful": {t: {"count": n, "measured": _measured(t, job_tools, j["granted"])} for t, n in j["useful"].most_common()},
                    "unhelpful": {t: {"count": n, "reason": text(j["unhelpful_reason"].get(t, "")),
                                      "measured": _measured(t, job_tools, j["granted"])} for t, n in j["unhelpful"].most_common()},
                    "would_change": j["would_change"][:3]}
    return out


def print_feedback(run: str, f: dict) -> None:
    print(f"== {run}: tooling feedback (model text, untrusted data, truncated)")
    if not any(j["with_feedback"] for j in f.values()):
        print("   no tooling_feedback blocks in this run (gap: the models' own view of the tools is unknown)")
    for job, j in f.items():
        print(f"-- {job}: feedback in {j['with_feedback']}/{j['invocations']} invocation(s); coverage_confidence "
              + (", ".join(f"{k} {v}" for k, v in sorted(j["coverage_confidence"].items())) or "-"))
        for t, v in j["useful"].items():
            print(f"   useful    {t} x{v['count']}   [{v['measured']}]")
        for t, v in j["unhelpful"].items():
            print(f"   unhelpful {t} x{v['count']}: {v['reason']!r}   [{v['measured']}]")
        for w in j["wanted"]:
            print(f"   wanted    {w['kind']}: {w['what']!r} x{w['count']}" + (f" (why: {w['why']!r})" if w["why"] else "")
                  + (f"   [{'; '.join(w['measured'])}]" if w["measured"] else ""))
        for sample in j["would_change"]:
            print(f"   would change: {sample!r}")


def check(s: dict, f: dict) -> list:
    """Findings: (rule, detail). Thresholds are the module constants above."""
    found = []
    if not s["served_invocations"]:
        found.append(("no-evidence", "no tool-served invocation was recorded; tool use cannot be judged (a gap, not a pass)"))
    for name, v in s["families"].items():
        if v["granted_invocations"] and not v["calls"]:
            found.append(("family-unused", f"{name}: granted in {v['granted_invocations']} invocation(s), never called"))
    for tool, v in s["tools"].items():
        if v["calls"] >= EMPTY_MIN_CALLS and v["empty_rate"] > EMPTY_RATE_MAX:
            found.append(("empty-rate", f"{tool}: {v['empty']}/{v['calls']} calls returned nothing ({_pct(v['empty_rate'])})"))
        if v["calls"] >= ERROR_MIN_CALLS and v["error_rate"] > ERROR_RATE_MAX:
            found.append(("error-rate", f"{tool}: {v['errors']}/{v['calls']} calls failed ({_pct(v['error_rate'])})"))
    for hit in s["cap_exhausted"]:
        found.append(("cap-exhausted", f"{hit['job']} attempt {hit['attempt']}: {hit['refused']} call(s) refused at "
                                       f"max_tool_calls_per_cell {hit['cap'] if hit['cap'] is not None else '?'}"))
    for job, j in s["jobs"].items():
        c = j["citations"]
        if c and c["cited"] and c["backed_rate"] < BACKING_MIN:
            found.append(("citation-backing", f"{job}: {c['backed']}/{c['cited']} cited paths read, surfaced or "
                                              f"pinned ({_pct(c['backed_rate'])}; tool {c['tool_backed']}, pinned "
                                              f"{c['pinned_backed']}), {c['unbacked']} unbacked"))
    lsp = s["lsp"]
    if lsp["granted"] and lsp["calls"] and lsp["failed"] == lsp["calls"]:
        found.append(("lsp-down", f"lsp tools granted in {lsp['granted']} invocation(s); all {lsp['calls']} call(s) "
                                  f"answered server failed / not ready"))
    total = sum(j["with_feedback"] for j in f.values())
    low = sum(j["coverage_confidence"].get("low", 0) for j in f.values())
    if total and low / total > LOW_CONFIDENCE_MAX:
        found.append(("low-confidence", f"{low}/{total} invocations with feedback reported coverage_confidence low"))
    return found


# ---- --diagnose ------------------------------------------------------------------------------------------
EXAMPLES, UNBACKED_SHOWN = 3, 10
EVIDENCE_WINDOW = 50   # evidence_mcp evidence_read limit maximum (shared tunable evidence_query_results_max)


def cause(message) -> str:
    """An error or reason with its specifics (quoted values, paths, hashes, numbers) replaced, for grouping."""
    value = text(message, 400)
    value = re.sub(r"'[^']*'|\"[^\"]*\"", "<q>", value)
    value = re.sub(r"sha256:[0-9a-f]+|\b[0-9a-f]{16,}\b", "<hash>", value)
    value = re.sub(r"(?<![\w<])[\w.+-]*(?:/[\w.+-]+)+/?", "<path>", value)
    value = re.sub(r"\b\d+\b", "N", value)
    return value[:160]


def _example(request: dict) -> str:
    return text(json.dumps(request.get("arguments"), sort_keys=True), 120)


def _group(rows) -> list[dict]:
    """[(cause text, example)] -> [{cause, count, examples}] most frequent first."""
    groups: dict[str, dict] = {}
    for message, example in rows:
        key = cause(message)
        group = groups.setdefault(key, {"cause": key, "count": 0, "examples": []})
        group["count"] += 1
        if example is not None and len(group["examples"]) < EXAMPLES and example not in group["examples"]:
            group["examples"].append(example)
    return sorted(groups.values(), key=lambda g: (-g["count"], g["cause"]))


def path_shape(path) -> str:
    """The form of an evidence path argument."""
    raw = str(path or "")
    match = _ROOT_REF.match(raw)
    if match:
        shape = ("target root ref (" if match.group(1) in TARGET_ROOTS else "other root ref (") + match.group(1) + ":)"
    elif raw.startswith(("source/", "evidence/")):
        shape = raw.split("/", 1)[0] + "/ prefix (index form)"
    elif raw.startswith("./"):
        shape = "./ prefix"
    elif raw.startswith("/"):
        shape = "absolute path"
    elif not raw:
        shape = "empty"
    else:
        shape = "bare repository path"
    return shape + (" + line suffix" if _LINE_SUFFIX.search(raw) else "")


def target_files(run: str, extra: set) -> set | None:
    """Repo-relative paths of the target: the accepted evidence index's source/ files, plus the target-root
    readable inputs of the persona requests found. None when neither is available."""
    found = set(extra)
    base = RUNS / run / "data" / "jobs" / "02-evidence-index" / "whole"
    pointer = _json(base / "accepted.json") or {}
    database = base / "attempts" / str(pointer.get("attempt_id")) / "index.sqlite"
    index = False
    if pointer.get("attempt_id") and database.is_file():
        try:
            connection = sqlite3.connect(database.as_uri() + "?mode=ro&immutable=1", uri=True)
            try:
                found |= {path[len("source/"):] for (path,) in connection.execute("SELECT path FROM files")
                          if path.startswith("source/")}
                index = True
            finally:
                connection.close()
        except sqlite3.Error:
            pass
    return found if found or index else None


def _lsp_record(run: str) -> dict:
    """What 02-lsp-xref published and what the broker recorded under data/lsp/."""
    data = RUNS / run / "data"
    jobs = data / "jobs" / "02-lsp-xref"
    pointer = _json(jobs / "accepted.json") or {}
    summaries = sorted((jobs / "attempts").glob("*/lsp-xref.json")) if (jobs / "attempts").is_dir() else []
    chosen = next((p for p in summaries if p.parent.name == pointer.get("attempt_id")), summaries[-1] if summaries else None)
    out = {"xref": None, "failures": [], "owners": Counter(), "recordings": 0, "recorded_gaps": [], "recoveries": 0}
    summary = _json(chosen) if chosen else None
    if isinstance(summary, dict):
        out["xref"] = {"attempt_id": chosen.parent.name, "accepted": chosen.parent.name == pointer.get("attempt_id"),
                       "status": summary.get("status"), "counts": summary.get("counts"),
                       "native_build": (summary.get("inputs") or {}).get("native_build"),
                       "servers": [{k: server.get(k) for k in ("server_key", "variant", "server", "image_id", "image_digest")}
                                   | {"build_input": {k: (server.get("build_input") or {}).get(k) for k in ("kind", "unit_id")}}
                                   for server in summary.get("servers") or [] if isinstance(server, dict)],
                       "gaps": [{"kind": gap.get("kind"), "detail": text(gap.get("detail"), 300)}
                                for gap in summary.get("gaps") or [] if isinstance(gap, dict)]}
    lsp = data / "lsp"
    for path in sorted((lsp / "failures").glob("*.json")) if (lsp / "failures").is_dir() else []:
        record = _json(path) or {}
        out["failures"].append({"lock": record.get("lock", path.stem), "attempts": record.get("attempts"),
                                "error": text(record.get("error"), 300), "at": record.get("at")})
    for owner in list(lsp.glob("locks/*.lock/owner.json")) + list(lsp.glob("locks/released/*/owner.json")):
        record = _json(owner) or {}
        out["owners"][f"{record.get('server_key', '?')}/{record.get('variant', '?')}: {record.get('state')}"
                      + (f" ({record.get('reason')})" if record.get("reason") else "")] += 1
    rows = []
    for path in lsp.glob("recordings/*/*.json"):
        out["recordings"] += 1
        record = _json(path) or {}
        response = record.get("response") or {}
        if response.get("status") != "OK":
            for gap in response.get("gaps") or [{"kind": "GAP", "detail": "no gap recorded"}]:
                rows.append((f"{gap.get('kind')}: {gap.get('detail')}", f"{record.get('method')} "
                             f"{(record.get('params') or {}).get('path')}:{(record.get('params') or {}).get('line')}"))
    out["recorded_gaps"] = _group(rows)
    out["recoveries"] = len(list(lsp.glob("recoveries/*.json")))
    out["owners"] = dict(sorted(out["owners"].items()))
    return out


def diagnose(run: str, loaded: dict) -> dict:
    invocations = loaded["invocations"]
    errors, lsp_reasons = defaultdict(list), []
    shapes = defaultdict(lambda: {"calls": 0, "errors": 0, "causes": []})
    over_window = {"calls": 0, "errors": 0}
    failed_paths, resolved = [], 0
    for (job, attempt), row in sorted(invocations.items()):
        for request, outcome in row["calls"]:
            tool, example = request["tool"], _example(request)
            if outcome.get("_kind") == "error":
                errors[tool].append((outcome.get("error", ""), example))
            if tool in LSP_TOOLS:
                for item in [outcome.get("error")] if outcome.get("_kind") == "error" else \
                        list(outcome.get("reasons") or []) + list(outcome.get("gaps") or []):
                    if item:
                        lsp_reasons.append((item, example))
            if tool == "evidence_read":
                arguments = request.get("arguments") or {}
                shape = shapes[path_shape(arguments.get("path"))]
                shape["calls"] += 1
                failed = outcome.get("_kind") == "error"
                if isinstance(arguments.get("limit"), int) and arguments["limit"] > EVIDENCE_WINDOW:
                    over_window["calls"] += 1
                    over_window["errors"] += 1 if failed else 0
                resolved += 1 if outcome.get("notes") else 0   # input_mcp resolved the path form or clamped the limit
                if failed:
                    shape["errors"] += 1
                    shape["causes"].append((outcome.get("error", ""), example))
                    failed_paths.append(str(arguments.get("path", "")))
    backs, given = {}, set()
    for key, row in sorted(invocations.items()):
        back = backing(row)
        if back is not None:
            backs[key] = back
            given |= {norm(e["path"]) for e in (back["request"] or {}).get("readable_inputs") or []
                      if isinstance(e, dict) and isinstance(e.get("path"), str) and e.get("root") in TARGET_ROOTS}
    target = target_files(run, given)
    in_target = sum(1 for path in failed_paths if target is not None and norm(path) in target)
    evidence = {"shapes": {name: {"calls": v["calls"], "errors": v["errors"], "causes": _group(v["causes"])}
                           for name, v in sorted(shapes.items(), key=lambda kv: -kv[1]["errors"])},
                "limit_over_window": over_window, "failed_paths_naming_a_target_file": in_target,
                "answered_with_a_note": resolved,
                "failed_paths": len(failed_paths), "target_files_known": target is not None}
    jobs = defaultdict(lambda: {"classes": Counter(), "examples": [], "invocations": 0, "pinned_inputs_found": 0,
                                "input_modes": Counter(), "cited_ids": 0})
    for (job, _attempt), back in backs.items():
        row = invocations[(job, _attempt)]
        read_raw, surfaced_raw = _looked_raw(row["calls"])
        legacy_seen = {_legacy(r) for r in read_raw | surfaced_raw}
        seen = back["read"] | back["surfaced"]
        j = jobs[job]
        j["invocations"] += 1
        j["pinned_inputs_found"] += 1 if back["request"] is not None else 0
        j["input_modes"][row.get("input_mode") or "unknown"] += 1
        j["cited_ids"] += len(back["ids"])
        for raw in sorted(back["raw"]):
            path = norm(raw)
            if path in seen:
                if _legacy(raw) in legacy_seen:
                    continue
                kind = "normalization-mismatch"
            elif path in back["pinned"]:
                kind = "pinned-inline"
            elif target is None:
                kind = "unclassified (target file list unavailable)"
            elif path in target:
                kind = "present-in-target-but-not-read"
            else:
                kind = "not-in-target"
            j["classes"][kind] += 1
            if len(j["examples"]) < UNBACKED_SHOWN:
                j["examples"].append({"cited": text(raw, 120), "as": text(path, 120), "class": kind})
    citations_out = {job: {"invocations": j["invocations"], "pinned_inputs_found": j["pinned_inputs_found"],
                           "input_modes": dict(j["input_modes"]), "cited_ids": j["cited_ids"],
                           "classes": dict(j["classes"].most_common()), "examples": j["examples"]}
                     for job, j in sorted(jobs.items()) if j["classes"] or j["cited_ids"]}
    return {"errors": {tool: {"calls": sum(1 for r in invocations.values() for q, _ in r["calls"] if q["tool"] == tool),
                              "errors": len(rows), "causes": _group(rows)} for tool, rows in sorted(errors.items())},
            "evidence_read": evidence,
            "lsp": {"tool_reasons": _group(lsp_reasons), **_lsp_record(run)},
            "citations": citations_out, "target_files": None if target is None else len(target)}


def print_diagnose(run: str, d: dict) -> None:
    print(f"== {run}: diagnose (arguments, paths and server text are data, truncated)")
    print("-- tool errors by cause")
    if not d["errors"]:
        print("   no tool call failed")
    for tool, v in d["errors"].items():
        print(f"   {tool}: {v['errors']} of {v['calls']} call(s) failed")
        for group in v["causes"][:8]:
            print(f"     {group['count']:>4} x {group['cause']}")
            for example in group["examples"]:
                print(f"            e.g. {example}")
    e = d["evidence_read"]
    if e["shapes"]:
        print("-- evidence_read path shapes (calls, errors)")
        for name, v in e["shapes"].items():
            print(f"   {name:<46} calls {v['calls']:>4}  errors {v['errors']:>4}"
                  + (f"  top: {v['causes'][0]['cause']}" if v["causes"] else ""))
        print(f"   limit over the {EVIDENCE_WINDOW}-line window: {e['limit_over_window']['calls']} call(s), "
              f"{e['limit_over_window']['errors']} failed")
        print(f"   failed paths naming a file the target has: {e['failed_paths_naming_a_target_file']} of {e['failed_paths']}"
              + ("" if e["target_files_known"] else " (target file list unavailable)")
              + f"; answered after resolving the path form or clamping the limit: {e['answered_with_a_note']}")
    lsp = d["lsp"]
    print("-- language servers")
    x = lsp["xref"]
    if x is None:
        print("   no 02-lsp-xref summary in this run (gap: readiness and server specs unknown)")
    else:
        print(f"   02-lsp-xref attempt {x['attempt_id']} ({'accepted' if x['accepted'] else 'NOT the accepted attempt'}): "
              f"status {x['status']}, counts {json.dumps(x['counts'], sort_keys=True)}")
        print(f"   native build bound: {'yes' if x['native_build'] else 'no'}")
        for server in x["servers"] or [{}]:
            print("   server " + (f"{server.get('server_key')}/{server.get('variant')} {server.get('server')} image "
                                  f"{server.get('image_id')} digest {str(server.get('image_digest'))[:19]} build input "
                                  f"{json.dumps(server.get('build_input'), sort_keys=True)}" if server else "none ready"))
        for gap in x["gaps"]:
            print(f"   gap {gap['kind']}: {gap['detail']}")
    for failure in lsp["failures"]:
        print(f"   start failure {failure['lock']} x{failure['attempts']} ({failure['at']}): {failure['error']}")
    for owner, n in lsp["owners"].items():
        print(f"   lock owner {owner} x{n}")
    print(f"   recordings {lsp['recordings']}, lock recoveries {lsp['recoveries']}")
    for group in lsp["recorded_gaps"][:8]:
        print(f"     recorded GAP {group['count']:>4} x {group['cause']}" + (f"  e.g. {group['examples'][0]}" if group["examples"] else ""))
    for group in lsp["tool_reasons"][:8]:
        print(f"     tool answer {group['count']:>4} x {group['cause']}" + (f"  e.g. {group['examples'][0]}" if group["examples"] else ""))
    print("-- cited paths no tool fetched (per job, up to 10)")
    if not d["citations"]:
        print("   none (or no job output found)")
    for job, j in d["citations"].items():
        print(f"   {job}: {j['invocations']} invocation(s) with output, pinned inputs found for {j['pinned_inputs_found']}, "
              f"input mode {json.dumps(j['input_modes'], sort_keys=True)}; "
              + ", ".join(f"{k} {n}" for k, n in j["classes"].items())
              + (f"; cited by id {j['cited_ids']} (claim stages: not path-backed)" if j["cited_ids"] else ""))
        for example in j["examples"]:
            print(f"     [{example['class']}] {example['cited']!r}" + (f" -> {example['as']!r}" if example["as"] != example["cited"] else ""))


def main() -> int:
    argv = sys.argv[1:]
    value_of = {flag: argv[argv.index(flag) + 1] for flag in ("--job", "--compare") if flag in argv and argv.index(flag) + 1 < len(argv)}
    args = [a for i, a in enumerate(argv) if not a.startswith("--") and (i == 0 or argv[i - 1] not in ("--job", "--compare"))]
    if not args:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    run, only, as_json = args[0], value_of.get("--job"), "--json" in argv
    if not (RUNS / run).is_dir():
        print(f"no such run: {RUNS / run}", file=sys.stderr)
        return 2
    if "--diagnose" in argv:
        d = diagnose(run, load(run, only))
        if as_json:
            print(json.dumps({"run_id": run, "diagnose": d}, indent=2, sort_keys=True, default=sorted))
        else:
            print_diagnose(run, d)
        return 0
    if "--summary" in argv or "--feedback" in argv or "--check" in argv or "--compare" in argv:
        loaded = load(run, only)
        s = summarize(loaded)
        doc = {"run_id": run}
        if "--summary" in argv or "--compare" in argv:
            doc["summary"] = s
        if "--compare" in argv:
            other = value_of.get("--compare")
            if not other or not (RUNS / other).is_dir():
                print(f"no such run to compare: {other}", file=sys.stderr)
                return 2
            doc["compare"] = {"other_run_id": other, "deltas": compare(s, summarize(load(other, only)))}
        f = feedback(loaded) if "--feedback" in argv or "--check" in argv else {}
        if "--feedback" in argv:
            doc["feedback"] = f
        findings = check(s, f) if "--check" in argv else []
        if "--check" in argv:
            doc["check"] = [{"rule": r, "detail": d} for r, d in findings]
        if as_json:
            print(json.dumps(doc, indent=2, sort_keys=True, default=sorted))
        else:
            if "summary" in doc:
                print_summary(run, s)
            if "compare" in doc:
                print_compare(run, doc["compare"]["other_run_id"], doc["compare"]["deltas"])
            if "feedback" in doc:
                print_feedback(run, f)
            if "--check" in argv:
                print(f"== tooling check {run}: " + (f"{len(findings)} finding(s)" if findings else "no finding"))
                for rule, detail in findings:
                    print(f"   [{rule}] {detail}")
        return 1 if findings else 0

    loaded = load(run, only)
    groups = {k: r for k, r in loaded["invocations"].items() if r["calls"]}
    for (job, attempt), row in sorted(groups.items(), key=lambda kv: kv[1]["calls"][0][0].get("time", "")):
        calls = row["calls"]
        tools = Counter(c[0]["tool"] for c in calls)
        errors = sum(1 for _, o in calls if o.get("_kind") == "error")
        empty = sum(1 for _, o in calls if o.get("_kind") == "result" and o.get("hits") == 0)
        print(f"== {job}  attempt {attempt}  ({calls[0][0].get('time', '')[:19]} .. {calls[-1][0].get('time', '')[11:19]})")
        print(f"   calls {len(calls)}: " + ", ".join(f"{t} {n}" for t, n in tools.most_common()))
        print(f"   errors {errors}, empty lookups {empty}, bytes returned "
              f"{sum(o.get('bytes', 0) for _, o in calls)}, time {sum(o.get('duration_ms', 0) for _, o in calls)} ms")
        back = backing(row)
        read, surfaced = looked(calls)
        print(f"   files read {len(read)}, files surfaced by searches {len(surfaced)}")
        code = defaultdict(lambda: Counter())
        for request, outcome in calls:
            if request["tool"].startswith("code_") and outcome.get("_kind") == "result":
                c = code[request["tool"]]
                c["calls"] += 1
                c["incomplete"] += 0 if outcome.get("complete") else 1
                c["escapes"] += int(outcome.get("escapes") or 0)
                c["truncated"] += 1 if outcome.get("truncated") else 0
                c["rows"] += int(outcome.get("rows") or 0)
        for tool, c in sorted(code.items()):
            print(f"   {tool:<20} calls {c['calls']}, complete=false {c['incomplete']}, "
                  f"escapes {c['escapes']}, truncated {c['truncated']}, rows {c['rows']}")
        unused = sorted(t for t in set(row["granted"] or []) - set(tools) if t.startswith("code_"))
        if unused:
            print("   granted code tools never called: " + ", ".join(unused))
        if back is not None:
            cited = back["cited"]
            print(f"   cited paths {len(cited)}: backed by a read/search {len(back['tool_backed'])}"
                  + (f" ({100 * len(back['tool_backed']) // len(cited)}%)" if cited else "")
                  + f", pinned input never fetched {len(back['pinned_backed'])}"
                  + f"; read files that were cited {len(read & cited)}/{len(read)}")
            if back["unbacked"]:
                print("   cited without being looked at: " + ", ".join(back["unbacked"][:10])
                      + (" ..." if len(back["unbacked"]) > 10 else ""))
        elif job != "(unattributed)":
            print("   (output not found; citation backing unavailable)")
        if "--calls" in argv:
            for request, outcome in calls:
                arguments = json.dumps(request.get("arguments"))[:120]
                status = "ERROR " + outcome.get("error", "")[:60] if outcome.get("_kind") == "error" else f"{outcome.get('hits')} hits"
                print(f"     {request.get('time', '')[11:19]} {request['tool']:<18} {arguments}  -> {status}")
    inline = [f"{r.get('job')} ({r.get('value')} bytes, {r.get('inputs')} files)" for r in loaded["inline"]]
    if inline:
        print("== inline (inputs pasted into the prompt, no tools): " + "; ".join(inline))
    if not groups and not inline:
        print("no retrieval audits or input-mode observations yet")
    return 0


if __name__ == "__main__":
    sys.exit(main())
