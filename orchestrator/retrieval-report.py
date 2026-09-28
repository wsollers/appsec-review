#!/usr/bin/env python3
"""How model jobs used their lookup tools in a run, and whether it paid off.

usage: orchestrator/retrieval-report.py <run_id> [--job JOB] [--calls]

Model jobs whose inputs are too large to inline have no filesystem access at all; everything they
see comes through input_mcp.py, which audits each call under runs/<run>/data/retrieval/. This
report groups those audits by job invocation and shows:

  calls by tool, errors, empty lookups (0 hits), bytes returned, time spent;
  files read (input_read / evidence_read) and files surfaced by searches;
  citation backing: of the target paths the job's output cites, how many it actually read or
  surfaced (a citation to a file never looked at is a red flag), and how much of what it read
  ended up cited.

--calls also prints each call (tool, arguments, hits). Inline-mode jobs (inputs pasted into the
prompt, no tools) are listed from size observations.
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

RUNS = Path(__file__).resolve().parent.parent / "appsec-review-process" / "runs"


def norm(ref: str) -> str:
    ref = str(ref)
    head, sep, rest = ref.partition(":")
    if sep and head in ("target", "target-repository", "upstream-artifacts"):
        ref = rest if head != "upstream-artifacts" else "upstream:" + rest
    if ref.startswith("source/"):
        ref = ref[len("source/"):]
    return ref


def citations(value, inside=False, found=None):
    """Target paths cited anywhere under a key containing 'citation' (or 'evidence')."""
    found = set() if found is None else found
    if isinstance(value, dict):
        for key, item in value.items():
            nested = inside or "citation" in key.lower() or key.lower() in ("evidence", "evidence_paths")
            if nested and key in ("path", "file", "source_path") and isinstance(item, str):
                found.add(norm(item))
            else:
                citations(item, nested, found)
    elif isinstance(value, list):
        for item in value:
            if inside and isinstance(item, str) and "/" in item or inside and isinstance(item, str) and "." in item:
                found.add(norm(item.split(":")[0] if item.count(":") == 1 and not item.startswith("target:") else item))
            else:
                citations(item, inside, found)
    return found


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    run = args[0]
    only = sys.argv[sys.argv.index("--job") + 1] if "--job" in sys.argv else None
    data = RUNS / run / "data"
    groups = defaultdict(list)
    for folder in sorted((data / "retrieval").glob("*")) if (data / "retrieval").is_dir() else []:
        try:
            request = json.loads((folder / "request.json").read_text())
        except (OSError, ValueError):
            continue
        outcome = {}
        for name in ("result.json", "error.json"):
            if (folder / name).is_file():
                outcome = json.loads((folder / name).read_text()); outcome["_kind"] = name[:-5]
        key = (request.get("job_id") or "(unattributed)", request.get("attempt_id") or "-")
        if only and key[0] != only:
            continue
        groups[key].append((request, outcome))

    for (job, attempt), calls in sorted(groups.items(), key=lambda kv: kv[1][0][0].get("time", "")):
        calls.sort(key=lambda c: c[0].get("time", ""))
        tools = Counter(c[0]["tool"] for c in calls)
        errors = sum(1 for _, o in calls if o.get("_kind") == "error")
        empty = sum(1 for _, o in calls if o.get("_kind") == "result" and o.get("hits") == 0)
        read, surfaced = set(), set()
        for request, outcome in calls:
            if outcome.get("_kind") != "result":
                continue
            refs = {norm(r) for r in outcome.get("refs", []) if r}
            if request["tool"] in ("input_read", "evidence_read"):
                read |= refs or {norm(request["arguments"].get("ref") or request["arguments"].get("path", ""))}
            else:
                surfaced |= refs
        print(f"== {job}  attempt {attempt}  ({calls[0][0].get('time', '')[:19]} .. {calls[-1][0].get('time', '')[11:19]})")
        print(f"   calls {len(calls)}: " + ", ".join(f"{t} {n}" for t, n in tools.most_common()))
        print(f"   errors {errors}, empty lookups {empty}, bytes returned "
              f"{sum(o.get('bytes', 0) for _, o in calls)}, time {sum(o.get('duration_ms', 0) for _, o in calls)} ms")
        print(f"   files read {len(read)}, files surfaced by searches {len(surfaced)}")
        root = calls[0][0].get("output_root")
        if root and Path(root).is_dir():
            cited = set()
            for path in Path(root).glob("*.json"):
                try:
                    cited |= citations(json.loads(path.read_text()))
                except (OSError, ValueError):
                    pass
            looked = read | surfaced
            backed = cited & looked
            print(f"   cited paths {len(cited)}: backed by a read/search {len(backed)}"
                  + (f" ({100 * len(backed) // len(cited)}%)" if cited else "")
                  + f"; read files that were cited {len(read & cited)}/{len(read)}")
            unbacked = sorted(cited - looked)
            if unbacked:
                print("   cited without being looked at: " + ", ".join(unbacked[:10]) + (" ..." if len(unbacked) > 10 else ""))
        elif job != "(unattributed)":
            print("   (output not found; citation backing unavailable)")
        if "--calls" in sys.argv:
            for request, outcome in calls:
                arguments = json.dumps(request.get("arguments"))[:120]
                status = "ERROR " + outcome.get("error", "")[:60] if outcome.get("_kind") == "error" else f"{outcome.get('hits')} hits"
                print(f"     {request.get('time', '')[11:19]} {request['tool']:<18} {arguments}  -> {status}")

    inline = []
    for path in sorted((data / "size-observations").glob("*.prompt_input_mode.json")) if (data / "size-observations").is_dir() else []:
        record = json.loads(path.read_text())
        if record.get("mode") == "inline" and (not only or record.get("job") == only):
            inline.append(f"{record.get('job')} ({record.get('value')} bytes, {record.get('inputs')} files)")
    if inline:
        print("== inline (inputs pasted into the prompt, no tools): " + "; ".join(inline))
    if not groups and not inline:
        print("no retrieval audits or input-mode observations yet")
    return 0


if __name__ == "__main__":
    sys.exit(main())
