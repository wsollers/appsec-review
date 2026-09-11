#!/usr/bin/env python3
"""
Looks up OSSF Scorecard scores for a list of dependencies via the public
api.scorecard.dev REST API (no auth/rate-limit burden - confirmed live with
a direct curl test: https://api.scorecard.dev/projects/github.com/ossf/scorecard).

Scorecard only scores projects it has actually analyzed, and only for repos
it can identify (github.com/<owner>/<repo> form) - so this is necessarily
partial coverage: private/internal deps, non-GitHub-hosted deps (GitLab,
self-hosted), and small/unindexed GitHub projects will show as "not found",
which is itself a signal worth recording (Scorecard has never looked at it),
not a scoring failure.

Input: a newline-delimited list of "owner/repo" GitHub slugs. This
deliberately does NOT try to auto-derive slugs from a raw SBOM (syft/CycloneDX
purls are frequently registry names - npm package names, Maven groupId:artifactId
- that don't map 1:1 to a GitHub owner/repo without a lookup step of their own,
which would be its own separate, fallible piece of tooling). Build the input
list from the SBOM by hand or with a short separate script once you've seen
what build_layered_sbom.py actually produced for this repo - dependencies with
an obvious GitHub source are usually a small, high-value subset worth checking,
not the whole dependency tree.

Usage:
    python3 check_ossf_scorecard.py --input deps.txt --out /evidence/ossf/scorecard.json
    # deps.txt: one "owner/repo" per line, '#' comments and blank lines ignored

Output: JSON array, one object per dependency, with the full Scorecard
response (if found) plus a synthesized "flag" field: "low" if overall score
< 5, "not-found" if Scorecard has no record, "ok" otherwise. A companion
.txt summary lists only the low/not-found ones for quick review.
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request

API_BASE = "https://api.scorecard.dev/projects/github.com"
LOW_SCORE_THRESHOLD = 5.0


def fetch_scorecard(owner_repo: str, timeout: float = 15.0) -> dict:
    url = f"{API_BASE}/{owner_repo}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"status": "ok", "data": json.loads(resp.read().decode("utf-8"))}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "not-found", "data": None}
        return {"status": "error", "data": None, "error": f"HTTP {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"status": "error", "data": None, "error": str(e.reason)}
    except Exception as e:  # noqa: BLE001 - this is a best-effort evidence-gathering script
        return {"status": "error", "data": None, "error": str(e)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True, help="Path to newline-delimited owner/repo list")
    ap.add_argument("--out", required=True, help="Path to write the full JSON results")
    ap.add_argument("--summary-out", default=None, help="Path to write a plain-text low/not-found summary (default: <out> with .txt)")
    ap.add_argument("--delay", type=float, default=0.3, help="Seconds to sleep between requests, be polite to the public API (default 0.3)")
    args = ap.parse_args()

    summary_out = args.summary_out or (args.out.rsplit(".", 1)[0] + ".summary.txt")

    with open(args.input, "r", encoding="utf-8") as f:
        slugs = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]

    if not slugs:
        print(f"No owner/repo entries found in {args.input} - nothing to check.", file=sys.stderr)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)
        with open(summary_out, "w", encoding="utf-8") as f:
            f.write("No dependencies were checked (empty input list).\n")
        return 0

    results = []
    for i, slug in enumerate(slugs, 1):
        print(f"[{i}/{len(slugs)}] {slug} ...", file=sys.stderr)
        result = fetch_scorecard(slug)
        overall_score = None
        if result["status"] == "ok" and result["data"] is not None:
            overall_score = result["data"].get("score")

        if result["status"] == "not-found":
            flag = "not-found"
        elif result["status"] == "error":
            flag = "error"
        elif overall_score is not None and overall_score < LOW_SCORE_THRESHOLD:
            flag = "low"
        else:
            flag = "ok"

        results.append({
            "dependency": slug,
            "status": result["status"],
            "overall_score": overall_score,
            "flag": flag,
            "error": result.get("error"),
            "scorecard": result["data"],
        })
        if i < len(slugs):
            time.sleep(args.delay)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    flagged = [r for r in results if r["flag"] in ("low", "not-found", "error")]
    with open(summary_out, "w", encoding="utf-8") as f:
        f.write(f"OSSF Scorecard check: {len(results)} dependencies checked, {len(flagged)} flagged.\n\n")
        for r in sorted(flagged, key=lambda x: (x["flag"], x["dependency"])):
            if r["flag"] == "low":
                f.write(f"[LOW SCORE {r['overall_score']}]  {r['dependency']}\n")
            elif r["flag"] == "not-found":
                f.write(f"[NOT FOUND]     {r['dependency']}  (Scorecard has never analyzed this repo)\n")
            else:
                f.write(f"[ERROR]         {r['dependency']}  ({r['error']})\n")
        if not flagged:
            f.write("Nothing flagged - all checked dependencies scored >= "
                     f"{LOW_SCORE_THRESHOLD} or otherwise came back clean.\n")

    print(f"Wrote {args.out} and {summary_out}", file=sys.stderr)
    print(f"{len(flagged)} of {len(results)} flagged (low score / not found / error).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
