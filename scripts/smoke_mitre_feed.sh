#!/usr/bin/env bash
# Smoke test: MITRE ATT&CK / CAPEC / CWE reference feed (ADR-0026, brief O1b, docs/mitre-feed.md). Run in WSL/Linux
# from the repo root:
#     bash scripts/smoke_mitre_feed.sh [feed-root]        # default data/feeds/mitre
# Steps: sync (the ONLY step that uses the network: two release-pinned files from raw.githubusercontent.com and
# cwec_v4.19.xml.zip from cwe.mitre.org), verify, resolve, one known technique validates, an invented id (T9999)
# is UNKNOWN_ID, a real CWE id outside the committed curated subset (CWE-1004) validates against the snapshot,
# CWE-99999 is rejected, and a copy of the snapshot aged past the ceiling reports MITRE_REFERENCE_STALE (tags
# withheld) and CWE_REFERENCE_STALE (curated fallback).
# SKIP_SYNC=1 skips the network step and smokes the snapshot already published. Expect "SMOKE OK".
set -euo pipefail
ROOT="${1:-data/feeds/mitre}"
PY="${PYTHON:-python3}"
FEED=appsec-review-process/mitre_feed.py
REF=appsec-review-process/attack_reference.py

if [ "${SKIP_SYNC:-0}" != "1" ]; then
  echo "== sync (network)"
  "$PY" "$FEED" sync --root "$ROOT"
fi
echo "== verify"
"$PY" "$FEED" verify --root "$ROOT"
echo "== resolve"
"$PY" "$FEED" resolve --root "$ROOT"

echo "== known technique T1190 (initial-access) validates"
"$PY" "$REF" --root "$ROOT" technique T1190 --tactic initial-access | tee /dev/stderr | grep -q '"status": "OK"'
echo "== known CAPEC-66 validates"
"$PY" "$REF" --root "$ROOT" capec CAPEC-66 | grep -q '"status": "OK"'
echo "== invented T9999 is UNKNOWN_ID"
set +e; OUT="$("$PY" "$REF" --root "$ROOT" technique T9999)"; CODE=$?; set -e
echo "$OUT"
[ "$CODE" -eq 1 ] && echo "$OUT" | grep -q '"status": "UNKNOWN_ID"' || { echo "SMOKE FAILED: T9999 was not UNKNOWN_ID" >&2; exit 1; }

echo "== CWE: full catalog from the snapshot (CWE-1004 is outside the curated subset); CWE-99999 rejected"
"$PY" - "$ROOT" <<'PY'
import json, pathlib, sys
sys.path.insert(0, "appsec-review-process")
import cwe_catalog
root = pathlib.Path(sys.argv[1])
catalog = cwe_catalog.Catalog(feed_root=root)
assert catalog.gap is None, catalog.gap
assert catalog.validate("CWE-1004") == "CWE-1004", "CWE-1004 did not validate"
try:
    catalog.validate("CWE-99999")
    raise SystemExit("SMOKE FAILED: CWE-99999 validated")
except cwe_catalog.CWEError:
    pass
manifest = json.loads((root / "snapshots" / catalog.source / "manifest.json").read_text())
entry = manifest["sources"]["cwe"]
print(f"CWE catalog in force: {catalog.version} from snapshot {catalog.source} ({len(catalog.names)} weaknesses)")
print(f"CWE zip sha256 (pin this in mitre_feed.SOURCES['cwe']): {entry['sha256']}")
PY

echo "== a snapshot older than the ceiling is stale and withholds tags"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
cp -a "$ROOT/." "$WORK/"
# The fake is a copy aged by moving 'now' past the ceiling (the published bytes stay untouched).
LATER="$("$PY" - "$WORK" <<'PY'
import json, sys, pathlib
from datetime import datetime, timedelta, timezone
sys.path.insert(0, "appsec-review-process")
import mitre_feed
root = pathlib.Path(sys.argv[1])
manifest = json.loads((root / "snapshots" / json.loads((root / "current.json").read_text())["snapshot_id"] / "manifest.json").read_text())
oldest = min(mitre_feed.parse_time(e["fetched_at"]) for e in manifest["sources"].values()
             if e["status"] != "FAILED" and e["kind"] in mitre_feed.REFERENCE_KINDS)
print(mitre_feed.timestamp(oldest + timedelta(seconds=mitre_feed.default_max_age_seconds() + 1)))
PY
)"
set +e; OUT="$("$PY" "$FEED" resolve --root "$WORK" --now "$LATER")"; CODE=$?; set -e
echo "$OUT"
[ "$CODE" -eq 3 ] && echo "$OUT" | grep -q MITRE_REFERENCE_STALE || { echo "SMOKE FAILED: over-age snapshot not reported stale" >&2; exit 1; }
"$PY" - "$WORK" "$LATER" <<'PY'
import sys
sys.path.insert(0, "appsec-review-process")
import attack_reference, mitre_feed
result = attack_reference.screen(["T1190"], ["CAPEC-66"], root=sys.argv[1], now=mitre_feed.parse_time(sys.argv[2]))
assert result["attack_refs"] == [] and result["capec_refs"] == [], result
assert result["gaps"][0]["code"] == "MITRE_REFERENCE_STALE", result
print("stale snapshot withholds:", result["gaps"][0]["withheld"])
PY
"$PY" - "$WORK" <<'PY'
import json, pathlib, sys
from datetime import timedelta
sys.path.insert(0, "appsec-review-process")
import cwe_catalog, mitre_feed
root = pathlib.Path(sys.argv[1])
manifest = json.loads((root / "snapshots" / json.loads((root / "current.json").read_text())["snapshot_id"] / "manifest.json").read_text())
fetched = mitre_feed.parse_time(manifest["sources"]["cwe"]["fetched_at"])
catalog = cwe_catalog.Catalog(feed_root=root, now=fetched + timedelta(seconds=mitre_feed.default_max_age_seconds() + 1))
assert catalog.gap and catalog.gap["code"] == "CWE_REFERENCE_STALE", catalog.gap
assert catalog.source == "committed-curated", catalog.source
print("stale CWE snapshot falls back:", catalog.gap_line())
PY
echo "SMOKE OK"
