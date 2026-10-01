#!/usr/bin/env bash
# Smoke test: OSV-Scanner (pinned image) scans a tiny SBOM fully OFFLINE against a published OSV feed snapshot.
# Run in WSL/Linux with Docker, after `python appsec-review-process/osv_feed.py sync` has published a snapshot:
#     bash scripts/smoke_osv_feed.sh [feed-root]      # default data/feeds/osv
# Expect: exit 0, "SMOKE OK", and at least one advisory for lodash 4.17.15 (npm) and django 2.2.0 (PyPI).
# The container has --network none and a read-only root; the snapshot is mounted read-only.
set -euo pipefail
ROOT="${1:-data/feeds/osv}"
IMAGE="${OSV_SCANNER_IMAGE:-tool-osv-scanner:local}"
python3 appsec-review-process/osv_feed.py verify --root "$ROOT"
SNAP="$(python3 - "$ROOT" <<'PY'
import json, sys, pathlib
root = pathlib.Path(sys.argv[1])
print(root / "snapshots" / json.loads((root / "current.json").read_text())["snapshot_id"])
PY
)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
cat > "$WORK/sbom.cdx.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[
 {"type":"library","name":"lodash","version":"4.17.15","purl":"pkg:npm/lodash@4.17.15"},
 {"type":"library","name":"django","version":"2.2.0","purl":"pkg:pypi/django@2.2.0"}]}
JSON
chmod 755 "$WORK"; chmod 644 "$WORK/sbom.cdx.json"
set +e
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m -e XDG_CACHE_HOME=/inputs/osv-db \
  -v "$WORK:/inputs/sbom:ro" -v "$PWD/$SNAP/db:/inputs/osv-db:ro" -v "$WORK:/scratch:rw" \
  --entrypoint /opt/tool/bin/osv-scanner "$IMAGE" \
  scan --experimental-offline-vulnerabilities --format json --output /scratch/osv.json --sbom /inputs/sbom/sbom.cdx.json
CODE=$?
set -e
# 0 = clean, 1 = findings (expected here). 127 = a local ecosystem database is missing (a recorded gap): fail the smoke.
if [ "$CODE" -ne 0 ] && [ "$CODE" -ne 1 ]; then echo "SMOKE FAILED: osv-scanner exit $CODE" >&2; exit 1; fi
python3 - "$WORK/osv.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
names = {p["package"]["name"] for r in data.get("results", []) for p in r.get("packages", []) if p.get("vulnerabilities")}
missing = {"lodash", "django"} - names
if missing:
    sys.exit(f"SMOKE FAILED: no advisories reported for {sorted(missing)}")
print("SMOKE OK:", sorted(names))
PY
