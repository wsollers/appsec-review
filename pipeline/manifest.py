#!/usr/bin/env python3
"""manifest.py <scratch> <project> <target> — write pregather-manifest.json (shared by pregather.sh/.ps1)."""
import json, sys, subprocess, os, glob
scr, proj, target = sys.argv[1:]
def digest(img):
    try: return subprocess.run(["docker","image","inspect",img,"--format","{{.Id}}"],capture_output=True,text=True).stdout.strip() or None
    except Exception: return None
m = {"project": proj, "target": os.path.realpath(target), "scratch": os.path.realpath(scr),
     "images": {i: digest(i) for i in ("audit-native:local","audit-codeql-native:local")},
     "artifacts": sorted(os.path.relpath(p, scr) for p in glob.glob(scr+"/*.json")+glob.glob(scr+"/linked/*.bc")+glob.glob(scr+"/codeql/*.sarif")+glob.glob(scr+"/csa/*.json"))}
feas = json.load(open(scr+"/feasibility.json")); m["tier"] = feas["tier_recommendation"]; m["tu_pass_rate"] = feas["pass_rate"]
json.dump(m, open(scr+"/pregather-manifest.json","w"), indent=1); print(json.dumps({k:m[k] for k in ("project","tier","tu_pass_rate")}))
