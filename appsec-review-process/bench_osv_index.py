#!/usr/bin/env python3
"""Measure OSV lookup strategies over real ``<db>/osv-scanner/<eco>/all.zip`` (or ``<db>/<eco>/all.zip``)
archives: naive scan of the zips vs an in-memory dict vs the SQLite/FTS5 index from ``osv_index``.

    python bench_osv_index.py --db DIR [--out results.json]

Each strategy runs in its own subprocess so peak RSS is attributable. Output is JSON (one object).
Decision rule from the brief: BUILD the index if a raw-zip package or symbol lookup is slower than
~1 s, or the index builds in < 2 min and < 2 GB. Nothing here touches the network.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import random
import resource
import statistics
import subprocess
import sys
import tempfile
import time
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import osv_index

ECOSYSTEMS = ("npm", "Go", "Maven", "crates.io", "NuGet", "Packagist", "PyPI")


def archives(db):
    db = Path(db)
    out = {}
    for eco in ECOSYSTEMS:
        for candidate in (db / "osv-scanner" / eco / "all.zip", db / eco / "all.zip"):
            if candidate.is_file():
                out[eco] = candidate
                break
    if not out:
        raise SystemExit("no archives found")
    return out


def rss_mb():
    with open("/proc/self/status") as status:
        for line in status:
            if line.startswith("VmRSS"):
                return int(line.split()[1]) / 1024
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def timed(function, repeat=1):
    samples = []
    result = None
    for _ in range(repeat):
        start = time.perf_counter()
        result = function()
        samples.append((time.perf_counter() - start) * 1000)
    return {"median_ms": round(statistics.median(samples), 3), "max_ms": round(max(samples), 3),
            "samples": len(samples)}, result


def sample_keys(paths, seed=7):
    """Pick lookup keys that exist: ids, aliases, packages, symbols. Uses the extractor, so costs one pass."""
    rng = random.Random(seed)
    ids, aliases, packages, symbols = [], [], [], []
    for eco, path in paths.items():
        for row in osv_index.iter_archive(path, eco):
            ids.append(row["id"])
            aliases.extend(row["aliases"])
            for item in row["affected"]:
                packages.append((item["ecosystem"], item["name"]))
                symbols.extend(s for _, s, _ in item["symbols"])
    pick = lambda values, n: rng.sample(values, min(n, len(values)))
    return {"ids": pick(ids, 50), "aliases": pick(aliases, 50), "packages": pick(packages, 50),
            "symbols": pick(symbols, 50), "total_advisories": len(ids)}


def phase_naive(paths, keys):
    """Raw zips, no index. By id = open the member named <id>.json; every other lookup = scan all members."""
    def scan(match):
        hits = []
        for eco, path in paths.items():
            with zipfile.ZipFile(path) as archive:
                for name in archive.namelist():
                    record = json.loads(archive.read(name).decode("utf-8-sig"))
                    if match(record):
                        hits.append(record["id"])
        return hits
    result = {}
    def by_id():
        found = 0
        for identifier in keys["ids"][:10]:
            for eco, path in paths.items():
                with zipfile.ZipFile(path) as archive:
                    try:
                        archive.read(identifier + ".json"); found += 1; break
                    except KeyError:
                        pass
        return found
    result["by_id_x10"], _ = timed(by_id)
    alias = keys["aliases"][0]
    result["by_alias_full_scan"], _ = timed(lambda: scan(lambda r: alias in (r.get("aliases") or [])))
    eco, name = keys["packages"][0]
    result["by_package_full_scan"], _ = timed(lambda: scan(lambda r: any(
        (a.get("package") or {}).get("name") == name for a in r.get("affected") or [])))
    symbol = keys["symbols"][0] if keys["symbols"] else "NoSuchSymbol"
    result["by_symbol_full_scan"], _ = timed(lambda: scan(lambda r: any(
        symbol in json.dumps(a.get("ecosystem_specific") or {}) for a in r.get("affected") or [])))
    return result


def phase_dict(paths, keys):
    start = time.perf_counter()
    before = rss_mb()
    by_id, by_alias, by_package, by_symbol = {}, {}, {}, {}
    for eco, path in paths.items():
        for row in osv_index.iter_archive(path, eco):
            by_id[row["id"]] = row
            for alias in row["aliases"]:
                by_alias.setdefault(alias, []).append(row["id"])
            for item in row["affected"]:
                by_package.setdefault((item["ecosystem"], item["name_norm"]), []).append(row["id"])
                for _, symbol, _ in item["symbols"]:
                    by_symbol.setdefault(symbol, []).append(row["id"])
    build_s = time.perf_counter() - start
    result = {"build_seconds": round(build_s, 2), "rss_mb_after_build": round(rss_mb(), 1),
              "rss_mb_growth": round(rss_mb() - before, 1)}
    result["by_id"], _ = timed(lambda: [by_id.get(k) for k in keys["ids"]], 20)
    result["by_alias"], _ = timed(lambda: [by_alias.get(k) for k in keys["aliases"]], 20)
    result["by_package"], _ = timed(lambda: [by_package.get((e, osv_index.normalise_name(e, n))) for e, n in keys["packages"]], 20)
    result["by_symbol"], _ = timed(lambda: [by_symbol.get(k) for k in keys["symbols"]], 20)
    result["note"] = "50 keys per timed sample; per-lookup latency = median_ms / 50"
    return result


def phase_sqlite(paths, keys):
    directory = tempfile.mkdtemp(prefix="osv-bench-")
    target = Path(directory) / osv_index.INDEX_NAME
    start = time.perf_counter()
    counts = osv_index.build(paths, target)
    build_s = time.perf_counter() - start
    connection = osv_index.connect(target)
    result = {"build_seconds": round(build_s, 2), "size_mb": round(target.stat().st_size / 1024 ** 2, 1),
              "peak_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1), "counts": counts}
    result["by_id"], _ = timed(lambda: [osv_index.by_id(connection, k) for k in keys["ids"]], 5)
    result["by_alias"], _ = timed(lambda: [osv_index.by_alias(connection, k) for k in keys["aliases"]], 5)
    result["by_package"], _ = timed(lambda: [osv_index.by_package(connection, e, n) for e, n in keys["packages"]], 5)
    result["by_package_with_version"], _ = timed(lambda: [osv_index.by_package(connection, e, n, "1.0.0") for e, n in keys["packages"]], 5)
    if keys["symbols"]:
        result["by_symbol"], _ = timed(lambda: [osv_index.by_symbol(connection, k) for k in keys["symbols"]], 5)
    result["fts_text_query"], _ = timed(lambda: connection.execute(
        "SELECT osv_id FROM advisory_fts WHERE advisory_fts MATCH 'deserialization' LIMIT 50").fetchall(), 5)
    result["note"] = "50 keys per timed sample; per-lookup latency = median_ms / 50"
    Path(target).unlink()
    Path(directory).rmdir()
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--phase", choices=("naive", "dict", "sqlite"), help="internal: run one phase and print JSON")
    parser.add_argument("--keys", type=Path, help="internal")
    args = parser.parse_args(argv)
    paths = archives(args.db)
    if args.phase:
        keys = json.loads(args.keys.read_text())
        print(json.dumps({"naive": phase_naive, "dict": phase_dict, "sqlite": phase_sqlite}[args.phase](paths, keys)))
        return 0
    started = time.perf_counter()
    keys = sample_keys(paths)
    report = {"archives": {e: {"bytes": p.stat().st_size} for e, p in paths.items()},
              "total_advisories": keys["total_advisories"], "keys_sampled": {k: len(v) for k, v in keys.items() if k != "total_advisories"},
              "key_sampling_seconds": round(time.perf_counter() - started, 1)}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(keys, handle)
    for phase in ("sqlite", "dict", "naive"):
        completed = subprocess.run([sys.executable, __file__, "--db", args.db, "--phase", phase, "--keys", handle.name],
                                   capture_output=True, text=True)
        report[phase] = json.loads(completed.stdout) if completed.returncode == 0 else {"error": completed.stderr[-500:]}
        if args.out:
            args.out.write_text(json.dumps(report, indent=2))
    os.unlink(handle.name)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
