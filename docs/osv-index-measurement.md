# OSV index measurement

Decision (brief A, step 5): **BUILD the index.** A raw-zip package or symbol lookup takes about
6 s (the brief's threshold is ~1 s), and the SQLite index builds in about 12 s and 195 MB (thresholds
2 min and 2 GB). Both criteria point the same way.

## Method

`appsec-review-process/bench_osv_index.py --db <dir>` runs each strategy in its own subprocess so
peak memory is attributable. Lookup keys are sampled from the data itself (50 each of ids, aliases,
packages, symbols; seeded), so every lookup is a hit. Timed samples are 50 lookups per sample, so
per-lookup latency is the figure divided by 50.

Data: the real OSV bulk archives for all seven ecosystems, fetched 2026-09-29 from
`storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip`. Host: 2 vCPU, 3 GB RAM Linux VM,
warm page cache, Python 3.12, SQLite 3.53.1 (FTS5 present).

| Ecosystem | all.zip size |
|---|---|
| npm | 216.7 MB |
| PyPI | 34.7 MB |
| Go | 11.9 MB |
| Packagist | 10.9 MB |
| Maven | 10.3 MB |
| crates.io | 3.5 MB |
| NuGet | 2.5 MB |

283,781 advisory records parsed; 283,404 distinct ids (377 appear under more than one ecosystem).
234,595 of them are `MAL-` (OpenSSF malicious packages, almost all npm), 35,076 `GHSA-`.

## Results

| Strategy | Build | Size / memory | by id | by alias | by package | by symbol |
|---|---|---|---|---|---|---|
| Raw zips, no index | none | none | 5.6 s per 10 ids (opens every zip's directory per id) | 6.1 s | 6.2 s | 6.4 s |
| In-memory dict | 9.3 s | +910 MB resident | < 0.01 ms | < 0.01 ms | < 0.01 ms | < 0.01 ms |
| SQLite + FTS5 | 12.2 s | 195 MB file, 208 MB peak RSS | 0.010 ms | 0.032 ms | 0.68 ms (1.0 ms with `--version`) | 0.18 ms |

(SQLite per-lookup figures: median of 5 samples of 50 keys. FTS text query: under 1 ms.)
Index content: 283,404 advisories, 111,657 aliases, 315,197 affected entries, 10,910 symbol rows.

## Reading the numbers

- The dict is fastest but costs about 0.9 GB of RAM in every process that wants it and must be rebuilt
  on start (about 9 s). A file index is opened in milliseconds and shared by every reader, so SQLite
  is the choice; the extra sub-millisecond per lookup is irrelevant.
- The naive by-id figure is dominated by opening the 229k-entry npm archive directory repeatedly,
  not by reading records; a single-archive by-id is cheaper, but a caller does not know which
  archive holds an id.
- **Symbol coverage is thin.** Only Go advisories carry symbols in practice (`ecosystem_specific.imports[].symbols`
  on about 1,150 of 9,392 Go records, plus a handful of `ecosystem_specific.symbols`). RustSec's
  `affected_functions` key exists on 1,254 crates.io affected entries but is `null` in every one in this
  data. No other ecosystem populates symbols. Wave 3 dependency reachability therefore gets symbols for
  Go only; an empty symbol result is never evidence that a package is safe.

## Reproduce

```
python appsec-review-process/bench_osv_index.py --db <dir holding <ecosystem>/all.zip> --out result.json
```

Numbers will vary with hardware and cache state; rerun on the target host before relying on them.
