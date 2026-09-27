# Offline dependency vulnerability live qualification — 2026-09-27

Run `offline-vuln-live-20260927f` completed the standalone accepted path:

`Syft SBOM -> offline Grype + offline OSV -> normalized SCA -> CVE reachability evidence`

The retained run is under
`.artifacts/dependency-live-qualification/runs/offline-vuln-live-20260927f/`. Its qualification
summary is `qualification/dependency-offline-live.json`
(`sha256:af6a3ebf66e7fb99e0a1ae9293e781177757768a2f4094cacde2523c133215ab`).

## Accepted generations

| Job | Attempt | Output SHA-256 |
|---|---|---|
| `02-sbom-inventory` | `02-sbom-inventory-4b14f82e5e28d25e8897` | `sha256:f1afaff0c3443480cc9c687b18ae6f36cbdf6513de1bd6446f21dcc55878ff4f` |
| `02-sca-vulnerability-match` | `02-sca-vulnerability-match-067a4a3ad125d3e67ad8` | `sha256:defdb59403bd512ec997dbdfb84d1d2c140fe77981bd7b9bc741637d5dd63009` |
| `06-cve-reachability` | `06-cve-reachability-a55e92f84d7487ecaf8c` | `sha256:dd2f62538f89d2f30d8da786810e793ee9662450116f6f7fc856d23e634678e0` |

The run inventoried two npm components and emitted three vulnerability matches for the deliberately
old `lodash` 4.17.20 qualification dependency: `CVE-2020-28500`, `CVE-2021-23337`, and
`CVE-2025-13465`. All three reachability classifications are `unknown`, with explicit coverage
gaps, because this run supplies no call, import, build, or configuration proof. The output claim
ceiling is `EVIDENCE_LEADS_ONLY`.

## Offline database identities

| Database | Snapshot | Tree SHA-256 | Data timestamp |
|---|---|---|---|
| Grype DB | `grype-v6.1.9-20260927-imported` | `sha256:50e9b83a8f462dfeadd5503dd3961efa66328f2d32b51c29db6cd6d329a547f9` | `2026-09-27T06:30:30Z` |
| OSV npm | `osv-npm-20260926` | `sha256:ffca0474b179e57d8c8251efd3bef4fc052b2ec47bee44783bbce6d8e4a52070` | `2026-09-26T15:36:17Z` |

Both scanner containers ran with network mode `none`. Grype's raw output hash is
`sha256:50f52d7cf52365fdced794b53673b7d3fe1b269f2fa9495d9b2d11e1b1129f81`; OSV's raw output hash
is `sha256:2a4a6edc37618d7f19e782fdf244be39a62c61f86f40aeeab4e2afcc28b9bd08`.
OSV Scanner 1.9.2 uses exit code 1 to report a successful scan with vulnerabilities. B13 retains
that nonzero container result, while the dependency adapter recognizes only that exact documented
finding exit as usable tool evidence. Other nonzero exits remain failures.

## Boundaries and residuals

- The OSV snapshot contains the npm ecosystem used by this bounded live qualification. Other
  ecosystems must be seeded before an engagement SBOM containing them can complete offline OSV
  matching.
- The registered Grype cache is the result of importing the verified official archive through the
  pinned Grype image. A flat `vulnerability.db` extraction is not executable: Grype also requires
  its cache layout and `import.json`.
- This qualifies the accepted standalone jobs. Automatic `full_review` request assembly remains a
  separate orchestration task.
