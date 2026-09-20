# Immutable OWASP and OpenCRE reference snapshots

This directory contains repository-pinned reference input for the OWASP control workbench. It is
not engagement evidence and does not establish target behavior, control satisfaction, a finding,
severity, exploitability, or certification.

The source lock pins the upstream repository, immutable ref, resolved commit, license source, raw
input selection, and extractor type. Each content-addressed snapshot contains:

- `manifest.json` with source identity, hashes, lineage, counts, and validation status;
- `LICENSE-or-usage.txt` copied from the pinned upstream source;
- `raw/` with the exact control, test, context, mapping, or export inputs;
- `normalized/catalog.json` with small assignable records.

The initial set is:

| Family | Edition | Snapshot | Records |
|---|---|---|---:|
| OWASP ASVS | 5.0.0 | `sha256-e48ca4caa6619973` | 345 controls |
| OWASP MASVS | 2.1.0 | `sha256-8fcf29b29ab85c0c` | 24 controls |
| OWASP MASTG | 2.0.0 | `sha256-b30f8847db095ea3` | 292 stable/beta tests |
| OWASP Top 10 | 2025 | `sha256-6c64c51786992d37` | 10 context categories |
| OWASP API Security Top 10 | 2023 | `sha256-34ea423fcbab6e26` | 10 context categories |
| OWASP GenAI LLM Top 10 | 2026 | `sha256-38a33b394c16ed6d` | 10 context categories |
| OpenCRE | dated 2026-09-19 export | `sha256-42bf4175932a5a36` | 522 crosswalk rows |

Top 10 records are routing context only. OpenCRE records are navigation and deduplication metadata
only. ASVS/MASVS proof obligations intentionally retain
`unclassified_requires_policy` evidence classification until the remaining G02 evidence-mode policy
is approved; the snapshot extractor does not invent static or dynamic sufficiency rules.

Verify every committed snapshot offline:

```powershell
python -B appsec-review-process/reference_snapshots.py verify
```

Materialization requires explicit local Git checkouts at the commits in `source-lock.json`. The
tool rejects a mismatched HEAD or modified tracked input. OpenCRE additionally requires the dated
CSV created by the pinned official exporter; review jobs never call its live API.

A changed source or extractor identity creates a sibling snapshot. Existing snapshot directories
must not be edited in place. Engagement selection records copy and pin the exact manifest and its
hash into run-owned data before any applicability or validation work begins.
