"""02-operations-doc-ingest item worker (ADR-0024 proof port).

Runs under job_executor's PROCESS phase: reads the redacted, schema-checked input document and writes
the same three artifacts the legacy lifecycle wrote, through the same extractor, plus the
worker-result.json the executor validates. Target content is untrusted data; nothing here executes it.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from execution_state import atomic_json, read_json  # noqa: E402
import static_intelligence_core as core  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('--job', '--run-id', '--attempt-id', '--input', '--output'):
        parser.add_argument(name, required=True)
    args = parser.parse_args(argv)
    job, out = args.job, Path(args.output)
    _contract, result_name, _schema = core.SPECS[job]
    need = read_json(args.input)['needs']['source']
    result = core.extract(job, run_id=args.run_id, attempt_id=args.attempt_id,
                          target=Path(need['target_path']), source=need['source'],
                          source_files=need['source_files'])
    atomic_json(out / result_name, result)
    source_hash = 'sha256:' + need['source']['source_fingerprint']
    atomic_json(out / 'permission.json', {'schema': core.PERMISSION_SCHEMA, 'run_id': args.run_id,
                                          'job_id': job, 'source_snapshot_sha256': source_hash,
                                          'permissions': core._permissions(job)})
    atomic_json(out / 'lineage.json', {'schema': core.LINEAGE_SCHEMA, 'run_id': args.run_id, 'job_id': job,
                                       'source_snapshot_sha256': source_hash, 'build_lineage_sha256': None})
    atomic_json(out / 'worker-result.json', {
        'execution_status': result['status'], 'gaps': result['coverage_gaps'],
        'summary': f"Published {len(result['records'])} redacted static intelligence record(s).",
        'artifacts': [result_name, 'permission.json', 'lineage.json'],
        'status': {'process': job, 'sources': len(result['sources']), 'records': len(result['records']),
                   'static_only': True, 'qualification': 'implemented_not_qualified'}})
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
