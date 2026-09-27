from vendor_evidence_workers import execute_and_build, fingerprint, materialize_attempt, probe
JOB = "02-binary-hardening"
def build(source_root, *, execution_root, now, **identity): return execute_and_build(JOB, source_root, execution_root=execution_root, now=now, **identity)
