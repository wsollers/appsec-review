from vendor_evidence_workers import build_documents, fingerprint, materialize_attempt, probe
JOB = "02-secrets-inventory"
def build(source_root, **identity): return build_documents(JOB, source_root, **identity)
