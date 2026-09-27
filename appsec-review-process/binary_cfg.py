"""02-binary-cfg nominal worker binding."""
import binary_evidence_core as core
JOB = "02-binary-cfg"
RESULT = core.SPECS[JOB][1]
def root(run_id): return core.root(run_id, JOB)
def run(run_id, dagster_id, force=False): return core.run(run_id, dagster_id, JOB, force)
def validate(run_id, pointer=None): return core.validate(run_id, JOB, pointer)
