"""02-native-build public worker binding."""
import build_replay

JOB = "02-native-build"
DAGSTER_JOB = "native_build"
RESULT = build_replay.SPECS[JOB]["result"]

def root(run_id): return build_replay.root(run_id, JOB)
def run(run_id, dagster_id, force=False): return build_replay.run(run_id, dagster_id, JOB, force)
def validate(run_id, pointer=None): return build_replay.validate(run_id, JOB, pointer)
