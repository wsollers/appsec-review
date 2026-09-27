from test_evidence import execution_record, permission, run_job, validate_job
JOB="02-test-execution"; RESULT="test-execution.json"; CONTRACT="test-execution"
def run(run_id,dagster_id,force=False): return run_job(run_id,dagster_id,JOB,force)
def validate(run_id,pointer=None): return validate_job(run_id,JOB,pointer)
