"""Zero-config lifecycle binding for automatically derived CVE reachability evidence."""
JOB="06-cve-reachability"
RESULT="outputs/cve-reachability.json"

def run(run_id, dagster_run_id, force=False):
    from analysis_feature_lifecycle import run as lifecycle_run
    return lifecycle_run(run_id, dagster_run_id, JOB, force)

def validate(run_id):
    from analysis_feature_lifecycle import validate as lifecycle_validate
    return lifecycle_validate(run_id, JOB)
