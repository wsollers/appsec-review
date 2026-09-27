"""02-build-configure public worker binding."""
import build_replay

JOB = "02-build-configure"
DAGSTER_JOB = "build_configure"
RESULT = build_replay.SPECS[JOB]["result"]

def root(run_id): return build_replay.root(run_id, JOB)
def run(run_id, dagster_id, force=False): return build_replay.run(run_id, dagster_id, JOB, force)
def validate(run_id, pointer=None): return build_replay.validate(run_id, JOB, pointer)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument("command", choices=["stage-control", "validate"])
    parser.add_argument("run_id"); args = parser.parse_args()
    print(build_replay.stage_control(args.run_id) if args.command == "stage-control" else validate(args.run_id))
