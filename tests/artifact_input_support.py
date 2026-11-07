"""Recorded upstream artifacts published by real fixture jobs, never by implicit latest grants."""
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound_json
from appsec_review.runtime import GraphRunner, Job, Unit
from appsec_review.runtime.handoff import collect_artifacts
from appsec_review.runtime.contracts import Availability, JobContract, MissingPolicy, accepted_inputs
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import atomic_json, file_sha256

PRODUCERS = ("job_language_build", "job_artifact_indexing")


def recorded_job(root, job_id):
    if job_id not in PRODUCERS:
        raise ValueError("not a recorded artifact producer")
    seed = root / "data/inputs/artifact-fixture" / (job_id + ".json")
    source = artifact_ref(root, seed)
    builtin = builtin_registry().build(job_id)
    upstream = () if job_id == "job_language_build" else accepted_inputs(
        "job_language_build", builtin_registry().build("job_language_build").datasets,
        availability=Availability.REQUIRED, missing=MissingPolicy.REJECT)

    def publish(unit):
        record = read_bound_json(root, source)
        document = dict(record["document"])
        if job_id == "job_artifact_indexing":
            document["language_build_handoff_sha256"] = unit.job.upstream_handoffs["job_language_build"]
        directory = "language-build" if job_id == "job_language_build" else "artifact-indexing"
        path = unit.job.attempt_root / "artifacts" / directory / "recorded.json"
        atomic_json(path, document)
        return {"artifact": artifact_ref(root, path), "index_manifest": record["manifest"],
                "artifacts": collect_artifacts(root, document),
                "gaps": document.get("gaps", []),
                "terminal_status": "COMPLETED_WITH_GAPS" if document.get("gaps") else "SUCCEEDED"}

    return Job(job_id, builtin.name, lambda _: {}, units=(Unit("acceptance.publish_handoff", publish),),
               datasets=builtin.datasets, contract=JobContract(inputs=upstream),
               schema_identity=builtin.schema_identity, input_identity=lambda _: file_sha256(seed))


def recorded_graph(config, jobs, run_id):
    root = config.runtime.runs_dir / run_id
    inputs = [recorded_job(root, name) for name in PRODUCERS
              if (root / "data/inputs/artifact-fixture" / (name + ".json")).is_file()]
    return GraphRunner(config, [*inputs, *jobs])
