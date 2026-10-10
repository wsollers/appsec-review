"""Independent Joern/c2cpg code property graph job for accepted C/C++ scopes.

The job consumes only the accepted ``job_cpp_compiled_analysis`` handoff. For every accepted
project scope it runs ``tool-joern``'s c2cpg frontend over the accepted sources and compile
database and retains the resulting CPG as hash-identified, run-owned evidence. Bounded CPG/PDG
export, source mapping, functional fixtures, and security acceptance are not implemented yet, so
each scope publishes a BLOCKED observation shard with zero observations and ``unavailable``
coverage. Generating a CPG is not CPG coverage.

``max_cpg_bytes`` is enforced while c2cpg writes: the container runs under RLIMIT_FSIZE of
``max_cpg_bytes + 1``, so the kernel stops any file from growing past the bound on the run volume.
A CPG that reaches the bound is discarded and the scope publishes an explicit producer gap.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from appsec_review.jobs.cpp_index_scopes import (
    CheckpointIntegrityError, IndexScope, accepted_cpp_scopes, artifact, checkpoint_identity, execute_scope_tool,
    publish_scope_indexes, save_scope_checkpoint, scope_checkpoint, tool_identity,
)
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, index_fingerprint,
)
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, canonical_json, file_sha256


JOB_ID = "job_cpg_analysis"
SCHEMA = "appsec-review/cpg-analysis/1"
TOOL_ID = "tool-joern"
ADAPTER = "joern-c2cpg-adapter/4"
CPG_MANIFEST_SCHEMA = "appsec-review/cpg-manifest/1"
ARGV = ("/opt/joern/joern-cli/c2cpg.sh", "/target/source", "--output", "/scratch/cpg.bin",
        "--compilation-database", "/scratch/compile_commands.json")
JOERN_GAP = (
    "BLOCKED: the hash-pinned Joern/c2cpg runtime (tool-joern) generated this scope's CPG as "
    "run-owned evidence, but bounded CPG/PDG export, source mapping, functional fixtures, and "
    "security acceptance are not complete; no CPG coverage is claimed."
)


def _settings(unit: UnitContext) -> Mapping[str, int]:
    return {"workers": int(unit.job.config.settings["workers"]),
            "max_cpg_bytes": int(unit.job.config.settings["max_cpg_bytes"])}


def _reuse(unit: UnitContext, root: Path, identity: str, scope: IndexScope) -> dict[str, Any] | None:
    reused = scope_checkpoint(root / "checkpoint.json", identity, unit.job.run_root, scope,
                              required=("execution.receipt", "execution.compile_database", "cpg_manifest"))
    if reused is None:
        return None
    manifest = json.loads((unit.job.run_root / reused["cpg_manifest"]["path"]).read_text(encoding="utf-8"))
    bound = {"schema": CPG_MANIFEST_SCHEMA, "checkpoint_identity": identity, "scope": scope.as_dict(),
             "cpg": reused["cpg"], "accepted_compile_database": dict(scope.compile_database),
             "resource_limit": reused["resource_limit"]}
    execution_keys = ("receipt", "compile_database", "image_id", "exit_code", "timed_out", "oom_killed")
    executed = manifest.get("execution") if isinstance(manifest.get("execution"), dict) else {}
    if {key: manifest.get(key) for key in bound} != bound or \
            {key: executed.get(key) for key in execution_keys} != {key: reused["execution"][key] for key in execution_keys}:
        raise CheckpointIntegrityError(f"{scope.scope_id}: CPG manifest does not match its checkpoint")
    if reused["cpg"] is not None and not reused["cpg"]["path"].startswith(
            (root / "run").relative_to(unit.job.run_root).as_posix() + "/"):
        raise CheckpointIntegrityError(f"{scope.scope_id}: checkpointed CPG left its scope root")
    return reused


def _generate(unit: UnitContext, scope: IndexScope, executor_factory: Any) -> dict[str, Any]:
    limits = _settings(unit)
    limit = limits["max_cpg_bytes"]
    root = unit.job.run_root / "data" / "code-index" / "joern" / scope.scope_id
    identity = checkpoint_identity({
        "schema": SCHEMA, "adapter": ADAPTER, "manifest_schema": CPG_MANIFEST_SCHEMA, "argv": list(ARGV),
        "scope": scope.as_dict(), "gap": JOERN_GAP,
        "container_compile_database": hashlib.sha256(canonical_json(scope.container_compile_database())).hexdigest(),
        "tool": tool_identity(unit.job.repository_root, TOOL_ID) if executor_factory is None
        else {"tool_id": TOOL_ID, "injected_executor": True},
        "max_cpg_bytes": limit, "limit_mechanism": "RLIMIT_FSIZE"})
    reused = _reuse(unit, root, identity, scope)
    if reused is not None:
        return reused
    scratch = root / "run"
    execution = execute_scope_tool(unit, scope, TOOL_ID, ARGV, scratch, executor_factory,
                                   file_size_limit_bytes=limit + 1)
    gaps: list[str] = []
    cpg_path = scratch / "cpg.bin"
    cpg = None
    regular = cpg_path.is_file() and not cpg_path.is_symlink()
    observed = cpg_path.lstat().st_size if regular else None
    limited = execution["file_size_limit_reached"] or (observed is not None and observed > limit)
    disposition = "LIMIT_REACHED" if limited else "WITHIN_LIMIT" if observed else "NOT_PRODUCED"
    if limited:
        # The kernel stopped the write at limit + 1 bytes; whatever exists is partial and is never evidence.
        gaps.append(f"Joern c2cpg reached the {limit}-byte CPG limit while writing; "
                    "the partial CPG was discarded")
    elif execution["timed_out"]:
        gaps.append("Joern c2cpg timed out before a CPG was produced")
    elif execution["oom_killed"]:
        gaps.append("Joern c2cpg was OOM-killed before a CPG was produced")
    elif execution["exit_code"] != 0:
        gaps.append(f"Joern c2cpg exited with status {execution['exit_code']}")
    elif not regular or observed == 0:
        gaps.append("Joern c2cpg produced no CPG")
    else:
        cpg = artifact(unit.job.run_root, cpg_path)
    if cpg is None and (cpg_path.exists() or cpg_path.is_symlink()):
        cpg_path.unlink()
    gaps.append(JOERN_GAP)
    resource_limit = {"mechanism": "RLIMIT_FSIZE", "max_cpg_bytes": limit, "enforced_bytes": limit + 1,
                      "disposition": disposition, "observed_bytes": observed}
    manifest_path = root / "cpg-manifest.json"
    atomic_json(manifest_path, {
        "schema": CPG_MANIFEST_SCHEMA, "checkpoint_identity": identity, "scope": scope.as_dict(), "cpg": cpg,
        "accepted_compile_database": dict(scope.compile_database), "resource_limit": resource_limit,
        "execution": {key: execution[key] for key in ("receipt", "compile_database", "image_id", "image_digest",
                                                     "argv_identity", "exit_code", "timed_out", "oom_killed")}})
    cpg_manifest = artifact(unit.job.run_root, manifest_path)

    shard = f"joern-{scope.scope_id}"
    artifacts = [execution["receipt"], execution["compile_database"], dict(scope.compile_database), cpg_manifest]
    if cpg is not None:
        artifacts.append(cpg)
    fingerprint = index_fingerprint(
        name="observations", target_snapshot=scope.case_snapshot, producer_artifacts=artifacts,
        tool_identity={"tool": TOOL_ID, "image": execution["image_id"],
                       "image_digest": execution["image_digest"]},
        parser_identity=ADAPTER, normalizer_identity=ADAPTER, mapping_identity="cpp-source-mapping/3")
    path = (unit.job.run_root / "data" / "indices" / "observations" /
            f"{fingerprint}-{hashlib.sha256(shard.encode()).hexdigest()[:16]}.sqlite")
    builder = IndexBuilder(path, name="observations", fingerprint=fingerprint,
                           target_snapshot=unit.job.source_fingerprint, shard_id=shard)
    evidence = LogicalIdentity.derive(EntityKind.EVIDENCE_ARTIFACT, scope.case_snapshot,
                                      {"project_id": scope.project_id, "producer": "joern",
                                       "status": "BLOCKED"})
    builder.add_entity(EntityRecord(evidence, f"joern:{scope.case_id}", "joern",
                                    "; ".join(gaps)[:16384],
                                    {"status": "BLOCKED", "observation_count": 0, "cpg": cpg,
                                     "cpg_manifest": cpg_manifest, "resource_limit": resource_limit,
                                     "project_id": scope.project_id, "shard_id": shard}))
    builder.add_coverage(f"joern:{scope.project_id}"[:256], "unavailable", "; ".join(gaps))
    sha = file_sha256(path) if path.exists() else builder.build()
    index = IndexIdentity("observations", "appsec-review/retrieval-index/2", sha, fingerprint,
                          path.relative_to(unit.job.run_root).as_posix(),
                          {"job": JOB_ID, "unit": unit.unit_id, "scope_id": scope.scope_id},
                          tuple(gaps), shard)
    result = {"scope_id": scope.scope_id, "case_id": scope.case_id, "project_id": scope.project_id,
              "execution": {key: execution[key] for key in ("receipt", "compile_database", "exit_code",
                                                              "timed_out", "oom_killed", "image_id",
                                                              "file_size_limit_bytes", "file_size_limit_reached")},
              "accepted_compile_database": dict(scope.compile_database), "resource_limit": resource_limit,
              "cpg": cpg, "cpg_manifest": cpg_manifest, "observation_count": 0, "index_identity": asdict(index),
              "gaps": gaps,
              "terminal_status": "COMPLETED_WITH_GAPS"}
    save_scope_checkpoint(root / "checkpoint.json", identity, result)
    return result


def _validate(context, _result) -> None:
    if tuple(context.config.steps) != ("load", "generate", "acceptance"):
        raise ValueError("CPG-analysis topology does not match central configuration")
    for step, task in (("load", "accepted_cpp"), ("generate", "scopes"), ("acceptance", "publish_handoff")):
        if tuple(context.config.step(step).tasks) != (task,):
            raise ValueError(f"CPG-analysis task configuration mismatch: {step}")


def build_job(*, executor_factory=None) -> Job:
    def load(unit: UnitContext) -> Mapping[str, Any]:
        accepted, scopes, unavailable = accepted_cpp_scopes(unit.job.run_root)
        if accepted["handoff"].get("source_fingerprint") != unit.job.source_fingerprint:
            raise ValueError("CPG target snapshot differs from the accepted C++ build")
        unit.job.events.write("CPG_SCOPES_LOADED", scope_count=len(scopes),
                              unavailable_count=len(unavailable))
        return {"upstream": {"handoff_sha256": accepted["handoff_sha256"], "manifest": accepted["manifest"]},
                "scopes": [scope.as_dict() for scope in scopes], "unavailable": unavailable}

    def generate(unit: UnitContext) -> Mapping[str, Any]:
        _accepted, scopes, unavailable = accepted_cpp_scopes(unit.job.run_root)
        planned = {item["scope_id"] for item in unit.output("load.accepted_cpp")["scopes"]}
        if {scope.scope_id for scope in scopes} != planned:
            raise ValueError("accepted C++ scopes changed between load and generate")
        with ThreadPoolExecutor(max_workers=max(1, _settings(unit)["workers"])) as pool:
            results = list(pool.map(lambda scope: _generate(unit, scope, executor_factory), scopes))
        gaps = list(dict.fromkeys(f"{item['case_id']}: {gap}" for item in results for gap in item["gaps"]))
        gaps.extend(f"{case_id}: {reason}" for case_id, reason in unavailable.items())
        status = "NOT_APPLICABLE" if not results and not unavailable else "COMPLETED_WITH_GAPS"
        return {"scopes": results, "scope_count": len(results), "gaps": gaps, "terminal_status": status}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        loaded, generated = unit.output("load.accepted_cpp"), unit.output("generate.scopes")
        manifest = publish_scope_indexes(unit, job_id=JOB_ID, index_name="observations", prefix="joern",
                                         results=generated["scopes"], unavailable=loaded["unavailable"],
                                         gaps=generated["gaps"])
        counts = {"scopes": len(generated["scopes"]),
                  "cpgs_generated": sum(item["cpg"] is not None for item in generated["scopes"]),
                  "observations": 0}
        summary_path = unit.unit_root / "cpg-analysis-summary.json"
        atomic_json(summary_path, {"schema": SCHEMA, "upstream": loaded["upstream"], "counts": counts,
                                   "scopes": generated["scopes"], "unavailable": loaded["unavailable"],
                                   "gaps": generated["gaps"]})
        unit.job.events.write("CPG_ANALYSIS_COMPLETED", **counts, gap_count=len(generated["gaps"]))
        return {"schema": SCHEMA, "artifact": artifact(unit.job.run_root, summary_path),
                "index_manifest": manifest, "item_count": 0, "counts": counts,
                "gaps": generated["gaps"], "terminal_status": generated["terminal_status"]}

    units = (
        Unit("load.accepted_cpp", load),
        Unit("generate.scopes", generate, ("load.accepted_cpp",)),
        Unit("acceptance.publish_handoff", publish, ("load.accepted_cpp", "generate.scopes")),
    )
    implementation = hashlib.sha256(
        b"".join(path.read_bytes() for path in sorted(Path(__file__).parent.glob("*.py"))) +
        Path(__file__).parents[1].joinpath("cpp_index_scopes.py").read_bytes() +
        (b"injected-executor" if executor_factory else b"container-executor")).hexdigest()
    return Job(JOB_ID, "cpg_analysis", UnitExecutor(units).execute, input_validators=(_validate,),
               schema_identity=SCHEMA, implementation_identity=implementation, units=units)
