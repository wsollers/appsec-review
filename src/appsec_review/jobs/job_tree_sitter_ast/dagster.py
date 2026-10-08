"""Dagster dynamic-map adapter for independent accepted Tree-sitter scopes."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import time
from types import MappingProxyType

from dagster import DynamicOut, DynamicOutput, In, Nothing, Out, graph, multiprocess_executor, op

from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.runtime import UnitContext
from appsec_review.storage import atomic_json

from .job import build_job
from .scope_execution import parse_scope


def build_dagster_job(config, runner_factory):
    job = build_job()

    @op(name="standalone__tree_sitter_ast__begin", out=Out(dict),
        tags={"appsec/pool": "lifecycle"}, pool="lifecycle")
    def begin(context):
        tags = dict(context.dagster_run.tags)
        target = Path(os.environ.get("APPSEC_REVIEW_TARGET",
            config.runtime.repository_root / "targets" / "appsec-multi-vuln")).resolve()
        claim = runner_factory(config).begin_or_reuse_attempt(job,
            run_id=tags.get("appsec/application_run_id"),
            trigger="schedule" if "dagster/schedule_name" in tags else "manual",
            orchestration={"system": "dagster", "run_id": context.run_id, "node": context.op.name},
            target_root=target, source_fingerprint=source_fingerprint(target))
        context.instance.add_run_tags(context.run_id, {
            "appsec/application_run_id": str(claim["run_id"]),
            "appsec/trigger": str(claim["trigger"]),
        })
        return dict(claim)

    @op(name="standalone__tree_sitter_ast__load__accepted_inputs",
        ins={"claim": In(dict)}, out=Out(dict), tags={"appsec/pool": "lifecycle"}, pool="lifecycle")
    def load(context, claim):
        correlated = {**claim, "orchestration": {**dict(claim.get("orchestration", {})),
                                                  "node": context.op.name}}
        return dict(runner_factory(config).execute_or_reuse_unit(job, correlated, "load.accepted_inputs"))

    @op(name="standalone__tree_sitter_ast__plan__route_scopes",
        ins={"claim": In(dict), "loaded": In(dict)}, out=DynamicOut(dict),
        tags={"appsec/pool": "lifecycle"}, pool="lifecycle")
    def route(context, claim, loaded):
        del loaded
        correlated = {**claim, "orchestration": {**dict(claim.get("orchestration", {})),
                                                  "node": context.op.name}}
        planned = runner_factory(config).execute_or_reuse_unit(job, correlated, "plan.route_scopes")
        for scope in planned["scopes"]:
            key = "scope_" + hashlib.sha256(scope["scope_id"].encode()).hexdigest()[:20]
            yield DynamicOutput(dict(scope), mapping_key=key)

    @op(name="standalone__tree_sitter_ast__parse__scope",
        ins={"scope": In(dict), "claim": In(dict)}, out=Out(dict),
        tags={"appsec/pool": "index"}, pool="index")
    def parse_dynamic(context, scope, claim):
        runner = runner_factory(config)
        correlated = {**claim, "orchestration": {**dict(claim.get("orchestration", {})),
                                                   "node": context.op.name}}
        loaded = runner.execute_or_reuse_unit(job, correlated, "load.accepted_inputs")
        job_context = runner._context_from_claim(job, claim)
        unit_root = job_context.attempt_root / "steps" / "parse" / "tasks" / "dynamic_scopes"
        unit = UnitContext(job_context, "parse.dynamic_scopes", "parse", "dynamic_scopes", unit_root,
                           MappingProxyType({"load.accepted_inputs": loaded}))
        started = time.monotonic_ns()
        result = dict(parse_scope(unit, scope))
        duration_ms = (time.monotonic_ns() - started) // 1_000_000
        dynamic_root = unit_root / "dynamic"
        dynamic_root.mkdir(parents=True, exist_ok=True)
        atomic_json(dynamic_root / f"{scope['scope_id']}.json", result)
        counts = result.get("counts", {})
        job_context.events.write("TREE_SITTER_SCOPE_COMPLETED", unit_id="parse.dynamic_scopes",
            scope_id=result["scope_id"], language=result["language"], disposition=result["terminal_status"],
            files_parsed=counts.get("files_parsed", 0), bytes_parsed=counts.get("bytes_parsed", 0),
            nodes_parsed=counts.get("nodes_parsed", 0), errors=counts.get("diagnostic_count", 0),
            gaps=len(result.get("gaps", ())), reused=bool(result.get("index_reused")),
            duration_ms=duration_ms)
        return result

    @op(name="standalone__tree_sitter_ast__parse__dynamic_scopes",
        ins={"results": In(list), "claim": In(dict)}, out=Out(Nothing),
        tags={"appsec/pool": "lifecycle"}, pool="lifecycle")
    def collect(context, results, claim):
        del results
        correlated = {**claim, "orchestration": {**dict(claim.get("orchestration", {})),
                                                  "node": context.op.name}}
        runner_factory(config).execute_or_reuse_unit(job, correlated, "parse.dynamic_scopes")

    @op(name="standalone__tree_sitter_ast__acceptance__publish_handoff",
        ins={"claim": In(dict), "parsed": In(Nothing)}, out=Out(Nothing),
        tags={"appsec/pool": "lifecycle"}, pool="lifecycle")
    def publish(context, claim):
        correlated = {**claim, "orchestration": {**dict(claim.get("orchestration", {})),
                                                  "node": context.op.name}}
        runner_factory(config).execute_or_reuse_unit(job, correlated, "acceptance.publish_handoff")

    @op(name="standalone__tree_sitter_ast__finalize",
        ins={"claim": In(dict), "published": In(Nothing)}, out=Out(dict),
        tags={"appsec/pool": "lifecycle"}, pool="lifecycle")
    def finalize(context, claim):
        outcome = runner_factory(config).finalize_attempt(job, claim)
        context.instance.add_run_tags(context.run_id, {
            "appsec/application_run_id": str(outcome["status"]["run_id"]),
            "appsec/job_tree_sitter_ast/status": str(outcome["status"]["status"]),
        })
        return {"run_id": outcome["status"]["run_id"],
                "handoffs": {"job_tree_sitter_ast": outcome["handoff_sha256"]},
                "completion_status": outcome["status"]["status"]}

    @graph(name="tree_sitter_ast")
    def tree_sitter_graph():
        claim = begin()
        loaded = load(claim)
        scopes = route(claim, loaded)
        results = scopes.map(lambda scope: parse_dynamic(scope, claim))
        parsed = collect(results.collect(), claim)
        published = publish(claim, parsed)
        return finalize(claim, published)

    executor = multiprocess_executor.configured({
        "max_concurrent": config.dagster.max_concurrent,
        "tag_concurrency_limits": [{"key": "appsec/pool", "value": pool, "limit": limit}
                                   for pool, limit in sorted(config.dagster.pool_limits.items())],
    })
    return tree_sitter_graph.to_job(description="Dynamic per-scope Tree-sitter AST production.",
                                    executor_def=executor)
