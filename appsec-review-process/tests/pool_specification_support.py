"""Shared builders for the pool specification tests (C01). Not a test module.

Every fixture is built by calling the B13 and B14 test builders, which call the real adapters'
builders and the real B11 evaluator: a group's request template is a real adapter request with the
expander-assigned fields removed, so every tested state is one an integrator can produce.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import container_execution as ce  # noqa: E402
import container_execution_support as b13  # noqa: E402
import persona_invocation as pi  # noqa: E402
import persona_invocation_support as b14  # noqa: E402
import pool_specification as ps  # noqa: E402
import resource_pools as rp  # noqa: E402

RUN, JOB, ATTEMPT = "run-c01", "job-c01", "attempt-c01"
SNAPSHOT = b14.SNAPSHOT
# Never echoed: hostile values carry this marker and every message is searched for it.
MARKER = "zq-hostile-marker"
NETWORK = [("fixed-network-destination", {"scheme": "https", "host": "api.example.org", "port": 443})]

symlinks_supported = b14.symlinks_supported


def permission(capabilities=None, *, job_id: str = JOB, run_id: str = RUN, now: str = b14.NOW) -> dict:
    return b14.permission(capabilities, now=now, job_id=job_id, run_id=run_id)


class PoolWorkspace:
    """A prompt root and a readable root (B14's workspace), a target tree to mount, and an empty
    pool parent. The pool parent lies INSIDE the readable root on purpose: that is the realistic
    layout (run data holds both evidence and pools) and the one in which privacy has to be proven."""

    def __init__(self, base: Path) -> None:
        self.base = base
        self.persona = b14.Workspace(base / "persona")
        self.data = self.persona.data
        self.targets = base / "targets"
        self.target = self.targets / "repo"
        self.target.mkdir(parents=True)
        (self.target / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        self.pool_parent = self.data / "pools" / "wave-1"
        self.pool_parent.mkdir(parents=True)

    def context_fields(self, **over) -> dict:
        fields = {
            "pool_parent": self.pool_parent, "registry_dir": pi.REGISTRY_DIR,
            "prompt_root": self.persona.prompts, "readable_roots": {"run-data": self.data},
            "allowed_models": (b14.MODEL, b14.OTHER_MODEL), "invoker_id": pi.FixtureInvoker.invoker_id,
            "images_dir": ce.IMAGES_DIR, "host_flavor": b13.runtime().host_flavor, "docker_host": None,
            "mount_roots": (self.targets,), "source_snapshot_sha256": SNAPSHOT, "registry_ceiling": None,
        }
        fields.update(over)
        return fields

    def context(self, **over) -> ps.PoolContext:
        return ps.PoolContext(**self.context_fields(**over))

    def persona_group(self, group_id: str = "reviewers", count: int = 1, *, capabilities=None,
                      memory_heavy: bool = False, **template_over) -> dict:
        request = self.persona.request(**template_over)
        return {"group_id": group_id, "worker_kind": ps.PERSONA, "count": count, "memory_heavy": memory_heavy,
                "permission": permission(capabilities),
                "persona_request": {name: request[name] for name in ps.PERSONA_TEMPLATE_FIELDS},
                "tool_request": None}

    def tool_group(self, group_id: str = "scanners", count: int = 1, *, capabilities=None,
                   memory_heavy: bool = False, target: Path | None = None, **template_over) -> dict:
        request = b13.request(self.target if target is None else target, ["/bin/echo", "hello"], **template_over)
        return {"group_id": group_id, "worker_kind": ps.PINNED_CONTAINER, "count": count,
                "memory_heavy": memory_heavy, "permission": permission(capabilities),
                "persona_request": None,
                "tool_request": {name: request[name] for name in ps.TOOL_TEMPLATE_FIELDS}}

    def spec(self, groups: list, **over) -> dict:
        groups = sorted(deepcopy(groups), key=lambda group: group["group_id"])
        total = sum(group["count"] for group in groups if isinstance(group["count"], int)
                    and not isinstance(group["count"], bool))
        value = {
            "schema": ps.SPEC_ID, "pool_id": "fixture-pool", "lane": "07-red-team-adversarial",
            "run_id": RUN, "job_id": JOB, "attempt_id": ATTEMPT, "budget_class": "standard",
            "pool_budget": {"max_instances": ps.MAX_INSTANCES, "max_persona_input_units": 2_000_000,
                            "max_persona_output_units": 2_000_000, "max_total_timeout_seconds": 86_400},
            "resource_pool_policy": {"allowed_pools": sorted([rp.DOCKER, rp.PERSONA_LLM])},
            "wait_all": True, "rendezvous_timeout_seconds": 3_600,
            "empty_pool_reason": None if total else "no_applicable_work",
            "worker_groups": groups,
        }
        value.update(deepcopy(over))
        return json.loads(json.dumps(value))

    def mixed(self, personas: int = 3, tools: int = 2, **over) -> dict:
        return self.spec([self.persona_group("reviewers", personas), self.tool_group("scanners", tools)], **over)

    def root(self, plan: ps.ExpansionPlan) -> Path:
        return self.pool_parent / plan.pool_directory

    def instance_root(self, plan: ps.ExpansionPlan, index: int) -> Path:
        return self.root(plan).joinpath(*plan.manifest["instances"][index]["attempt_root"].split("/"))


def tree(path: Path) -> list:
    return sorted(item.relative_to(path).as_posix() for item in path.rglob("*"))
