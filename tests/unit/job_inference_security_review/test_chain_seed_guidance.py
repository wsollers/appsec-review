"""Discovery cells retain bounded, pinned guidance with optional downstream chain hints."""
from copy import deepcopy
import json
import shutil

import pytest

from appsec_review.guidance import load_registry, pin_bundle, render_prompt, verify_bundle
from appsec_review.guidance.compose import section_sha256
from appsec_review.jobs.job_inference_security_review import teams
from appsec_review.review.models import IntegrityError, Lane, Role
from appsec_review.review.package_view import PackageView
from appsec_review.storage import file_sha256
from tests.unit.job_inference_security_review.test_t173_evidence_and_budgets import (
    evidence_core, review_context,  # noqa: F401
)


@pytest.mark.parametrize("role,task,lane", [
    (Role.RED_TEAM_ANALYST, "lead_red_stack", Lane.LEAD),
    (Role.HYPOTHESIS_HUNTER, "sink_up", Lane.HUNT),
], ids=["lead", "hunt"])
def test_registered_discovery_cells_pin_optional_seed_guidance(review_context, tmp_path, role, task, lane):
    ctx = review_context
    repository = tmp_path / "repository"
    shutil.copytree(ctx.repository_root / "pipeline", repository / "pipeline")
    (repository / "docs" / "schemas").mkdir(parents=True)
    shutil.copyfile(ctx.repository_root / "docs" / "schemas" / "retrieval-mcp-tools.json",
                    repository / "docs" / "schemas" / "retrieval-mcp-tools.json")
    ctx.repository_root = repository
    entity = ctx.core.find(name="parse_token", limit=1)["results"][0]["identity"]
    work = teams.PackageWork("package", lane, "a" * 64, {"scope": {}}, (1, "package"),
                             "b" * 64, (entity,), None)
    view = PackageView({}, {"K1": entity}, {}, frozenset(), (), frozenset((entity,)))
    cell = teams._cell(ctx, work, {"stack": "generic"}, role=role, persona="generalist",
                       task=task, kind="red", task_input={"package": view.document}, view=view)
    cell.capability.verify()
    directory = ctx.run_root / "data" / "guidance" / cell.spec.guidance_bundle_sha256
    bundle = json.loads((directory / "bundle.json").read_bytes())
    prompt = (directory / "prompt.md").read_text()
    assert verify_bundle(bundle) == cell.spec.guidance_bundle_sha256
    assert prompt == cell.spec.guidance_text == render_prompt(bundle)
    assert len(prompt) <= 32000
    assert all(section_sha256(section) == section["sha256"] for section in bundle["sections"])
    sections = {section["name"]: section for section in bundle["sections"]}
    registry_role = load_registry(repository)["roles"][role.value]
    source = repository / registry_role["path"]
    assert sections["role"]["text"] == source.read_text()
    assert sections["role"]["id"] == role.value and sections["task"]["id"] == task
    assert sections["task"]["input"] == {"lane": lane.value}
    assert sections["receipt"]["capability"] == {
        "granted_tools": [tool for tool in cell.capability.tools if tool != "expand"],
        "max_queries": cell.capability.max_queries, "max_turns": cell.capability.max_turns,
        "page_size": cell.capability.page_size,
        "query_sources": [], "query_procedures": {},
    }
    assert registry_role["output_schema"] == "red-compact"
    no_seed = {"claims": [], "no_claim": [], "blocked": []}
    ctx.schemas.validate(registry_role["output_schema"], no_seed)
    assert ctx.schemas.errors(registry_role["output_schema"], {**no_seed, "accept_claim": True})
    normalized = " ".join(prompt.split())
    assert "post-adjudication chain composition uses admitted supported/confirmed claims with optional seed hints" in normalized
    assert "without a seed no chain is composed" not in normalized
    assert "without seeds no chain is composed" not in normalized
    assert ("never a claim" if lane is Lane.LEAD else "not claims") in normalized

    before = {name: (directory / name).read_bytes() for name in ("bundle.json", "prompt.md")}
    pinned = pin_bundle(ctx.run_root, bundle)
    assert pinned["bundle_sha256"] == cell.spec.guidance_bundle_sha256
    assert before == {name: (directory / name).read_bytes() for name in before}
    tampered = deepcopy(bundle)
    next(section for section in tampered["sections"] if section["name"] == "role")["text"] += "\nchanged"
    with pytest.raises(IntegrityError, match="role"):
        pin_bundle(ctx.run_root, tampered)
    assert before == {name: (directory / name).read_bytes() for name in before}
    (tmp_path / "guidance-identities.json").write_text(json.dumps({
        "role": role.value, "task": task, "source_sha256": file_sha256(source),
        "bundle_sha256": bundle["sha256"], "section_sha256": bundle["section_sha256"],
        "capability_sha256": cell.capability.capability_sha256, "pin": pinned,
    }, sort_keys=True))
