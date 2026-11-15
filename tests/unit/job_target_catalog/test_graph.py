from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_target_catalog import job as catalog
from tests.unit.job_target_catalog.support import (
    COMPILE, COMPONENTS, DEPENDENCIES, INDEX_UNITS, PARTITION, PROJECTS, SYSTEMS, TARGETS,
    context,
)

EXPECTED = {
    PARTITION: (),
    "repository_discovery.census_languages": (PARTITION,),
    SYSTEMS: (PARTITION,),
    PROJECTS: (PARTITION, SYSTEMS),
    COMPILE: (PARTITION,),
    TARGETS: (SYSTEMS, COMPILE, PARTITION),
    COMPONENTS: (PROJECTS,),
    DEPENDENCIES: (COMPONENTS,),
    INDEX_UNITS[0]: (PARTITION,),
    INDEX_UNITS[1]: (PARTITION,),
    INDEX_UNITS[2]: (COMPONENTS,),
    INDEX_UNITS[3]: (PARTITION,),
    "publish_catalog.validate_catalog": INDEX_UNITS,
    "publish_catalog.publish_handoff": (
        "publish_catalog.validate_catalog", TARGETS, DEPENDENCIES,
        "repository_discovery.census_languages",
    ),
}


def test_graph_ids_dependencies_validators_and_result_identity():
    job = catalog.build_job()
    assert (job.job_id, job.name, job.schema_identity) == (
        "job_target_catalog", "target_catalog", "appsec-review/target-catalog-job/1")
    assert job.strict_gaps is True
    assert {unit.unit_id: unit.dependencies for unit in job.units} == EXPECTED
    assert [unit.handler.__name__ for unit in job.units] == [
        "partition", "census", "build_systems", "projects", "compile_commands", "build_targets",
        "components", "dependencies", "path_index", "symbol_index", "component_index",
        "document_index", "validate_catalog", "publish",
    ]
    assert job.input_validators == (catalog._validate_config,)
    assert job.output_validators == ()
    assert job.result_transform is None
    assert all(unit.output_validators == () for unit in job.units)
    result = {"status": "SUCCEEDED", "outputs": {"example": {"value": 1}}}
    assert job.finalize_result(SimpleNamespace(), result) is result


def test_shipped_configuration_matches_topology():
    config = load_config(Path(__file__).resolve().parents[3] / "appsec-review.toml").job("job_target_catalog")
    catalog._validate_config(SimpleNamespace(config=config), None)
    assert tuple(config.steps) == tuple(catalog.TOPOLOGY)
    for step, tasks in catalog.TOPOLOGY.items():
        assert tuple(config.step(step).tasks) == tasks


@pytest.mark.parametrize("bad_step", ["steps", *sorted(catalog.TOPOLOGY)])
def test_configuration_rejects_missing_steps_and_task_order(bad_step):
    steps = dict(catalog.TOPOLOGY)
    if bad_step == "steps":
        steps.pop("publish_catalog")
    config = SimpleNamespace(steps=steps, step=lambda name: SimpleNamespace(
        tasks=tuple(reversed(catalog.TOPOLOGY[name])) if name == bad_step else catalog.TOPOLOGY[name]))
    message = ("target catalog topology does not match configuration" if bad_step == "steps"
               else f"target catalog task order mismatch: {bad_step}")
    with pytest.raises(catalog.CatalogConfigurationError, match=f"^{message}$"):
        catalog._validate_config(SimpleNamespace(config=config), None)


@pytest.mark.parametrize("unit_id", sorted(EXPECTED))
def test_injected_failure_is_scoped_before_any_handler_read(tmp_path, unit_id):
    job = catalog.build_job(fail_task=unit_id)
    unit = next(unit for unit in job.units if unit.unit_id == unit_id)
    ctx = context(tmp_path, unit_id)
    with pytest.raises(catalog.TargetCatalogFailed, match=f"^injected bounded failure: {unit_id}$"):
        unit.handler(ctx)
    assert ctx.reads == [] and ctx.events == []
