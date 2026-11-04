from pathlib import Path

import pytest

from appsec_review.config import load_config


ROOT = Path(__file__).parents[1]


def test_retention_defaults_and_zero_are_not_semantic_build_inputs(tmp_path):
    source = (ROOT / "appsec-review.toml").read_text()
    path = tmp_path / "appsec-review.toml"
    path.write_text(source)
    normal = load_config(path)
    assert normal.build_workspaces.build_workspace_retention_runs == 3
    frozen = normal.resolved_json
    path.write_text(source.replace("build_workspace_retention_runs = 3", "build_workspace_retention_runs = 0"))
    disabled = load_config(path)
    assert disabled.build_workspaces.build_workspace_retention_runs == 0
    assert disabled.resolved_json == frozen
    path.write_text(source.replace("[build_workspaces]\nbuild_workspace_retention_runs = 3\n", ""))
    assert load_config(path).build_workspaces.build_workspace_retention_runs == 3


@pytest.mark.parametrize("value", ["-1", "true", '"3"'])
def test_retention_refuses_invalid_central_values(tmp_path, value):
    source = (ROOT / "appsec-review.toml").read_text()
    path = tmp_path / "appsec-review.toml"
    path.write_text(source.replace("build_workspace_retention_runs = 3",
                                   f"build_workspace_retention_runs = {value}"))
    with pytest.raises(ValueError, match="retention"):
        load_config(path)
