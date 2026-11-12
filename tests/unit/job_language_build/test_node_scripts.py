"""The Node lifecycle policy classifies the whole package-script graph a recipe runs."""

from __future__ import annotations

import json
from pathlib import Path

from appsec_review.jobs.job_language_build import node
from appsec_review.jobs.job_language_build.node_scripts import MAX_SCRIPT_DEPTH


APP = "may execute a target application"


def _package(root: Path, directory: str, scripts: dict[str, str], **fields: object) -> None:
    path = root / directory if directory != "." else root
    path.mkdir(parents=True, exist_ok=True)
    (path / "package.json").write_text(json.dumps({**fields, "scripts": scripts}), encoding="utf-8")


def _gaps(root: Path, *commands: list[str], source_dir: str = ".") -> list[str]:
    return node.validate_lifecycle_scripts(root, source_dir, [["npm", "ci"], *commands])


def _npm_monorepo(root: Path, root_build: str) -> None:
    _package(root, ".", {"build": root_build}, private=True, workspaces=["packages/*"])
    _package(root, "packages/api", {"build": "tsc -p tsconfig.json&&node scripts/copy.mjs"},
             name="@demo/api")
    _package(root, "packages/web", {"build": "tsc --noEmit && vite build"}, name="@demo/web")


def test_npm_workspace_scripts_are_classified_with_the_full_chain(tmp_path: Path) -> None:
    for build in ("npm run build --workspace @demo/api && npm run build -w packages/web",
                  "npm run build --workspaces", "npm --prefix packages/api run build",
                  "npm run build --prefix=packages/api"):
        _npm_monorepo(tmp_path, build)
        assert _gaps(tmp_path, ["npm", "run", "build"]) == [
            f"package lifecycle script build {APP}: package.json#scripts.build → "
            "packages/api/package.json#scripts.build → node scripts/copy.mjs"], build
    # The member unit itself is blocked by the same rule at depth one.
    assert _gaps(tmp_path, ["npm", "run", "build"], source_dir="packages/api") == [
        f"package lifecycle script build {APP}: packages/api/package.json#scripts.build → "
        "node scripts/copy.mjs"]
    assert _gaps(tmp_path, ["npm", "run", "build"], source_dir="packages/web") == []


def test_benign_nested_graph_and_syntax_checks_pass(tmp_path: Path) -> None:
    _package(tmp_path, ".", {"build": "npm run build --workspaces", "prebuild": "npm run lint"},
             private=True, workspaces=["packages/*"])
    _package(tmp_path, "packages/web", {"build": "vite build", "lint": "node --check index.js"})
    assert _gaps(tmp_path, ["npm", "run", "build"]) == []


def test_pre_and_post_hooks_are_followed_at_every_depth(tmp_path: Path) -> None:
    _package(tmp_path, ".", {"prebuild": "npm run build -w packages/lib", "build": "tsc"},
             private=True, workspaces=["packages/*"])
    _package(tmp_path, "packages/lib", {"build": "tsc", "postbuild": "ts-node gen.ts",
                                        "pretest": "x"})
    assert _gaps(tmp_path, ["npm", "run", "build"]) == [
        f"package lifecycle script prebuild {APP}: package.json#scripts.prebuild → "
        "packages/lib/package.json#scripts.postbuild → ts-node gen.ts"]


def test_pnpm_filter_recursive_and_dependency_selectors(tmp_path: Path) -> None:
    (tmp_path / "pnpm-workspace.yaml").write_text(
        "packages:\n  - 'apps/*'\n  - \"libs/*\"  # shared\n", encoding="utf-8")
    _package(tmp_path, "apps/web", {"build": "vite build"}, name="web",
             dependencies={"core": "workspace:*"})
    _package(tmp_path, "libs/core", {"build": "tsx scripts/emit.ts"}, name="core")
    chain = ("libs/core/package.json#scripts.build → tsx scripts/emit.ts")
    for build in ("pnpm --filter web... run build", "pnpm -r build", "pnpm --filter ./libs/** build",
                  "pnpm -C libs/core build", "pnpm --dir=libs/core run build",
                  "pnpm --filter {libs/core} run build"):
        _package(tmp_path, ".", {"build": build}, private=True)
        assert _gaps(tmp_path, ["pnpm", "run", "build"]) == [
            f"package lifecycle script build {APP}: package.json#scripts.build → {chain}"], build
    _package(tmp_path, ".", {"build": "pnpm --filter web run build"}, private=True)
    assert _gaps(tmp_path, ["pnpm", "run", "build"]) == []
    _package(tmp_path, ".", {"build": "pnpm --filter missing build"}, private=True)
    [gap] = _gaps(tmp_path, ["pnpm", "run", "build"])
    assert gap.startswith("package lifecycle script build could not be resolved:")
    assert "pnpm filter 'missing' matches no member" in gap


def test_yarn_workspace_and_foreach(tmp_path: Path) -> None:
    _package(tmp_path, "services/api", {"build": "tsc && node build.js"}, name="api")
    _package(tmp_path, "services/ui", {"build": "vite build"}, name="ui")
    chain = "services/api/package.json#scripts.build → node build.js"
    for build in ("yarn workspace api build", "yarn workspace api run build",
                  "yarn workspaces foreach -A run build", "yarn workspaces foreach --all -pt build",
                  "yarn --cwd services/api build", "yarn workspaces run build"):
        _package(tmp_path, ".", {"build": build}, private=True, workspaces=["services/*"])
        # foreach -A includes the root but skips the root script that started it: no false cycle.
        assert _gaps(tmp_path, ["yarn", "build"]) == [
            f"package lifecycle script build {APP}: package.json#scripts.build → {chain}"], build
    _package(tmp_path, ".", {"build": "yarn workspaces foreach -A --exclude api run build"},
             private=True, workspaces=["services/*"])
    assert _gaps(tmp_path, ["yarn", "build"]) == []


def test_cycles_are_named_gaps(tmp_path: Path) -> None:
    _package(tmp_path, ".", {"build": "npm run compile", "compile": "tsc && npm run build"})
    assert _gaps(tmp_path, ["npm", "run", "build"]) == [
        "package lifecycle script build forms a package-script cycle: package.json#scripts.build → "
        "package.json#scripts.compile → package.json#scripts.build"]


def test_depth_bound_is_a_named_gap(tmp_path: Path) -> None:
    scripts = {f"s{index}": f"npm run s{index + 1}" for index in range(MAX_SCRIPT_DEPTH + 2)}
    _package(tmp_path, ".", scripts)
    [gap] = _gaps(tmp_path, ["npm", "run", "s0"])
    assert gap.startswith(f"package lifecycle script s0 exceeds the package-script depth bound "
                          f"of {MAX_SCRIPT_DEPTH}: package.json#scripts.s0 → ")
    assert gap.count("→") == MAX_SCRIPT_DEPTH
    shallow = {f"s{index}": f"npm run s{index + 1}" for index in range(MAX_SCRIPT_DEPTH - 1)}
    _package(tmp_path, ".", {**shallow, f"s{MAX_SCRIPT_DEPTH - 1}": "tsc"})
    assert _gaps(tmp_path, ["npm", "run", "s0"]) == []


def test_nested_test_runners_script_groups_and_unresolved_targets(tmp_path: Path) -> None:
    _package(tmp_path, ".", {"build": "run-s build:*", "build:js": "tsc",
                             "build:check": "cross-env CI=1 vitest run"})
    assert _gaps(tmp_path, ["npm", "run", "build"]) == [
        "package lifecycle script build requests a test runner: package.json#scripts.build → "
        "package.json#scripts.build:check → vitest run"]
    _package(tmp_path, ".", {"build": "npm --prefix ../outside run build"})
    [gap] = _gaps(tmp_path, ["npm", "run", "build"])
    assert "escapes the build workspace" in gap
    _package(tmp_path, ".", {"build": "npm run build -w nowhere"}, workspaces=[])
    [gap] = _gaps(tmp_path, ["npm", "run", "build"])
    assert "npm workspace 'nowhere' matches no member" in gap
