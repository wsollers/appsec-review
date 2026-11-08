"""The build-topology fixture monorepo: prepare it as a target, and score a plan against its expectations.

``test/topology/monorepo`` is a tiny committed repository whose directory shapes reproduce the
intake-through-build failures of real monorepo targets (vendored libraries under a parent driver,
sibling-path includes, Cargo/Go/npm workspaces, an engine project, an Xcode project, a multi-module
Gradle tree, a PHP site with and without composer, a conditional nested CMake root, and one genuinely
independent second native root). ``test/topology/monorepo.expectations.json`` is the **target
contract** for the build-discovery -> topology -> plan layer over that tree, validated against
``docs/schemas/topology-fixture-expectations.schema.json``. It describes behaviour the runtime
does not have yet; each unmet expectation names a reason code, and ``tests/test_topology_fixture.py``
turns those into strict expected failures that flip when the behaviour lands.

Commands (read-only on run trees; nothing here changes runtime behaviour):

``prepare --into <dir>``   copy the fixture into a new directory after verifying MANIFEST.json
``evaluate [--target DIR]`` run the real discovery/topology/plan code in-process and print the diff
``score --run <run>``      read a run's accepted analysis plan and print the per-shape diff
``manifest [--write]``     verify (or regenerate) MANIFEST.json

Everything is **reported, never asserted**: ``score`` prints and exits nonzero on a mismatch and
never raises. Only the standard library is imported at module level; the job code and jsonschema
are imported inside the functions that need them.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import sys
from typing import Any

REPOSITORY = Path(__file__).resolve().parents[3]
FIXTURE_ROOT = REPOSITORY / "test" / "topology" / "monorepo"
EXPECTATIONS_PATH = REPOSITORY / "test" / "topology" / "monorepo.expectations.json"
SCHEMA_PATH = REPOSITORY / "docs" / "schemas" / "topology-fixture-expectations.schema.json"
MANIFEST_NAME = "MANIFEST.json"
MANIFEST_SCHEMA = "appsec-review/topology-fixture-manifest/1"
EXPECTATIONS_SCHEMA = "appsec-review/topology-fixture-expectations/1"
BUILD_MODES = ("compiled", "package-only", "source-only", "skipped_policy", "unsupported_platform")
# Fields a case can check. ``discovered`` is whether a unit/component exists in the plan at all;
# the other fields are compared only when it does.
UNIT_FIELDS = ("discovered", "ownership")
COMPONENT_FIELDS = ("discovered", "build_mode", "recipe", "materialization_root")
RELATIONSHIP_FIELDS = ("relationship",)


class TopologyFixtureError(ValueError):
    """A fixture, manifest, expectations or plan input is unusable."""


# ------------------------------------------------------------------------------------- manifest

def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fixture_files(root: Path) -> list[Path]:
    """Every regular file of the fixture except the manifest itself, in sorted POSIX order."""
    root = Path(root)
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise TopologyFixtureError(f"fixture contains a symlink: {path.relative_to(root).as_posix()}")
        if not path.is_file() or path.relative_to(root).as_posix() == MANIFEST_NAME:
            continue
        files.append(path)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def fixture_manifest(root: Path) -> dict[str, Any]:
    """The regenerable byte inventory of the fixture (sha256 and size of every file)."""
    root = Path(root)
    entries = [{"path": path.relative_to(root).as_posix(), "sha256": _sha256(path),
                "size_bytes": path.stat().st_size} for path in fixture_files(root)]
    return {"schema": MANIFEST_SCHEMA, "file_count": len(entries),
            "total_bytes": sum(item["size_bytes"] for item in entries), "files": entries}


def load_manifest(root: Path) -> dict[str, Any]:
    path = Path(root) / MANIFEST_NAME
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise TopologyFixtureError(f"{path}: unreadable manifest: {error}") from error
    if not isinstance(value, Mapping) or value.get("schema") != MANIFEST_SCHEMA:
        raise TopologyFixtureError(f"{path}: schema must be {MANIFEST_SCHEMA!r}")
    return dict(value)


def manifest_drift(root: Path, manifest: Mapping[str, Any] | None = None) -> list[str]:
    """Differences between the committed manifest and the files on disk, as one line each."""
    manifest = load_manifest(root) if manifest is None else manifest
    recorded = {item["path"]: item for item in manifest.get("files", ())}
    actual = {item["path"]: item for item in fixture_manifest(root)["files"]}
    drift = [f"missing: {path}" for path in sorted(set(recorded) - set(actual))]
    drift += [f"unlisted: {path}" for path in sorted(set(actual) - set(recorded))]
    drift += [f"changed: {path}" for path in sorted(set(actual) & set(recorded))
              if (actual[path]["sha256"], actual[path]["size_bytes"]) !=
              (recorded[path].get("sha256"), recorded[path].get("size_bytes"))]
    if manifest.get("file_count") != len(recorded):
        drift.append("manifest file_count disagrees with its own file list")
    return drift


def write_manifest(root: Path) -> Path:
    path = Path(root) / MANIFEST_NAME
    path.write_text(json.dumps(fixture_manifest(root), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------------- expectations

def load_expectations(path: Path = EXPECTATIONS_PATH, *, schema_path: Path = SCHEMA_PATH) -> dict[str, Any]:
    """Read the expectations and validate them against the checked-in JSON Schema."""
    from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise TopologyFixtureError(f"unreadable expectations or schema: {error}") from error
    Draft202012Validator.check_schema(schema)
    errors = sorted(Draft202012Validator(schema).iter_errors(document), key=lambda item: list(item.absolute_path))
    if errors:
        first = errors[0]
        where = "/".join(str(part) for part in first.absolute_path) or "<root>"
        raise TopologyFixtureError(f"{path}: {where}: {first.message}")
    if document.get("schema") != EXPECTATIONS_SCHEMA:
        raise TopologyFixtureError(f"{path}: schema must be {EXPECTATIONS_SCHEMA!r}")
    codes = set(document["reason_codes"])
    for shape in document["shapes"]:
        for group in ("units", "components", "relationships"):
            for item in shape.get(group, ()):
                unknown = set(item.get("gaps", {}).values()) - codes
                if unknown:
                    raise TopologyFixtureError(
                        f"{path}: shape {shape['id']} names undeclared reason codes: {sorted(unknown)}")
    return dict(document)


def expected_units(expectations: Mapping[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    values = {}
    for shape in expectations["shapes"]:
        for unit in shape.get("units", ()):
            key = (unit["root"], unit["build_system"])
            if key in values:
                raise TopologyFixtureError(f"expectations list unit twice: {key}")
            values[key] = {**unit, "shape_id": shape["id"], "shape_name": shape["name"]}
    return values


# -------------------------------------------------------------------- in-process catalog and plan

def catalog_fixture(root: Path, *, source_fingerprint: str | None = None) -> dict[str, Any]:
    """Build the planning catalog of ``root`` the way ``job_target_catalog`` does, in process.

    This mirrors the catalog job's ``partition_repository``, ``discover_projects``,
    ``discover_build_systems``, ``catalog_build_targets`` and ``catalog_components`` tasks with the
    same library functions, so the plan compiled from it is the plan a run would compile. The
    fixture is untrusted input: descriptor bytes are hash-checked against the inventory before use.
    """
    from appsec_review.jobs.build_discovery import (
        android_descriptor_facts, descriptor_package, discover_build_units, required_image_profile,
        source_only_scopes,
    )
    from appsec_review.jobs.cataloging import (
        BUILD_FILES, PROJECT_FILES, PROJECT_FILE_SUFFIXES, inventory, source_fingerprint as fingerprint,
    )
    from appsec_review.jobs.engine_discovery import discover_unity
    from appsec_review.storage.shared import safe_path

    root = Path(root).resolve(strict=True)
    snapshot = inventory(root)
    files = list(snapshot["files"])
    accepted = {str(item["path"]): item for item in files}

    def read_bytes(relative: str) -> bytes | None:
        identity = accepted.get(relative)
        if identity is None or int(identity["size_bytes"]) > 64 * 1024:
            return None
        path = safe_path(root, relative)
        if not path.is_file():
            return None
        raw = path.read_bytes()
        if len(raw) != identity["size_bytes"] or hashlib.sha256(raw).hexdigest() != identity["sha256"]:
            raise TopologyFixtureError(f"descriptor changed during cataloging: {relative}")
        return raw

    def read_text(relative: str) -> str | None:
        raw = read_bytes(relative)
        try:
            return None if raw is None else raw.decode("utf-8")
        except UnicodeError:
            return None

    engines = discover_unity(files, read_text=lambda descriptor, _limit: read_bytes(str(descriptor["path"])) or b"")
    units = discover_build_units(files, read_text=read_text, engine_discovery=engines)
    targets = []
    for item in units:
        package = descriptor_package(root, item, files)
        if item.get("build_system") == "unity":
            package["inventory"] = list(item["markers"])
            facts = dict(item["descriptor_facts"])
        else:
            facts = android_descriptor_facts(package) or {}
        target = {**item, "descriptor_package": package,
                  "project_type": facts.get("kind", "unity" if item.get("engine") else "generic") if facts else "generic",
                  "descriptor_facts": facts or {}}
        targets.append({**target, "required_image_profile": required_image_profile(target)})
    engine_roots = [PurePosixPath(project["root"]) for project in engines["projects"]]
    projects = []
    for item in files:
        path = Path(item["path"])
        logical = PurePosixPath(item["path"])
        owner = next((value for value in engine_roots if value.as_posix() == "." or value in logical.parents), None)
        if owner is not None and (path.suffix.lower() in PROJECT_FILE_SUFFIXES or
                                  path.name == "package.json" and "Packages" in logical.relative_to(owner).parts[:-1]):
            continue
        if path.name in PROJECT_FILES or path.suffix.lower() in PROJECT_FILE_SUFFIXES:
            projects.append({"manifest": item["path"], "root": path.parent.as_posix(), "sha256": item["sha256"]})
    for project in engines["projects"]:
        marker = next(item for item in project["markers"] if PurePosixPath(item["path"]).name == "ProjectVersion.txt")
        projects.append({"manifest": marker["path"], "root": project["root"], "sha256": marker["sha256"],
                         "engine": project["engine"]})
    components = [{"component_id": f"component:{index:04d}", "root": project["root"],
                   "manifest": project["manifest"], "manifest_sha256": project["sha256"]}
                  for index, project in enumerate(projects, 1)] or [
        {"component_id": "component:0001", "root": ".", "manifest": None, "manifest_sha256": None}]
    build_files = [{"path": item["path"], "kind": Path(item["path"]).name, "sha256": item["sha256"]}
                   for item in files if Path(item["path"]).name in BUILD_FILES or Path(item["path"]).name in PROJECT_FILES
                   or Path(item["path"]).suffix.lower() in PROJECT_FILE_SUFFIXES]
    return {
        "source_fingerprint": source_fingerprint or fingerprint(root),
        "catalog_handoff_sha256": hashlib.sha256(json.dumps(snapshot["snapshot"], sort_keys=True).encode()).hexdigest(),
        "files": tuple(files), "projects": tuple(projects), "components": tuple(components),
        "build_files": tuple(build_files), "build_units": tuple(targets),
        "source_only_scopes": tuple(source_only_scopes(files, units)),
        "compile_databases": (), "accepted_artifacts": (),
        "gaps": tuple(snapshot["gaps"]) + tuple(engines["gaps"]),
        "engine_discovery": engines,
    }


def plan_fixture(root: Path = FIXTURE_ROOT, *, enable_swift: bool = False) -> dict[str, Any]:
    """The deterministic analysis plan ``job_target_analysis_plan`` would compile over ``root``.

    ``enable_swift`` mirrors ``tools.enable_swift`` (default false): the plan job removes Swift
    inventory from every planning input before compiling, and the accepted-plan reader rejects a plan
    that still carries it.
    """
    from appsec_review.jobs.job_target_analysis_plan.job import apply_swift_catalog_policy
    from appsec_review.jobs.job_target_analysis_plan.planning import deterministic_plan, summarize_catalog

    catalog = apply_swift_catalog_policy(catalog_fixture(root), enabled=enable_swift)
    summary = summarize_catalog(catalog, max_items=512, max_bytes=262144, sample_per_prefix=8)
    return deterministic_plan(catalog, summary)


# ----------------------------------------------------------------------------------- observation

@dataclass(frozen=True)
class ObservedUnit:
    root: str
    family: str
    build_system: str
    disposition: str
    owner_root: str | None
    required_image_profile: str
    recipe: Mapping[str, Any] | None
    materialization_root: str

    def ownership(self) -> dict[str, Any]:
        return {"disposition": self.disposition, "owner_root": self.owner_root}


@dataclass(frozen=True)
class Observation:
    units: Mapping[tuple[str, str], ObservedUnit]
    source_only_roots: tuple[tuple[str, str], ...]
    edges: tuple[tuple[str, str, str], ...]
    relations: tuple[tuple[str, str | None, str, str | None], ...]
    graph_gaps: tuple[tuple[str, tuple[str, ...]], ...]

    def units_under(self, root: str) -> list[ObservedUnit]:
        return [unit for key, unit in sorted(self.units.items())
                if root == "." or unit.root == root or unit.root.startswith(root + "/")]


def observe_plan(plan: Mapping[str, Any]) -> Observation:
    """Index what an accepted (or in-process) plan says about units, ownership, recipes and edges."""
    topology = plan.get("build_topology", {})
    graph = topology.get("executable_graph")
    actions = topology.get("build_actions", ())
    if not isinstance(graph, Mapping) or not isinstance(actions, list):
        raise TopologyFixtureError("plan has no executable build graph or build actions")
    roots = {node["build_unit_id"]: node["root"] for node in graph["nodes"]}
    nodes = {node["build_unit_id"]: node for node in graph["nodes"]}
    units: dict[tuple[str, str], ObservedUnit] = {}
    for action in actions:
        node = nodes.get(action["build_unit_id"])
        if node is None:
            raise TopologyFixtureError(f"build action without a graph node: {action['build_unit_id']}")
        recipe = action.get("recipe")
        # Recipes bind source_dir to the unit root (validate_build_recipe), so until a recipe can name a
        # wider source closure the materialized workspace of a unit is its own root.
        materialization = str(recipe["source_dir"]) if isinstance(recipe, Mapping) and recipe.get("source_dir") else str(action["root"])
        key = (str(action["root"]), str(action["build_system"]))
        if key in units:
            raise TopologyFixtureError(f"plan lists a build unit twice: {key}")
        units[key] = ObservedUnit(
            root=str(action["root"]), family=str(action["family"]), build_system=str(action["build_system"]),
            disposition=str(node["disposition"]), owner_root=roots.get(node.get("owner_build_unit_id")),
            required_image_profile=str(action.get("required_image_profile", action["family"])),
            recipe=recipe if isinstance(recipe, Mapping) else None, materialization_root=materialization)
    if set(nodes) != {action["build_unit_id"] for action in actions}:
        raise TopologyFixtureError("graph nodes and build actions do not account for the same units")
    return Observation(
        units=units,
        source_only_roots=tuple(sorted((str(item["root"]), str(item["language"]))
                                       for item in topology.get("source_only_scopes", ()))),
        edges=tuple(sorted((roots[edge["producer_build_unit_id"]], roots[edge["consumer_build_unit_id"]], edge["kind"])
                           for edge in graph.get("edges", ()))),
        relations=tuple(sorted((roots[item["consumer_build_unit_id"]], roots.get(item.get("producer_build_unit_id")),
                                str(item.get("kind")), item.get("interface"))
                               for item in graph.get("relations", ()))),
        graph_gaps=tuple(sorted((gap["code"], tuple(sorted(roots[uid] for uid in gap["build_unit_ids"])))
                                for gap in graph.get("coverage_gaps", ()))),
    )


# ------------------------------------------------------------------------------------ comparison

@dataclass(frozen=True)
class Check:
    """One expectation compared with one observation."""

    shape_id: str
    shape_name: str
    kind: str          # unit | component | relationship | edges
    subject: str       # the unit root / component root / "consumer -> producer"
    field: str         # discovered | ownership | build_mode | recipe | materialization_root | relationship | edges
    expected: Any
    observed: Any
    reason_code: str | None   # declared gap: the current runtime is not expected to satisfy this

    @property
    def ok(self) -> bool:
        return bool(self.expected == self.observed)

    @property
    def case_id(self) -> str:
        return f"{self.shape_id}/{self.kind}/{self.field}/{self.subject}"

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "ok": self.ok, "case_id": self.case_id}


def _recipe_view(recipe: Mapping[str, Any] | None, unit_root: str, materialization_root: str) -> dict[str, Any] | None:
    """Project an accepted recipe onto the expectation's shape: cwd relative to the materialization root."""
    if recipe is None:
        return None
    cwd = str(recipe.get("execution_cwd", {}).get("build", recipe.get("source_dir", unit_root)))
    if materialization_root != "." and cwd.startswith(materialization_root + "/"):
        cwd = cwd[len(materialization_root) + 1:]
    elif cwd == materialization_root:
        cwd = "."
    return {"cwd": cwd, "configure": [list(argv) for argv in recipe.get("configure_commands", ())],
            "build": [list(argv) for argv in recipe.get("build_commands", ())]}


def _reason(gaps: Mapping[str, str], field: str, *, present: bool, expected: Any) -> str | None:
    """The declared reason code for a field: its own gap, or the ``discovered`` gap when the subject is
    absent and the field expects something (an absent subject trivially meets an expected ``None``)."""
    if present:
        return gaps.get(field)
    return gaps.get(field) or (gaps.get("discovered") if expected is not None else None)


def compare(plan: Mapping[str, Any], expectations: Mapping[str, Any]) -> list[Check]:
    """Every expectation of the contract compared with the plan; ``ok`` and ``reason_code`` tell the story."""
    observation = observe_plan(plan)
    checks: list[Check] = []
    for shape in expectations["shapes"]:
        sid, name = shape["id"], shape["name"]
        for unit in shape.get("units", ()):
            gaps = unit.get("gaps", {})
            observed = observation.units.get((unit["root"], unit["build_system"]))
            present = observed is not None
            if not present and unit.get("may_be_absent"):
                # The contract is "never a standalone root"; no unit at all satisfies it.
                checks.append(Check(sid, name, "unit", unit["root"], "discovered", "optional", "optional", None))
                checks.append(Check(sid, name, "unit", unit["root"], "ownership", "absent", "absent", None))
                checks.append(Check(sid, name, "unit", unit["root"], "standalone", False, False, None))
                continue
            checks.append(Check(sid, name, "unit", unit["root"], "discovered", True, present, gaps.get("discovered")))
            expected_ownership = {"disposition": unit["disposition"], "owner_root": unit["owner_root"]}
            checks.append(Check(sid, name, "unit", unit["root"], "ownership", expected_ownership,
                                observed.ownership() if observed is not None else None,
                                _reason(gaps, "ownership", present=present, expected=expected_ownership)))
            checks.append(Check(sid, name, "unit", unit["root"], "standalone", unit["dispatch_standalone"],
                                observed.disposition == "independent" if observed is not None else None,
                                _reason(gaps, "standalone", present=present, expected=unit["dispatch_standalone"])))
        for component in shape.get("components", ()):
            gaps = component.get("gaps", {})
            root = component["root"]
            if component["build_system"] == "source-only":
                scope = (root, component["family"]) in observation.source_only_roots
                identity = {"family": component["family"], "build_system": "source-only"}
                checks.append(Check(sid, name, "component", root, "discovered", identity,
                                    identity if scope else None, gaps.get("discovered")))
                # A source-only scope is the plan's own disposition for an interpreted tree without a build.
                checks.append(Check(sid, name, "component", root, "build_mode", "source-only",
                                    "source-only" if scope else None,
                                    _reason(gaps, "build_mode", present=scope, expected="source-only")))
            else:
                observed_unit = observation.units.get((root, component["build_system"]))
                present = observed_unit is not None
                identity = {"family": component["family"], "build_system": component["build_system"]}
                checks.append(Check(sid, name, "component", root, "discovered", identity,
                                    {"family": observed_unit.family, "build_system": observed_unit.build_system}
                                    if observed_unit is not None else None, gaps.get("discovered")))
                # No plan field carries a per-component build mode yet; a future plan records it on the
                # build action as ``build_mode``.
                action_mode = next((action.get("build_mode") for action in plan["build_topology"]["build_actions"]
                                    if action["root"] == root and action["build_system"] == component["build_system"]), None)
                checks.append(Check(sid, name, "component", root, "build_mode", component["build_mode"], action_mode,
                                    _reason(gaps, "build_mode", present=present, expected=component["build_mode"])))
                if "required_image_profile" in component:
                    checks.append(Check(sid, name, "component", root, "required_image_profile",
                                        component["required_image_profile"],
                                        observed_unit.required_image_profile if observed_unit is not None else None,
                                        _reason(gaps, "required_image_profile", present=present,
                                                expected=component["required_image_profile"])))
                checks.append(Check(sid, name, "component", root, "materialization_root",
                                    component["materialization_root"],
                                    observed_unit.materialization_root if observed_unit is not None else None,
                                    _reason(gaps, "materialization_root", present=present,
                                            expected=component["materialization_root"])))
                recipe = (_recipe_view(observed_unit.recipe, observed_unit.root, component["materialization_root"])
                          if observed_unit is not None else None)
                checks.append(Check(sid, name, "component", root, "recipe", component["recipe"], recipe,
                                    _reason(gaps, "recipe", present=present, expected=component["recipe"])))
            if component.get("dispatchable", True) is False:
                # Nothing under a non-dispatchable component may carry a recipe for a build image.
                dispatched = sorted(unit.root for unit in observation.units_under(root) if unit.recipe is not None)
                checks.append(Check(sid, name, "component", root, "dispatch", [], dispatched, gaps.get("dispatch")))
        for relationship in shape.get("relationships", ()):
            gaps = relationship.get("gaps", {})
            consumer, producer = relationship["consumer_root"], relationship["producer_root"]
            subject = f"{consumer}->{producer}"
            if relationship["scope"] == "cross-component":
                observed_edge = (producer, consumer, relationship["kind"]) in observation.edges
            else:
                # Intra-component dependencies are recorded relations (evidence), never scheduling edges.
                observed_edge = any(item[0] == consumer and item[1] == producer for item in observation.relations)
            checks.append(Check(sid, name, "relationship", subject, "relationship", True, observed_edge,
                                gaps.get("relationship")))
        expected_edges = sorted((item["producer_root"], item["consumer_root"], item["kind"])
                                for item in shape.get("relationships", ()) if item["scope"] == "cross-component")
        shape_roots = tuple(shape["paths"])
        observed_edges = sorted(edge for edge in observation.edges
                                if any(edge[1] == root or edge[1].startswith(root + "/") for root in shape_roots))
        checks.append(Check(sid, name, "edges", ",".join(shape_roots), "edges",
                            [list(edge) for edge in expected_edges], [list(edge) for edge in observed_edges], None))
    return checks


def unexpected_units(plan: Mapping[str, Any], expectations: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Units the plan has that no expectation mentions: a fixture/contract drift, never silently fine."""
    observation = observe_plan(plan)
    known = set(expected_units(expectations))
    return sorted(key for key in observation.units if key not in known)


def render_lines(checks: Sequence[Check], *, unexpected: Sequence[tuple[str, str]] = ()) -> list[str]:
    """One line per check, then a summary; mismatches with a declared reason code are labelled as gaps."""
    lines = []
    for check in checks:
        if check.ok:
            label = "ok   " if check.reason_code is None else "ok   (unexpected: declared gap now met)"
        else:
            label = f"GAP  [{check.reason_code}]" if check.reason_code else "FAIL "
        lines.append(f"   topology {check.shape_id} {check.shape_name} {check.kind} {check.subject} {check.field}: "
                     f"{label} expected={json.dumps(check.expected, sort_keys=True)} "
                     f"observed={json.dumps(check.observed, sort_keys=True)}")
    for root, system in unexpected:
        lines.append(f"   topology ? unexpected unit {root} ({system}): not described by the expectations")
    met = sum(check.ok for check in checks)
    declared = sum(not check.ok and check.reason_code is not None for check in checks)
    undeclared = sum(not check.ok and check.reason_code is None for check in checks)
    flipped = sum(check.ok and check.reason_code is not None for check in checks)
    lines.append(f"   topology summary checks={len(checks)} met={met} declared_gaps={declared} "
                 f"undeclared_failures={undeclared} declared_gaps_now_met={flipped} unexpected_units={len(unexpected)}")
    return lines


def verdict(checks: Sequence[Check], unexpected: Sequence[tuple[str, str]] = ()) -> int:
    """0 when every expectation is met or is a declared gap, 1 otherwise (including a gap that flipped)."""
    if unexpected:
        return 1
    if any(not check.ok and check.reason_code is None for check in checks):
        return 1
    if any(check.ok and check.reason_code is not None for check in checks):
        return 1
    return 0


# -------------------------------------------------------------------------------------- prepare

def prepare(into: Path, *, source: Path = FIXTURE_ROOT) -> Path:
    """Copy the fixture into ``into`` (new or empty) after verifying MANIFEST.json; return ``into``."""
    into = Path(into)
    drift = manifest_drift(source)
    if drift:
        raise TopologyFixtureError("fixture does not match its manifest: " + "; ".join(drift))
    if into.exists() and (not into.is_dir() or any(into.iterdir())):
        raise TopologyFixtureError(f"{into}: must be a new or empty directory")
    into.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, into, symlinks=False, dirs_exist_ok=True)
    copied = manifest_drift(into)
    if copied:
        raise TopologyFixtureError("copied fixture does not match the manifest: " + "; ".join(copied))
    return into


def load_run_plan(run_root: Path) -> Mapping[str, Any]:
    """The run's accepted ``job_target_analysis_plan`` plan, through the normal verified reader."""
    from appsec_review.jobs.job_target_analysis_plan.job import load_accepted_plan

    return load_accepted_plan(Path(run_root))


# ------------------------------------------------------------------------------------------ CLI

def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m appsec_review.acceptance.topology",
                                     description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare", help="copy the fixture into a new directory as a review target")
    prep.add_argument("--into", type=Path, required=True, help="new or empty directory (for example targets/topology-monorepo)")
    score = commands.add_parser("score", help="diff a run's accepted analysis plan against the expectations")
    score.add_argument("--run", required=True, help="a run directory, or a run id under <repo>/runs")
    score.add_argument("--expectations", type=Path, default=EXPECTATIONS_PATH)
    score.add_argument("--json", action="store_true", help="print the checks as JSON")
    evaluate = commands.add_parser("evaluate", help="compile the plan in process over a fixture copy and diff it")
    evaluate.add_argument("--target", type=Path, default=FIXTURE_ROOT, help="the fixture or a prepared copy")
    evaluate.add_argument("--expectations", type=Path, default=EXPECTATIONS_PATH)
    evaluate.add_argument("--json", action="store_true")
    manifest = commands.add_parser("manifest", help="verify MANIFEST.json, or regenerate it with --write")
    manifest.add_argument("--root", type=Path, default=FIXTURE_ROOT)
    manifest.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            print(prepare(args.into))
            return 0
        if args.command == "manifest":
            if args.write:
                print(write_manifest(args.root))
                return 0
            drift = manifest_drift(args.root)
            for line in drift:
                print(f"topology manifest: {line}")
            print("topology manifest: ok" if not drift else f"topology manifest: {len(drift)} drifted entries")
            return 0 if not drift else 1
        expectations = load_expectations(args.expectations)
        if args.command == "score":
            from .funnel import resolve_run
            run_root = resolve_run(args.run, REPOSITORY)
            if not (run_root / "data").is_dir():
                print(f"topology: no run tree at {run_root}", file=sys.stderr)
                return 2
            plan = load_run_plan(run_root)
        else:
            plan = plan_fixture(args.target)
        checks = compare(plan, expectations)
        unexpected = unexpected_units(plan, expectations)
    except (TopologyFixtureError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"topology: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"checks": [check.as_dict() for check in checks],
                          "unexpected_units": [list(item) for item in unexpected]}, indent=1, sort_keys=True))
    else:
        print("\n".join(render_lines(checks, unexpected=unexpected)))
    return verdict(checks, unexpected)


if __name__ == "__main__":
    raise SystemExit(main())
