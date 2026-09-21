"""Vendor pre-pass node declaration (ADR-0010, task V02): the acceptance clauses, proven from data.

Nothing here carries a copy of the answer. The expected nodes, dependencies, assembly edges, skip
reasons and file lists are read from the accepted ADR's tables, from the three fixtures under
``docs/proposals/vendor-prepass/`` and from the merged output-contract records, and the declared graph
must agree with all of them at once. The one pinned constant is ``CONTRACT_FILES_NOT_IN_THE_ADR``: a
known, already-merged divergence that has to be written down rather than appear silently.

Files are located from the module ``ROOT`` (``/opt/process`` in the code-server, whose siblings are
``/opt/docs`` and ``/opt/schemas``), never through a ``<repo>/appsec-review-process`` literal. A
missing ADR or fixture is a failure, not a skip.
"""
from __future__ import annotations

import ast
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT.parent / "docs"
sys.path.insert(0, str(ROOT))

from execution_state import Blocked
import job_graph
import validate_job_output
from validate_design_parity import validate_manifest
from worker_result import load_contract, validate_worker_result

ADR = DOCS / "decisions" / "ADR-0010-vendor-prepass-decomposition.md"
PROPOSALS = DOCS / "proposals" / "vendor-prepass"
NODE_FIXTURE = PROPOSALS / "job-nodes.proposal.json"
STEP_MAP = PROPOSALS / "legacy-step-map.proposal.json"
PRODUCERS = PROPOSALS / "threat-workbench-producers.proposal.yaml"
CONTRACTS = ROOT / "registry" / "output-contracts"
ASSEMBLY = "02-evidence-assembly"
NUMBER_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
                "nine": 9, "ten": 10, "eleven": 11, "twelve": 12}

# V04 and V07 merged (PR 18, 19, 21) with contract files the ADR's contract table and the node fixture
# do not list: the probe receipt every skippable node needs, and for binary-hardening a redaction
# receipt, with binskim.sarif made conditional because a SKIPPED node never ran BinSkim. Their own
# suites pin the same differences. The graph follows the contract records; this pin makes the
# divergence explicit and fails when either side is reconciled, so that it is then deleted.
CONTRACT_FILES_NOT_IN_THE_ADR = {
    "iac-config-evidence": ({"outputs/applicability-probe-receipt.json"}, set()),
    "container-image-inventory": ({"outputs/container-image-applicability.json"}, set()),
    "binary-hardening": ({"outputs/binary-hardening-applicability.json", "outputs/redaction-receipt.json"},
                         {"outputs/binskim.sarif"}),
}


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def backticked(cell):
    return re.findall(r"`([^`]+)`", cell)


def adr_table(text, first_header):
    """Rows of the one markdown table whose first header cell is ``first_header``."""
    lines = text.replace("\r\n", "\n").split("\n")
    starts = [i for i, line in enumerate(lines) if line.startswith(f"| {first_header} |")]
    if len(starts) != 1:
        raise AssertionError(f"expected exactly one ADR table headed {first_header!r}, found {len(starts)}")
    rows = []
    for line in lines[starts[0] + 2:]:
        if not line.startswith("|"):
            break
        rows.append([cell.strip() for cell in line.strip().strip("|").split("|")])
    return rows


class Sources:
    """Everything the clauses are checked against, loaded once and never skipped."""

    def __init__(self):
        for path in (ADR, NODE_FIXTURE, STEP_MAP, PRODUCERS, job_graph.GRAPH, ROOT / "design-parity-manifest.json",
                     ROOT / "worker-result-contract.json", ROOT / "TODO.md", ROOT / "dagster_workflow.py"):
            if not path.is_file():
                raise AssertionError(f"required source is not reachable from the module ROOT: {path}")
        self.adr_text = ADR.read_text(encoding="utf-8")
        self.fixture = read_json(NODE_FIXTURE)
        self.proposed = {node["proposed_job_id"]: node for node in self.fixture["proposed_nodes"]}
        self.adopted = {job: node for job, node in self.proposed.items() if node["adopted"]}
        self.graph = job_graph.load_graph()
        self.jobs = self.graph["jobs"]
        self.manifest = read_json(ROOT / "design-parity-manifest.json")
        self.rows = {row["id"]: row for row in self.manifest["jobs"]}
        self.registry = load_contract()
        node_rows = adr_table(self.adr_text, "Proposed node")
        self.adr_nodes, self.adr_not_adopted = {}, set()
        for row in node_rows:
            (job,) = backticked(row[0])
            if "~~" in row[0]:
                self.adr_not_adopted.add(job)
            else:
                self.adr_nodes[job] = row
        self.adr_files = {backticked(row[0])[0]: {f"outputs/{name}" for name in backticked(row[1])}
                          for row in adr_table(self.adr_text, "Contract")}

    def assembly_edges(self, job):
        return [edge for edge in self.jobs[ASSEMBLY]["dependencies"] if edge["job"] == job]


class VendorPrepassGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = Sources()
        cls.new = sorted(cls.s.adopted)
        cls.reason = cls.s.fixture["proposed_new_skip_reason"]["id"]

    # ---- the set of nodes -------------------------------------------------------------------------

    def test_declared_nodes_are_the_fixtures_adopted_nodes_and_the_adr_node_table_rows(self):
        s = self.s
        self.assertTrue(self.new)
        self.assertEqual(set(s.adopted), set(s.adr_nodes))
        self.assertEqual({job for job, node in s.proposed.items() if not node["adopted"]}, s.adr_not_adopted)
        self.assertEqual({job for job in s.proposed if job in s.jobs}, set(s.adopted))
        for job in s.adr_not_adopted:
            self.assertNotIn(job, s.jobs)
            self.assertNotIn(job, s.rows)
            self.assertFalse((ROOT / "registry" / "job-templates" / f"{job}.json").exists())
        # No alias: a graph node that emits one of the ADR's contracts is one of the ADR's nodes.
        proposed_contracts = {node["proposed_output_contract_id"] for node in s.proposed.values()}
        self.assertEqual({job for job, node in s.jobs.items() if node["contract"] in proposed_contracts}, set(s.adopted))

    def test_node_count_matches_the_adr(self):
        s = self.s
        (word,) = re.findall(r"^(\w+) new `02-evidence-pregather` nodes", s.adr_text, flags=re.M)
        (edges,) = re.findall(r"`02-evidence-assembly` gains (\w+) required edges", s.adr_text)
        self.assertEqual(len(self.new), NUMBER_WORDS[word.lower()])
        self.assertEqual(len([e for e in s.jobs[ASSEMBLY]["dependencies"] if e["job"] in s.adopted]),
                         NUMBER_WORDS[edges.lower()])
        result = validate_manifest(s.manifest)
        self.assertEqual(result["status"], "PASS", result["errors"])
        self.assertEqual(result["job_count"], len(s.jobs))
        (stated,) = re.findall(r"Every one of the (\d+) graph job IDs appears in this backlog",
                               (ROOT / "TODO.md").read_text(encoding="utf-8"))
        self.assertEqual(int(stated), len(s.jobs))
        backlog = (ROOT / "TODO.md").read_text(encoding="utf-8")
        for job in s.jobs:
            self.assertIn(f"`{job}`", backlog, f"{job} is a graph job ID the backlog never names")

    # ---- validity and order -----------------------------------------------------------------------

    def test_graph_validates_is_acyclic_and_the_checks_are_live(self):
        s = self.s
        job_graph.validate_graph(deepcopy(s.graph))
        remaining = {job: {edge["job"] for edge in node["dependencies"]} for job, node in s.jobs.items()}
        order = []
        while remaining:
            ready = sorted(job for job, deps in remaining.items() if not deps & set(remaining))
            self.assertTrue(ready, f"dependency cycle among {sorted(remaining)}")
            order += ready
            for job in ready:
                del remaining[job]
        for job in self.new:
            for edge in s.jobs[job]["dependencies"]:
                self.assertLess(order.index(edge["job"]), order.index(job))
            self.assertLess(order.index(job), order.index(ASSEMBLY))
        # The validators are not vacuous for the new nodes: a back edge and a wrong edge contract fail.
        leaf = next(job for job in self.new if any(e["job"] in s.adopted for e in s.jobs[job]["dependencies"]))
        upstream = next(e["job"] for e in s.jobs[leaf]["dependencies"] if e["job"] in s.adopted)
        cyclic = deepcopy(s.graph)
        cyclic["jobs"][upstream]["dependencies"].append(
            {"job": leaf, "kind": "required", "contract": s.jobs[leaf]["contract"], "allowed_skip_reasons": []})
        with self.assertRaisesRegex(ValueError, "dependency cycle"):
            job_graph.validate_graph(cyclic)
        wrong = deepcopy(s.graph)
        wrong["jobs"][leaf]["dependencies"][0]["contract"] = "pregather"
        with self.assertRaisesRegex(ValueError, "dependency contract mismatch"):
            job_graph.validate_graph(wrong)

    def test_no_pregather_node_depends_on_characterization_or_any_later_lane(self):
        s = self.s
        for job, node in s.jobs.items():
            if job.startswith("02-"):
                for edge in node["dependencies"]:
                    self.assertRegex(edge["job"], r"^0[02]-", f"{job} depends on {edge['job']}")

        def ancestors(job, seen):
            for edge in s.jobs[job]["dependencies"]:
                if edge["job"] not in seen:
                    seen.add(edge["job"])
                    ancestors(edge["job"], seen)
            return seen
        for job in self.new:
            above = ancestors(job, set())
            self.assertNotIn(ASSEMBLY, above)
            for name in above:
                self.assertRegex(name, r"^0[02]-")
        self.assertEqual(s.fixture["cycle_rule"], "no proposed 02-* node depends on 01-*, 03-* or any later node")

    def test_no_edge_runs_from_a_new_node_to_anything_but_a_sibling_or_the_assembly_join(self):
        s = self.s
        for consumer, node in s.jobs.items():
            for edge in node["dependencies"]:
                if edge["job"] in s.adopted:
                    self.assertTrue(consumer == ASSEMBLY or consumer in s.adopted,
                                    f"{consumer} has a direct edge from {edge['job']}")
        for prefix in ("03-", "06-", "15-"):
            lane_nodes = [job for job in s.jobs if job.startswith(prefix)]
            self.assertTrue(lane_nodes)
            for job in lane_nodes:
                self.assertFalse({edge["job"] for edge in s.jobs[job]["dependencies"]} & set(s.adopted))

    # ---- dependencies -----------------------------------------------------------------------------

    def test_dependencies_agree_across_the_graph_the_adr_the_fixture_and_the_legacy_step_map(self):
        s = self.s
        steps = read_json(STEP_MAP)["steps"]
        for job in self.new:
            with self.subTest(job=job):
                declared = s.jobs[job]["dependencies"]
                self.assertEqual(declared, s.adopted[job]["dependencies"])
                names = [edge["job"] for edge in declared]
                self.assertEqual(len(names), len(set(names)))
                self.assertEqual(sorted(names), sorted(backticked(s.adr_nodes[job][2])))
                for edge in declared:
                    self.assertEqual(edge["kind"], "required")
                    self.assertEqual(edge["contract"], s.jobs[edge["job"]]["contract"])
                    self.assertEqual(edge["allowed_skip_reasons"], [])
                legacy = {step for tool in s.adopted[job]["tool_instances"] for step in tool.get("legacy_steps", [])}
                mapped = [step for step in steps if step.get("proposed_job_id") == job]
                self.assertEqual({step["legacy_step"] for step in mapped}, legacy)
                for step in mapped:
                    self.assertEqual(sorted(step["dependencies"]), sorted(names), step["legacy_step"])
                self.assertEqual(s.rows[job]["graph"]["dependencies"], names)
        self.assertTrue(any(step.get("proposed_job_id") in s.adopted for step in steps))

    # ---- the assembly join and the skip reason ----------------------------------------------------

    def test_each_new_node_joins_assembly_once_and_only_the_conditional_edges_may_skip(self):
        s = self.s
        skippable = set()
        for job in self.new:
            with self.subTest(job=job):
                (edge,) = s.assembly_edges(job)
                self.assertTrue(s.adopted[job]["joins_02_evidence_assembly"])
                self.assertEqual(edge, {"job": job, **s.adopted[job]["evidence_assembly_edge"]})
                self.assertEqual(edge["kind"], "required")
                self.assertEqual(edge["contract"], s.jobs[job]["contract"])
                marked = "†" in s.adr_nodes[job][4]
                self.assertEqual(marked, "SKIPPED" in s.adopted[job]["permitted_terminal_statuses"])
                self.assertEqual(edge["allowed_skip_reasons"], [self.reason] if marked else [])
                if not marked:
                    self.assertEqual(s.adr_nodes[job][4], "none")
                else:
                    self.assertEqual(backticked(s.adr_nodes[job][4]), [self.reason])
                    skippable.add(job)
        (count,) = re.findall(r"`SKIPPED` only for the (\w+) nodes whose assembly edge authorizes a skip reason", s.adr_text)
        self.assertEqual(len(skippable), NUMBER_WORDS[count.lower()])
        uses = {(consumer, edge["job"]) for consumer, node in s.jobs.items() for edge in node["dependencies"]
                if self.reason in edge["allowed_skip_reasons"]}
        self.assertEqual(uses, {(ASSEMBLY, job) for job in skippable})
        self.assertEqual(s.jobs[ASSEMBLY]["join_policy"]["mode"], s.fixture["consumer_join"]["join_policy_mode"])
        self.assertEqual(s.fixture["consumer_join"]["job"], ASSEMBLY)

    def test_the_skip_reason_is_registered_and_every_consumer_of_the_registry_accepts_it(self):
        s = self.s
        registered = s.registry["skip_reasons"]
        self.assertEqual(len(registered), len(set(registered)))
        self.assertEqual(set(registered), set(s.fixture["registered_skip_reasons_checked"]) | {self.reason})
        self.assertNotIn(self.reason, s.fixture["registered_skip_reasons_checked"])
        self.assertIn(f"`{self.reason}`", s.adr_text)
        every_edge_reason = {reason for node in s.jobs.values() for edge in node["dependencies"]
                             for reason in edge["allowed_skip_reasons"]}
        self.assertLessEqual(every_edge_reason, set(registered))
        envelope = {
            "schema": "appsec-review/worker-result-envelope/1.0", "run_id": "run-1", "attempt_id": "attempt-1",
            "worker_kind": "pinned_container", "execution_status": "SKIPPED", "acceptance_status": "CURRENT",
            "input_fingerprint": "sha256:" + "a" * 64, "started_at": "2026-09-20T10:00:00Z",
            "finished_at": "2026-09-20T10:01:00Z", "summary": "no matching inputs", "artifacts": [], "gaps": [],
            "skip_reason": self.reason, "cause": None, "retry": {"allowed": False, "resume_command": None},
            "superseded_by_attempt_id": None,
        }
        other = next(reason for reason in registered if reason != self.reason)
        for job in self.new:
            with self.subTest(job=job):
                (edge,) = s.assembly_edges(job)
                may_skip = bool(s.adopted[job]["evidence_assembly_edge"]["allowed_skip_reasons"])
                allowed, errors = validate_job_output._skip_reasons(s.graph, job, ASSEMBLY)
                self.assertEqual((allowed, errors), ({self.reason} if may_skip else set(), []))
                document = dict(envelope, job_id=job, output_contract=s.jobs[job]["contract"])
                problems = validate_worker_result(document, allowed_skip_reasons=allowed)
                if may_skip:
                    self.assertEqual(problems, [])
                    self.assertIsNone(job_graph.dependency_ok(edge, {"status": "SKIPPED", "reason": self.reason}))
                    with self.assertRaisesRegex(Blocked, "incompatible skip"):
                        job_graph.dependency_ok(edge, {"status": "SKIPPED", "reason": other})
                    wrong = validate_worker_result(dict(document, skip_reason=other), allowed_skip_reasons=allowed)
                    self.assertIn("is not authorized for this dependency edge", "\n".join(wrong))
                else:
                    self.assertIn("is not authorized for this dependency edge", "\n".join(problems))
                    with self.assertRaisesRegex(Blocked, "incompatible skip"):
                        job_graph.dependency_ok(edge, {"status": "SKIPPED", "reason": self.reason})
                # failure is never a skip, on any of the new edges
                with self.assertRaisesRegex(Blocked, "dependency not accepted"):
                    job_graph.dependency_ok(edge, {"status": "FAILED"})
                for inner in s.jobs[job]["dependencies"]:
                    with self.assertRaisesRegex(Blocked, "incompatible skip"):
                        job_graph.dependency_ok(inner, {"status": "SKIPPED", "reason": self.reason})

    # ---- the node records -------------------------------------------------------------------------

    def test_every_new_node_is_an_unimplemented_templateless_planned_node(self):
        s = self.s
        for job in self.new:
            with self.subTest(job=job):
                node, proposed = s.jobs[job], s.adopted[job]
                self.assertIs(node["implemented"], False)
                self.assertIsNone(node["template"])
                self.assertEqual(node["namespace"], job)
                self.assertEqual(node["lane"], proposed["lane"])
                self.assertEqual(node["contract"], proposed["proposed_output_contract_id"])
                self.assertEqual(backticked(s.adr_nodes[job][3]), [node["contract"]])
                self.assertIsInstance(node["planned_scope"], str)
                self.assertGreater(len(node["planned_scope"]), 40)
                self.assertEqual(set(node), {"lane", "contract", "template", "implemented", "namespace",
                                             "dependencies", "planned_scope", "required_artifacts"})
                self.assertFalse((ROOT / "registry" / "job-templates" / f"{job}.json").exists())
                self.assertFalse(proposed["registered"] or proposed["runnable"])

    def test_required_artifacts_are_exactly_the_merged_contracts_required_files(self):
        s = self.s
        self.assertLessEqual(set(CONTRACT_FILES_NOT_IN_THE_ADR), {s.jobs[job]["contract"] for job in self.new})
        for job in self.new:
            contract_id = s.jobs[job]["contract"]
            with self.subTest(job=job):
                record = read_json(CONTRACTS / f"{contract_id}.json")
                self.assertEqual(record["contract_id"], contract_id)
                artifacts = s.jobs[job]["required_artifacts"]
                self.assertEqual(artifacts, record["required_files"])
                self.assertEqual(len(artifacts), len(set(artifacts)))
                self.assertEqual(artifacts[:2], ["manifest.json", "status.json"])
                self.assertIn(record["result_schema"]["artifact"], artifacts)
                added, dropped = CONTRACT_FILES_NOT_IN_THE_ADR.get(contract_id, (set(), set()))
                in_fixture = set(s.adopted[job]["required_artifacts"])
                in_adr = s.adr_files[contract_id] | {"manifest.json", "status.json"}
                self.assertEqual(in_fixture, in_adr)
                self.assertEqual(set(artifacts) - in_fixture, added)
                self.assertEqual(in_fixture - set(artifacts), dropped)
        promised = PRODUCERS.read_text(encoding="utf-8").replace("\r\n", "\n")
        for block in promised.split("- job: ")[1:]:
            job = block.split("\n", 1)[0].strip()
            if job in s.adopted and "artifacts:" in block:
                listed = set(re.findall(r"outputs/[A-Za-z0-9._-]+", block.split("artifacts:", 1)[1].split("\n\n", 1)[0]))
                self.assertTrue(listed, job)
                self.assertLessEqual(listed, set(s.jobs[job]["required_artifacts"]), job)

    # ---- readiness --------------------------------------------------------------------------------

    def test_no_readiness_flag_turned_true_and_the_blockers_are_the_honest_ones(self):
        s = self.s
        backlog = (ROOT / "TODO.md").read_text(encoding="utf-8")
        (sentence,) = re.findall(r"Implemented baseline job nodes are ([^.]+)\.", backlog)
        self.assertEqual({job for job, node in s.jobs.items() if node["implemented"]}, set(backticked(sentence)))
        self.assertFalse(set(backticked(sentence)) & set(s.adopted))
        for job in self.new:
            with self.subTest(job=job):
                row, proposed = s.rows[job], s.adopted[job]
                self.assertIs(row["graph"]["implemented"], False)
                self.assertEqual(row["readiness"], "missing_prerequisites")
                self.assertIsNone(row["registry"])
                self.assertEqual(row["execution"], {"mode": "none", "worker": None, "validator": None})
                self.assertEqual(row["dagster"]["lifecycle_binding"]["kind"], "blocked_op")
                self.assertEqual(row["dagster"]["standalone_jobs"], [])
                self.assertEqual(row["dagster"]["launcher_jobs"], [])
                self.assertEqual(row["qualification"], {"levels": ["none"], "references": []})
                self.assertEqual(row["permissions"], [])
                for gap in ("missing_worker", "missing_validator", "missing_registry_composition", "no_qualification"):
                    self.assertIn(gap, row["gaps"])
                record = read_json(CONTRACTS / f"{s.jobs[job]['contract']}.json")
                self.assertEqual(row["output"], {
                    "contract": record["contract_id"],
                    "contract_file": f"appsec-review-process/registry/output-contracts/{record['contract_id']}.json",
                    "schema_file": "schemas/" + record["result_schema"]["schema_file"],
                    "claim_class": record["claim_class"]["claim_class_id"]})
                self.assertEqual(record["claim_class"], proposed["proposed_claim_class"])
                blocker = row["next_prerequisite"]
                self.assertIn("WORKER_NOT_IMPLEMENTED", blocker)
                self.assertIn("validate_job_output.py", blocker)
                owner = re.match(r"M\d+", proposed["owning_followup_batch"]).group(0)
                self.assertIn(f"({owner})", blocker)
                if proposed["worker_kind"] == "pinned_container":
                    self.assertIn("B13", blocker)
                if "M02" in proposed["owning_followup_batch"]:
                    self.assertIn("M02", blocker)
                if any(tool["tool_id"] == "grype" for tool in proposed["tool_instances"]):
                    for task in ("V16", "V17", "V18"):
                        self.assertIn(task, blocker)
                if "reference-table-identity.json" in " ".join(proposed["required_artifacts"]):
                    self.assertIn("reference table", blocker)
        (full_review,) = [item for item in s.manifest["dagster_inventory"]["standalone_relationships"]
                          if item["job"] == "full_review"]
        self.assertEqual(set(full_review["lifecycle_jobs"]), set(s.jobs))

    # ---- the blocked stub -------------------------------------------------------------------------

    def workflow_tree(self):
        return ast.parse((ROOT / "dagster_workflow.py").read_text(encoding="utf-8"))

    def test_full_review_gives_every_new_node_the_graph_driven_blocked_stub(self):
        """``LIFECYCLE_OPS`` is a comprehension over the validated graph: every node becomes
        ``blocked_op(name, node)`` unless it is named in the exclusion tuple or rebound afterwards."""
        tree = self.workflow_tree()
        comprehension, rebound = None, set()
        for statement in tree.body:
            if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
                continue
            target = statement.targets[0]
            if isinstance(target, ast.Name) and target.id == "LIFECYCLE_OPS":
                comprehension = statement.value
            if (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
                    and target.value.id == "LIFECYCLE_OPS"):
                rebound.add(ast.literal_eval(target.slice))
        self.assertIsInstance(comprehension, ast.DictComp)
        self.assertEqual(ast.unparse(comprehension.value), "blocked_op(name, node)")
        (generator,) = comprehension.generators
        self.assertEqual(ast.unparse(generator.iter), "LIFECYCLE.items()")
        (condition,) = generator.ifs
        self.assertIsInstance(condition.ops[0], ast.NotIn)
        excluded = set(ast.literal_eval(condition.comparators[0]))
        for job in self.new:
            self.assertNotIn(job, excluded | rebound)
        source = ast.unparse(tree)
        self.assertIn("LIFECYCLE = load_graph()['jobs']", source)

    def test_the_blocked_stub_records_worker_not_implemented_for_every_new_node(self):
        """Runs the real ``blocked_op`` source against stand-ins for the Dagster decorator, so the
        behaviour is proven on a host without Dagster; the live check belongs to the coordinator."""
        (function,) = [node for node in self.workflow_tree().body
                       if isinstance(node, ast.FunctionDef) and node.name == "blocked_op"]
        written = {}

        class Failure(Exception):
            def __init__(self, description, metadata=None):
                super().__init__(description)
                self.metadata = metadata

        class MetadataValue:
            path = staticmethod(lambda value: value)

        def op(**declared):
            def wrap(body):
                body.declared = declared
                return body
            return wrap

        class Context:
            run_id = "dagster-run-v02"

        with tempfile.TemporaryDirectory() as scratch:
            namespace = {"op": op, "In": lambda kind: kind, "Failure": Failure, "MetadataValue": MetadataValue,
                         "now": lambda: "2026-09-20T00:00:00+00:00",
                         "data_path": lambda run_id, *parts: Path(scratch, run_id, *parts),
                         "atomic_json": lambda path, value: written.__setitem__(str(path), deepcopy(value))}
            exec(compile(ast.Module(body=[function], type_ignores=[]), "dagster_workflow.py", "exec"), namespace)
            for job in self.new:
                with self.subTest(job=job):
                    written.clear()
                    stub = namespace["blocked_op"](job, self.s.jobs[job])
                    self.assertEqual(stub.declared["name"], "job_" + job.replace("-", "_"))
                    self.assertIn("BLOCKED: worker not implemented", stub.declared["description"])
                    upstream = [{"status": "OK"}] * len(self.s.jobs[job]["dependencies"])
                    with self.assertRaisesRegex(Failure, re.escape(job) + ": WORKER_NOT_IMPLEMENTED; no downstream acceptance"):
                        stub(Context(), {"engagement_run_id": "run-v02"}, upstream)
                    ((path, record),) = written.items()
                    self.assertTrue(path.endswith(str(Path("orchestration", "dagster", Context.run_id, job, "pre.json"))))
                    self.assertEqual(record["status"], "BLOCKED")
                    self.assertEqual(record["reason"], "WORKER_NOT_IMPLEMENTED")
                    self.assertEqual(record["job"], job)
                    self.assertEqual(record["definition"], self.s.jobs[job])
                    self.assertEqual(record["dependency_count"], len(upstream))
                    self.assertIn("--job full_review", record["resume_command"])

    def test_with_dagster_installed_full_review_registers_a_blocked_op_for_every_new_node(self):
        if importlib.util.find_spec("dagster") is None:
            self.skipTest("Dagster is not installed on this host; this case runs in the code-server. The two "
                          "tests above prove the same behaviour from the graph-driven source without it.")
        import dagster_workflow
        registered = {node.name for node in dagster_workflow.full_review.graph.node_defs}
        for job in self.new:
            stub = dagster_workflow.LIFECYCLE_OPS[job]
            self.assertEqual(stub.name, "job_" + job.replace("-", "_"))
            self.assertIn(stub.name, registered)
            self.assertIn("BLOCKED: worker not implemented", stub.description)
            self.assertIs(dagster_workflow.LIFECYCLE[job]["implemented"], False)

    # ---- generated views --------------------------------------------------------------------------

    def test_generated_views_name_every_new_node_and_are_current(self):
        s = self.s
        self.assertEqual((DOCS / "phase-1-job-graph.mmd").read_text(encoding="utf-8"), job_graph.mermaid(s.graph))
        for name in ("phase-1-job-graph.mmd", "full-review-workflow.mmd", "design-parity-readiness.md",
                     "design-parity-report.md"):
            text = (DOCS / name).read_text(encoding="utf-8")
            for job in self.new:
                self.assertIn(job, text, f"{name} does not show {job}")
        planned = (DOCS / "phase-1-job-graph.mmd").read_text(encoding="utf-8")
        for job in self.new:
            self.assertIn(f'["{job} (planned; not dispatched)"]', planned)


if __name__ == "__main__":
    unittest.main()
