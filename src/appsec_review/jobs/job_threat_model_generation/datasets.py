"""Dataset declarations and the typed input contract of job_threat_model_generation (T-107).

Design: docs/architecture/dfd-and-threat-model-generation.md sections 3, 3.1 and 8. Every dataset is
artifact-only routing context: a generated model may guide where a reviewer looks and never
satisfies an obligation, so nothing here claims an index shard and nothing is written to the
``documents`` index. A declaration is a contract, not evidence that the output was produced.
"""
from __future__ import annotations

from appsec_review.jobs.job_artifact_indexing.datasets import DATASETS as _ARTIFACT_INDEXING
from appsec_review.jobs.job_code_graph_index.datasets import DATASETS as _CODE_GRAPH_INDEX
from appsec_review.jobs.job_cpp_compiled_analysis.datasets import DATASETS as _CPP_COMPILED_ANALYSIS
from appsec_review.jobs.job_language_build.datasets import DATASETS as _LANGUAGE_BUILD
from appsec_review.jobs.job_review_prioritization.datasets import DATASETS as _REVIEW_PRIORITIZATION
from appsec_review.jobs.job_target_catalog.datasets import DATASETS as _TARGET_CATALOG
from appsec_review.jobs.job_tree_sitter_ast.datasets import DATASETS as _TREE_SITTER_AST
from appsec_review.runtime.contracts import (
    Availability, DispatchClass, JobContract, MissingPolicy, TargetAccess, accepted_inputs,
)
from appsec_review.runtime.datasets import EvidenceAuthority, artifact_only
from appsec_review.threat_model.contract import (
    DFD_SCHEMA, EVIDENCE_SCHEMA, JOB_ID, RESULT_SCHEMA, THREAT_MODEL_SCHEMA,
)
from appsec_review.threat_model.index_view import DECLARED_INPUTS

STEP = "publication"
ARTIFACT_DIRECTORY = "artifacts/threat-model"
_A = f"data/jobs/{JOB_ID}/attempts/*/{ARTIFACT_DIRECTORY}"
REASON = "generated model; routing context, not general retrieval evidence"


def _dataset(output_kind: str, schema: str, description: str, *patterns: str):
    return artifact_only(output_kind, STEP, "threat_model", schema, description,
                         artifacts=tuple(f"{_A}/{pattern}" for pattern in patterns), reason=REASON,
                         sensitivity="internal", authority=EvidenceAuthority.ROUTING_CONTEXT)


DATASETS = (
    _dataset("generated_dfd", DFD_SCHEMA,
             "Generated data-flow diagram: elements, flows, trust boundaries and unknowns, each citing evidence.",
             "dfd.json"),
    _dataset("generated_threat_model", THREAT_MODEL_SCHEMA,
             "Generated threat model: actors, entry points, candidate threats and unknowns.",
             "threat-model.json"),
    _dataset("generated_model_evidence", EVIDENCE_SCHEMA,
             "Every evidence reference the generated DFD and threat model cite, once.",
             "evidence.json"),
    _dataset("generated_model_views", "text/markdown",
             "Generated Mermaid diagrams and the Markdown view, re-rendered from the published JSON.",
             "views/*.mmd", "views/*.md"),
    _dataset("threat_model_documents", RESULT_SCHEMA,
             "Result document (input ledger, counts, joined gaps, artifact references) and the canonical "
             "working records the attempt's units hand to each other.",
             "result.json", "work/*.json"),
)


# The producers' own declarations supply each input's schema and authority; imported statically so
# the release closure of this job covers them.
PRODUCER_DATASETS = {
    "job_artifact_indexing": _ARTIFACT_INDEXING,
    "job_code_graph_index": _CODE_GRAPH_INDEX,
    "job_cpp_compiled_analysis": _CPP_COMPILED_ANALYSIS,
    "job_language_build": _LANGUAGE_BUILD,
    "job_review_prioritization": _REVIEW_PRIORITIZATION,
    "job_target_catalog": _TARGET_CATALOG,
    "job_tree_sitter_ast": _TREE_SITTER_AST,
}


def _inputs():
    requirements = []
    for producer in sorted({producer for producer, _ in DECLARED_INPUTS}):
        kinds = sorted(kind for name, kind in DECLARED_INPUTS if name == producer)
        declared = PRODUCER_DATASETS[producer]
        required = producer == "job_target_catalog"
        requirements.extend(accepted_inputs(
            producer, declared, output_kinds=kinds,
            availability=Availability.REQUIRED if required else Availability.OPTIONAL,
            missing=MissingPolicy.REJECT if required else MissingPolicy.GAP))
    return tuple(requirements)


CONTRACT = JobContract(
    inputs=_inputs(),
    schedule_after=("job_owasp_control_assessment", "job_dependency_intelligence", "job_security_tagging"),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.ACCEPTED_EVIDENCE,
)
CONSUMES = CONTRACT.consumes
