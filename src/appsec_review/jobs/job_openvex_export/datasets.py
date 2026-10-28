"""Protected local exports; retrieval exposes sanitized inventory metadata only."""
from appsec_review.runtime.datasets import protected

from .contracts import CONSUMES, OPENVEX_EXPORT_RESULT_SCHEMA, VERIFIED_INPUTS_SCHEMA

_A = "data/jobs/job_openvex_export/attempts/*/steps"
_E = _A + "/export/tasks/assemble/"
_REASON = "Internal vulnerability disclosure artifacts; no content retrieval or external publication."
DATASETS = (
    protected("openvex_verified_inputs", "load", "inference_review", VERIFIED_INPUTS_SCHEMA,
              "Verified accepted review boundary and exact offline schema snapshots.",
              artifacts=(_A + "/load/**",), reason=_REASON),
    protected("openvex_documents", "export", "inference_review", "https://openvex.dev/ns/v0.2.0",
              "Affected-only statements for the exact reviewed source snapshot and configuration.",
              artifacts=(_E + "openvex.json",), reason=_REASON),
    protected("openvex_export_accounting", "acceptance", "inference_review", OPENVEX_EXPORT_RESULT_SCHEMA,
              "Exact included/excluded accounting, companion manifest and accepted result.",
              artifacts=(_E + "openvex-manifest.json", _E + "openvex-result.json", _A + "/acceptance/**"),
              reason=_REASON),
)
