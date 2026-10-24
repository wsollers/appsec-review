# Role-selected review procedures

The guidance composer combines knowledge, responsibility and reusable procedure without changing
worker capabilities. `compose_bundle` keeps its existing arguments (`role`, `persona`, `stack`,
`task`, bounded `task_input`, `capability`, vocabulary and crosswalk). `render_prompt` renders the
verified result; `pin_bundle` stores its exact JSON and rendered prompt under the bundle hash.

## Selection and provenance

Inference bundles use `appsec-review/guidance-bundle/3`, in this order: governing rules, role,
persona, stack, task, procedures, receipt. Each procedure item records its registered id, path,
complete source text and source SHA-256. The section hash and bundle hash cover these items.
Verification also checks each procedure's source hash. Existing bundle/2 verification, rendering
and pinning remain supported; old workbench bundle/1 verification remains supported.

| Role/task | Selected runtime procedure |
| --- | --- |
| Hypothesis hunter or lead analyst | Generative investigation |
| Hypothesis hunter, control-gap task | Generative investigation and effective-control verification |
| Blue refuter | Effective-control verification |
| Independent verifier | Predicate verification |
| Adjudication judge | Conflict resolution |

Selection is deterministic from validated role/task ids, never target text. The procedures are
registered runtime-worker skills, loaded through `load_runtime_skill` for
`job_inference_security_review`. Composer loads disable package fallback: a missing selected file
is an assembly failure rather than substituted content from another installation. The loader's
default fallback remains available for existing callers. Procedure validation rejects new tool
requests, budgets, authority declarations and cross-section policy conflicts.

No procedure changes the result schema, tool receipt, model selection, reasoning setting, timeout
or execution policy. Independent-verifier model separation remains a configuration responsibility.
The neutral verifier hypothesis supplies the security predicate, affected labels, preconditions
and weakness; the worker reconstructs the bounded condition without another worker's prose.

## Evidence-conditioned knowledge

Both persona views now include `Hand-offs`. The governing rules interpret these as bounded
cross-specialist cues, not delegation. Where the compact contract supports it, `evidence_requests`
can nominate a specialist and cite local anchors for a missing fact. An `obligations` item remains
a question, not discharged evidence. A `taint_paths` edge distinguishes accepted analysis from
an analyst hypothesis; absence of a proven asynchronous link remains a gap.

False-positive patterns are possibilities conditioned on the actual path, attack class, version
and effective configuration. In particular, source buffer availability does not establish
destination capacity, and a guard must dominate the operation and survive mutation. Build
assessment similarly separates requested settings, observed compile/link settings, mapped artifact
facts, and supported consequences or gaps. Hardening absence alone is not exploitation evidence.

Workbench composition preserves its closed role/persona allowlists and bounded task/result
contracts. Its bundle/1 now carries rich knowledge sections and source hashes, including the
existing `api_web` to `network_api_surface` and `deployment_operations` to
`cloud_container_deployment` migrations. Assessors and applicability routers receive the effective
control procedure; evidence verifiers and independent reviewers receive predicate verification;
result adjudicators receive conflict resolution. These skills are separately job-allowlisted for
`job_owasp_control_assessment`; no inference-only output instructions or new tools are introduced.

## Examples and bounds

Compact examples include vulnerable/fixed capacity checks, unresolved effective CI permissions,
authorization across a queue, and an atomicity invariant. Every example uses the real compact
schema and local evidence labels. The PoC writer retains its accepted source fixture and five
validator-refused source variants, with redundant counterexample metadata removed. Generated and
compile-verified output is not a reproduced observation; no model or network PoC is run by these
tests.

`tests/test_guidance_procedures.py` checks actual rendered guidance for registered review tasks
(32,000 characters maximum on the representative native persona/stack), selected procedure text
(2,400 characters each, at most two), workbench examples (13,000 serialized characters), and PoC
writer guidance (12,500 characters). These are deterministic regression bounds, not token-usage,
latency or detection-quality claims; task input and other personas can change prompt size.

The [opt-in evaluation harness](../operations/guidance-evaluation.md) uses separate vulnerable,
fixed and incomplete-evidence fixtures and the actual role bundles. It reports role-appropriate
quality and usage metrics and supports a hash-distinct procedure-only ablation. Offline tests do
not establish live performance gains.

Technical reference points:
- [Python TAR extraction filters](https://docs.python.org/3/library/tarfile.html#extraction-filters):
  introduced in 3.12, `data` default in 3.14; ZIP APIs are separate.
- [.NET BinaryFormatter security](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide):
  binders cannot make it safe for untrusted input.
- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use):
  token permissions and action pinning require the actual trust and configuration context.
