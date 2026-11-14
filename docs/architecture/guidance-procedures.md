---
title: "Role-selected review procedures"
kind: "architecture"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_inference_security_review", "job_owasp_control_assessment"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
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
New specialized and workbench publications use the same verifier/publisher with explicit
job-selected `/4` sections. See the [effective worker inventory and card contract](worker-prompt-contracts.md).

| Role/task | Selected runtime procedure |
| --- | --- |
| Hypothesis hunter or lead analyst | Generative investigation |
| Hypothesis hunter, control-gap task | Generative investigation and effective-control verification |
| Blue refuter | Effective-control verification |
| Independent verifier | Predicate verification |
| Adjudication judge | Conflict resolution |

These assignments also apply to production medium/low exploratory lead packages and all
package-local follow-up rounds; `variant` hunters use generative investigation, not a new
model or skill. Both production profiles enable exploration while both development profiles
leave it disabled. See the [effective production assignments](../operations/inference-security-review.md#effective-production-assignments-and-bounds)
for exact providers, model IDs, reasoning, persona/stack routing, job units and pool capacities.
Runtime skills are model guidance, not pool assignments.

When the accepted retrieval manifest includes a configured binary shard, the composer appends
`binary-evidence` to each review cell's role/task selection. Coverage-only binary shards do not
enable it. The selection participates in the guidance-cache key and pinned bundle hash; it is
never inferred from target-authored instructions.

`stateful-invariant-analysis` is additionally selected for the `business_logic_abuse`,
`authentication_session` and `filesystem_resources` personas, only for hunter `entry_down` /
`control_gap`, lead analyst `lead_red_preconditions`, refuter `blue_control`, and verifier
`blind_verifier` dispatches. The legacy `select_review_procedures` call without `persona` keeps
its existing selection. Remediation writer/reviewer bundles also select this procedure: their
existing tasks already ask for violated/corrected invariants. Other build, triage, scoring and
judging workers do not acquire it.

The procedure checks one bounded transition sequence, retries after uncertain commit, ownership
and lifetime, idempotency scope, rollback and resource accounting. It uses existing output fields,
not a new state-machine schema or worker panel. Generative and predicate procedures make attacker
capability, entry and environment assumptions explicit in their existing summaries/obligations;
they do not presume an anonymous web attacker or invent a deployment selection.

Selection is deterministic from validated role/task/persona ids, never target text. The procedures are
registered runtime-worker skills, loaded through `load_runtime_skill` for
`job_inference_security_review`; the stateful procedure also allows exactly the remediation planning
and validation jobs. Composer loads disable package fallback: a missing selected file
is an assembly failure rather than substituted content from another installation. The loader's
default fallback remains available for existing callers. Procedure validation rejects new tool
requests, budgets, authority declarations and cross-section policy conflicts.

No procedure changes the result schema, tool receipt, model selection, reasoning setting, timeout
or execution policy. Independent-verifier model separation remains a configuration responsibility.
The neutral verifier hypothesis supplies the security predicate, affected labels, preconditions
and weakness; the worker reconstructs the bounded condition without another worker's prose.

## Evidence-conditioned knowledge

Both investigation persona views now include `Hand-offs`. The blind adjudication judge omits that
section so specialist identifiers cannot disclose either side's persona; its conflict-resolution
procedure remains available. The governing rules interpret hand-offs as bounded
cross-specialist cues, not delegation. Where the compact contract supports it, `evidence_requests`
can nominate a specialist and cite local anchors for a missing fact. An `obligations` item remains
a question, not discharged evidence. A `taint_paths` edge distinguishes accepted analysis from
an analyst hypothesis; absence of a proven asynchronous link remains a gap.

False-positive patterns are possibilities conditioned on the actual path, attack class, version
and effective configuration. In particular, source buffer availability does not establish
destination capacity, and a guard must dominate the operation and survive mutation. Build
assessment similarly separates requested settings, observed compile/link settings, mapped artifact
facts, and supported consequences or gaps. Hardening absence alone is not exploitation evidence.

Numeric range, bound, wrap or loop reasoning in a prompt fragment must cite a tool fact (an R, G,
P, M or C label) or name a tool artifact in the same list item or paragraph
(`numeric-reasoning-guardrail/1`); `tests/test_prompt_numeric_reasoning.py` enforces it with a
small reviewed allowlist for bullets that only name a weakness pattern.

Workbench composition preserves its closed role/persona allowlists and bounded task/result
contracts. Its bundle/4 carries rich knowledge sections and source hashes, including the
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
(2,400 characters each, at most two for that native selection), workbench examples (13,000 serialized characters), and PoC
writer runtime skill (12,500 characters, excluding the assembled role/rules/card). These are deterministic regression bounds, not token-usage,
latency or detection-quality claims; task input and other personas can change prompt size.
`tests/test_stateful_guidance.py` additionally covers the selected persona/task matrix (under
26,000 UTF-8 bytes and at most three procedures without a binary shard), excluded selections,
job restrictions, source tampering, missing guidance and unchanged remediation schemas/citations.

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
