# Config — Static Deployment Hardening (L15)

Design reference: docs/design-v3.md §4 (lane table), §12 (static deployment hardening specifics).

## Required Inputs

- IaC scan evidence: `static-evidence/iac/{trivy-config.json,tfsec.json,results_json.json}` (Trivy config, tfsec, Checkov)
- Terraform-specific SAST evidence: `static-evidence/sast-multi/semgrep-terraform.json` (Semgrep `p/terraform`, added 2026-09-19)
- Kubernetes/Helm lint evidence: `static-evidence/iac-k8s/kube-linter.json`
- Dockerfile lint and base-image inventory: `static-evidence/iac-docker/{hadolint.txt,base-images.txt}`
- Component-purpose map (for mapping images/manifests to components)
- Any supplied image manifests, digests, or signature/provenance artifacts
- Declared network/IAM configuration present in the repo (source and config only — no live cloud access; see design §2.1)

## Persona Pool (pilot, added 2026-09-19)

This lane is the pilot for the persona-pool mechanism described in `docs/design-v3.md` §5.5
(job config not yet built; `review_cli.py` has no `--persona` flag yet). Until the real launcher
exists, dispatch one persona at a time by hand: give the dispatched instance the exact
`persona_id` from `subprompts.md` to operate as, tell it to ignore the other persona entries in
that file, and have it write to `outputs/15-deployment-hardening/personas/<persona_id>/` (not the
lane's shared `result.md`/`status.json`) — the same scoped-output shape the real launcher will use,
so a manual merge today looks like the automated merge later. See `subprompts.md` for the four
persona entries: `iac-cloud-terraform-auditor`, `iac-k8s-helm-hardening-reviewer`,
`iac-container-dockerfile-auditor`, `iac-network-iam-exposure-modeler`.

One dependency is now resolved and one remains open. The curated DISA reference file
(`data/disa-stig-reference.json`, added 2026-09-19) is built — but read its `scope_finding`
entries before assuming it unblocks much: only 4 of the Kubernetes STIG's 91 rules are actually
evaluable from static K8s-manifest evidence (the rest require a live cluster or control-plane host
access, out of this lane's scope), and none of the Container Platform SRG's rules are evaluable from
Dockerfile/hadolint evidence at all (that SRG governs the platform/registry/runtime, not Dockerfile
content) — `iac-container-dockerfile-auditor` must never set `disa_stig_id`, full stop, not
provisionally. See each persona's own "Standards discipline" note in `subprompts.md` for the exact,
now-current rule. **Target resolved 2026-09-19**: `targets/iac-goof` (github.com/snyk-labs/infrastructure-as-code-goof,
cloned at commit `f8605c5`, Apache-2.0, Snyk Labs' own deliberately-vulnerable IaC demo repo) gives
this lane real surface — 207 Terraform files under `terraform/{aws,azurerm,gcp}` (largely paired
`_allowed.tf`/`_denied.tf` per rule, good for exercising cross-tool reconciliation and true-positive
vs. true-negative behavior), 40 Kubernetes manifests under `k8s/` (including the single-issue
`k8s/templates/*.yaml` set plus three documented scenario dirs — PrivilegedPod, ResourceLimitation,
RBAC-Misconfiguration), and 5 Dockerfiles embedded in those k8s scenario dirs (thin coverage — not a
rich hadolint-rule corpus, worth pairing with a second source later if `iac-container-dockerfile-auditor`
needs deeper Dockerfile-rule exercise). A large vendored `helm/` chart (kube-prometheus-stack) and a
`cloudformation/` directory are also present but outside these four personas' current scope. This
closes the "no target" blocker for `iac-cloud-terraform-auditor`, `iac-k8s-helm-hardening-reviewer`,
and `iac-container-dockerfile-auditor`; `iac-network-iam-exposure-modeler` still needs the other three
personas' real output to compose over before it can be piloted.

**Evidence gathered 2026-09-19** via
`pipeline/Invoke-VendorAuditPrePass.ps1 -RepoPath targets\iac-goof -EvidencePath
scratch\iac-goof-engagement\static-evidence -Steps
iac-checkov,iac-trivy,iac-tfsec,sast-multi-semgrep-terraform,iac-k8s,dockerfile-lint,docker-base-images`,
run by the repo owner directly on hal5000 (not through the device bridge, per the standing
constraint — `device_bash`'s Linux VM has no Docker, confirmed live). Verified directly against the
output files, not the script's own manifest: checkov (158/168 dockerfile, 2707/3570 kubernetes,
1239/2904 terraform, 176/254 cloudformation, 0/7 secrets passed — checkov scans the whole workspace
regardless of IaC type, so this one file covers several of `standard_refs`' evidence needs at once),
trivy config (2041 misconfigs / 222 files), tfsec (182 results), semgrep `p/terraform` (74 results),
kube-linter (334 reports), hadolint (2 of 5 Dockerfiles flagged — `RBAC-Misconfiguration/app`,
`ResourceLimitation/app1`, `app2`; `PrivilegedPod`'s two Dockerfiles came back clean), and a
5-Dockerfile base-image inventory (`php:7.4-cli`, `php:7.4.22-cli`, `mhart/alpine-node:15.13.0`,
`python:3`, `python:3.10.0b4` — all old/unpinned-minor, good material for the persona's EOL-reference
check). Real, substantive evidence in every file — this target is ready for a persona pilot.

## Required Outputs

- `deployment-image-map.json` update: static chain from deployment configuration to referenced image/digest and image assessment; unresolved image references are `IMAGE_ARTIFACT_NOT_PROVIDED`, not PASS
- `network-exposure.json` update: DECLARED_EXPOSURE inventory built from source/configuration only, explicitly not labeled OBSERVED_EXPOSURE
- `identity-graph.json` update: workload → identity → role → action → resource, modeled statically
- HARDENING_BASELINE_ASSESSMENT status against applicable CIS/DISA/NIST baselines for Kubernetes/IaC — do not report PASS unless every applicable requirement was actually evaluated
- FOLLOW_ON_EFFECTIVE_STATE_REVIEW_RECOMMENDED where live state would materially change assurance, instead of performing any live access
- Findings citing image user/entrypoint/layers/package residue/exposed ports/secrets/setuid-setgid files/base-image lifecycle where evidence supports it

## Success Criteria

- Every image reference in deployment configuration is either resolved against a supplied image artifact or explicitly marked IMAGE_ARTIFACT_NOT_PROVIDED
- No PASS is recorded for a hardening baseline unless all applicable requirements were evaluated
- No exposure or IAM claim is labeled as observed/runtime state
