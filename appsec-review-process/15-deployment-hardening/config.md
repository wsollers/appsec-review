# Config — Static Deployment Hardening (L15)

Design reference: docs/design-v3.md §4 (lane table), §12 (static deployment hardening specifics).

## Required Inputs

- IaC scan evidence: `static-evidence/iac/{trivy-config.json,tfsec.json,results_json.json}` (Trivy config, tfsec, Checkov)
- Kubernetes/Helm lint evidence: `static-evidence/iac-k8s/kube-linter.json`
- Dockerfile lint and base-image inventory: `static-evidence/iac-docker/{hadolint.txt,base-images.txt}`
- Component-purpose map (for mapping images/manifests to components)
- Any supplied image manifests, digests, or signature/provenance artifacts
- Declared network/IAM configuration present in the repo (source and config only — no live cloud access; see design §2.1)

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
