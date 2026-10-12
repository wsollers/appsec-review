---
id: iac_kubernetes
version: 1
covers: []
standards: ["k8s-pss", "k8s-top10-2022", "nist53r5", "cwe"]
max_tokens: 1500
---
## Runtime and framework model
Declarative infrastructure: Dockerfiles and Compose files, Kubernetes manifests, Helm charts,
Kustomize overlays, operators and CRDs, Terraform/OpenTofu, CloudFormation, CDK, Pulumi, Bicep/ARM,
Ansible, and serverless framework files. What the repository declares is rendered by tools
(templating, variables, overlays, modules) and then reconciled against a live environment that
may differ. Rendered output, not the template, is what runs.

## Trust and interface layer
- Exposure is defined by Services (`LoadBalancer`, `NodePort`), Ingress and Gateway resources,
  cloud load balancers, security groups, firewall rules, and public endpoints on managed services.
- Identity is defined by Kubernetes ServiceAccounts and RBAC, cloud IAM roles and policies,
  workload identity bindings, and instance profiles.
- Boundaries: namespace, node, cluster, VPC, and cloud account; the question is always which
  boundary a compromised workload can cross.

## Idiomatic security mechanisms
- Pod `securityContext`: `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation:
  false`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`.
- Namespace Pod Security Admission labels (`pod-security.kubernetes.io/enforce: restricted`),
  Kyverno or Gatekeeper policies.
- Default-deny NetworkPolicies; private clusters; API server authorized networks.
- Terraform: `aws_s3_bucket_public_access_block`, encryption blocks, `kms_key_id`, IMDSv2
  (`http_tokens = "required"`), least-privilege `aws_iam_policy_document`s with conditions.
- External secret operators or CSI secret stores instead of literal `Secret` manifests.

## Stack-specific pitfalls
- Helm values that change security posture (`securityContext: {}` defaults, `rbac.create` with
  wildcard rules, `service.type: LoadBalancer`), where the chosen values file decides reality.
- Kustomize patches in the production overlay that remove or override base hardening.
- Secrets in `values.yaml`, `terraform.tfvars`, `ConfigMap`s, or base64 `Secret` manifests in Git.
- Terraform `count`/`for_each` conditionals that enable public access in one workspace only.
- Remote Terraform modules or Helm chart dependencies pinned to branches.
- Operators with cluster-wide `*` permissions processing CRDs that tenants can create.
- `docker-compose` files mounting the Docker socket or using `network_mode: host`.

## Build and deployment facts to check
- Which overlay, values file, workspace, or stack is the deployed one; render it before judging.
- Admission controllers and organization policies that enforce or override declared settings.
- Cloud provider defaults for resources whose security attributes are omitted.
- Drift: the live state may differ from the declaration; record a deployed-state gap when only
  the declaration is available.
