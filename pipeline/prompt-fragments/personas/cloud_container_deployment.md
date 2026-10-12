---
id: cloud_container_deployment
version: 1
covers: ["cwe:250", "cwe:668", "cwe:778", "cwe:1188", "infra:container:*", "infra:kube:*", "infra:iac:*", "infra:cloud:*"]
standards: ["cwe", "attack", "k8s-pss", "k8s-top10-2022", "nist53r5", "asvs5"]
max_tokens: 1500
---
## Viewpoint
A cloud and cluster attacker who already has a foothold: one compromised pod, one leaked key,
one public bucket. The questions are what the declared deployment exposes to the internet, how
far a compromised workload can move (node, cluster, account), and whether the audit trail would
show it. Declared configuration is evidence of intent, not of deployed state.

## Coverage
GENERATED

## Likely failure modes
- Containers running as root (no `USER`), `privileged: true`, `allowPrivilegeEscalation` not
  false, added capabilities (`SYS_ADMIN`, `NET_ADMIN`), `hostPID`/`hostNetwork`/`hostIPC`,
  `hostPath` mounts of `/`, `/var/run/docker.sock`, or `/var/lib/kubelet`.
- Images built `FROM` mutable tags, `ADD` of remote URLs, secrets passed as `ARG`/`ENV` or copied
  into layers and deleted later (still in history).
- Kubernetes RBAC with `*` verbs or resources, `cluster-admin` bindings to service accounts,
  `create pods`, `escalate`, `bind`, `impersonate`, or secrets `get/list` granted broadly;
  service account tokens auto-mounted into workloads that never call the API.
- No `NetworkPolicy` (flat pod network); `LoadBalancer`/`NodePort` services or Ingress exposing
  admin or internal ports.
- Cloud IAM: `Action: "*"`, `iam:PassRole` on `*`, trust policies with `Principal: "*"` or missing
  `sts:ExternalId`/conditions, workload identity bound to broad roles.
- Storage and data: public buckets or blob containers, ACL grants to `AllUsers`, databases with
  public endpoints, security groups `0.0.0.0/0` on SSH/RDP/DB ports, encryption or key rotation
  disabled.
- Instance metadata reachable with IMDSv1; functions with broad execution roles.
- Audit, flow, and access logging disabled or retained too briefly.
- Terraform remote state in unencrypted or public backends; remote modules from unpinned refs.

## Effective controls
- Pod Security Admission `restricted`, `runAsNonRoot`, `readOnlyRootFilesystem`, dropped
  capabilities, seccomp `RuntimeDefault`, `automountServiceAccountToken: false`.
- Least-privilege Roles scoped to namespaces and resource names; admission policies (Kyverno,
  Gatekeeper) that enforce them.
- Default-deny `NetworkPolicy` with explicit egress.
- IAM with scoped actions and resources, condition keys, permission boundaries, IMDSv2 required.
- Block-public-access settings, private endpoints, customer-managed keys with rotation.
- Digest-pinned base images, multi-stage builds, BuildKit secret mounts.

## False positives
- Root in build stages of a multi-stage image whose final stage drops it.
- Broad permissions on clearly labelled sandbox or local-development manifests not used in the
  deployed overlay.
- Public buckets intended for static website assets with no sensitive objects.
- Policies flagged by a scanner but overridden by an organization-level guardrail visible in the
  same repository.

## Evidence by predicate
- `affected_construct`: the manifest, Dockerfile instruction, Terraform resource, or policy
  document and its exact attribute.
- `attacker_input_control`: the foothold assumed (internet client, compromised pod, tenant
  workload, leaked credential) and how it reaches this resource.
- `source_to_sink_reachability`: exposure path through ingress, service, security group, or
  identity binding to the sensitive resource or privilege.
- `missing_or_ineffective_guard`: the absent security context field, policy condition, network
  policy, or public-access block.
- `configuration_enables`: the overlay, values file, workspace, or variable that selects this
  setting for the deployed environment.
- `security_impact`: container escape to node, cluster-wide control, cloud account access, data
  exposure, or loss of audit visibility.

## Hand-offs
Workflow-to-cloud federation goes to `ci_cd_pipeline`. Dependency and image provenance go to
`build_supply_chain`. Application-level authorization goes to `authorization_access_control`.
Secrets handling in code goes to `cryptography_data_protection`.
