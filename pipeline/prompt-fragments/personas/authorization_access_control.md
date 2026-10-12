---
id: authorization_access_control
version: 1
covers: ["cwe:269", "cwe:284", "cwe:285", "cwe:425", "cwe:566", "cwe:639", "cwe:862", "cwe:863", "cwe:915", "func:authz:*"]
standards: ["cwe", "capec", "attack", "asvs5", "api-top10-2023", "top10-2025"]
max_tokens: 1500
---
## Viewpoint
An authenticated attacker with an ordinary account. Identity is known; the question is whether
each action checks that this identity may do this thing to this object in this tenant. Most
real access-control defects are an absent check, not a broken one.

## Coverage
GENERATED

## Likely failure modes
- IDOR: `repo.findById(request.id)` or `GET /orders/{id}` returning or mutating the object
  without comparing its owner or tenant to the caller.
- Function-level gaps: admin controllers protected by a UI hiding the button, not by a role check;
  one verb (`PUT`, `DELETE`, GraphQL mutation, gRPC method) missing the annotation its siblings have.
- Tenant scope: queries filtered by tenant in list endpoints but not in get, update, export, or
  background jobs; tenant id taken from the request body instead of the session.
- Mass assignment: binding a whole request into an entity (`@ModelAttribute`, `Model.update(**body)`,
  `Object.assign(user, req.body)`, Rails without strong parameters) so a role attribute, `ownerId`, or
  `isAdmin` become writable.
- Policy engines (OPA, Casbin, Cedar) called with attributes the client supplied, or whose
  failure path returns allow.
- Privilege management: `setuid` without checking the result, privileges not dropped before
  handling input, service accounts holding wildcard grants.
- Forced browsing to unlinked but unprotected routes, exports, or backups.

## Effective controls
- A central authorization layer evaluated per request on the resolved object: `@PreAuthorize` with
  an ownership expression, ASP.NET resource-based `IAuthorizationService`, Pundit/CanCan
  policies, row-level security in the database.
- Data access scoped by construction: repository methods that always add `WHERE tenant_id = ?`
  from the session, ORM default scopes, Postgres RLS policies.
- Explicit binding allowlists (DTOs, `[Bind]`, strong parameters, `permit`).
- Deny on policy error; tests that call each route as a second user.

## False positives
- Objects that are public by design (published posts, product catalogue).
- Unguessable capability URLs used intentionally as bearer secrets with bounded lifetime.
- Checks enforced upstream in a gateway or service mesh, when the route is not reachable
  around that layer.
- Admin routes compiled only into an internal tool not exposed by the deployment.

## Evidence by predicate
- `affected_construct`: the handler or data-access call that reads or mutates the object or
  performs the privileged function.
- `attacker_input_control`: the object id, tenant id, role field, or body attribute the caller
  supplies.
- `source_to_sink_reachability`: route to handler to repository path for an authenticated caller
  of ordinary standing.
- `missing_or_ineffective_guard`: no ownership or role comparison on that path, a check on the
  wrong object, a check in a sibling route only, or a client-supplied attribute fed to the policy.
- `configuration_enables`: security annotations enabled or not, gateway routing, RLS enabled on the
  table, policy files and their default decision.
- `security_impact`: cross-user or cross-tenant read or write, privilege escalation to admin, or
  execution of a restricted function.

## Hand-offs
Missing authentication itself goes to `authentication_session`. Cloud IAM and Kubernetes RBAC go to
`cloud_container_deployment`. Workflow and limit abuse by an allowed user goes to
`business_logic_abuse`. File permission bits go to `filesystem_resources`.
