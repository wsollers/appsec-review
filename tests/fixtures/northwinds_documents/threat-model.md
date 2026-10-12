# Northwind Sample Application — STRIDE Threat Model

> Companion to `northwind-app-design.md` and `data-flow-diagram.md`.
> Models the target-state (secure) design and the controls that mitigate each
> threat category.

## Method

Threats are enumerated with **STRIDE** (Spoofing, Tampering, Repudiation,
Information disclosure, Denial of service, Elevation of privilege) against the
elements and trust boundaries in the data-flow diagram:

- **Elements**: React SPA, API gateway/Express, AuthN middleware, AuthZ service,
  REST controllers, GraphQL resolvers, service layer, repository layer, SQLite
  store, OAuth2/OIDC provider, external fetch targets.
- **Trust boundaries**: TB1 (Browser↔API), TB2 (API↔IdP), TB3 (API↔Datastore),
  TB4 (API↔External fetch).

Each threat is rated qualitatively (Low/Med/High likelihood × impact) assuming
controls are **not** in place, then paired with the mitigating control.

---

## S — Spoofing

| # | Threat | Boundary | Risk | Mitigation |
|---|--------|----------|------|------------|
| S1 | Attacker impersonates a user with a forged or stolen token | TB1/TB2 | High | OIDC auth-code + PKCE; short-lived RS256 JWTs; verify `alg`, `iss`, `aud`, `exp`; reject `none`/HS downgrades; rotating refresh tokens |
| S2 | Forged OAuth callback (CSRF on the login flow) | TB2 | High | Per-request `state` and `nonce`, stored and verified; exact redirect-URI allow-list |
| S3 | Spoofed origin calling the API with credentials | TB1 | Med | Strict CORS allow-list; credentials permitted only for known origins; no wildcard origin reflection |

## T — Tampering

| # | Threat | Boundary | Risk | Mitigation |
|---|--------|----------|------|------------|
| T1 | SQL injection via crafted input | TB3 | High | Parameterized queries only in the repository layer; no string-built SQL; input validation at the edge |
| T2 | Mass-assignment of fields the caller shouldn't set | TB1 | Med | Explicit field allow-lists on mutations; server-owned fields never bound from client |
| T3 | Request/response tampering in transit | TB1 | Med | TLS/HTTPS; HSTS; integrity-checked tokens |
| T4 | CSRF forcing a state-changing action | TB1 | High | Anti-CSRF tokens on form posts; `SameSite` cookies; bearer-token APIs |

## R — Repudiation

| # | Threat | Boundary | Risk | Mitigation |
|---|--------|----------|------|------------|
| R1 | User denies performing an administrative mutation | Server | Med | Audit logging of admin mutations with authenticated subject and timestamp |
| R2 | Gaps in logs around auth events | Server | Low | Structured logging of login, token issuance, and authz denials |

## I — Information disclosure

| # | Threat | Boundary | Risk | Mitigation |
|---|--------|----------|------|------------|
| I1 | IDOR — reaching another record by guessing an identifier | TB1/TB3 | High | Object-level authorization on every read/update/delete; knowing an ID is never sufficient |
| I2 | Verbose errors / stack traces leak internals | TB1 | Med | Consistent error envelope; detailed errors are development-only |
| I3 | GraphQL introspection exposes schema in production | TB1 | Med | Introspection enabled only in non-production profiles |
| I4 | Secrets committed or logged | Server | High | Secrets via env/config only; never committed; scrubbed from logs |
| I5 | Reflected/stored/DOM XSS leaking session data | TB1 | High | React escaping; avoid `dangerouslySetInnerHTML`; server-side sanitization; restrictive CSP |

## D — Denial of service

| # | Threat | Boundary | Risk | Mitigation |
|---|--------|----------|------|------------|
| D1 | Expensive/deeply nested GraphQL queries | TB1 | Med | Query depth and complexity limits; pagination required on list fields |
| D2 | Unbounded result sets exhaust memory | TB1/TB3 | Med | Mandatory pagination; capped page sizes |
| D3 | Request flooding | TB1 | Med | Rate limiting / throttling at the gateway |

## E — Elevation of privilege

| # | Threat | Boundary | Risk | Mitigation |
|---|--------|----------|------|------------|
| E1 | Client-side-only role checks bypassed | TB1 | High | RBAC evaluated server-side on every request; UI state is never the source of truth |
| E2 | SSRF reaching internal services via a user-supplied URL | TB4 | High | Allow-list of fetch targets; block internal/link-local ranges; do not follow redirects blindly |
| E3 | Missing authz on a newly added endpoint | Server | Med | Deny-by-default middleware; authz required before any resolver/controller logic |

---

## Residual risk & assumptions

- Assumes TLS terminates at a trusted edge and the IdP is correctly configured.
- Assumes dependencies are kept patched (tracked separately via dependency
  scanning).
- Residual risk after the controls above is considered **Low** for this sample
  application's intended use.

## Traceability

Each mitigation maps to a section of `northwind-app-design.md`:
auth (§6), web baseline (§7), data access (§8), GraphQL limits (§5.2),
configuration/profiles (§10).
