# Northwind Sample Application — Data Flow Diagram (DFD)

> Companion to `northwind-app-design.md` and `stride-threat-model.md`.
> Describes the target-state (secure) architecture.

This document presents the application's data flows at Level 0 (context) and
Level 1 (major processes), with the trust boundaries used by the STRIDE threat
model.

---

## Trust boundaries

- **TB1 — Browser ↔ API**: the public network edge between the user's browser
  and the backend. Everything beyond it is server-controlled.
- **TB2 — API ↔ Identity Provider**: the boundary with the OAuth2/OIDC
  authorization server.
- **TB3 — API ↔ Datastore**: the boundary between application code and the
  SQLite database.
- **TB4 — API ↔ External fetch targets**: the boundary crossed by any feature
  that retrieves a remote resource on the user's behalf.

---

## Level 0 — Context diagram

```mermaid
flowchart LR
    user([End User / Browser])
    idp([OAuth2 / OIDC Provider])
    app[[Northwind Application]]
    ext([External URL targets])

    user -- "HTTPS: UI, REST, GraphQL" --> app
    app  -- "responses" --> user
    app  -- "authz-code / token exchange (TB2)" --> idp
    idp  -- "ID/access tokens" --> app
    app  -- "allow-listed outbound fetch (TB4)" --> ext
```

---

## Level 1 — Major processes and stores

```mermaid
flowchart TB
    subgraph client[Client zone]
        spa["React SPA (Tailwind)"]
    end

    subgraph edge[Server zone]
        gw["API gateway / Express<br/>(validation, CORS, CSRF, headers)"]
        authn["AuthN middleware<br/>(JWT verify: alg/iss/aud/exp)"]
        authz["AuthZ service<br/>(RBAC + object-level checks)"]
        rest["REST controllers"]
        gql["GraphQL resolvers<br/>(depth/complexity limits)"]
        svc["Service layer<br/>(business rules, transactions)"]
        repo["Repository layer<br/>(parameterized queries)"]
    end

    db[("SQLite<br/>(Northwind schema + seed)")]
    idp([OAuth2 / OIDC Provider])
    ext([External fetch targets])

    spa -- "1. HTTPS request + bearer token (TB1)" --> gw
    gw --> authn
    authn -- "token introspection / JWKS (TB2)" --> idp
    authn --> authz
    authz --> rest
    authz --> gql
    rest --> svc
    gql --> svc
    svc -- "allow-listed, SSRF-guarded fetch (TB4)" --> ext
    svc --> repo
    repo -- "parameterized SQL (TB3)" --> db
    db -- "rows" --> repo
    repo --> svc
    svc --> rest
    svc --> gql
    rest -- "JSON response" --> gw
    gql -- "GraphQL response" --> gw
    gw -- "response (TB1)" --> spa
```

---

## Data stores and classification

| Store              | Contents                                  | Sensitivity |
| ------------------ | ----------------------------------------- | ----------- |
| SQLite (Northwind) | Business records: customers, orders, etc. | Internal    |
| Session/token data | Access/refresh tokens, OAuth state/nonce  | Secret      |
| Config/secrets     | Signing keys, DB path, allow-lists        | Secret      |

---

## Notes

- Every request crosses TB1 and is authenticated (TB2 artifacts) and authorized
  before any service logic runs.
- The repository layer is the only component that crosses TB3; all access is
  parameterized.
- Only the service layer crosses TB4, and only through an allow-listed,
  SSRF-guarded fetch utility.
