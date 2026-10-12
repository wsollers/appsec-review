# Northwind Sample Application — Design Document

> Status: Draft · Audience: Engineering, QA, Security · Scope: Reference design
> for a standard Northwind CRUD web application.

This document describes the application **as it should be built**: a conventional,
well-architected CRUD system over the classic Microsoft Northwind sample dataset.
It is a reference/target-state design. It does not describe any particular
deployment and contains no implementation secrets.

---

## 1. Purpose and scope

The application provides create/read/update/delete management of the Northwind
business entities (customers, employees, orders, order details, products,
suppliers, categories, shippers) through a web UI and a documented API. It is
intended as a representative, mid-sized line-of-business application: realistic
enough to exercise typical architecture, data-access, authentication, and
front-end concerns, while small enough to reason about end to end.

In scope:

- A REST API and a GraphQL API over the Northwind entities.
- A React single-page front end styled with Tailwind CSS.
- Authentication and role-based authorization.
- A SQLite datastore seeded with the Northwind dataset.
- API documentation (OpenAPI/Swagger) and a test suite.

Out of scope: production hosting topology, payment processing, and multi-tenant
isolation.

---

## 2. Architecture overview

```
┌──────────────┐     HTTPS      ┌───────────────────────────┐     ┌──────────┐
│  React SPA   │ ─────────────▶ │  Node.js / TypeScript API │ ──▶ │  SQLite  │
│ (Tailwind)   │ ◀───────────── │  Express + Apollo GraphQL │ ◀── │   (file) │
└──────────────┘                └───────────────────────────┘     └──────────┘
        │                                   │
        │                                   ├─ Auth service (OAuth2 / OIDC, JWT)
        │                                   ├─ REST controllers
        │                                   ├─ GraphQL resolvers
        │                                   └─ Data-access layer (repositories)
```

- **Front end**: React + TypeScript SPA, built with Vite, styled with Tailwind.
  Talks to the backend over HTTPS using JSON (REST) and GraphQL.
- **Backend**: Node.js + TypeScript. Express hosts the REST controllers and an
  Apollo Server instance for GraphQL. A thin service layer holds business rules;
  a repository layer owns all database access.
- **Datastore**: SQLite accessed through a single parameterized data-access
  layer. The Northwind schema and seed data are applied via versioned migrations.

### Layering

1. **Transport** — Express routers / Apollo schema. Input validation and
   serialization only.
2. **Service** — business rules, authorization decisions, transaction
   boundaries.
3. **Repository** — parameterized queries, mapping rows to domain objects.
4. **Domain model** — typed entities shared across layers.

No layer skips the one below it; controllers never issue SQL directly.

---

## 3. Technology stack

| Concern            | Choice                                   |
| ------------------ | ---------------------------------------- |
| Language           | TypeScript (strict mode)                 |
| Runtime            | Node.js 22.x                             |
| HTTP framework     | Express                                  |
| GraphQL            | Apollo Server                            |
| Database           | SQLite (via a parameterized query layer) |
| Migrations/seed    | SQL migration files, applied in order    |
| Front end          | React + Vite                             |
| Styling            | Tailwind CSS                             |
| API docs           | OpenAPI 3 / Swagger UI                    |
| Tests              | Vitest (unit), Supertest (API)           |
| API client samples | Postman collection                       |

---

## 4. Data model

The Northwind schema, unchanged in shape:

- **Categories** (`CategoryID`, `CategoryName`, `Description`)
- **Suppliers** (`SupplierID`, `CompanyName`, contact fields, address)
- **Products** (`ProductID`, `ProductName`, `SupplierID`, `CategoryID`,
  `UnitPrice`, `UnitsInStock`, `Discontinued`)
- **Customers** (`CustomerID`, `CompanyName`, contact fields, address)
- **Employees** (`EmployeeID`, name, title, `ReportsTo`, address)
- **Shippers** (`ShipperID`, `CompanyName`, `Phone`)
- **Orders** (`OrderID`, `CustomerID`, `EmployeeID`, dates, `ShipVia`, freight,
  ship-to fields)
- **Order Details** (`OrderID`, `ProductID`, `UnitPrice`, `Quantity`,
  `Discount`)

Relationships follow the standard Northwind foreign keys. Referential integrity
is enforced in the database (foreign-key constraints enabled) and mirrored by
validation in the service layer.

---

## 5. API design

### 5.1 REST

Resource-oriented endpoints under `/api/v1`, e.g.:

```
GET    /api/v1/products            list, with pagination + filtering
POST   /api/v1/products            create
GET    /api/v1/products/{id}       read
PUT    /api/v1/products/{id}       update
DELETE /api/v1/products/{id}       delete
```

Conventions:

- JSON request/response bodies, validated against typed schemas at the edge.
- Pagination via `page`/`pageSize`; filtering via explicit, whitelisted query
  params mapped to parameterized query fragments.
- Consistent error envelope (`{ error: { code, message } }`) with appropriate
  HTTP status codes; internal details are not leaked to clients.
- All identifiers are opaque to the client; enumeration is mitigated by
  authorization checks on every resource access (see §6).

### 5.2 GraphQL

A single `/graphql` endpoint exposing queries and mutations mirroring the REST
surface. Design points:

- Schema-first SDL with typed resolvers.
- Resolvers delegate to the same service layer as REST (no duplicate business
  logic).
- Depth and complexity limits are applied to incoming queries.
- Introspection is enabled in non-production environments only.

### 5.3 Documentation

The REST surface is described by an OpenAPI 3 document served through Swagger UI.
A Postman collection mirrors the documented endpoints for manual exploration and
contract smoke tests.

---

## 6. Authentication and authorization

### Authentication

- Standards-based **OAuth 2.0 / OIDC** authorization-code flow with PKCE for the
  SPA. The front end never handles long-lived credentials directly.
- The authorization server issues short-lived **JWT access tokens** and
  rotating refresh tokens.
- Tokens are signed with an asymmetric key (RS256); the expected `alg`, issuer,
  audience, and expiry are all validated on every request. `none` and
  symmetric-key downgrades are rejected.
- OAuth `state` and `nonce` are generated per request, stored, and verified on
  callback; redirect URIs are matched against an exact allow-list.

### Authorization

- **Role-based access control** evaluated **on the server** for every request.
  Roles (e.g. `viewer`, `sales`, `admin`) gate operations.
- **Object-level checks**: every read/update/delete verifies that the caller is
  permitted to act on that specific record, not just that they hold the role in
  general. The client UI reflecting a permission is never the source of truth.
- Mutating fields are bound through explicit allow-lists; clients cannot set
  fields they do not own (no mass assignment).

---

## 7. Web/front-end security baseline

- **CSRF**: state-changing requests use anti-CSRF tokens (or are restricted to
  bearer-token APIs with `SameSite` cookies); forms carry a per-session token
  verified server-side.
- **XSS**: React's default escaping is relied upon; `dangerouslySetInnerHTML` is
  avoided; any user-supplied HTML is sanitized server-side. A restrictive
  Content-Security-Policy is sent.
- **CORS**: a strict allow-list of known front-end origins; credentials are only
  permitted for those exact origins. Wildcard reflection of arbitrary origins is
  not used.
- **SSRF**: any feature that fetches a remote URL on the user's behalf validates
  the target against an allow-list and blocks internal/link-local address
  ranges; redirects are not followed blindly.
- Standard hardening headers (HSTS, `X-Content-Type-Options`, frame options) are
  set, and secrets are supplied via environment/config, never committed.

---

## 8. Data access and integrity

- All SQL is parameterized through the repository layer; string concatenation of
  user input into queries is prohibited.
- Write operations that span multiple tables (e.g. creating an order with its
  line items) run inside a transaction.
- Input is validated and normalized before it reaches the repository.
- Identifiers used in URLs are validated for type and existence, and every
  access is authorized (see §6) so that knowing an ID is never sufficient to
  reach a record.

---

## 9. Testing strategy

- **Unit tests** (Vitest) for service-layer business rules and validation.
- **API tests** (Supertest) exercising REST and GraphQL happy paths and error
  handling, including authentication and authorization boundaries.
- **Contract checks** against the OpenAPI document and the Postman collection.
- CI runs the suite on every change; migrations and seed are applied to a
  throwaway SQLite database for test runs.

---

## 10. Environments and configuration

- Configuration is centralized and typed; values come from environment variables
  with safe defaults for local development only.
- Separate configuration profiles for `development`, `test`, and `production`
  (e.g. GraphQL introspection and verbose errors are development-only).
- The SQLite file lives outside the web root; migrations run on startup in
  non-production and via an explicit step in production.

---

## 11. Open questions / future work

- Pagination strategy for very large order histories (cursor vs. offset).
- Whether to add a read model / caching layer for product catalog queries.
- Audit logging of administrative mutations.

---

*Companion documents: a STRIDE threat model and a data-flow diagram are
maintained alongside this design in `docs/`.*
