# Northwind document fixtures

These public inputs come from `wsollers/appsec-multi-vuln`,
`projects/northwinds-v2/`. The Markdown, Postman collection, TypeScript OpenAPI
source, and orders API test are copied without changing their content.
`openapi.json` is the materialized output of
`buildOpenApiDocument('http://localhost:4000')` from the copied OpenAPI source.

The fixtures contain target-owned statements and tests. They are untrusted
inputs and do not establish that any control is implemented or enforced.
