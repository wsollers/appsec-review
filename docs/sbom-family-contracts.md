# SBOM-Family Output Contracts (ADR-0010 V05)

Four registry contracts, their schemas and one read-only verifier module. Nothing here runs syft,
Grype or scancode, registers a node, or is wired into `validate_job_output.py`; V11 and the
integration owner adopt it.

| Contract | Node | Result document | Verifier |
|---|---|---|---|
| `sbom-inventory` | `02-sbom-inventory` | `outputs/sbom-manifest.json` (binds `outputs/sbom.cdx.json`) | `verify_sbom_attempt` |
| `sca-vulnerability-match` | `02-sca-vulnerability-match` | `outputs/sca-vulnerability-match.json` | `verify_sca_attempt` |
| `license-inventory` | `02-license-scan` | `outputs/license-inventory.json` | `verify_license_attempt` |
| `dependency-lifecycle` | `02-dependency-lifecycle` | `outputs/dependency-lifecycle.json` | `verify_lifecycle_attempt` |

Module: `appsec-review-process/sbom_family_contracts.py`. Every argument of every verifier is
required; none has a default. Each returns a fresh `list[str]` (stable error name, `: `, message)
and nothing else. A record is a cache, never an authority: a consumer re-derives.

## Order

1. Presence of every required file (regular, non-linked, bounded). Nothing is parsed.
2. `outputs/redaction-receipt.json` is verified against the published bytes
   (`evidence_redaction.verify_receipt`). If it fails, nothing else is parsed and only the receipt's
   errors are returned.
3. `status.json` and `manifest.json` (outside `outputs/`, never quoted).
4. Each published document is parsed only if the receipt publishes it and its bytes hash to the
   receipt's `published_sha256`.
5. Forbidden claims are rejected by name, alone; then schemas; then the V03 aggregate.
6. Caller bindings, upstream documents (parsed only after their bytes hash to what the caller
   expects), then the contract's own rules and the on-disk source-file bindings.

No error message quotes a value read from an attempt. V03's aggregate messages do quote document
values, so they are reduced to `aggregate:<v03-error-name>` plus caller-declared tool ids.

## What differs from the ADR-0010 fixture, and why

- Every contract also requires `outputs/redaction-receipt.json` (G9; same choice as V04 and V07).
- `sca-vulnerability-match` also requires `outputs/sca-coverage-gaps.json`: M5 sends the workbench an
  aggregated summary with the per-component list **by reference**. The V03 `coverage.json` shape is
  closed and has no place for a per-component list, so the list is its own file and
  `coverage-gap-summary.json` names it by path and sha256. `coverage.json` carries one
  `unmapped-components` gap with the same count.
- `dependency-lifecycle` also requires `outputs/tool-results.json`: V03's coverage rules are defined
  against the tool instance, and the transform's reference-table identity lives in its
  `data_identities`.
- `sbom-inventory`'s `result_schema` artifact is `outputs/sbom-manifest.json`, not the first listed
  file `outputs/sbom.cdx.json`. CycloneDX cannot be expressed as a closed, every-property-required
  schema in the supported subset. The CycloneDX file is bound by sha256, size and spec version and
  must project to the same `(name, version, purl)` multiset as the manifest.
  Because the CycloneDX file is itself published, it is also a claim surface: CycloneDX can carry VEX
  (`vulnerabilities[].analysis.state: not_affected`), ratings and nested components, none of which the
  projection sees. The verifier therefore allows only the top-level members `$schema`, `bomFormat`,
  `specVersion`, `serialNumber`, `version`, `metadata`, `components` and `dependencies`, requires flat
  components, and applies the forbidden-claim-word check to every property name in the file. V11's
  normalizer must flatten syft's output and strip anything else before publishing.
- The ADR's contract table still says `vulnerability-database-identity.json` (singular, no gap
  summary); the fixtures PR #20 updated say `vulnerability-database-identities.json` and
  `coverage-gap-summary.json`. The fixtures were followed.
- `02-license-scan` has no graph edge from `02-sbom-inventory` in the ADR, yet this contract binds
  the licence inventory to an SBOM (task requirement; the lifecycle transform needs the join). V02
  must either add that edge or the binding must move into the lifecycle transform.

## Not duplicated from `06-cve-reachability`

A match is "an advisory range covers the declared version". No property name may contain a word of
`FORBIDDEN_CLAIM_WORDS` (reachable, exploitable, affected, severity, cvss, used, disposition,
recommendation, compliant, ...), no enum value is a member of the `cve-reachability` verdict
taxonomy, and lifecycle status is `supported | end-of-life | unknown`, a reference-table fact, not
06's `known_eol / known_supported_but_old` disposition.

## Known limits

- A `declared` component is bound to a file that exists, hashes correctly and is a manifest or
  lockfile **of its ecosystem by name**. The verifier does not parse manifests, so it cannot prove
  the file really lists the component.
- Version parseability is a conservative per-scheme regular expression. A version that fails is
  certainly a gap; one that passes may still be unparseable by the matcher.
- Matches cannot be re-derived without the databases. They are bound to the cited tool output's
  hash; whether Grype really reported them is V11's normalizer's proof.
- Reference-table matching is exact `(ecosystem, name)` plus longest dotted-prefix `cycle`.
- A licence expression is checked for the SHAPE of an SPDX expression (identifiers joined by
  `AND` / `OR` / `WITH`, balanced parentheses), not against the SPDX licence list: `MIT compliant`
  is rejected, a single made-up identifier is not.
- A file at the attempt root that no contract names (beside `status.json`, `manifest.json` and
  `outputs/`) is ignored, not rejected; everything beneath `outputs/` is bound.
