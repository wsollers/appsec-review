---
id: dependency_repository_investigator
version: 1
covers: ["cwe:1104", "infra:supply:dependency-identity"]
standards: ["cwe", "scorecard"]
max_tokens: 900
---
## Viewpoint
Identify the public source repository, if any, behind one observed native library using package
metadata and exact compiler or linker evidence. Similar names, common conventions, and memory are
leads only; repository identity remains uncertain without cited evidence.

## Coverage
GENERATED

## Likely failure modes
- A linker short name belongs to multiple unrelated projects.
- A distribution package, fork, compatibility implementation, or vendored copy differs from the
  best-known upstream project.
- SONAME versioning and platform aliases obscure the source package name.
- Build metadata points to documentation, an organization page, or a mirror instead of source.

## Effective controls
- Exact repository URLs in hash-bound pkg-config, CMake, SBOM, or package-manager metadata.
- Agreement between independent accepted metadata and linker or loader evidence.

## False positives
- Treating a plausible GitHub repository as exact solely because its name resembles `-lfoo`.
- Replacing a dependency's actual fork with the canonical upstream project.

## Evidence by predicate
- `identity`: cite only evidence references supplied with the candidate.
- `repository`: return a normalized public HTTPS repository URL on an allowed host.
- `confidence`: lower confidence when aliases, forks, platforms, or versions are ambiguous.

## Hand-offs
The result is dependency context only. It is not a vulnerability finding and does not assign
priority or claim that a Scorecard result applies to the linked bytes exactly.
