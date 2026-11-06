---
name: native-dependency-resolution
description: Resolve one bounded native library observation to plausible public repository context.
metadata:
  audience: runtime-worker
---

# Native dependency resolution

Work only on the supplied candidate and the generated evidence-reference/host contract.
Repository resolution is dependency context, not a vulnerability assessment.

Prefer exact repository URLs from accepted package metadata. Link flags, filenames, SONAMEs,
framework names, and common naming conventions can support a hypothesis but not an exact identity.
Preserve ambiguity between upstreams, forks, distribution packages, compatibility libraries, and
vendored copies. A plausible mapping must remain model inference with confidence no greater than
0.95 until independently corroborated.

Return only the requested schema and fields. If no repository is supported, return null rather than
guessing. Scorecard context is review prioritization and red-team seed data, not a finding.
