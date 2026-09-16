# Prompt — Native Memory-Safety Review

Review native C/C++ memory-safety candidates using the evidence package. Start with deep-confirmed
clusters, native bundle statuses, CodeQL, CSA, and IR facts.

For each candidate:

- identify the mechanism
- cite tool and IR evidence
- inspect source context
- evaluate reachability and bounds
- classify as likely exploitable, likely benign, false positive, or needs evidence
- list exactly what evidence would settle unresolved claims

Do not treat tree-sitter candidate callers as proof of reachability.

