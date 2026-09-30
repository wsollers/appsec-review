<!-- tool-guide: evidence_similar v1 tools: evidence_similar -->
### evidence_similar (ssdeep candidates)

When: find copies or near-copies of a file (vendored forks, duplicated parsers, templated configs).
How: an indexed `path`; scores run 0-100.
Limits: ssdeep is a hint, SHA-256 is identity. Even a score of 100 is not byte identity unless the
result says `exact`. Short or empty files have uninformative fuzzy hashes.
Cite: only for "these files are candidates for comparison"; read both before claiming they share a flaw.
