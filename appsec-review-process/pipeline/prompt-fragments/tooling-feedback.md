## Optional tooling feedback

Because this job was granted lookup tools, the response object may carry one more top-level key,
`"tooling_feedback"`, beside the keys above. It is optional, never validated with your result and
never used as evidence: `{"useful_tools": [tool names], "unhelpful_tools": [{"tool", "reason"}],
"wanted": [{"kind": "query|data|language|file_type|tool|other", "what", "why"}],
"coverage_confidence": "low|medium|high", "would_change": "..."}`. At most 8 tools each, 5 wanted
items, 200 characters per reason/what/why, 300 for would_change. Say what would have let you go
deeper or be more exhaustive. Omit the key rather than guess.
