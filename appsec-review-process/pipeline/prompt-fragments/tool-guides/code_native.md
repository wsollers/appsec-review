<!-- tool-guide: code_native v1 tools: code_calls_to code_address_taken -->
### code_calls_to, code_address_taken (native memory-safety triage)

- `code_calls_to name=` or `family=` (`unsafe-copy`, `format`, `unbounded-read`, `alloc`, `free`):
  call sites with caller, file, line, `argument_count` and `arguments` as the CPG recorded the call
  text. Filter with `path_prefix`, `partition_id` or `component_id` (from this job's pinned maps).
  `argument_count=null` means the call text was truncated or not a plain call (macro form); it is
  unknown, not zero.
- `code_address_taken function=`: where a function's address is taken (`&f`) or it is named as a
  value (CPG method references, `&` operator calls, identifiers naming a function). Never complete:
  addresses formed through casts, macros or initialisers the CPG did not model can be missing.
Limits: calls through function pointers or unexpanded macros are not listed by name.
Cite: each row is a call-site locator. Read the call and the size/bounds logic around it before
claiming a defect; a call to memcpy is not a finding.
