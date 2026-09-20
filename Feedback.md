## [P1] Canonicalize output paths before enforcing single ownership

`verify_outputs_on_disk()` keys `owners` by the raw path string (`appsec-review-process/tool_instance_shapes.py:559-566`), while the output-path schema and `_output_errors()` allow non-normalized aliases such as `shared/./result.json` and `shared//result.json`. Consequently, two tool instances can list `shared/result.json` and `shared/./result.json`; both resolve to the same file, both size/hash checks pass, and the verifier returns no errors. This defeats the function's stated guarantee that an output file is listed by only one tool instance and permits ambiguous artifact ownership.

Reject non-normalized POSIX paths in the schema/cross-record validator, or canonicalize them before duplicate-owner checks. Add a regression test with two instances claiming the same file through a `.` or repeated-separator alias.
