[P1] Verify the redaction receipt before inspecting or reporting published fields

`verify_attempt()` calls `validate_result()` and emits header mismatches before it verifies `outputs/redaction-receipt.json`. A tampered, high-entropy `run_id` is therefore returned verbatim in a `header-mismatch` error even though the receipt subsequently fails. Verify the receipt and bind the published bytes before parsing or reporting values from those documents.

[P1] Enforce the registered `status.json` contract

The verifier reads `status.json` but never validates its required `status`, `attempt_id`, or `dagster_run_id` fields. Replacing a valid attempt's file with `{"status":"FAILED","attacker":"..."}` produces no validation error. Validate the strict JSON object and bind its required fields to the node status and worker envelope.
