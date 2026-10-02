# Intake review cell (deterministic; no model reads this)

Decision D4 (2026-10-02, prompt/persona/role alignment plan): the two intake review cells of
`persona-tool-pool-dispatch` do not call a model. `persona_tool_pool_lifecycle.GraphReviewInvoker`
writes the canonical candidate, derived by Python from accepted intake, and records "No model was
called" in the invoker output.

This file stays because the pool protocol pins an assembled prompt in every cell request; the prompt
is never sent. If a future change lets a model judge intake, rewrite this task in the plan shape
first and move the templates back to `prompt_lint.DISPATCHED`.
