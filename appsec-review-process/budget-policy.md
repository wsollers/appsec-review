# Model and Work Budget Policy

Budget values are operational configuration, not prose defaults. The tracked base values live in
`appsec-review.toml`; a run owns an immutable resolved copy. Job and task overrides use:

```toml
[job_####.step_name]
[job_####.step_name.task_####]
```

Resolution is tracked defaults, then run configuration, then step, then task. Runtime code obtains
the typed result through `configuration.py`; workers must not reparse TOML or invent environment
fallbacks. Existing readers of `model-config.json` and `pipeline/tunables.json` remain migration
exceptions listed in `configuration-migration-inventory.json` until their vertical slices move.

Every model invocation must receive explicit input/output unit limits, byte/file limits, tool-call
limit, wall-clock timeout, model identity and monetary ceiling where the provider supports one.
Exhaustion produces a bounded partial result or named gap according to the output contract; it does
not license omitted scope or a fabricated conclusion.

The result records the effective configuration fingerprint, scope inspected, scope deferred,
actual usage available from the provider, and the next bounded batch when work remains.
