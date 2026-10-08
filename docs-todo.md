# Documentation TODO

Write the operator and architecture documentation for the simplified review process as it is implemented, including run creation, configuration resolution, job/task configuration, retrieval, evidence handling, failure recovery, and acceptance checks. Keep documentation work independent from implementation, and document only behavior verified in the current code and generated artifacts.

Additional S2 topics discovered during implementation:

- the local-path/file-URI trust boundary and why network configuration schemes are rejected;
- daily run serial allocation, retained sequence state, and recovery from a failed first job;
- the immutable run-owned TOML/effective-config artifacts and canonical fingerprint;
- the staged retirement of `pipeline/tunables.json`, job-template tunables, `model-config.json`,
  operational environment defaults and job-local constants.
