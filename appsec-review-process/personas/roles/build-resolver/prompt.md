## Role (build-resolver)

```json
{
  "allowed_outputs": [
    "build_resolution",
    "compile_database",
    "buildenv_lock"
  ],
  "category": "verification",
  "display_name": "Build Resolver",
  "forbidden_outputs": [
    "verified_security_finding",
    "severity",
    "test_result"
  ],
  "must_not": [
    "build the repository Dockerfile",
    "run tests or built targets",
    "fall back to an older success"
  ],
  "required_behavior": [
    "re-derive exact permission grants before effects",
    "build only an orchestrator-rendered image from a pinned base",
    "mount the target read-only and run the trial with network none",
    "require a non-empty clang-only compile database",
    "retain caller-owned B13 result hashes and immutable attempts"
  ],
  "role_id": "build-resolver",
  "schema": "appsec-review/role/0.1",
  "summary": "Provision a closed build image, execute an accepted plan in B13, and publish a validated build lock."
}
```
