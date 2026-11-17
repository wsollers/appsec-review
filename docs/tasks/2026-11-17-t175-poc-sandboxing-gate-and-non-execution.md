---
title: "Task plan T-175: Gate dynamic PoC and sanitizer execution on sandboxing architecture review"
kind: "task"
subsystem: "testing and operations"
status: "current"
jobs: ["job_poc_generation", "job_sanitizer_build"]
last reconciled: "7dce146454df1a220fe6e1772207503aa655ef43"
---
# Task plan T-175: Gate dynamic PoC and sanitizer execution on sandboxing architecture review

This plan documents **T-175** (`docs/TODO.md`, **State: `blocked`** on dedicated sandboxing design
discussion with the user): enforcing a hard policy gate prohibiting dynamic execution of generated
Proof-of-Concept (PoC) code while specifying the threat model and architectural options to review
with the user before any future dynamic replay runner is built.

## Current mandatory policy gate

- **Zero PoC execution:** `job_poc_generation` produces static exploit specifications, HTTP/CLI/FFI
  input vectors, and Tree-sitter syntax-checked harness code (`T-174`) with
  `generated_code_execution = "not_performed_by_policy"`.
- **No subprocess/container invocation of generated exploit payloads:** Neither `job_poc_generation`
  nor `job_remediation_validation` may invoke `subprocess`, Docker containers, compilers with
  arbitrary build scripts/proc-macros, or target binaries against LLM-generated PoCs until this
  sandboxing review is completed and explicitly approved.
- **`job_sanitizer_build` scope boundary:** Remains restricted to deterministic ASan/UBSan
  compilation readiness (`sanitizer-build`) without executing synthesized exploit inputs.

## Threat model for future dynamic PoC sandboxing (for user discussion)

Running untrusted target binaries together with LLM-synthesized exploit payloads introduces risks
that standard rootless Docker containers sharing the host WSL2 Linux kernel do **not** fully
mitigate:

1. **Shared-kernel syscall surface:** Kernel vulnerabilities reachable from container namespaces
   if `seccomp` profiles allow broad syscalls or `io_uring` / unprivileged userns primitives.
2. **Network & metadata exfiltration:** SSRF, DNS tunneling, or local loopback probes against
   Dagster, Docker sockets, or host services if network namespaces are not completely air-gapped.
3. **Filesystem & secret leakage:** Volume mounts accidentally exposing repository `.git` configs,
   host credentials, or sibling run artifacts.
4. **Denial-of-service / fork bombs / memory exhaustion:** Payloads triggering algorithmic
   complexity blowups, huge allocations under ASan shadow memory, or disk-filling core dumps.
5. **Non-deterministic side effects:** Time-dependent race harnesses (`TSan`) or stateful DB
   mutations corrupting reproducibility.

## Candidate sandboxing tiers to evaluate with the user

| Tier | Isolation Mechanism | Kernel Boundary | Pros | Trade-offs |
|---|---|---|---|---|
| **Tier A (Recommended for Linux/WSL2)** | **Firecracker microVM or Kata Containers / QEMU KVM** per PoC run | Dedicated guest kernel per execution | Hardware virtualization boundary; fast snapshot restore (<200 ms); zero host-kernel sharing | Requires nested `/dev/kvm` enabled in `.wslconfig` on Windows host |
| **Tier B** | **gVisor (`runsc`) OCI runtime** + `--network=none` + read-only rootfs | User-space application kernel (`Sentry`) intercepts syscalls | Drop-in Docker runtime (`--runtime=runsc`); strong host-kernel syscall isolation without nested KVM | Minor syscall compatibility edge cases with `ptrace` / ASan `clone` flags (configurable via platform `systrap`) |
| **Tier C** | **Disposable remote VM / Azure Confidential Container pool** | Separate ephemeral host | Complete physical/host separation from developer workstation | Network orchestration, artifact transfer latency, and cloud cost |

## Proposed mandatory sandbox controls (once a tier is chosen)

```text
Required controls before unblocking T-175:
- Guest / user-space kernel boundary (Firecracker KVM or gVisor runsc; never plain runc)
- Network: completely offline (--network=none, loopback-only inside isolated netns)
- Filesystem: read-only rootfs + size-capped tmpfs (/tmp <= 64 MiB, noexec except pre-built target binary)
- Resource ceilings: cgroup v2 memory.max, memory.swap.max=0, pids.max=64, cpu quota, hard wall timeout <= 15s
- Inputs: only immutable target binary + static data blob stdin/argv/socket replay (no shell evaluation)
- Oracle capture: structured exit status, ASan/UBSan stack trace parser, zero core-dump retention outside redacted summary
```

## Seven-point acceptance criteria

1. **Documentation & dataflow updates:** Maintain explicit policy boundary in
   [`../operations/poc-generation.md`](../operations/poc-generation.md),
   [`../operations/sanitizer-build.md`](../operations/sanitizer-build.md), and `docs/TODO.md`
   (`T-175`), registered in `docs/docs-ledger.json`.
2. **Full indexing for downstream inference:** Index static PoC harness readiness and sanitizer
   build-readiness metadata without claiming dynamic exploit verification (`not_performed_by_policy`).
3. **Fast, isolated unit tests (`<10s`):** Unit tests in `tests/unit/job_poc_generation/` verify
   that attempting to configure or invoke dynamic PoC execution raises a hard policy refusal and
   never spawns a subprocess (`<10s`, zero Docker/VM dependencies).
4. **Common querying & indexing skills doc alignment:** Reflect static-only PoC evidence status in
   [`../architecture/querying-and-indexing-skills.md`](../architecture/querying-and-indexing-skills.md).
5. **Frontier prompting, roles & skills alignment:** `poc_writer` prompt explicitly instructs the
   worker to produce reviewable, non-destructive static harnesses/inputs and never claim live
   execution occurred.
6. **Metrics & telemetry:** Record `poc.execution_status = "not_performed_by_policy"` in attempt
   telemetry and executive/dossier reports so readers never confuse static syntax validity with
   dynamic crash reproduction.
7. **Proper schema versioning & user sign-off:** Keep dynamic execution fields gated behind an
   explicit future schema revision until the user reviews and approves Tier A/B/C sandboxing.
