# Joern runtime closure: license and security review

Reviewed 2026-10-10 for Joern `v4.0.630` (`joern-cli-linux-x86_64.zip`, SHA-256
`92ee27a948b273b83499a8e63c33b604d0abf531ffc43343683492489af41e8d`). The archive is not committed.
The repository holds only the lock, the inventory, and integration code.

## Joern

Joern is Apache-2.0 ([LICENSE at the tag](https://github.com/joernio/joern/blob/v4.0.630/LICENSE),
SHA-256 `2e50a616...`).

**Provenance.** The archive is an immutable GitHub release asset, built by upstream GitHub Actions
(`release-github.yml`). The SHA-512 sidecar is produced by the same job and served from the same
channel. It is an integrity checksum, **not** a signature.

**Signatures.** No detached signature, sigstore bundle, SLSA attestation, or reproducible-build
record is published. The tag object is unsigned. The commit's GitHub web-flow signature does not
cover release assets. Signature status is therefore `not-published`.

## Bundled third-party licenses (installed closure only)

The archive ships **no** top-level LICENSE or NOTICE files for its bundled dependencies.

Licenses were taken from embedded JAR metadata (Maven `pom.xml` and OSGi `Bundle-License`) where it
was present, and otherwise attributed from the project's identity:

- **Permissive:** Apache-2.0, MIT, BSD-2/3-Clause, ICU, WTFPL. This covers the Scala, Typelevel,
  lihaoyi, Log4j, Jackson, Commons, Undertow, XNIO, JBoss, protobuf, jline, zstd-jni, ANTLR,
  slf4j, and json4s components.
- **Weak copyleft, file or library scoped:**
  - EPL-2.0: the Eclipse CDT core (`io.joern.eclipse-cdt-core`) and the Eclipse platform/Equinox
    bundles.
  - LGPL-2.1: `trove4j` (sole license).
  - Choice of licenses: `jna` (Apache-2.0 or LGPL-2.1), `javassist` (MPL-1.1, LGPL-2.1, or
    Apache-2.0), `javax.json` (CDDL-1.1 or GPL-2.0 with Classpath exception), `h2-mvstore`
    (MPL-2.0 or EPL-1.0), and `jruby-complete` (EPL-2.0, GPL-2.0, or LGPL-2.1, plus Ruby-licensed
    standard library).
- **No component is GPL-only** without an alternative or a Classpath exception.

Conclusion: acceptable for internal, unmodified execution inside this repository's runtime.

## Open licensing items (not waived)

1. About 60 JARs, mostly in the Scala ecosystem, carry no embedded license metadata. Their
   attribution comes from project identity only. Per-artifact verification against Maven Central
   POMs was blocked during the review (HTTP 429) and remains open.
2. Bundled NOTICE files were not assembled. Redistributing the image outside the operator's
   organization requires a third-party notices bundle and source offers for the LGPL/EPL/MPL
   components first. The image must not be published to a registry until then.

## Known advisories in the installed closure

Matched against an OSV Maven bulk export: `Maven/all.zip`, SHA-256 `c0e8f6d2...dfaf`, fetched
2026-10-10T06:10Z. The match used the Maven coordinates and file names in `inventory.json`.

| Component | Advisories | Exposure in this runtime |
| --- | --- | --- |
| undertow-core 2.3.18 | CVE-2025-12543 (critical, Host header), CVE-2024-4027, CVE-2024-3884, CVE-2025-9784, CVE-2026-3260 | Reached only by `joern --server`. The runtime has no network, and integration must never use server mode. |
| protobuf-java 3.20.1 | CVE-2022-3171, CVE-2022-3509, CVE-2022-3510, CVE-2024-7254 (DoS) | Parses only CPGs that the run itself produces, in scratch. |
| jackson-core 2.17.2 | CVE-2026-18401, CVE-2026-68494, CVE-2026-89407, CVE-2026-89425 (DoS) | May parse target-derived JSON, such as compile databases. Bounded by the container's memory, CPU, PID, and timeout limits. |
| msgpack-core 0.9.1 | CVE-2026-21452 (DoS) | Same as jackson-core: DoS only, bounded by the container limits. |
| commons-lang3 3.17.0 | CVE-2025-48924 (recursion DoS) | Same as jackson-core: DoS only, bounded by the container limits. |
| jline-reader 3.29.0 | CVE-2026-77420 (ReDoS) | Reached only through the interactive REPL `HISTORY_IGNORE`, which is not used. |
| log4j-core/api 2.19.0 and 2.20.0 | CVE-2025-68161, CVE-2026-34477, CVE-2026-34480, CVE-2026-49844 | Affect the socket/TLS appenders, XmlLayout, and MapMessage JSON, none of which the shipped console-only `log4j2.xml` configures. Not affected by Log4Shell (fixed in 2.17.1). |

No advisory gives remote code execution through the c2cpg parsing path. These remain
**unresolved upstream findings**, not waivers. Bounded export integration (the next work item)
must:

- never use `--server`, `-d`/`--dep`, `-r`/`--repo`, or plugin management;
- treat all parser and exporter output as untrusted;
- rely on the container limits.

**Not assessed:**

- gems vendored inside `jruby-complete` and `io.joern.rubysrc2cpg`;
- the JNI libraries embedded in JARs (zstd-jni, jna, jline-native, jansi, jffi, libfixposix,
  prism) beyond their parent artifact's advisories;
- the Temurin base, which `base-jre` owns.

## Runtime notes for functional acceptance

- JNI libraries (zstd-jni, jna) unpack into `java.io.tmpdir` at load time. The central runtime
  policy mounts `/tmp` as `noexec`, so CPG serialization that needs zstd may fail until an
  exec-capable, run-owned temp location is reviewed.
- The central policy caps every tool at 1 GiB of memory and 600 seconds. Real C/C++ projects will
  likely need a reviewed per-tool resource profile. This must be decided by the bounded-export
  work, not by weakening the policy here.

The launcher and integration files in this directory (`Dockerfile`, `joern-version`, and the TOML/JSON contracts) belong to this repository and do not redistribute
Joern.
