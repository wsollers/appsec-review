---
id: filesystem_resources
version: 1
covers: ["cwe:22", "cwe:23", "cwe:36", "cwe:59", "cwe:73", "cwe:276", "cwe:367", "cwe:377", "cwe:379", "cwe:400", "cwe:404", "cwe:434", "cwe:552", "cwe:732", "cwe:770", "cwe:772", "func:fs:*", "func:data:file-upload"]
standards: ["cwe", "capec", "attack", "asvs5"]
max_tokens: 1500
---
## Viewpoint
A filesystem and resource attacker. Paths are a language with `..`, symlinks, absolute roots,
drive letters, and encodings. Files have owners, modes, and races. Every resource the service
allocates on request (memory, disk, descriptors, threads, connections) has a limit or it is a
denial-of-service lever.

## Coverage
GENERATED

## Likely failure modes
- Traversal: `open(base + "/" + name)`, `os.path.join(base, user)` where `user` is absolute,
  `Paths.get(base, name)` without `normalize` plus `startsWith`, `res.sendFile(req.params.f)`,
  `File(dir, name)` with `..`, URL-decoding after the check, Windows `\` and `C:` forms.
- Archive extraction writing entry names verbatim (zip slip, tar with `../` or absolute paths,
  symlink entries pointing outside the target).
- Upload: client-supplied filename or content type trusted, files stored under the web root with
  executable extensions, no size limit, image libraries fed unvalidated formats.
- Symlink and TOCTOU: `access()` or `stat()` followed by `open()`, writes into world-writable
  directories without `O_NOFOLLOW`/`O_EXCL`, `chmod` after creation.
- Temp files: `mktemp`, `tempfile.mktemp`, predictable names in `/tmp`, `File.createTempFile`
  then reopen by name.
- Permissions: files or sockets created `0666`/`0777`, `umask(0)`, secrets written world-readable,
  Windows ACLs granting `Everyone`.
- Exhaustion: unbounded `read()` of bodies, in-memory buffering of uploads, per-request thread or
  goroutine creation, missing timeouts, file handles or connections not closed on error paths.

## Effective controls
- Resolve then contain: `realpath`/`Path.toRealPath`/`filepath.Rel` and a check that the result is
  under the canonical base; `openat2` with `RESOLVE_BENEATH`; Go `os.Root`; mapping ids to stored
  names instead of using client names.
- Atomic creation: `O_CREAT|O_EXCL|O_NOFOLLOW`, `mkstemp`, `tempfile.NamedTemporaryFile`,
  `Files.createTempFile` with restrictive attributes.
- Upload storage outside the web root with generated names, size and type limits enforced
  server-side.
- Explicit limits: request body caps, `LimitReader`, pool sizes, timeouts, `try-with-resources`,
  `defer Close()`, `using`.

## False positives
- Path joins whose component comes from a server-side enum or a database id.
- Files read from directories only the service user can write, in single-tenant deployments.
- Temp-file names in a private per-process directory created with `0700`.
- Resource limits enforced by a fronting proxy that the code path cannot bypass.

## Evidence by predicate
- `affected_construct`: the open, write, extract, chmod, or allocation call and the path or size
  expression it uses.
- `attacker_input_control`: the filename, archive entry, path segment, upload, or request size
  under external control.
- `source_to_sink_reachability`: the handler path from that input to the file operation or
  allocation.
- `missing_or_ineffective_guard`: absent canonicalization and containment check, a check on the
  unnormalized string, non-atomic creation, or no size or count limit.
- `configuration_enables`: web root and storage locations, process umask, container volume
  mounts, body-size settings, filesystem case sensitivity.
- `security_impact`: arbitrary file read or overwrite, code execution via written files,
  privilege escalation through a shared directory, or service unavailability.

## Hand-offs
Decompression ratio bombs go to `parsing_deserialization`. Loader paths for libraries go to
`injection_interpreters`. Host-path and volume mounts go to `cloud_container_deployment`.
Mobile app storage goes to `mobile_platform`.
