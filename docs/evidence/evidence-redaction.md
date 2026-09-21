# Evidence Redaction And The Redaction Receipt

Status: module, schema and tests only (ADR-0010 Decision G9-A, task V06). **No worker, launcher,
graph node, publication runtime or `02-evidence-index` code calls it yet**; adoption is V10-V13.
Until a producer adopts it, legacy `evidence-scrub` remains the only scrub and its limits stand.

- Module: `appsec-review-process/evidence_redaction.py` (imports only the standard library,
  `execution_state` and `schema_validate`; no logging, no subprocess, no third-party package).
- Schema: `schemas/redaction-receipt.schema.json`.
- Tests and fixture templates: `appsec-review-process/tests/test_evidence_redaction.py`,
  `appsec-review-process/tests/fixtures/evidence-redaction/`.

Behaviour (a secret-name-aware pass plus an entropy/shape pass) is ported from the legacy
`scripts/scrub_evidence.py`. Its code is not reused, and nothing was added under `scripts/`.

## Why a publication boundary

Scanners other than the secrets scanner quote the matched source line, so a hardcoded credential
lands in SARIF `snippet.text`, `message.text`, code flows, command lines and logs. A scrub that runs
last is too late: the value already sits in an accepted attempt and in the evidence index. So every
scanner-backed producer redacts **its own** output, from an attempt-private directory into the
directory it is about to publish, and publishes a receipt beside it. A consumer requires a valid
receipt from the same `CURRENT` attempt or treats the source as absent.

## API

```python
from evidence_redaction import DEFAULT_LIMITS, redact_tree, verify_receipt

receipt = redact_tree(private_dir, to_publish_dir, on_unhandled="refuse", limits=DEFAULT_LIMITS)
verify_receipt(receipt, to_publish_dir, on_unhandled="refuse", limits=DEFAULT_LIMITS)  # raises
```

`on_unhandled` and `limits` are **required keyword arguments** of both functions, and
`published_dir` is a required argument of `verify_receipt`. There is no default policy and no
"unbounded". `Limits` has no default field values; `DEFAULT_LIMITS` is a named constant a caller
must choose to pass (16 MiB per file, 128 KiB per line or JSON string, 2000 files, 128 MiB total,
JSON depth 64, path length 512).

Every source file ends in exactly one of three states:

| Disposition | Meaning |
|---|---|
| `unchanged` | No detection. Published byte-identical; `source_sha256 == published_sha256`. |
| `redacted` | At least one detection. Published with markers. |
| `withheld` | Could not be proven handled. **Not published**, listed with a reason. |

There is no state in which a file is copied without having been scanned.

Policy decides what a `withheld` file does to the publication:

- `refuse` -- any withheld file raises `PublicationRefused` and **nothing** is written.
- `withhold` -- handled files are published; withheld files are listed in the receipt.
- More entries than `max_files` is refused under **both** policies (the listing itself is unbounded).

Withheld reasons: `file-size-limit`, `line-length-limit`, `total-bytes-limit`, `json-depth-limit`,
`binary-content` (a NUL byte, which also covers UTF-16), `not-utf8`, `unsupported-type` (extension
not in the JSON or text allow-list), `symlink`, `not-regular-file`, `unsafe-path`, `reserved-name`
(a source file called `redaction-receipt.json`), `read-error`, `internal-error`, `not-converged`,
`unstable-output`. A producer whose tool writes UTF-16 must transcode inside its private directory.

Boundary rules: the source is opened read-only (`O_NOFOLLOW`, regular files only, bounded read) and
never modified; every path goes through `execution_state.beneath`; links are recorded as withheld
and never followed or descended; the published directory must be absent or empty and neither
directory may contain the other; output is computed in memory (bounded by `max_total_bytes`) before
anything is written; the receipt is written **last**, so an interrupted publication has no receipt
and is absent to every consumer.

## Markers

`[REDACTED:<kind>:<n>]`, where `<n>` is an ordinal within the file. A marker never contains a hash,
prefix, suffix or length of the value. Kinds: `named-secret`, `private-key-block`, `url-credential`,
`bearer-token`, `provider-token`, `jwt`, `high-entropy`, `fingerprint`. Existing markers in the input
are opaque to detection and are never rewritten, which is what makes redaction idempotent; they are
counted as `preexisting_markers`.

## The two passes

1. **Secret-name-aware.** A value tied to a secret-ish name is redacted whatever its entropy or
   length -- this is the pass that catches human passwords. Names: password/passwd/passphrase,
   `pass`/`pwd` as a whole word, secret, token, api/access/account/private/signing/encryption key,
   shared access key/signature, connection string, credential, bearer, authorization. Forms:
   `name = "v"`, `name: v`, `==`/`!=` comparisons, `=>`, `:=`, `name: str = "v"`, `.name("v")`
   calls, JSON-escaped quotes (`\"name\": \"v\"`), `Authorization: <scheme> v`, `--name v` and
   `--name=v` flags, `<name>v</name>`, `Bearer v`, and URL userinfo passwords. An unterminated quote
   redacts to end of line. In JSON, anything beneath a secret-named key is redacted wholesale
   (strings and numbers, through nested objects and arrays), and a string following a secret-named
   flag in an array (`["--db-password", "v"]`) is redacted.
2. **Entropy / shape.** PEM/OpenSSH/PGP **private-key blocks** (the whole block, across real or
   JSON-escaped newlines; a block with no END line is redacted to the end of the text), provider
   token shapes, JWTs, and high-entropy runs of 20+ token characters.

Both passes run to a fixed point, and a redacted file is re-processed before it is accepted: if the
output would change again, or no longer fits the limits, it is withheld as `unstable-output`.

**Public keys and certificates are not secrets and are not redacted**: `CERTIFICATE`, `PUBLIC KEY`,
`CERTIFICATE REQUEST` and `X509 CRL` blocks and `ssh-*`/`ecdsa-*` public-key lines are exempt from
the entropy pass (every other rule still applies inside them).

## Structured input

`.json` and `.sarif` files are parsed (duplicate keys, `NaN`/`Infinity` and syntax errors all count
as malformed) and walked, so `results[].locations[].physicalLocation.region.snippet.text`,
`message.text`, `codeFlows`, and `invocations[].commandLine`/`arguments` are redacted inside their
strings and the output is still valid JSON. Object keys are scanned too. In `sarif` mode
`fingerprints`, `partialFingerprints` (they can be a hash of the matched line, i.e. a per-value hash)
and **every** `invocations[].environmentVariables` value are redacted wholesale.

`parser_mode` records what actually happened: `sarif` (has `version` and `runs`), `json` (valid JSON
-- including a `.sarif` file that is not SARIF), `text`, or `fallback-text`. Malformed JSON is
**never repaired**: it gets the text passes and is published still malformed. In the text passes
`\uXXXX` escapes are decoded for detection only, so a value split across escapes is still found.

Output is byte-deterministic on every platform: files are read and written in binary, text-mode
redaction preserves CRLF/LF exactly, a redacted JSON document is re-serialized with
`ensure_ascii`, two-space indent, `\n` newlines and its original BOM if it had one (number spelling
is normalized by Python's `json`), and an unchanged file is never re-serialized.

## The receipt

Closed objects, every property required. Redactor identity (`module_version`, `ruleset_sha256` --
the digest of `RULESET`, which holds every pattern and threshold), `policy`, `limits`, per-file
records (`path`, `disposition`, `withheld_reason`, `parser_mode`, `source_sha256`,
`published_sha256`, `published_bytes`, `redactions` by kind, `preexisting_markers`), `totals`, the
ADR statement `unredacted_file_in_published_set: false`, and `receipt_sha256` over every other field.

Deliberate omissions, enforced by a schema hygiene test:

- No value, fragment, per-value hash, value length, line text or entropy figure.
- **No source hash for a redacted or withheld file, and no source size.** The redacted output
  reveals everything except the value, so a hash of the source bytes is an offline oracle for a
  low-entropy value, and a size difference is its length. `source_sha256` is non-null only for
  `unchanged` files, where it equals `published_sha256`. (This narrows the V06 task text, which
  asked for a source hash on every record.)
- No timestamp: the receipt is a pure function of the input bytes, the ruleset, the policy and the
  limits. The worker envelope carries time.
- **Paths are published, so they are scanned.** A path that trips the detector, is over-long, or is
  not clean UTF-8 is withheld and recorded as `[WITHHELD-PATH:<n>]`. Keep private directory names
  plain; a long random directory name (a ULID, say) will be treated as high-entropy.

## Verification

`verify_receipt` raises `ReceiptVerificationError` (with `.errors`) unless all of this holds:
schema-valid; `receipt_sha256` matches; redactor identity equals **this** module's; `limits` and
`policy` equal what the verifier demands; each record is internally consistent; real paths are
unique and ascending and placeholders are numbered `1..n`; `totals` equal the per-file sums; the
published directory holds **exactly** the non-withheld files plus `redaction-receipt.json` (no extra
file, no missing file, no links), and that on-disk receipt equals the one being verified; and for
every published file the sha256, size, `parser_mode` and marker counts are recomputed from the
bytes, and **the redactor is re-run over the bytes and must find nothing** (within the limits).

`receipt_sha256` is an integrity check, **not an authenticator**: whoever can rewrite the receipt can
rehash it. That is why verification re-derives from the published bytes instead of trusting fields,
and why the tamper tests re-seal every mutated receipt. Authenticity comes from where the receipt
lives: inside an immutable attempt whose artifact hashes the common envelope already binds.

What verification **cannot** do: a withheld record describes a file that was deliberately left
behind, so its reason cannot be re-derived, and a re-sealed receipt that drops a withheld record
still verifies. Verification proves the published bytes; it says nothing about the private source.
When per-kind counts and `preexisting_markers > 0` coexist, counts are bounded rather than exact.

## Logs and errors

The module has no logger and prints only from the CLI. Exceptions name a relative path that has
itself passed the detector (otherwise `[UNSAFE-PATH]` or a placeholder) and a reason -- never
content, and never a chained cause. Schema errors from a hostile receipt are reduced to location and
rule. Any unexpected failure while processing a file becomes `withheld: internal-error`.

CLI (uses `DEFAULT_LIMITS`; prints counts, safe paths and reasons only):

```text
python -B appsec-review-process/evidence_redaction.py redact <src> <dst> --policy refuse|withhold
python -B appsec-review-process/evidence_redaction.py verify <dst>/redaction-receipt.json <dst> --policy refuse|withhold
```

Exit 0 success, 1 error or failed verification, 2 publication refused.

## This repository's own evidence documents

The redactor sits on the publication path of documents this repository defines (tool-results,
coverage, probe receipts, wave manifests). It must not rewrite their structure. Version 1.0.0 did:
the key `source_snapshot_sha256` was classed as a high-entropy token and replaced with a marker,
which made every such document schema-invalid, and about a third of run ids in the repository's
own format (`20260919T123919Z-0b9e70`) were flagged too. Version 1.1.0 fixes both **narrowly**, in
`RULESET`, so `ruleset_sha256` moves with the change:

- `wordy_technical_pieces` is a closed list of algorithm and format NAMES (`sha256`, `md5`,
  `base64`, `x509`, ...). One of them may appear as a PIECE of a kebab/snake identifier that is
  otherwise made of at least two plain words. A short digit counter (`0001`) is allowed the same
  way. A string that merely contains such a token is still judged on its entropy.
- `exempt_patterns` holds the run-id shape: a UTC stamp plus a hex suffix of at most 12 characters.

JSON object keys are **not** exempted wholesale: a secret can be a key, and the provider, JWT,
private-key and entropy rules all still apply to keys. Tests pair every relaxation with a
must-still-flag case, assert that no property name in any schema under `schemas/` is an entropy
hit, and pass the repository's own evidence fixtures through `redact_tree` expecting `unchanged`.

One constraint remains by design: in JSON, the VALUE beneath a secret-ish key name is redacted
wholesale. A document shape that will be published through the redactor must therefore not name a
property with a secret-ish keyword (`secret_kind`, `token_count`, `authorization`, ...) unless
wholesale redaction of its value is intended. V04 renamed `secret_kind` to `data_class` for this
reason.

## Known false negatives

This is a heuristic, not a proof. A valid receipt means "this ruleset found nothing more", not
"no secret is present".

- A low-entropy value with **no** secret-ish name nearby (`x = "Hunter2"`, a bare `key`, `pin`, a
  generic `-p<value>` on an unrecognised command), or whose name and value are on different lines (YAML block scalars, tables, CSV
  columns headed `password`).
- Encoded or transformed values: base64/hex/URL-encoding of a labelled password, gzip, encrypted
  blobs. Escapes other than `\uXXXX` in the text passes.
- Pure-hex strings of digest length (32/40/56/64/96/128) and UUIDs are treated as digests unless
  named, so an unnamed hex API key of those lengths survives. (SARIF fingerprints are the exception.)
- Random strings under 20 characters, letter-only strings with no case mixing, and `/`-separated
  base64 with no long segment, no `+` and no padding.
- Kebab/snake-case strings that look like words (three or more mostly alphabetic pieces).
- Quoted values spanning lines other than triple-quoted strings and key blocks; backtick quotes.
- Secrets inside a block that looks like a certificate or public key are hidden from the entropy
  pass only.
- Content of withheld files is not published at all, which is safe but is a coverage gap the
  producer must report.

Positional credentials are covered only for the clients named in `RULESET["cli_credentials"]`:
the MySQL/MariaDB family's `-p<value>`, `sshpass -p`, and `user:password` after `-u`/`--user` for
`curl`/`wget`/`http`. The operator-less directive form (`ENV API_KEY value`, `ARG NPM_TOKEN value`,
`export SIGNING_KEY value`) is covered when the NAME is secret-ish, because Dockerfile linters quote
such lines verbatim. Both were added after independent verification found them leaking; a
positional password on any other command line remains a false negative.

## Known false positives

- Any value beneath a secret-ish name, including harmless ones: `max_tokens: 4096`,
  `token_type = "Bearer"`, `password = getpass()`, `PWD=/home/ci`, `${DB_PASSWORD}` references, and
  prose such as `credential: password`.
- A whole attribute or connection string when its name is secret-ish.
- Every SARIF fingerprint and environment variable, including `PATH`.
- Long mixed-case-and-digit identifiers, non-digest-length hex, SRI integrity strings, base64 data
  URIs, long random path segments.
- In JSON, non-secret siblings beneath a secret-named object (`credentials.login`).

A false positive costs legibility; a false negative publishes a credential. The thresholds lean
toward the first.

## Adoption (V10-V13; not done here)

1. Run the tool with its own redaction enabled, writing raw output, normalized output and the
   retained stdout/stderr you intend to keep into an attempt-**private** directory that is not under
   any path the envelope declares as an artifact.
2. `receipt = redact_tree(private_dir, attempt_root / "outputs" / "redacted", on_unhandled=...,
   limits=...)`. Use `refuse` when every file is required by the output contract; use `withhold`
   only when the contract records each withheld file as a named coverage gap.
3. Declare only files beneath the redacted directory (including `redaction-receipt.json`) as
   artifacts; build `tool-results.json`/`coverage.json` from counts and identities, never matches.
4. Delete the private directory before the terminal envelope is written, then call the common
   validation/publication path. Redaction therefore happens before anything is offered to
   `02-evidence-index`.
5. Consumers (`02-evidence-index`, the threat-workbench lane-in) call `verify_receipt` with the
   policy and limits the contract names, against the accepted `CURRENT` attempt, and treat a failure
   as "source absent".
6. Record `redactor.module_version` and `ruleset_sha256` in the producer's input fingerprint so a
   ruleset change invalidates reuse.
