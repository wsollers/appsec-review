# Design content indexing and document conversion

## Purpose

`job_design_artifact_discovery` finds design documents, threat models, specifications, and IDL, and
publishes only structured facts about them. Review workers also need to search what those files
say and ask exact questions about the interfaces they declare. Two jobs supply that:

- `job_document_conversion` turns binary design documents (PDF, DOCX, ODT, RTF, EPUB) into text
  with the pinned offline `tool-doc-convert` image. The catalog can only name these documents.
- `job_design_content_index` splits text artifacts and converted documents into structure-aware
  full-text chunks. It also extracts declared HTTP, async, gRPC, and GraphQL operations, and
  publishes both as the `analysis/design_content` retrieval shard.

Neither job reports security findings. Every chunk and operation resolves to exact source bytes,
or, for converted documents, to a hash-pinned run-owned text artifact. Missing, failed, or bounded
work is a named gap.

## Placement

```text
target_catalog -> design_artifact_discovery -> document_conversion -> design_content_index
  -> [ci_configuration_analysis] -> target_analysis_plan -> ...
```

The direct CLI graph and the Dagster `wave1_review` graph use the same serial order. Conversion
publishes no index. The content job composes its manifest on top of the accepted manifest, so the
`design_content` shard carries forward to the planner and every later job, as described in
[`design-artifact-discovery.md`](design-artifact-discovery.md).

## Document conversion

**Inputs.**
- The accepted discovery handoff, which is required.
- Artifacts categorized as design documents, threat models, or API specifications whose suffix is
  `.pdf`, `.docx`, `.odt`, `.rtf`, or `.epub`.
- Formats with no offline converter (`.doc`, `.ppt`/`.pptx`, `.vsd`/`.vsdx`, `.xlsx`) are named as
  gaps.

**Integrity.** The job hashes each document before running the converter. The converter
independently reports the SHA-256 of the bytes it read, and the job compares the two.
- If they differ, the target changed during the run and the job fails.
- If the catalog recorded a hash, it must also match.

**Execution.** Each document is one execution of `/opt/tool/bin/doc-convert` under the central
container policy:
- no network;
- read-only root and target;
- uid 10001;
- all capabilities dropped;
- bounded CPU, memory, PIDs, time, and output.

The converter writes `text.txt` and `manifest.json`. The job validates the manifest schema, the
input and text hashes, and the character ranges, and rejects oversized output.

**Image.** `containers/tools/doc-convert/` holds the image definition and its build `README.md`.
- PDF: `pypdf` 6.19.0 (pure-Python wheel). Each page becomes a segment.
- DOCX/ODT/RTF/EPUB: the static `pandoc` 3.9.0.2 binary, always run with `--sandbox`, emitting
  GitHub-flavored Markdown so headings survive.

This replaces the deferred `audit-doc-convert` design (pdftotext and pandoc from Debian
packages). That design needed a hash-complete offline `.deb` closure, which none of these assets
require.

**Outcomes.** Each document ends in one of these statuses:

| Status | Meaning |
| --- | --- |
| `SUCCEEDED` | Text was extracted; it may still carry bounded gaps such as page or character limits. |
| `NO_TEXT` | Scanned or image-only document; OCR is not attempted. |
| `ENCRYPTED` | Encrypted with a non-empty or unsupported password. |
| `TIMEOUT` | The converter or pandoc ran out of time. |
| `FAILED` | The document could not be parsed. |
| `TOO_LARGE` | Above `max_input_bytes`. |
| `UNAVAILABLE` | The pinned image is not available locally. |

Every non-success is a named gap and the job completes `PARTIAL`. Only `SUCCEEDED` documents
publish text.

**Settings.** `[jobs.job_document_conversion.settings]`:

| Setting | Default |
| --- | --- |
| `max_documents` | 200 |
| `max_input_bytes` | 32 MiB |
| `max_pages` | 500 |
| `max_chars` | 2,000,000 |
| `pandoc_timeout_seconds` | 120 |

**Resume.** The runtime identity hashes the tool tag, the tool manifest, any pinned image id, and
the converter script. A changed image or converter re-runs conversion and everything after it.

## Interface extraction

`interface_extraction.extract_interfaces` runs over cataloged artifacts whose discovery subtype has
an extractor. Specifications are parsed without executing or fetching anything.

**OpenAPI 3 / Swagger 2.** Parsed with PyYAML's safe composer, keeping node positions.
- Documents that contain YAML anchors or aliases are rejected first. Alias expansion is the classic
  YAML size bomb, and specifications do not need it.
- Only same-document `$ref`s are resolved. External references are recorded as unresolved and
  never fetched.
- Each method under `paths` becomes one operation. The effective security is the operation's
  `security` if present, otherwise the root `security`, reported as:

  | `security_state` | Effective `security` value |
  | --- | --- |
  | `none` | `[]`, or only empty requirements `[{}]` |
  | `optional` | An empty requirement alongside real schemes |
  | `required` | Only real schemes |
  | `unspecified` | No `security` anywhere |
  | `invalid` | Anything else |

- Scheme names map to their declared types, for example `http:bearer`, `apiKey`, or `oauth2`.
- Path-level and operation-level parameters are merged; the operation wins on the same
  name/location pair.
- The record also keeps request media types, response codes, `deprecated`, and
  `insecure_transport`: an `http://` server or Swagger `schemes: [http]`.

**AsyncAPI 2 and 3.**
- 2: `channels.*.publish` and `channels.*.subscribe`.
- 3: `operations.*`, with a local channel reference resolved to its `address`.

**Protobuf.** A comment- and string-aware tokenizer extracts each `service`/`rpc` with:
- package-qualified names and request/response types;
- `stream` on either side;
- `google.api.http` rules;
- `deprecated` options.

**GraphQL.** The extractor reads root types (default `Query`/`Mutation`/`Subscription`, or as
remapped by `schema {}`) and emits one operation per root field. Block-string descriptions are
blanked first, so their text cannot look like fields.

**Spans.** Every operation keeps the inclusive line span that declares it. PyYAML end marks fall on
the next key's indentation, so the span stops at the line before.

## Chunking

`content_chunking.chunk_documents` covers cataloged discovery artifacts in every category except
tests, plus successfully converted documents. Diagrams, images, and binary suffixes are skipped.
Chunk boundaries follow each format's own structure:

| Input | Boundary |
| --- | --- |
| Markdown | `#` headings, ignoring fenced code, with a breadcrumb `heading_path`. |
| AsciiDoc | `=` headings |
| reStructuredText | Underlined titles, with levels assigned in order of first use. |
| Org | `*` headings |
| OpenAPI/AsyncAPI with extracted operations | One chunk per operation span; the remaining lines become `specification` windows. |
| Protobuf, Thrift, Avro IDL, FlatBuffers, Cap'n Proto, Smithy, OMG IDL, AIDL, GraphQL | Top-level `keyword Name { ... }` blocks, with single-line declarations closed in place. Lines outside any block become `declarations` chunks. |
| `.http` / `.rest` | `###` request separators |
| Converted PDF | One chunk per page, windowed further if needed. |
| Converted pandoc output | Markdown sections |
| Anything else | Line windows |

Any chunk above `max_chunk_lines` or `max_chunk_bytes` is split into windows that keep its heading
context. Every non-blank line of an indexed file lands in some chunk.

**Settings.** `[jobs.job_design_content_index.settings]`:

| Setting | Default |
| --- | --- |
| `max_files` | 5000 |
| `max_file_bytes` | 1 MiB |
| `max_chunk_lines` | 80 |
| `max_chunk_bytes` | 8 KiB |
| `max_chunks` | 100,000 |
| `max_operations` | 50,000 |

Reaching any bound is a named gap.

## Index and trust

The `analysis/design_content` shard holds:

- **`source_span` chunks.**
  - Searchable text is the heading breadcrumb plus the chunk text.
  - Cataloged chunks carry an exact byte/line `SourceLocation` against the file's catalog
    SHA-256, so `read_excerpt` re-verifies and returns the bytes.
  - Converted chunks have no target location, because their offsets are into converted text, not
    target bytes. Instead they carry the text artifact identity, the character range, the page or
    segment label, and the bounded chunk text as `converted_excerpt`.
  - Each chunk has a `DERIVED_FROM` relation to its discovery artifact.
- **`interface_operation` entities.**
  - The payload holds every extracted facet, and a `SourceLocation` covers the declaring span.
  - Each operation has a `DERIVED_FROM` relation to the chunk that contains it.
- **Coverage rows** for chunks, interfaces, and converted documents, carrying the job's gaps.

Chunk text is target-controlled data. It is indexed and returned only as bounded results through
the retrieval tools, with its source identity attached. It is never placed in a review-worker
prompt or treated as an instruction. Discovery's structure-only shard stays separate, so the trust
difference is visible in the data.

## Reviewer tools

- **`search_design_content(query, category, path_prefix, chunk_kind, converted, limit, cursor)`**
  - Full-text search over chunks only, ranked by bm25, with the shard's coverage gaps attached.
  - `path_prefix` is a normalized literal folder prefix.
- **`query_interface_operations(protocol, method, route_prefix, security_state, security_scheme,
  streaming, operation_id, path_prefix, limit, cursor)`**
  - Exact facets over declared operations.
  - `route_prefix` is a literal string prefix. `streaming` matches either direction.

Both tools return an availability gap when the shard is absent. Generic `search`, `find`, `trace`,
and `read_excerpt` work over the shard as well.

## Non-goals

- No OCR. Image-only PDFs are reported as `NO_TEXT`.
- No execution, rendering, or network access while converting or parsing.
- No embeddings yet. Vector recall stays conditional on measured full-text-search gaps; see
  `docs/TODO.md`.
- Interface scanners (Checkov OpenAPI, Spectral) are still planned.
