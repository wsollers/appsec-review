---
title: "Crash aggregation APIs and source-linked test data"
kind: "task"
subsystem: "scanners and evidence collection"
status: "historical"
jobs: []
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# Crash aggregation APIs and source-linked test data

Research for T-072 crash-report ingestion and its remaining T-075 integration, 2026-11-12.
Expanded to cover Windows and in-house development, including Crashpad and Breakpad.
Further expanded with a proposed canonical adapter architecture, detector-coverage assessment,
reusable-rule promotion and repository-wide variant discovery.
Repository examined: `wsollers/appsec-review`, commit
`60e562e0c2f8672061007d67d25bef2282f44132`.

## Conclusion

Yes: crash services can supply ranked crash groups, recent regressions, individual stacks and,
where instrumented, memory/resource and network context. They can support a useful "hot breaks"
summary and prioritize security investigation. They cannot establish exploitability or security
severity merely from a stack, frequency, vendor priority, or an out-of-memory label.

Recommended starting points:

- **Mozilla Socorro/Firefox** for an immediately accessible, real production crash API with
  corresponding source. Public aggregation, processed stacks and an exact source revision were
  successfully retrieved during this research.
- **Sentry** as the first commercial connector: broad coverage and an existing local parser,
  although its query API response requires conversion to the parser's accepted format.
- **Backtrace and BugSplat** for native/game-team integrations; **Crashlytics** for mobile/Unity.
- **Crashpad** for new in-house native Windows crash collection; **Breakpad** for existing
  integrations and its Windows sample. Neither is a hosted aggregation/query service.
- **WER LocalDumps and ProcDump** for internal Windows diagnostics without embedding a crash SDK;
  **Partner Center analytics** for eligible applications' Microsoft-collected field reports.
- **GlitchTip** for an open-source, self-hosted API test environment; **minidump-pipeline** for
  controlled native crashes with source and symbols; **OSS-Fuzz/libxml2** for disclosed
  sanitizer/security examples.

Service acquisition should remain outside the review job. Export a bounded, sanitized snapshot;
the offline job consumes that immutable snapshot.

## What already exists in this checkout

The original task description is behind the implementation:

| Component | Observed state |
| --- | --- |
| T-060 fingerprint | Implemented in `src/appsec_review/observability/findings/identity.py:1-67`; TODO registry marks T-060 done. |
| Three first-tranche parsers | `adapter_stackwalk.py`, `adapter_sanitizer.py`, and `adapter_sentry.py` exist under `src/appsec_review/observability/findings/crash/`. |
| Normalized record | `records.py:1-70` defines bounded `appsec-review/crash-report/1` fields, validation constants and privacy exclusions. |
| Binding/corroboration | Offline modules exist; the architecture records implementation limitations. This is not proof of correct real-export behavior. |
| Review job and lead integration | T-075 remains open: `docs/TODO.md:1062-1076`. Runtime network access remains excluded. |

Relevant authoritative context: `docs/architecture/finding-metrics.md:270-362,479-504` and
`docs/operations/finding-metrics.md`, section 3.

Two immediate compatibility issues matter to this research:

1. **Sentry API JSON is not the current parser's input.** The documented event API returns
   `entries[]` and fields such as `lineNo`, `absPath` and `instructionAddr`. The parser expects
   payload interfaces such as `exception.values[]`, `lineno`, `abs_path` and `instruction_addr`;
   its docstring explicitly excludes the API shape. A connector needs a tested conversion or a
   distinct adapter, not simply a downloaded file renamed as `sentry_event`.
2. **Memory/network diagnostic context is deliberately discarded today.** The Sentry parser
   drops breadcrumbs, requests, device context, tags, messages and extras. The normalized record
   has no memory-usage or network-diagnostic fields. Supporting those summaries requires an
   explicit typed, privacy-reviewed extension or separate diagnostic record, not a change that
   silently preserves all vendor metadata.

The architecture also records that current bucket merging crosses builds and retains one
report's build. That is insufficient for accurate per-release trend and fix-support analysis.

## Popularity: useful evidence, not a universal ranking

[42matters Android](https://42matters.com/sdk-analysis/top-crash-reporting-and-performance-sdks)
and [iOS](https://42matters.com/sdk-analysis/app-store/top-crash-reporting-and-performance-sdks)
pages, both marked updated November 10, 2026, report:

| SDK as named by the source | Android app share | iOS app share |
| --- | ---: | ---: |
| Firebase Crashlytics Fabric | 33.17% | 36.34% |
| Sentry | 8.72% | 14.90% |
| Firebase Crashlytics NDK | 7.17% | Not used here |

These are shares **among apps using the source's crash-reporting/performance SDK category**,
not all apps, customers, revenue or game studios. SDKs can coexist; the Crashlytics rows must not
be added together. Generic Firebase installations are not evidence of Crashlytics usage. The
category also mixes aggregators with SDKs and other monitoring tools.

This supports prioritizing Crashlytics and Sentry for mobile reach. BugSnag and Datadog also
appear in those lists. Backtrace/BugSplat are included for native/game suitability, not because
this research established a global market-share ranking for them.

## Commercial API comparison

All commercial routes below require authorized project/account access. Public API documentation
does not make a customer's crashes public. No commercial tenant was queried.

| Service | Read/query access | Useful queries and detail | Important boundary |
| --- | --- | --- | --- |
| **Sentry** | REST issue lists and event details. | Explicit time windows, project/environment filters, frequency/new/trend ordering; stack frames, releases and debug metadata. Optional device memory context and HTTP breadcrumbs if captured. | Use read scopes: issue list documents `event:read`; project event detail documents `project:read`. A submission DSN is not a read credential. API and SDK-payload JSON differ. |
| **Firebase Crashlytics** | Supported mobile analytics route is export to **BigQuery**, then SQL via BigQuery APIs. | Group by issue, build, time and fatal/nonfatal/ANR; inspect threads, symbols, memory used/free, storage and custom keys. Session export can support crash-rate denominators. | Not equivalent to a general Crashlytics issues REST endpoint. Batch export is daily; streaming requires the eligible paid setup. Query/storage costs and IAM apply. |
| **BugSnag** | Data Access API, separate from error submission. | Vendor client implements project errors, events and error-event lists; event/user/first-seen/last-seen sorting and filters. | Current overview plus vendor SDK source verified; detailed legacy reference was inaccessible. Verify exact filter syntax, token permissions and exported native fields against an authorized tenant before implementation. |
| **Backtrace / Sauce Error Reporting** | Coroner query API and object retrieval. | Indexed attributes, time filters, fingerprint grouping, folds/aggregations, sorting and pagination; native modules, stack data and optional resource attributes. | Token scopes include `query:post` and `object:get`; a submit-only token is insufficient. Optional raw memory exists in its format but should not enter review artifacts. |
| **BugSplat** | REST crash-group summaries, group members and crash detail. | Summary supports `crashSum`, first/last report, stack keys; crash queries support application version/time and common filtering/sorting/paging. | OAuth2 client credentials documented. All data endpoints require authentication. Summary lifetime counts must not be mistaken for time-window occurrence counts without confirming endpoint semantics. |
| **Datadog Error Tracking** | Issue search and detail API; related telemetry has separate APIs. | Search by event syntax and time interval; order by total count, first seen, impacted sessions or priority; select logs/trace/RUM track. | Issue search documents a maximum 100 results per request. Account/site permissions and retained logs, traces or RUM determine available diagnostic detail. |
| **Rollbar** | Items, occurrences, top-active reports, metrics and RQL APIs. | Time-window occurrence summaries, issue/event drill-down, filtering and custom aggregation. | Top-active defaults to severity then count; use the documented occurrence sorting when ranking volume. Read tokens differ from post-item tokens. |

Sources:

- Sentry [issue query](https://docs.sentry.io/api/events/list-an-organizations-issues/),
  [event detail](https://docs.sentry.io/api/events/retrieve-an-event-for-a-project/),
  [contexts](https://develop.sentry.dev/sdk/foundations/envelopes/event-payloads/contexts/),
  [breadcrumbs](https://develop.sentry.dev/sdk/foundations/envelopes/event-payloads/breadcrumbs/).
- Crashlytics [export setup](https://firebase.google.com/docs/crashlytics/bigquery-export)
  and [dataset schema](https://firebase.google.com/docs/crashlytics/bigquery-dataset-schema).
- BugSnag [Data Access overview](https://developer.smartbear.com/bugsnag/docs/data-access),
  vendor client [errors](https://github.com/bugsnag/bugsnag-api-ruby/blob/master/lib/bugsnag/api/client/errors.rb)
  and [events](https://github.com/bugsnag/bugsnag-api-ruby/blob/master/lib/bugsnag/api/client/events.rb).
- Backtrace [API/scopes](https://docs.saucelabs.com/dev/api/error-reporting/) and
  [vendor query client](https://github.com/backtrace-labs/backtrace-forensics).
- BugSplat [API/authentication](https://docs.bugsplat.com/api-reference/api.md),
  [crash groups](https://docs.bugsplat.com/api-reference/api/crash-groups.md),
  [filtering](https://docs.bugsplat.com/api-reference/paging-filtering-and-grouping.md).
- Datadog [issue search](https://docs.datadoghq.com/api/latest/error-tracking/search-error-tracking-issues.md).
- Rollbar [API index](https://docs.rollbar.com/reference/llms.txt) and
  [top-active semantics](https://docs.rollbar.com/reference/get-top-active-items.md).

### Concrete query levels

**Level 1: hot groups.** Request a fixed interval and release/platform filters; return the most
frequent, newly appearing or increasing groups. Compare adjacent equal-duration windows. Show
raw counts and, only when an appropriate sessions/users/request denominator is available, rates.
Keep crashes, handled errors, hangs and ANRs distinguishable.

**Level 2: representative evidence.** Fetch a bounded selection of events from each selected
group, including relevant build and fault variants. Preserve provider group ID, event ID, exact
query interval, symbols, module debug IDs and build/revision provenance. A group is a vendor
clustering heuristic, not necessarily one root cause.

**Level 3: diagnostic correlation.** Retrieve allowlisted memory/resource readings, typed network
failures, or linked trace/log context where the SDK collected it and permissions permit it.
An HTTP timeout can be correlated with a crash without proving it caused the crash. Captured
fields are not automatically searchable indexed fields.

**Level 4: security corroboration.** Bind the crash to the reviewed build/source, examine
attacker-controlled input and relevant code, then correlate with a finding. This requires
repository evidence and cannot be replaced by a provider's "critical" or "security" label.

## What "memory/network/security related" can mean

| Evidence | Reasonable classification | What remains unproved |
| --- | --- | --- |
| Sanitizer reports use-after-free or buffer overflow | Strong evidence of that defect class under the recorded execution. | Attacker reachability, production applicability, impact and exploitability. |
| Access violation, heap corruption or execute fault | Memory-safety investigation candidate. | Root cause and whether bad input, hardware, drivers or another component caused it. |
| OOM or low free-memory reading | Resource-pressure/exhaustion signal. | Memory leak, malicious exhaustion or remotely triggerable denial of service. |
| Network exception, timeout, TLS/DNS error, HTTP breadcrumb | Connectivity/protocol/availability signal when actually recorded. | Packet contents, causation, attacker control or a security vulnerability. |
| Assertion, near-null read or hang | Stability/control-flow signal; sometimes a security-relevant availability issue. | That it is harmless, or that it is exploitable. |

Memory **usage**, memory **corruption**, and a raw **memory dump** are different data products.
Most crash services are not heap profilers or packet-capture systems. Missing telemetry cannot be
reconstructed from a stack trace. Hangs may need multiple threads; the existing parsers retain
only the crashing thread, so broader deadlock analysis is outside their current evidence shape.

Maintain separate diagnostic category, observed impact and security assessment. An initial
security assessment should allow **unknown** rather than forcing a safe/unsafe answer.

## Real public test candidate: Firefox / Socorro

[Socorro API documentation](https://crash-stats.mozilla.org/api/) exposes `SuperSearch`,
`ProcessedCrash`, signature/bug mapping and other endpoints. Public views redact protected data;
raw minidumps and protected fields need additional permission. Set an identifying User-Agent and
use bounded queries.

### Observed public query

The following unauthenticated GET returned HTTP 200 during this research:

```text
https://crash-stats.mozilla.org/api/SuperSearch/?product=Firefox&_results_number=0&_facets=signature&_facets_size=5&date=%3E%3D2026-11-11&date=%3C2026-11-12
```

The response reported **50,769** matching crash reports for that date filter. Its top five
signature buckets were:

| Signature | Reports |
| --- | ---: |
| `OOM \| small` | 7,795 |
| `OOM \| large \| js::AutoEnterOOMUnsafeRegion::crash_impl \| js::AutoEnterOOMUnsafeRegion::crash_impl \| js::AutoEnterOOMUnsafeRegion::crash \| js::gc::AllocateTenuredCellInGC` | 2,486 |
| `OOM \| unknown \| js::AutoEnterOOMUnsafeRegion::crash_impl \| js::AutoEnterOOMUnsafeRegion::crash \| js::gc::AllocateTenuredCellInGC` | 1,340 |
| `OOM \| unknown \| js::AutoEnterOOMUnsafeRegion::crash_impl \| js::gc::FreeSpan::allocate` | 1,012 |
| `js::gc::detail::ChunkPtrHasStoreBuffer` | 964 |

These are submitted-report counts, not unique users, total Firefox crashes or crash rates.
They demonstrate aggregation access, not a security assessment of Firefox. A future request may
return different counts due to processing, retention or corrections.

### Observed source-linked event

A second bounded search selected one report from the fifth bucket. Its
[processed report](https://crash-stats.mozilla.org/api/ProcessedCrash/?crash_id=b1dec5b0-58a6-4a7c-83aa-c05640261111)
returned:

- Product version `159.0.1`, build `20261102144711`.
- Windows NT, `amd64`, confirmed through the public processed-report API.
- Crash type `EXCEPTION_ACCESS_VIOLATION_READ`.
- Crashing thread index `17`.
- Frame `js::GCMarker::markCurrentColorInParallel`, module `xul.dll`.
- Source locator containing commit `6181e6b5f28a8fbae1d5c3ef6f6626b5a2180213`,
  file `js/src/gc/Marking.cpp`, line `1522`.
- Module `xul.dll`, symbols `xul.pdb`, reported Breakpad-style debug identifier
  `77B4B7670D0DA1884C4C44205044422E1`.

That exact revision and line were retrieved successfully from the public Firefox repository:
[source location](https://github.com/mozilla-firefox/firefox/blob/6181e6b5f28a8fbae1d5c3ef6f6626b5a2180213/js/src/gc/Marking.cpp#L1522).
This establishes a resolvable source link, **not** root cause or vulnerability confirmation.

No raw dump was downloaded. Socorro's response wraps the stackwalk payload in `json_dump`;
its Git-style source locators need deliberate parsing into repository, revision and relative path.
The existing stackwalk parser must not be assumed to accept the outer response unchanged.

## Other open-source test options

| Project | Source plus crash availability | Best use / limitation |
| --- | --- | --- |
| **GlitchTip** | Open-source self-hosted aggregator compatible with Sentry SDKs. Its public OpenAPI document was retrieved and includes organization issue lists, event lists/details and event JSON export. | Controlled connector tests using our own small instrumented application and generated events. Public schema is not public customer crash data. Native minidump/symbolication parity with Sentry was not established. |
| **Gankra/minidump-pipeline** | Builds its `crash-client`, collects symbols, runs a crash suite and produces minidumps plus stackwalk JSON and a report manifest. | Particularly good source+symbols+crashes candidate for `stackwalk_json`; it is a tooling pipeline, not a production query service. Generation would be an explicitly requested manual run. |
| **rust-minidump testdata** | Recorded dumps and symbols exist. The README identifies `pipeline-inlines-macos-segv.dmp` as generated by minidump-pipeline. | Useful recorded fixtures, but the maintainers explicitly warn much of the remaining corpus is not reproducible. Prefer source-linked cases, review licensing/privacy and freeze sanitized exports. |
| **getsentry/sentry-native examples** | `examples/crash.c` and documented example builds provide controlled crash source. | Exercise Sentry native ingestion/export in an authorized test project, with a pinned source and symbols. This is a crash generator, not an already-public crash feed. |
| **OSS-Fuzz / ClusterFuzz, e.g. libxml2** | Disclosed reports can include sanitizer class, stacks, reproducer and revision ranges. Public libxml2 record `OSV-2025-457` identifies a heap-buffer-overflow write and introduced/fixed revisions. | Stronger security-labelled corpus than generic field crashes, but not user-impact frequency. The OSV record is not a full sanitizer log; its actual testcase/log download and local reproduction were not verified here. |

Specific references:

- GlitchTip [source/project](https://glitchtip.com/),
  [installation](https://glitchtip.com/documentation/install/),
  [OpenAPI](https://app.glitchtip.com/api/openapi.json).
  Observed GET paths include
  `/api/0/organizations/{organization_id_or_slug}/issues/` and
  `/api/0/organizations/{organization_id_or_slug}/issues/{issue_id}/events/{event_id}/json/`.
- [minidump-pipeline](https://github.com/Gankra/minidump-pipeline),
  [rust-minidump fixture provenance](https://github.com/rust-minidump/rust-minidump/blob/main/testdata/README.md).
- [Sentry native examples](https://github.com/getsentry/sentry-native/tree/master/examples).
- [libxml2 public crash record](https://github.com/google/oss-fuzz-vulns/blob/main/vulns/libxml2/OSV-2025-457.yaml),
  [underlying issue](https://issues.oss-fuzz.com/issues/424242614),
  [OSS-Fuzz reproduction guide](https://google.github.io/oss-fuzz/advanced-topics/reproducing/),
  [disclosure policy](https://google.github.io/oss-fuzz/getting-started/bug-disclosure-guidelines/),
  [ClusterFuzz triage](https://google.github.io/clusterfuzz/using-clusterfuzz/workflows/triaging-new-crashes/).

OSS-Fuzz is not an unrestricted public crash-query API equivalent to Socorro. Unreleased
security reports have access controls, and disclosure timing applies. Source and public
advisories do not guarantee every attachment or exact historical build remains obtainable.

## Windows and in-house development

### Separate capture, processing and aggregation

**Breakpad is the Google-origin open-source toolkit in the question. Crashpad is the newer
Google/Chromium crash-capture system I would evaluate first for a new native integration.**
Both support Windows. This recommendation is not a claim that Breakpad is unsupported or that
an existing integration should be replaced.

| Option | What it supplies | Query/API level and in-house use |
| --- | --- | --- |
| **Crashpad** | Embedded client plus a separate handler process, minidump capture, persistent local report database and optional upload to a configured collector. | Native programmatic interfaces and `crashpad_database_util` expose local report state. There is no fleet-wide REST analytics service in the client; use an existing compatible backend or provide collection, processing and indexing separately. Recommended new native Windows capture candidate. |
| **Breakpad** | Native capture, symbol-dumping and minidump-processing tools; Windows in-process and out-of-process integration. | C++ interfaces and sender/processor tools, not a hosted query API. Its Windows documentation points to a source-controlled out-of-process crash-generation sample. Suitable for existing deployments and controlled fixtures. |
| **WER LocalDumps** | Windows can save per-application mini/full/custom user-mode dumps after a crash without changing application source. | Local files, not a central search API. Useful for internal desktop applications, services and QA machines. Administrator configuration is required; Microsoft explicitly excludes applications doing their own custom crash reporting from this feature. |
| **ProcDump** | On-demand or triggered dumps: unhandled exceptions, hung windows, CPU usage, memory commit and performance-counter thresholds. | CLI suitable for controlled internal support/QA automation; indexing and export are separate. It can capture a resource problem even when the process has not crashed. |
| **DbgHelp `MiniDumpWriteDump`** | Windows API for writing user-mode minidumps with selected streams. | Low-level building block, not aggregation. Prefer established capture tooling to a new home-grown crash handler. Microsoft recommends calling from a separate process where possible and synchronizing DbgHelp calls. |
| **Partner Center / Microsoft Store analytics** | Microsoft-collected failure aggregates, available event details and stack traces for eligible enrolled applications. | Authenticated REST querying exists. Not an automatic feed for every internal EXE; enrollment, application ownership, diagnostic collection and account access matter. |
| **MSVC AddressSanitizer** | Instrumented Windows C/C++ development and CI diagnostics, including specific memory-error classes and optional sanitizer-enriched dumps. | Existing `sanitizer_report` is the intended text-ingestion family, subject to confirming Windows report variants. Better defect classification than generic access violations; not production crash-rate telemetry. |
| **`dotnet-dump` / SOS** | Managed .NET dump collection and GC/managed-crash analysis on Windows and other supported platforms. | CLI and managed diagnostic commands. Separate from native stackwalking; the tool explicitly does not display native stack frames. Do not claim native minidump parsing covers managed heap analysis. |

Crashpad's project status documents its Windows client and Chromium's Windows adoption in 2015.
Some surrounding status text and Breakpad's historic product list are old, so they should not
be treated as a current market-share survey. The design and Windows integration documents are
the evidence for the capabilities above.

The Crashpad local database is an upload queue, **not a production crash aggregator**:
`completed` can mean successfully uploaded, upload disabled, or an upload failure that will not
be retried. An exporter must not interpret every completed report as delivered successfully.
The documented upload-enable bit starts false when a database is created; application
configuration controls it. Client identifiers and other local metadata should still be removed
before evidence publication.

Sources: [Crashpad overview](https://chromium.googlesource.com/crashpad/crashpad/+/main/doc/overview_design.md),
[platform status](https://chromium.googlesource.com/crashpad/crashpad/+/main/doc/status.md),
[local database utility](https://crashpad.chromium.org/man/crashpad_database_util.html),
[Breakpad overview](https://github.com/google/breakpad/blob/main/docs/getting_started_with_breakpad.md),
[Windows integration](https://github.com/google/breakpad/blob/main/docs/windows_client_integration.md),
[WER LocalDumps](https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps),
[ProcDump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump),
[MiniDumpWriteDump](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump),
[MSVC ASan](https://learn.microsoft.com/en-us/cpp/sanitizers/asan?view=msvc-170),
[dotnet-dump](https://learn.microsoft.com/en-us/dotnet/core/diagnostics/dotnet-dump).

### Microsoft has an actual desktop crash-query API

The documented desktop route is:

```text
GET https://manage.devcenter.microsoft.com/v1.0/my/analytics/desktop/failurehits
    -> failureHash
GET https://manage.devcenter.microsoft.com/v1.0/my/analytics/desktop/failuredetails
    -> cabIdHash
GET https://manage.devcenter.microsoft.com/v1.0/my/analytics/desktop/stacktrace
```

Requests require the application ID and an authorized bearer token. The aggregate endpoint
supports date ranges, application-version/OS/failure filters, grouping and pagination. The
documentation limits retrieval to the last **30 days**; week/month aggregation limits
failure-name/hash values to **1,000 buckets**. Collect bounded complete results before computing
a ranking: the documented `orderby` list does not include `eventCount`, so do not invent a
server-side count-sort parameter.

The stack endpoint documents frame number, image, function and function-relative offset. It
does not promise file/line, a source revision, heap data, read/write/execute direction or module
debug identifiers. Symbol availability and an internal release-to-build manifest therefore
remain important. Its offset is not automatically the module-relative offset used by our
normalized native frames.

Microsoft's GDK health report also describes crashes, hangs, memory failures, applicable stack
traces/CABs and a development-sandbox filter, and links to analytics APIs. Product-specific API
coverage and permissions must be confirmed with the account owner; the desktop endpoint above
is not a claim of universal console/devkit access.

An important security-classification limitation: the documented health-report changes collapse
several old read/write/execute categories into **ACCESS_VIOLATION**. Do not infer a write or
execute fault from that aggregate label. Preserve the missing detail as a gap unless an
authorized lower-level report supplies it.

Sources: Microsoft [desktop aggregates](https://learn.microsoft.com/en-us/windows/uwp/monetize/get-desktop-application-error-reporting-data),
[failure details](https://learn.microsoft.com/en-us/windows/uwp/monetize/get-details-for-an-error-in-your-desktop-application),
[desktop stack trace](https://learn.microsoft.com/en-us/windows/uwp/monetize/get-the-stack-trace-for-an-error-in-your-desktop-application),
and [GDK health report](https://learn.microsoft.com/en-us/partner-center/insights/health-report).
These authenticated endpoints were documented, not exercised.

### Proposed in-house path

For native Windows applications we own, preserve a build manifest mapping the exact executable
and matching PDB identities to the source revision, toolchain, configuration and architecture.
Keep private symbols private. A matching version label alone is weaker than matching module
debug identity; wrong or missing symbols must produce a named gap rather than a plausible
source association.

```text
Internal application + Crashpad/Breakpad
  OR controlled WER/ProcDump capture
  -> private dump intake / operator-selected local export
  -> isolated symbolication using matching PDB-derived symbols
  -> bounded stackwalk JSON + sanitized build/provenance manifest
  -> existing offline crash ingestion
```

For a private, vendor-free deployment, the capture clients and stackwalking tools are available
as components. Socorro is an open-source aggregation system worth evaluating, but adapting and
operating it is additional work, not a turnkey consequence of installing Crashpad. For a small
first test, an operator-exported directory is enough: do not build a fleet-wide service just to
exercise the ingestion parser. A compatible commercial backend can replace private
collection/indexing without changing the offline review boundary.

For **memory growth, CPU stalls and network delays**, augment capture with a deliberately
configured telemetry source. ProcDump threshold captures provide point-in-time evidence;
[WPR/ETW](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-recorder)
can record a timeline for resource analysis. Network operations require appropriate application
events or network tracing, not an assumption that a minidump contains a packet history. Export
only typed, approved summaries rather than raw request bodies, credentials, arbitrary logs or
process memory. Even a small/triage dump is not guaranteed free of sensitive data.

For **developer/CI memory defects**, MSVC ASan is a complementary route. Its optional
`ASAN_SAVE_DUMPS` output contains extra sanitizer metadata; a generic stackwalker must not be
assumed to preserve that diagnosis. Keep the structured/text sanitizer report and bind it to
the build separately.

### Windows source-plus-crashes test selection

1. **Real field data: Firefox/Socorro.** The report already inspected above was confirmed as
   Windows NT/amd64 and includes `xul.pdb` identity plus a resolvable source commit. It is a
   genuine Windows test candidate, not just a cross-platform analogy.
2. **Controlled open-source application: Breakpad's
   [Windows crash-generation sample](https://github.com/google/breakpad/tree/main/src/client/windows/tests/crash_generation_app).**
   The Windows integration guide identifies it as an out-of-process example. Pin its source,
   build it with symbols and preserve sanitized processed output when an execution is requested.
3. **New integration candidate: the existing Sentry native `examples/crash.c`, using its
   configured Crashpad backend**, or a minimal owned native application linked directly to
   Crashpad. Confirm the selected build/backend/platform rather than assuming every build uses
   Crashpad. Keep reports local or in an authorized private test service.
4. **Instrumented internal application: MSVC ASan build.** Record the report, build/source
   manifest and expected defect class from controlled tests. This provides evidence for
   `sanitizer_report` independently of a SaaS service.

No Windows application was built, instrumented or crashed during this research. No registry,
system crash handler, upload configuration or machine telemetry setting was changed.

## Proposed pluggable architecture and detector feedback loop

This section is a design recommendation, not an implemented schema or an assertion that the
review runtime already performs the complete loop.

### One canonical contract, with separate plugin boundaries

```text
Sentry / Socorro / Backtrace / BugSplat / Microsoft / internal exports
  -> acquisition adapters: authenticated queries or operator files
  -> immutable, sanitized export boundary
  -> format adapters: vendor payload -> canonical observations
  -> validated canonical evidence
  -> build/source binding and root-cause investigation
  -> existing detector coverage assessment
  -> candidate search / confirmed-pattern variant search
  -> reusable detector proposal and reviewed rule-pack publication
```

Keep three extension points rather than one plugin that can do everything:

| Boundary | Responsibility | Must not do |
| --- | --- | --- |
| Acquisition adapter | Discover provider capabilities; fetch bounded groups/events or accept an operator export; preserve query scope, counts, provenance and gaps. | Run inside the offline review worker, expose credentials to it, or declare security findings. |
| Format adapter | Pure, bounded transformation of exported bytes to the canonical contract, including explicit field mapping, unit conversion and redaction. | Fetch missing data, execute dump tools, silently guess unknown fields or promote a vendor label to a confirmed defect. |
| Detector integration | Expose versioned rule capabilities, prerequisites and normalized execution/results for the selected engine. | Treat an installed rule as executed, or run an unreviewed generated query through a read-only retrieval tool. |

Symbolication is a controlled preprocessing operation, separate from pure parsing. The existing
`crash/adapters.py:31-80` registry and validation boundary should be reused, not replaced with a
second adapter mechanism. Plugins are repository-controlled code registered explicitly in typed
configuration; an input file cannot nominate a Python module or executable to load.

Provider capability declarations should distinguish aggregate queries, event retrieval, time
filters, release filters, source identity, native faults, memory measurements, network events
and attachments. A supported provider feature does not imply it was enabled for this project,
captured for this event, or retained for the requested period.

### Canonical data model: common core plus typed optional sections

Evolve the existing `appsec-review/crash-report/1` contract through an explicit schema version
for incompatible additions. Do not add undeclared keys to the current strict format.

The proposed observation structure is:

| Section | Canonical meaning |
| --- | --- |
| Identity and provenance | Observation identity, provider and adapter/version, source event/group references, source/export hashes, transformation identity and originating query snapshot. |
| Observation kind | Crash occurrence, aggregate bucket, sanitizer observation, or associated hang/resource/network diagnostic. The kind determines which fields can be required. |
| Time and count | Event time versus ingestion time; aggregate interval; occurrences and their counting unit; sampling/retention/partial-export state. |
| Build and source | Product/release/configuration/platform/architecture; module code/debug IDs; exact revision when known; source mapping and binding evidence. |
| Fault and sanitizer | Reported exception/signal, access direction and address class when available; sanitizer-reported defect class. Security interpretation remains separate. |
| Threads and frames | Crashing/relevant-thread identity, frames, raw and normalized symbols, inline context, relative source paths, lines, typed offsets and symbolication state. Bounds and omitted-thread coverage are explicit. |
| Memory/resource diagnostics | Typed measurements with units, subject and timing, such as system free memory or process committed bytes; explicit OOM observations. Not raw memory. |
| Network diagnostics | Typed operation category, result/error class, status and timing where recorded; sanitized service/route identity only if approved. Not raw URLs, payloads, packet captures or credentials. |
| Completeness and field provenance | Which fields were observed, derived, unsupported, not captured, redacted or unavailable; resolving evidence for derivations and conflicts. |

Different sources populate the same semantic fields; they do not have to populate every field.
For example:

- Sentry `contexts.device.free_memory` and Crashlytics `memory.free` describe system/device
  memory in their documented contexts. They must not be renamed to process heap usage.
- A ProcDump memory-commit trigger is a trigger condition, not proof of an OOM exception.
- Microsoft desktop stack offsets are function-relative; stackwalker `module_offset` is
  module-relative. Preserve the offset kind rather than making them falsely interchangeable.
- A Sentry issue total and one exported representative event are not two independent occurrence
  counts. Aggregate-bucket and event records must be distinguishable and must not double count.
- An unknown read/write direction remains unknown even when the provider names the bucket
  `ACCESS_VIOLATION`.

Use centrally defined field semantics and units. Do not force everything into a lowest-common-
denominator stack, but do not introduce an arbitrary unbounded `vendor_payload` object either.
If a new diagnostic cannot fit the existing sections, add a registered, versioned, typed
extension. Its unknown or unsupported fields remain explicit gaps until downstream consumers
understand them. Raw sensitive exports stay outside run-owned normalized evidence.

Cross-source deduplication also needs evidence: two services receiving the same crash are not
automatically two independent occurrences, while similar stacks are not proof of duplication.
Keep provider grouping, cross-source duplicate assessment and finding fingerprint distinct.
Preserve per-build occurrence distributions rather than retaining only the first build.

### A case view can unify the workflow without mixing facts and opinions

The canonical observation is immutable evidence. A separate derived case view links:

```text
Case
  observation references
  source/build binding assessments
  root-cause hypotheses and adjudicated findings
  detector coverage assessments
  similar-code candidates and their dispositions
  proposed reusable check and its validation evidence
```

Providers populate observations, not the coverage verdict or confirmed-finding fields.
Analysis writes separately versioned assessments with their own evidence and producer identity.
Consumers can present this as one common case while retaining which statements came from a
crash service, deterministic normalization, a scanner or a reviewer.

The eventual summary can answer:

```text
What happened? | What code/build? | Existing check? | Did it run?
Did it detect this defect? | Why not? | Can detection improve?
Where else is the pattern? | Is a reusable check ready?
```

### Question 1: is this already covered by OpenGrep, CodeQL or another detector?

This must not be a Boolean lookup by CWE or crashing function. A crash may occur inside an
allocator or copy routine while the root cause is an earlier lifetime, bounds or ownership
mistake elsewhere.

Keep the following axes independent:

| Axis | Evidence required |
| --- | --- |
| Catalog support | A rule/query exists in the pinned inventory, and its documented predicate covers all or a named subset of the suspected defect. Matching only a CWE is a candidate association. |
| Applicability | Language, framework, build configuration, source availability and required models support analysis of this construct. |
| Enablement and execution | Exact rule/pack version was enabled, the relevant source was included and parsed/extracted, and execution completed for that scope. |
| Observed result | A corresponding accepted result exists, no corresponding result was emitted, or execution/coverage prevents evaluation. |
| Review disposition | The result was admitted, suppressed, deduplicated, dismissed, or became a finding. A downstream dismissal is not a scanner miss. |

Useful derived outcomes include:

- **Detected:** the accepted scanner observation is correlated to the same source-bound defect.
- **Available, not evaluated:** there is an applicable detector, but it was disabled, not run or
  did not cover the relevant build/source.
- **Evaluated, no corresponding result:** the rule ran over an eligible scope but no correlated
  result exists. Call this a false negative only once the defect, applicability and relevant
  coverage are established.
- **Partial detector support:** the catalog names the uncovered form or missing modeling.
- **No known detector in the examined inventory:** not a universal assertion that no tool has one.
- **Insufficient evidence:** root cause, source binding, execution receipt or input coverage is
  missing.

Reuse the authoritative `rules/registry.toml` pack inventory and existing per-rule mappings,
including `rules/sei-cert/mappings/` and `rules/cpp-cert/coverage.json`. The SEI CERT model already
separates supported subsets from dataflow, compiler, CodeQL and manual-review requirements.
An indexed detector-capability view should derive from those authorities and verified engine
metadata rather than becoming another manually maintained, conflicting inventory.

`review/tool_rules.py` is **not** that detector catalog: it maps the evidentiary predicates a
scanner observation may support. Preserve its distinction between point results and path
results. Neither a matching rule ID nor a matching source line confirms a vulnerability.

The current MCP interfaces can retrieve accepted observations by scanner/rule/path and inspect
coverage. Determining this full per-case assessment still needs the proposed orchestration and
scope-correlated execution receipts; it is not already supplied by a single tool.

### Question 2: if it is not covered, can it be?

First identify why it was not detected. Often the appropriate change is enabling an existing
rule, fixing extraction or adding a framework model, not writing another rule.

| Established defect characteristic | Candidate detection approach |
| --- | --- |
| Local syntactic misuse, such as a narrowly defined allocation/deallocation mismatch | Portable OpenGrep/Semgrep pattern, with safe alternatives and near misses tested. |
| A source-to-sink condition, relational bounds or cross-function propagation | CodeQL or another suitably modeled dataflow engine. Applicability and model completeness remain explicit. |
| Resolved C++ type/lifetime/layout or path-sensitive semantics | Compiler-backed analysis, appropriate CodeQL modeling or another analyzer, depending on the precise condition. |
| Timing/race, environment-dependent resource exhaustion or protocol state | Dynamic instrumentation, sanitizer/fuzz/regression tests or targeted review may be more reliable than a generic SAST check. |
| Only an unexplained stack or OOM count is available | Investigate first; do not manufacture a vulnerability rule from the symptom. |

Engine support differs by version, language and configured models. OpenGrep-compatible rules
must stay within the repository's tested portable subset when claiming portability. A
syntactic candidate finder must not be presented as equivalent to a semantic proof.

### Question 3: can it become a generic, standard item useful to other projects?

Yes, for a demonstrated generalizable condition. The reusable unit should be a **check
definition with engine implementations**, not a vendor crash signature or one repository's
function name.

Proposed check metadata:

- Stable check ID, version and original description of the violated invariant.
- CWE/CERT mappings where justified, with mapping provenance.
- Applicable languages, APIs/frameworks, build assumptions and required models.
- Defined bad condition, required preconditions, safe guards/exceptions and known limitations.
- One or more engine implementations, pinned dependencies and their distinct covered subsets.
- Synthetic or shareable positive, variant, fixed/negative and near-miss fixtures.
- Evaluation results, false-positive/false-negative risks, runtime cost, owner and license.

For example, an observed allocation-related overflow might justify a reusable check for
**unchecked size arithmetic feeding allocation and subsequent writes**. It should not become
"flag this project's parser name" or "flag every multiplication before malloc." A valid guard,
bounded input, checked arithmetic and safe allocation helpers are essential negative examples.

Promotion should progress from source-bound case to candidate detector, minimized positive and
fixed/negative examples, broader variants, held-out examples, and review before inclusion in a
versioned pack. Evaluation must establish the claimed subset rather than merely compile the
query or rediscover the original line. Where one rule already captures the predicate, extend
its models/tests instead of adding a duplicate.

Use the existing pack registration, validation, hash-locking and per-rule coverage mechanisms.
CodeQL compilation and any requested runtime evaluation remain explicit operations, not an MCP
retrieval side effect. A generated detector cannot automatically modify the immutable rules
of the review run that generated it; evaluate it in a separate approved context.

"Standard" initially means a reusable maintained item in this system's catalog, with SARIF
compatibility for applicable scanner outputs and established weakness identifiers. Upstream
contribution to a vendor/community pack is a separate publishing and licensing decision;
acceptance is not automatic. Do not export private source, crashes or proprietary logic while
generalizing a rule. Use independently authored minimized fixtures or approved licensed data.

### Question 4: can we search the rest of the target repository for similar cases?

Yes, with two distinct stages:

1. **Candidate discovery:** search the accepted target snapshot for relevant symbols, API use,
   syntax, callers/callees and comparable guards or dataflow. A crash hypothesis can guide
   exploratory retrieval, but its search hits remain unconfirmed candidates.
2. **Variant confirmation:** once the defect predicate is established, test each candidate
   against the same preconditions, unsafe behavior and counterexamples. Only confirmed,
   re-resolvable findings can seed the runtime's existing automated variant-hunt mechanism.

Repository interfaces already available in source:

| Existing interface | Role |
| --- | --- |
| `search`, `find` | Bounded discovery over accepted immutable evidence and exact entity facets. |
| `read_excerpt`, `resolve_evidence` | Read hash-verified source and resolve supporting evidence. |
| `query_syntax` | Written calls/identifiers/definitions within an exact indexed source or AST identity; syntax is not semantic resolution. |
| `query_observations`, `query_codeql` | Existing accepted detector results, including exact rule/source filters. |
| `query_debug_symbols` | Build-bound PDB/DWARF evidence for mapping the crash to code. |
| `list_codeql_databases`, `query_codeql_neighborhood`, `query_code_graph`, `trace` | Bounded precomputed graph, call, path and guard evidence within admitted scope. |
| `coverage`, dataset inventory | What was indexed, omitted, partial or unavailable. |

These names are repository-defined interfaces, not a claim that this chat has a mounted target
run or can invoke them against an arbitrary repository now.

Critical limits:

- The current `query_codeql` tool filters **stored observations**; it does not execute arbitrary
  QL. Neither neighborhood nor graph retrieval runs CodeQL. New rule execution and expanded
  graph production go through explicit job execution.
- Seeded graphs only cover bounded neighborhoods. Absence outside the neighborhood is not
  evidence of no similar defect; a wider scan/export may be needed.
- Current automatic follow-up variant hunts are package-local. Cross-package/cross-lane
  variant coordination is documented as a gap. A whole-repository loop must deliberately
  enumerate admitted components/build units and aggregate coverage, rather than quietly
  broadening one worker's access.
- A selected top-N or budget-limited search cannot claim full-repository coverage. Record the
  source revision, eligible files/build scopes, queries, boundaries, result caps and unresolved
  candidates.
- GitHub code search or semantic search can help discover additional candidates where access
  permits. An indexed default-branch hit must be re-resolved against the target revision before
  it becomes evidence for a crash from an older build.
- Windows crash ingestion does not itself establish Windows build-analysis coverage. T-043
  still records MSVC capture/CodeQL work; T-087 records crash-symbol normalization work.

The useful end product is therefore not just "three similar strings found." It is a
source-resolving candidate list with the reason each candidate matches or fails the defect
predicate, alongside the exact searched scope and gaps.

### Existing foundations and implementation boundaries

Verified source references for this design:

- `src/appsec_review/observability/findings/crash/adapters.py:31-80,97-167`:
  registration, canonical normalization and current bucket merging.
- `src/appsec_review/mcp/schema.py:23-67,124-220`:
  read-only search, evidence, scanner-result and bounded graph interfaces.
- `src/appsec_review/retrieval/core.py:1070-1115,1300-1392`:
  accepted-result filtering and delegation to bounded graph/symbol readers.
- `src/appsec_review/review/tool_rules.py:1-32,67-80`:
  rule-result evidentiary predicates, not full detector capability coverage.
- `rules/README.md` and `rules/registry.toml`: authoritative pack inventory and verification.
- `docs/architecture/sei-cert-rule-pack.md` and `docs/operations/sei-cert-rule-pack.md`:
  per-rule capability statuses, exception handling, fixtures and promotion procedure.
- `docs/architecture/seeded-codeql-neighborhoods.md`, sections 2, 4 and 8:
  bounded precomputation, seed coverage and retrieval limits.
- `docs/architecture/inference-security-review.md:25-31`:
  confirmed-only package-local variants and cross-package limitations.

The new work proposed here is the richer canonical contract, provider-to-field capability
mapping, per-case detector assessment, controlled detector-promotion loop and whole-repository
variant coordination. None is claimed implemented by this research. Existing T-075 job
integration and T-087 symbol normalization remain relevant prerequisites where applicable.

## Recommended integration shape

```text
Authorized provider API / operator export
  -> bounded acquisition outside the review runtime
  -> sanitized, immutable export with query/provenance manifest
  -> offline crash parser and job contract
  -> diagnostic summary + review leads
  -> source/build binding and independently evaluated finding corroboration
```

The acquisition manifest should distinguish:

- Provider/project scope, query interval, capture time, filters, grouping semantics and API version.
- Total matching occurrences versus exported representative events; sampling, retention,
  pagination completion, truncation and unavailable fields.
- Provider group/event identity versus the review system's finding fingerprint.
- Per-build/release counts, relevant denominators and their definitions, without personal IDs.
- Sanitized export hashes and any transformations; no secrets, raw dumps or sensitive URLs.

A useful summary row would contain the group, occurrence count/window, change from a comparable
window, affected builds, diagnostic category, source-binding tier, security assessment,
evidence references and explicit gaps. Do not collapse those dimensions into one opaque
"security score."

Reuse the implemented parsers rather than making a parallel parser tree in the new job.
T-075 integration should use the existing typed job-contract, accepted-input and producer-gap
mechanisms. Adding API acquisition or new diagnostic fields is a separate scope decision from
wiring the offline job.

Recommended validation sequence, not executed:

1. Freeze a small sanitized Socorro sample to exercise real API-to-stackwalk conversion and
   source-locator handling.
2. Use source-linked minidump-pipeline output and an authorized Sentry native example export for
   native format fidelity; use GlitchTip for isolated API/auth/pagination/event tests.
3. Obtain a disclosed OSS-Fuzz full sanitizer report and its corresponding source/reproducer,
   rather than treating an advisory summary as a parser fixture.
4. Add focused regressions for conversions, repeated-event deduplication, per-build counts,
   bounds/redaction and source binding, then integrate the job under T-075.

## Research boundary

This work inspected repository source, current documentation and public read-only endpoints.
Commercial authentication, account entitlements, quotas and real tenant exports remain
unverified. No service was deployed, no crash generator or reproducer was executed, and no
review job was launched. This report is committed research and proposed design, not implemented
runtime behavior; repository implementation and TODO state were not changed.
