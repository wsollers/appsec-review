# Native component curation

## Question
Which supplied native candidates represent individual libraries or SDK modules, which belong to
coherent SDK distributions, and which remain uncertain or are not components?

Inspect all supplied path context for every candidate, including physical roots, nested paths,
headers, library names, and packaging context. A generic root name need not be the component name:
recover specific component identities from the context beneath it. Retain an unfamiliar but
explicitly named SDK module when its headers or distribution layout support its identity; lack of
a familiar public package name is not a reason to discard it.

This is a read-only proposal from supplied context, with no tools, retrieval, broad filesystem
access, online lookup, or execution. Path evidence can support component curation without proving
a version, upstream identity, or other package metadata.

## Expected result
Return only one JSON object with exactly this shape:

```json
{
  "schema": "appsec-review/native-component-curation/1",
  "input_records": 0,
  "libraries": [
    {
      "name": "component name",
      "kind": "component kind",
      "candidate_ids": ["supplied candidate ID"],
      "supporting_paths": ["exact supplied path"],
      "basis": "specific identity and packaging evidence"
    }
  ],
  "sdk_groups": [
    {
      "name": "SDK distribution name",
      "component_names": ["retained component name"],
      "candidate_ids": ["supplied candidate ID"],
      "supporting_paths": ["exact supplied path"],
      "basis": "coherent distribution or header evidence for grouping"
    }
  ],
  "rejected_candidate_ids": [],
  "uncertain_candidate_ids": []
}
```

The object above illustrates member shapes, not evidence or a default answer. Set `input_records`
to the number of supplied candidate records. Use empty arrays where there is nothing to propose.

Account for every supplied candidate ID: retain it in at least one `libraries` entry, reject it in
`rejected_candidate_ids` when the context establishes it is not a component, or explicitly abstain
in `uncertain_candidate_ids` when the context is insufficient or conflicting. These dispositions
are mutually exclusive. Do not silently drop a candidate, invent an ID, or use an SDK group as its
only disposition.

Preserve the exact IDs and supporting path strings, including their physical roots. Do not merge
distinct physical copies merely because their names match, or collapse differing copies into one
versionless identity. Keep separate library entries for distinct roots even when the names repeat.
A generic candidate root can support multiple specific components; repeated references to that
candidate ID do not create new input records.

Use `name` and `kind` to describe the component supported by its supplied packaging context, not a
guessed upstream package. Each retained entry needs nonempty candidate IDs, supporting paths from
their supplied context, and a concrete `basis`; a common prefix alone is not that basis.

Group common-prefix components only when coherent distribution or header evidence supports a
shared SDK. Preserve the individual libraries or modules even when grouped. Group members refer
only to retained component names and their candidate IDs, and the paths keep repeated names
traceable to the right roots. Grouping neither establishes common versions nor propagates parent
metadata. Explicitly named but otherwise unknown modules remain individual components.

Do not add metadata claims, confidence scores, or extra fields. Recognition or confidence is not
evidence of identity.
