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
      "kind": "library",
      "candidate_ids": ["supplied candidate ID"],
      "supporting_paths": ["exact path from context_paths"],
      "basis": "specific identity and packaging evidence"
    }
  ],
  "sdk_groups": [
    {
      "name": "SDK distribution name",
      "component_names": ["retained component name"],
      "candidate_ids": ["supplied candidate ID"],
      "supporting_paths": ["exact path from context_paths"],
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

Preserve the exact IDs and supporting path strings from each candidate's `context_paths`, citing at
least one `context_paths` entry for every referenced `candidate_id`. Same-named inputs (for example
one dependency observed across several link commands, build units, or roots) share one `libraries`
entry whose `name` appears once and whose `candidate_ids` and `supporting_paths` list every
matching candidate ID and cited context path; runtime curation partitions distinct physical roots
automatically without collapsing differing copies into one versionless identity. A generic
candidate root can support multiple specific components; repeated references to that candidate ID
do not create new input records.

Set `kind` to `"library"` or `"sdk-component"` and use `name` to describe the component supported
by its supplied packaging context, not a guessed upstream package. Sort `libraries` and
`sdk_groups` by `name`, and sort and deduplicate all `candidate_ids`, `supporting_paths`,
`component_names`, `rejected_candidate_ids`, and `uncertain_candidate_ids` arrays. Each retained
entry needs nonempty candidate IDs, supporting paths from their supplied `context_paths`, and a
concrete `basis`; a common prefix alone is not that basis.

Group common-prefix components only when coherent distribution or header evidence supports a
shared SDK. Preserve the individual modules in `libraries` with `kind` set to `"sdk-component"`
when grouped. Group members refer only to retained `"sdk-component"` names, and each group's
`candidate_ids` and `supporting_paths` must equal the exact sorted unions of its member
`libraries` entries. Grouping neither establishes common versions nor propagates parent metadata.
Explicitly named but otherwise unknown modules remain individual components.

Do not add metadata claims, confidence scores, statuses, or extra fields. Recognition or
confidence is not evidence of identity.
