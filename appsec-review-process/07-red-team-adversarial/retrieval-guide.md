# Retrieval Guide For Red-Team Lanes

Use deterministic artifacts first, then source. Prefer `rg` for text/code search and keep searches
scoped to the target repo or cited evidence directories.

## Required Starting Points

Read:

- `appsec-review-process/runs/<run_id>/inputs/artifact-manifest.json`
- component-purpose map from `derived_artifacts.component_purpose_map_json`
- `scratch/<project>-engagement/llm/ENGAGEMENT_LLM_INPUT.md`
- `scratch/<project>-engagement/llm/retrieval-plan.md`
- `scratch/<project>-engagement/llm/deep-confirmation.md`
- component IR slice, if present: `scratch/<project>-engagement/llm/component-ir/<component_id>.md`
- source files listed in the component's `representative_locations`

## Source Search

Run searches from the repo root. Substitute the target path and component search terms from the
component-purpose map.

```bash
rg -n --hidden --glob '!build/**' --glob '!test/**' --glob '!benchmark/**' \
  '<term1>|<term2>|<term3>' <target_path>
```

For a focused component, search representative files first:

```bash
rg -n '<term1>|<term2>|<term3>' \
  <target_path>/source \
  <target_path>/include/EASTL
```

When reviewing a candidate line, pull nearby source context:

```bash
rg -n -C 8 '<symbol_or_function_name>' <target_path>
```

## Evidence Search

Search the LLM evidence package and tool outputs for the component id, source file, function name,
rule id, and relevant issue terms:

```bash
rg -n '<component_id>|<source_file>|<function>|<issue_term>' scratch/<project>-engagement/llm
rg -n '<source_file>|<function>|<issue_term>' scratch/<project>-engagement/static-evidence
rg -n '<source_file>|<function>|<issue_term>' scratch/<project>-engagement/native-scratch
```

Use `component-ir/<component_id>.md` to identify compiled functions, direct calls,
GEP/pointer-arithmetic locations, and memory intrinsics. Treat this as compiled retrieval evidence,
not proof of exploitability.

## Semantic Index

If `static-evidence/semantic-index/index.json` exists and is marked complete, use
`scripts/query_semantic_index.py` for concept searches. Keep queries specific to the component and
attack class.

```bash
python scripts/query_semantic_index.py \
  --index scratch/<project>-engagement/static-evidence/semantic-index \
  --query '<component purpose plus issue class>' \
  --top-k 10
```

## CodeQL Follow-Up

If `retrieval-plan.md` contains CodeQL follow-up commands, copy the relevant command and constrain
review to the component's files/symbols. CodeQL output is evidence, not a final finding, unless the
specific path is source-reviewed or independently verified.

## FC04 EASTL Probe Terms

For the EASTL FC04 string/encoding rehearsal, start with:

```bash
rg -n 'DecodePart|UTF8ToUCS|UCS[24]ToUTF8|memmove|EASTL_ASSERT|pSource|pDestination|sourceEnd|destEnd|char8_t|char16_t|char32_t' targets/eastl/source targets/eastl/include/EASTL
```

Primary evidence files:

- `scratch/eastl-engagement/llm/component-ir/FC04.md`
- `scratch/eastl-engagement/llm/deep-confirmation.md`
- `scratch/eastl-engagement/llm/retrieval-plan.md`
- `targets/eastl/source/string.cpp`

