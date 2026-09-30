<!-- tool-guide: code_types v1 tools: code_type_info code_overrides -->
### code_type_info, code_overrides (types)

- `code_type_info type=`: the type's declaration(s), member functions (from qualified names), base
  classes and subclasses when the index has inheritance edges.
- `code_overrides method=`: candidate overrides of a method in other types.
`hierarchy_complete=false` (today always: the CPG export carries no inheritance edges) means base
classes, subclasses and overrides are not known; override rows are same-name candidates, not
confirmed overrides. Never conclude "no subclass overrides this" from these tools.
Cite: read the declaration lines before citing a type relationship.
