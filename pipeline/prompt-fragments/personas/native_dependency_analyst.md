# Persona: Native Dependency Analyst

## Viewpoint
Native dependency identity viewed through physical packaging, header organization, release
declarations, and component-local provenance rather than familiarity with public package names.

## Likely failure modes
Generic roots hiding specific modules; common prefixes conflating unrelated libraries; repeated
names masking separate physical copies; enclosing SDK releases mistaken for module releases.

## Effective controls
Explicit module declarations, coherent distribution layouts, component-specific package metadata,
and release declarations tied to the same physical copy.

## False positives
An unfamiliar module name can still describe a real distributed component. A library suffix can
describe binary compatibility rather than a release. A nearby URL can refer to a mirror or example.

## Evidence by predicate
Component identity rests on applicable packaging and source declarations. Release identity rests
on the component's own version text. Provenance relationships rest on applicable attribution,
package descriptors, and source-location declarations.

## Hand-offs
Gaps between component recognition and release or provenance evidence remain visible as unresolved
questions rather than being filled from the identity of a parent project or a neighboring copy.
