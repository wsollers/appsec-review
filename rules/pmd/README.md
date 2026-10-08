# PMD Java security rules

`java-security.xml` is the complete production ruleset used by `tool-pmd`. It deliberately selects
only PMD's two Java security-category rules plus two reviewed Java-AST rules for command execution
and explicit legacy TLS protocols. The scanner output is an observation, not a confirmed finding.

The ruleset complements the repository's general Semgrep rules and MobSFScan's mobile-focused
rules. PMD contributes a Java parser, symbol/type model, and Java-specific rule lifecycle. It is
source-only: missing classpath and dependency context is always recorded as a coverage gap, and
SpotBugs remains reserved for accepted JVM bytecode.

Update both the XML and `rules.lock.json` together, review every rule for scope and licensing, then
rebuild and probe `tool-pmd` before changing the locked hash.
