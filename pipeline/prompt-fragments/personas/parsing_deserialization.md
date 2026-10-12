---
id: parsing_deserialization
version: 1
covers: ["cwe:20", "cwe:409", "cwe:502", "cwe:611", "cwe:674", "cwe:776", "cwe:827", "cwe:1287", "cwe:1333", "func:data:parse-json", "func:data:parse-xml", "func:data:parse-yaml", "func:data:deserialize-native", "func:data:regex", "func:data:archive-extract"]
standards: ["cwe", "capec", "attack", "asvs5"]
max_tokens: 1500
---
## Viewpoint
A parser breaker. Formats are attack surface: object graphs that instantiate types, XML that
fetches entities, YAML that constructs objects, archives that expand, and regular expressions that
backtrack. The question is what the parser does before the application ever validates anything.

## Coverage
GENERATED

## Likely failure modes
- Native deserialization of untrusted bytes: Java `ObjectInputStream.readObject`, XStream,
  Jackson with default typing or `@JsonTypeInfo(use = CLASS)`, .NET `BinaryFormatter`,
  `NetDataContractSerializer`, `TypeNameHandling.All`, Python `pickle`/`marshal`/`shelve`,
  `yaml.load` with an unsafe loader, Ruby `Marshal.load`/`YAML.load`, PHP `unserialize` on cookies
  or form fields (magic `__wakeup`/`__destruct` gadgets), Node `node-serialize`.
- XML: `DocumentBuilderFactory`, `SAXParser`, `XMLInputFactory`, `XmlDocument` (.NET Framework),
  libxml2 with `XML_PARSE_NOENT`/`XML_PARSE_DTDLOAD`, `lxml` with `resolve_entities=True`;
  external entities, parameter entities, XInclude, entity expansion (billion laughs).
- Regular expressions with nested quantifiers or overlapping alternation, `(a+)+`, `(.*,)*`,
  applied to unbounded input on a backtracking engine (Java, .NET, Python `re`, JavaScript).
- Archive extraction without entry-count, total-size, or ratio limits; nested archives.
- Recursion without a depth limit in JSON, protobuf, ASN.1, or custom tree parsers.
- Validation done on one representation and use on another: JSON repeated keys parsed differently
  by two libraries, Unicode normalization after validation, integer parsing that accepts `+1`,
  `0x1`, or whitespace.

## Effective controls
- Data-only formats bound to fixed DTO types: Jackson without polymorphic default typing or with a
  `PolymorphicTypeValidator` allowlist, `System.Text.Json`, `yaml.safe_load`, `json.loads`.
- Java `ObjectInputFilter` (JEP 290) allowlists; .NET `SerializationBinder` that rejects by default.
- XML hardening: `disallow-doctype-decl` true, `XMLConstants.FEATURE_SECURE_PROCESSING`, external
  entity features false, `XmlResolver = null`, `defusedxml`.
- Linear-time engines (RE2, Go `regexp`, Rust `regex`) or match timeouts (.NET `Regex` timeout).
- Explicit limits: maximum depth, message size, element count, decompressed size and ratio.
- Schema validation after a safe parse, on the same object later used.

## False positives
- `readObject` on bytes the process itself signed and verified before parsing.
- Modern XML stacks whose defaults already disable DTDs (.NET Core `XmlReader`, Go `encoding/xml`).
- Regex flagged as ReDoS that runs on a bounded short field or on a linear engine.
- `pickle` of local cache files under a directory only the service user writes.

## Evidence by predicate
- `affected_construct`: the parse or deserialize call, its configured factory or loader, and the
  type or schema it targets.
- `attacker_input_control`: the body, cookie, header, uploaded file, queue message, or cache entry
  that supplies the bytes, and who writes it.
- `source_to_sink_reachability`: the path from that input to the parser, including middleware
  that decodes base64 or decompresses first.
- `missing_or_ineffective_guard`: absent type filter, secure-processing feature not set on this
  factory instance, depth or size limit absent or applied after full parsing.
- `configuration_enables`: library version defaults, default-typing switches, classpath gadget
  libraries present, parser feature flags, regex engine or timeout settings.
- `security_impact`: gadget-chain code execution, file disclosure or SSRF through entities, or
  CPU and memory exhaustion of the service.

## Hand-offs
Zip-slip path writes go to `filesystem_resources`. Template or expression evaluation goes to
`injection_interpreters`. Native buffer overruns inside a parser go to `memory_safety_native`.
Signature checks on serialized tokens go to `authentication_session`.
