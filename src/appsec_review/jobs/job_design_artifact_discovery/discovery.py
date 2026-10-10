"""Deterministic classification of design, interface, specification, and test artifacts.

Classification reads only cataloged target-relative paths and, for bounded content probes, a
hash-verified prefix of cataloged bytes. Target content is matched against fixed patterns and is
never interpreted, executed, or retained as free text.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import PurePosixPath
import re
from typing import Any


RULESET_IDENTITY = "design-artifact-rules/1"
CATEGORIES = (
    "design_document", "threat_model", "api_specification", "interface_definition",
    "data_schema", "api_test", "test",
)

_DOC_SUFFIXES = {".md", ".markdown", ".rst", ".adoc", ".asciidoc", ".txt", ".org", ".html", ".htm"}
_DIAGRAM_SUFFIXES = {".drawio": "diagram", ".puml": "diagram", ".plantuml": "diagram",
                     ".mmd": "diagram", ".mermaid": "diagram", ".c4": "diagram"}
_BINARY_DOC_SUFFIXES = {".pdf", ".docx", ".doc", ".vsdx", ".vsd", ".pptx", ".odt", ".png", ".svg"}
_DESIGN_DIRS = {"design", "designs", "architecture", "arch", "adr", "adrs", "decisions",
                "decision-records", "rfc", "rfcs", "proposals", "specs", "specifications"}
_THREAT_WORDS = re.compile(r"threat[-_ ]?model|threatmodel|threat[-_]?dragon|threagile|"
                           r"\bstride\b|attack[-_]?tree|misuse[-_]?case|security[-_]?design")
_IDL_SUFFIXES = {".proto": "protobuf", ".thrift": "thrift", ".avdl": "avro_idl",
                 ".fbs": "flatbuffers", ".capnp": "capnproto", ".smithy": "smithy",
                 ".idl": "omg_idl", ".aidl": "android_aidl"}
_SPEC_SUFFIXES = {".raml": "raml", ".apib": "api_blueprint", ".wsdl": "wsdl",
                  ".graphql": "graphql_schema", ".graphqls": "graphql_schema", ".gql": "graphql_schema"}
_SCHEMA_SUFFIXES = {".xsd": "xml_schema", ".avsc": "avro_schema", ".jsonschema": "json_schema"}
_SOURCE_SUFFIXES = {".py", ".go", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".kt", ".kts",
                    ".scala", ".groovy", ".cs", ".fs", ".vb", ".rb", ".php", ".rs", ".c", ".cc", ".cpp",
                    ".cxx", ".h", ".hpp", ".swift", ".m", ".mm", ".dart", ".ex", ".exs", ".erl", ".lua",
                    ".sh", ".ps1"}
_TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "testing", "unittest", "unittests",
              "e2e", "end-to-end", "end_to_end", "cypress", "playwright", "selenium",
              "integration-tests", "integration_tests", "integrationtest", "system-tests", "system_tests",
              "ui-tests", "component-tests", "load-tests", "loadtest"}
_INTEGRATION_DIRS = {"integration", "integration-tests", "integration_tests", "integrationtest",
                     "it", "contract", "contracts", "component-tests"}
_SYSTEM_DIRS = {"e2e", "end-to-end", "end_to_end", "system", "system-tests", "system_tests",
                "acceptance", "functional", "cypress", "playwright", "selenium", "ui-tests", "smoke"}
_PERFORMANCE_DIRS = {"perf", "performance", "load", "load-tests", "loadtest", "benchmark",
                     "benchmarks", "stress", "k6", "gatling", "locust"}
_TEST_NAME = re.compile(
    r"(^test_.+\.py$)|(.+_test\.py$)|(^conftest\.py$)|(.+_test\.go$)|"
    r"(.+\.(test|spec|e2e|cy)\.(js|jsx|mjs|cjs|ts|tsx)$)|(.+_(spec|test)\.rb$)|"
    r"(.+_(test|unittest)\.(c|cc|cpp|cxx)$)|(^test_.+\.(c|cc|cpp|cxx|rs)$)|(.+_test\.(rs|exs|dart)$)|"
    r"(.+\.tests?\.(ps1|sh|lua)$)")
# Case-sensitive so that names such as Audit.java or Latest.cs are not tests.
_TEST_CLASS_NAME = re.compile(r".+(Test|Tests|IT|Spec)\.(java|kt|scala|groovy|cs|php)$")
_TEST_HARNESS = {"pytest.ini", "tox.ini", "noxfile.py", "jest.config.js", "jest.config.ts",
                 "jest.config.mjs", "vitest.config.ts", "vitest.config.js", "karma.conf.js",
                 "phpunit.xml", "phpunit.xml.dist", "cypress.config.js", "cypress.config.ts",
                 "playwright.config.ts", "playwright.config.js", ".mocharc.json", ".mocharc.yml",
                 "codecept.conf.js", "testng.xml", "ctesttestfile.cmake", "dredd.yml", "dredd.yaml"}
_PROBE_SUFFIXES = {".yaml", ".yml", ".json", ".xml", ".py", ".proto", ".graphql", ".graphqls", ".gql",
                   ".tm7", ".jsonschema", ".avsc", ".feature"}
_PROBE_EXCLUDED_NAMES = {"package.json", "package-lock.json", "tsconfig.json", "composer.json",
                         "composer.lock", "pnpm-lock.yaml", "yarn.lock", ".eslintrc.json",
                         "pom.xml", "appsettings.json", "launchsettings.json"}


def _match(category: str, subtype: str, rule: str, method: str = "path") -> dict[str, Any]:
    return {"category": category, "subtype": subtype, "rule": rule, "method": method}


def _test_level(parts: tuple[str, ...], name: str, original: str) -> str:
    folders = set(parts[:-1])
    if folders & _PERFORMANCE_DIRS or name in {"locustfile.py"} or name.endswith(".jmx"):
        return "performance_test"
    if folders & _SYSTEM_DIRS or re.search(r"\.(e2e|cy)\.[jt]sx?$", name):
        return "system_test"
    if folders & _INTEGRATION_DIRS or "integration" in name or re.search(r"IT\.(java|kt)$", original):
        return "integration_test"
    return "unit_test"


def classify_path(path_value: str) -> list[dict[str, Any]]:
    """Return every path rule matched by one cataloged, target-relative path."""
    path = PurePosixPath(path_value)
    name = path.name.lower()
    parts = tuple(part.lower() for part in path.parts)
    folders = set(parts[:-1])
    suffix = path.suffix.lower()
    lowered = path_value.lower()
    matches: list[dict[str, Any]] = []

    if suffix in {".tm7", ".tm"} or name in {"threagile.yaml", "threagile.yml"} or (
            _THREAT_WORDS.search(lowered) and (suffix in _DOC_SUFFIXES | _DIAGRAM_SUFFIXES.keys() |
                                               _BINARY_DOC_SUFFIXES | {".json", ".yaml", ".yml", ".py"})):
        subtype = ("microsoft_tmt" if suffix in {".tm7", ".tm"} else
                   "threagile" if name.startswith("threagile") else
                   "diagram" if suffix in _DIAGRAM_SUFFIXES else
                   "structured" if suffix in {".json", ".yaml", ".yml", ".py"} else "document")
        matches.append(_match("threat_model", subtype, "threat-model-path"))
    elif name.startswith("security.") and suffix in _DOC_SUFFIXES:
        matches.append(_match("design_document", "security_policy", "security-policy-name"))
    elif suffix in _DIAGRAM_SUFFIXES or name in {"workspace.dsl"}:
        matches.append(_match("design_document", "diagram", "diagram-suffix"))
    elif suffix in _DOC_SUFFIXES | _BINARY_DOC_SUFFIXES and (
            folders & _DESIGN_DIRS or re.search(r"(^|[-_.])(design|architecture|adr|rfc)([-_.\d]|$)", name)):
        subtype = ("adr" if folders & {"adr", "adrs", "decisions", "decision-records"} or
                   re.match(r"(adr[-_]?)?\d{3,4}[-_]", name) else
                   "rfc" if folders & {"rfc", "rfcs", "proposals"} or "rfc" in name else
                   "architecture" if "architecture" in lowered or "arch" in folders else "design")
        if suffix not in {".png", ".svg"} or folders & _DESIGN_DIRS:
            matches.append(_match("design_document", subtype, "design-document-path"))

    if suffix in _IDL_SUFFIXES:
        matches.append(_match("interface_definition", _IDL_SUFFIXES[suffix], "idl-suffix"))
    if suffix in _SPEC_SUFFIXES:
        matches.append(_match("api_specification", _SPEC_SUFFIXES[suffix], "specification-suffix"))
    stem = name.rsplit(".", 1)[0] if "." in name else name
    if suffix in {".yaml", ".yml", ".json"} and re.search(r"(^|[-_.])(openapi|swagger|asyncapi)([-_.]|$)", stem):
        kind = "asyncapi" if "asyncapi" in stem else ("swagger" if "swagger" in stem else "openapi")
        matches.append(_match("api_specification", kind, "specification-name"))
    if suffix in _SCHEMA_SUFFIXES:
        matches.append(_match("data_schema", _SCHEMA_SUFFIXES[suffix], "schema-suffix"))
    elif suffix in {".json", ".yaml", ".yml"} and (stem.endswith(".schema") or stem.endswith("-schema")
                                                   or folders & {"schemas", "jsonschema", "json-schema"}):
        matches.append(_match("data_schema", "json_schema", "schema-name"))

    if name.endswith(".postman_collection.json") or (folders & {"postman"} and suffix == ".json"):
        matches.append(_match("api_test", "postman_collection", "postman-name"))
    elif suffix in {".http", ".rest"}:
        matches.append(_match("api_test", "http_request_file", "http-request-suffix"))
    elif suffix == ".bru":
        matches.append(_match("api_test", "bruno_request", "bruno-suffix"))
    elif folders & {"pacts", "pact"} and suffix == ".json":
        matches.append(_match("api_test", "pact_contract", "pact-path"))
    elif name in {"dredd.yml", "dredd.yaml"}:
        matches.append(_match("api_test", "dredd_configuration", "dredd-name"))

    if name in _TEST_HARNESS:
        matches.append(_match("test", "harness_configuration", "test-harness-name"))
    elif suffix == ".feature":
        matches.append(_match("test", "system_test", "gherkin-feature"))
    elif suffix == ".jmx" or name == "locustfile.py":
        matches.append(_match("test", "performance_test", "load-test-name"))
    elif suffix in _SOURCE_SUFFIXES and (
            _TEST_NAME.search(name) or _TEST_CLASS_NAME.search(path.name) or folders & _TEST_DIRS
            or "/src/test/" in f"/{lowered}"):
        matches.append(_match("test", _test_level(parts, name, path.name), "test-path"))
    return matches


_PROBES: tuple[tuple[str, str, str, re.Pattern[bytes]], ...] = (
    ("api_specification", "openapi", "openapi-root-key",
     re.compile(rb"(?m)^\s*[\"']?openapi[\"']?\s*:\s*[\"']?3\.")),
    ("api_specification", "swagger", "swagger-root-key",
     re.compile(rb"(?m)^\s*[\"']?swagger[\"']?\s*:\s*[\"']?2\.")),
    ("api_specification", "asyncapi", "asyncapi-root-key",
     re.compile(rb"(?m)^\s*[\"']?asyncapi[\"']?\s*:\s*[\"']?[23]\.")),
    ("api_specification", "raml", "raml-header", re.compile(rb"\A\s*#%RAML")),
    ("data_schema", "json_schema", "json-schema-dialect",
     re.compile(rb"[\"']?\$schema[\"']?\s*:\s*[\"']https?://json-schema\.org/")),
    ("api_test", "postman_collection", "postman-schema",
     re.compile(rb"schema\.getpostman\.com|\"_postman_id\"")),
    ("api_test", "insomnia_export", "insomnia-export", re.compile(rb"\"__export_format\"\s*:\s*4")),
    ("api_test", "pact_contract", "pact-specification", re.compile(rb"\"pactSpecification\"")),
    ("threat_model", "threat_dragon", "threat-dragon-model",
     re.compile(rb"(?s)\"diagrams\".{0,8192}\"threats\"|\"threat-dragon")),
    ("threat_model", "pytm", "pytm-import", re.compile(rb"(?m)^\s*from\s+pytm\s+import|^\s*import\s+pytm")),
    ("threat_model", "microsoft_tmt", "tmt-root", re.compile(rb"<ThreatModel[\s>]")),
)
_PROTO_SERVICE = re.compile(rb"(?m)^\s*service\s+[A-Za-z_]\w*\s*\{")
_PROTO_RPC = re.compile(rb"(?m)^\s*rpc\s+[A-Za-z_]\w*\s*\(")
_GRAPHQL_ROOT = re.compile(rb"(?m)^\s*(?:extend\s+)?type\s+(Query|Mutation|Subscription)\b")
_OPENAPI_PATH = re.compile(rb"(?m)^\s{2}[\"']?/[^\s:\"']*[\"']?\s*:")


def needs_probe(path_value: str, matches: list[Mapping[str, Any]]) -> bool:
    path = PurePosixPath(path_value)
    if path.name.lower() in _PROBE_EXCLUDED_NAMES:
        return False
    suffix = path.suffix.lower()
    if suffix not in _PROBE_SUFFIXES:
        return False
    if suffix == ".py":
        return not matches or any(item["category"] == "threat_model" for item in matches)
    return True


def probe_content(path_value: str, prefix: bytes) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Match fixed content signatures in a bounded prefix; return matches and numeric signals."""
    suffix = PurePosixPath(path_value).suffix.lower()
    matches = [_match(category, subtype, rule, "content")
               for category, subtype, rule, pattern in _PROBES
               if (suffix == ".py") == (subtype == "pytm") and pattern.search(prefix)]
    signals: dict[str, int] = {}
    if suffix == ".proto":
        signals = {"service_count": len(_PROTO_SERVICE.findall(prefix)),
                   "rpc_count": len(_PROTO_RPC.findall(prefix))}
    elif suffix in {".graphql", ".graphqls", ".gql"}:
        signals = {"root_operation_type_count": len(_GRAPHQL_ROOT.findall(prefix))}
    elif any(item["category"] == "api_specification" for item in matches):
        signals = {"path_entry_count": len(_OPENAPI_PATH.findall(prefix))}
    return matches, signals


def merge(path_matches: Iterable[Mapping[str, Any]],
          content_matches: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Merge path and content evidence into one entry per category, preferring content subtypes."""
    by_category: dict[str, dict[str, Any]] = {}
    for item in (*path_matches, *content_matches):
        current = by_category.get(item["category"])
        evidence = {"method": item["method"], "rule": item["rule"]}
        if current is None:
            by_category[item["category"]] = {"category": item["category"], "subtype": item["subtype"],
                                              "evidence": [evidence]}
            continue
        if item["method"] == "content":
            current["subtype"] = item["subtype"]
        if evidence not in current["evidence"]:
            current["evidence"].append(evidence)
    return [by_category[key] for key in sorted(by_category)]
