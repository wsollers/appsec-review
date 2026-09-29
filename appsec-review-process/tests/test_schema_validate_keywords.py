from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import schema_keyword_lint as lint  # noqa: E402
import schema_validate as sv  # noqa: E402


def check(instance, schema, store=None):
    return sv.validate(instance, schema, store or sv.SchemaStore())


class KeywordCoverage(unittest.TestCase):
    def test_string_bounds_and_format(self):
        schema = {"type": "string", "minLength": 2, "maxLength": 3}
        self.assertEqual(check("ab", schema), [])
        self.assertTrue(check("a", schema))
        self.assertTrue(check("abcd", schema))
        stamp = {"type": "string", "format": "date-time"}
        self.assertEqual(check("2026-09-29T10:00:00Z", stamp), [])
        self.assertEqual(check("2026-09-29T10:00:00.123+02:00", stamp), [])
        for bad in ("2026-09-29", "2026-02-30T10:00:00Z", "2026-09-29T24:00:00Z",
                    "2026-09-29T10:00:00", "2026-09-29T10:00:00Z\n"):
            self.assertTrue(check(bad, stamp), bad)
        self.assertEqual(check("2024-02-29", {"format": "date"}), [])
        self.assertTrue(check("2023-02-29", {"format": "date"}))

    def test_numeric_bounds(self):
        schema = {"type": "integer", "minimum": 1, "maximum": 3}
        self.assertEqual(check(1, schema), [])
        self.assertTrue(check(0, schema))
        self.assertTrue(check(4, schema))
        self.assertTrue(check(1, {"exclusiveMinimum": 1}))
        self.assertTrue(check(3, {"exclusiveMaximum": 3}))
        self.assertTrue(check(5, {"multipleOf": 2}))
        self.assertEqual(check(True, {"minimum": 5}), [], "booleans are not numbers")
        self.assertTrue(check(1.0, {"type": "integer"}), "unchanged: a float is not an integer")

    def test_array_keywords(self):
        self.assertTrue(check([1, 2, 3], {"maxItems": 2}))
        self.assertTrue(check(["a", "a"], {"uniqueItems": True}))
        self.assertTrue(check([{"a": 1, "b": 2}, {"b": 2, "a": 1}], {"uniqueItems": True}))
        self.assertEqual(check([1, True], {"uniqueItems": True}), [], "true != 1 in JSON")
        tuple_schema = {"prefixItems": [{"type": "string"}], "items": {"type": "integer"}}
        self.assertEqual(check(["a", 1, 2], tuple_schema), [])
        self.assertTrue(check(["a", "b"], tuple_schema))
        contains = {"contains": {"const": 1}, "minContains": 2, "maxContains": 2}
        self.assertEqual(check([1, 1, 0], contains), [])
        self.assertTrue(check([1, 0], contains))
        self.assertTrue(check([1, 1, 1], contains))

    def test_object_keywords(self):
        schema = {"type": "object", "additionalProperties": {"type": "integer"},
                  "patternProperties": {"^x-": {"type": "string"}},
                  "propertyNames": {"pattern": "^[a-z-]+$"}, "minProperties": 1,
                  "maxProperties": 2, "dependentRequired": {"a": ["b"]}}
        self.assertEqual(check({"x-y": "s", "b": 1}, schema), [])
        self.assertTrue(check({"x-y": 1}, schema))
        self.assertTrue(check({"c": "s"}, schema), "additionalProperties is a schema, not ignored")
        self.assertTrue(check({"A": 1}, schema))
        self.assertTrue(check({}, schema))
        self.assertTrue(check({"a": 1, "b": 1, "c": 1}, schema))
        self.assertTrue(check({"a": 1}, schema))

    def test_combinators_and_conditionals(self):
        self.assertTrue(check(5, {"allOf": [{"minimum": 1}, {"maximum": 3}]}))
        self.assertEqual(check("a", {"anyOf": [{"type": "integer"}, {"type": "string"}]}), [])
        self.assertTrue(check(None, {"anyOf": [{"type": "integer"}, {"type": "string"}]}))
        one_of = {"oneOf": [{"type": "integer"}, {"minimum": 0}]}
        self.assertEqual(check(-1, one_of), [])
        self.assertTrue(check(1, one_of), "matches two branches")
        self.assertTrue(check(1, {"not": {"type": "integer"}}))
        conditional = {"if": {"properties": {"k": {"const": "a"}}},
                       "then": {"required": ["x"]}, "else": {"required": ["y"]}}
        self.assertEqual(check({"k": "a", "x": 1}, conditional), [])
        self.assertTrue(check({"k": "a", "y": 1}, conditional))
        self.assertEqual(check({"k": "b", "y": 1}, conditional), [])
        self.assertTrue(check({"k": "b", "x": 1}, conditional))
        self.assertEqual(check(1, True), [])
        self.assertTrue(check(1, False))

    def test_const_and_enum_use_json_equality(self):
        self.assertTrue(check(True, {"const": 1}))
        self.assertTrue(check(0, {"enum": [False]}))
        self.assertEqual(check(1.0, {"const": 1}), [])

    def test_unsupported_is_rejected_not_ignored(self):
        for schema in ({"unevaluatedProperties": False}, {"$dynamicRef": "#x"},
                       {"format": "email"}, {"type": "text"}, {"items": [{"type": "string"}]},
                       {"pattern": "[^/\\]"}):
            with self.assertRaises(sv.UnsupportedSchema, msg=schema):
                check(["a"], schema)
        with self.assertRaises(sv.UnsupportedSchema):
            check(1, {"$ref": "https://example.invalid/x.json"})
        with self.assertRaises(sv.UnsupportedSchema):
            check(1, {"$ref": "#/$defs/missing"})

    def test_ref_forms(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "common").mkdir()
            (base / "common" / "f.schema.json").write_text(json.dumps(
                {"$defs": {"hex": {"type": "string", "pattern": "^[0-9a-f]+\\Z"},
                           "alias": {"$ref": "#/$defs/hex"}}}))
            (base / "doc.schema.json").write_text(json.dumps(
                {"type": "object",
                 "properties": {"a": {"$ref": "common/f.schema.json#/$defs/alias"},
                                "b": {"$ref": "#/$defs/local"}},
                 "$defs": {"local": {"type": "integer"}}}))
            store = sv.SchemaStore(base)
            self.assertEqual(sv.validate_document({"a": "ab", "b": 1}, "doc.schema.json", store), [])
            errors = sv.validate_document({"a": "XY", "b": "1"}, "doc.schema.json", store)
            self.assertEqual(len(errors), 2, errors)
            self.assertEqual(sv.validate_document("ff", "common/f.schema.json#/$defs/alias", store), [])

    def test_ref_siblings_apply(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = sv.SchemaStore(Path(tmp))
            schema = {"$defs": {"s": {"type": "string"}}, "$ref": "#/$defs/s", "maxLength": 1}
            self.assertTrue(sv.validate("ab", schema, store))

    def test_repo_local_ref_schemas_now_validate(self):
        # binary-cfg / debug-symbol-index use "#/$defs/..." refs, which the subset validator used
        # to resolve as a file named "" (a crash). They now resolve inside the document.
        errors = sv.validate_document({}, "debug-symbol-index.schema.json")
        self.assertTrue(errors)


class KeywordLint(unittest.TestCase):
    # Real schema defects the lint found; fixing them edits a top-level schema, which changes every
    # job's definition hash, so each waits for owner approval (TODO "L formats").
    KNOWN_PROBLEMS = {
        "threat-model-reconciliation.schema.json#/$defs/citation/properties/path: "
        "pattern does not compile",
    }

    def test_every_used_keyword_is_supported(self):
        result = lint.survey()
        unexpected = [p for p in result["problems"]
                      if not any(p.startswith(k) for k in self.KNOWN_PROBLEMS)]
        self.assertEqual(unexpected, [])
        self.assertTrue(result["used"]["$ref"])

    def test_lint_flags_unsupported_keyword_format_and_bad_ref(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "x.schema.json").write_text(json.dumps(
                {"type": "object", "properties": {
                    "a": {"unevaluatedItems": False},
                    "b": {"type": "string", "format": "uri"},
                    "c": {"$ref": "#/$defs/nope"},
                    "d": {"$ref": "missing.schema.json"}}}))
            problems = lint.survey(base)["problems"]
        text = "\n".join(problems)
        self.assertIn("unsupported keyword 'unevaluatedItems'", text)
        self.assertIn("unsupported format 'uri'", text)
        self.assertIn("'#/$defs/nope'", text)
        self.assertIn("'missing.schema.json'", text)


if __name__ == "__main__":
    unittest.main()
