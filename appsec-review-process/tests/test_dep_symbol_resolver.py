"""dep_symbol_resolver: advisory symbols -> language-level names through each ecosystem's own manifest."""
from __future__ import annotations

from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dep_reachability  # noqa: E402
import dep_symbol_resolver as resolver  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "dep-symbol-resolver"


def _symbols(*rows):
    kept, rejected = dep_reachability.clean_symbols(
        [row if isinstance(row, dict) else {"symbol": row} for row in rows], "reviewed-map")
    assert not rejected
    return kept


def _names(document):
    return {(row["package"], row["symbol"]) for row in document["names"]}


class PythonTests(unittest.TestCase):
    def test_top_level_maps_the_distribution_to_its_import_module(self):
        document = resolver.resolve("pypi", "PyYAML", "5.3.1", _symbols("load", "yaml.constructor.FullConstructor.construct",
                                                                          "yaml.main.dump"), FIXTURES / "python")
        self.assertEqual(document["language"], "python")
        self.assertIn(("yaml", "load"), _names(document))
        self.assertIn(("yaml.constructor", "FullConstructor.construct"), _names(document))
        self.assertIn(("yaml.main", "dump"), _names(document))
        self.assertIn(("yaml", "dump"), _names(document))                 # __init__ re-export
        self.assertEqual(document["vendored_roots"], ["site-packages/yaml"])
        self.assertEqual(document["gaps"], [])
        self.assertTrue(any("top_level.txt" in step for step in document["steps"]))

    def test_record_is_the_fallback_and_a_wrong_version_is_ignored(self):
        document = resolver.resolve("pypi", "jinja2", None, _symbols("utils.urlize"), FIXTURES / "python")
        self.assertIn(("jinja2", "utils.urlize"), _names(document))
        self.assertEqual(document["vendored_roots"], ["site-packages/jinja2"])
        stale = resolver.resolve("pypi", "PyYAML", "6.0", _symbols("load"), FIXTURES / "python")
        self.assertIn("dependency-source-absent:pypi:PyYAML", stale["gaps"])
        self.assertIn(("pyyaml", "load"), _names(stale))                   # heuristic, recorded as such
        self.assertTrue(any("heuristic" in step for step in stale["steps"]))


class NpmTests(unittest.TestCase):
    def test_exports_give_deep_import_specifiers(self):
        document = resolver.resolve("npm", "lodash", "4.17.15", _symbols("merge", "lodash.template"), FIXTURES / "npm")
        names = _names(document)
        self.assertIn(("lodash", "merge"), names)
        self.assertIn(("lodash/merge", "default"), names)
        self.assertIn(("lodash", "template"), names)
        self.assertIn(("lodash/template", "default"), names)
        self.assertEqual(document["vendored_roots"], ["node_modules/lodash"])
        self.assertTrue(any("CJS" in step for step in document["steps"]))

    def test_esm_scoped_and_absent_packages(self):
        esm = resolver.resolve("npm", "@scope/esm", None, _symbols("run"), FIXTURES / "npm")
        self.assertIn(("@scope/esm", "run"), _names(esm))
        self.assertTrue(any("ESM" in step for step in esm["steps"]))
        absent = resolver.resolve("npm", "minimist", "1.2.0", _symbols("parse"), FIXTURES / "npm")
        self.assertIn("dependency-source-absent:npm:minimist", absent["gaps"])
        self.assertEqual(absent["vendored_roots"], [])


class MavenTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "lib").mkdir()
        with zipfile.ZipFile(self.root / "lib" / "jackson-databind-2.9.8.jar", "w") as jar:
            jar.writestr("META-INF/maven/com.fasterxml.jackson.core/jackson-databind/pom.properties",
                         "groupId=com.fasterxml.jackson.core\nartifactId=jackson-databind\nversion=2.9.8\n")
            jar.writestr("META-INF/maven/com.fasterxml.jackson.core/jackson-databind/pom.xml",
                         "<project><build><plugins><plugin><configuration><relocations><relocation>"
                         "<pattern>com.fasterxml.jackson.databind.util</pattern>"
                         "<shadedPattern>shaded.jackson.util</shadedPattern></relocation></relocations>"
                         "</configuration></plugin></plugins></build></project>")
            jar.writestr("com/fasterxml/jackson/databind/ObjectMapper.class", b"\xca\xfe")
            jar.writestr("com/fasterxml/jackson/databind/ObjectMapper$1.class", b"\xca\xfe")
            jar.writestr("com/fasterxml/jackson/databind/util/ClassUtil.class", b"\xca\xfe")
            jar.writestr("META-INF/versions/11/com/fasterxml/jackson/databind/Module11.class", b"\xca\xfe")

    def tearDown(self):
        self.temporary.cleanup()

    def test_jar_classes_resolve_packages_types_and_relocations(self):
        document = resolver.resolve("maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.8",
                                    _symbols("com.fasterxml.jackson.databind.ObjectMapper.readValue",
                                             "ClassUtil.checkAndFixAccess"), self.root)
        names = _names(document)
        self.assertIn(("com.fasterxml.jackson.databind", "ObjectMapper.readValue"), names)
        self.assertIn(("com.fasterxml.jackson.databind.util", "ClassUtil.checkAndFixAccess"), names)
        self.assertIn(("shaded.jackson.util", "ClassUtil.checkAndFixAccess"), names)
        self.assertEqual(document["vendored_roots"], ["lib/jackson-databind-2.9.8.jar"])
        self.assertTrue(any("multi-release [11]" in step for step in document["steps"]))

    def test_absent_jar_splits_by_naming_convention_with_a_gap(self):
        document = resolver.resolve("maven", "org.apache.logging.log4j:log4j-core", "2.14.1",
                                    _symbols("org.apache.logging.log4j.core.lookup.JndiLookup.lookup"), self.root)
        self.assertEqual(_names(document), {("org.apache.logging.log4j.core.lookup", "JndiLookup.lookup")})
        self.assertIn("dependency-source-absent:maven:org.apache.logging.log4j:log4j-core", document["gaps"])

    def test_a_non_jar_named_like_the_artifact_is_ignored(self):
        (self.root / "lib" / "jackson-databind-9.jar").write_text("not a zip")
        document = resolver.resolve("maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.8",
                                    _symbols("ObjectMapper.readValue"), self.root)
        self.assertIn(("com.fasterxml.jackson.databind", "ObjectMapper.readValue"), _names(document))


class GoTests(unittest.TestCase):
    def test_import_path_vendor_and_replace(self):
        document = resolver.resolve("golang", "golang.org/x/text", "v0.3.7",
                                    _symbols({"package": "golang.org/x/text/language", "symbol": "Parse"}),
                                    FIXTURES / "go")
        self.assertEqual(_names(document), {("golang.org/x/text/language", "Parse")})
        self.assertEqual(document["vendored_roots"], ["vendor/golang.org/x/text"])
        replaced = resolver.resolve("golang", "gopkg.in/yaml.v2", "v2.2.7", _symbols("Unmarshal"), FIXTURES / "go")
        self.assertEqual(_names(replaced), {("gopkg.in/yaml.v2", "Unmarshal")})   # imports keep the path
        self.assertEqual(replaced["vendored_roots"], ["third_party/yamlfork"])
        self.assertTrue(any("replace gopkg.in/yaml.v2 => ./third_party/yamlfork" in step for step in replaced["steps"]))
        absent = resolver.resolve("golang", "github.com/x/y", None, _symbols("Do"), FIXTURES / "go")
        self.assertIn("dependency-source-absent:golang:github.com/x/y", absent["gaps"])


class NugetCargoComposerTests(unittest.TestCase):
    def test_nuget_assemblies_are_namespaces(self):
        document = resolver.resolve("nuget", "Newtonsoft.Json", "12.0.1",
                                    _symbols("Newtonsoft.Json.JsonConvert.DeserializeObject"), FIXTURES / "nuget")
        self.assertEqual(_names(document), {("Newtonsoft.Json", "JsonConvert.DeserializeObject")})
        self.assertEqual(document["vendored_roots"], ["packages/Newtonsoft.Json.12.0.1"])
        self.assertTrue(any("netstandard2.0" in step for step in document["steps"]))

    def test_cargo_lib_name_differs_from_the_crate_name(self):
        document = resolver.resolve("cargo", "foo-bar", "0.2.0", _symbols("foo_bar::decode::parse"), FIXTURES / "cargo")
        self.assertEqual(_names(document), {("foobar", "decode::parse")})
        self.assertEqual(document["vendored_roots"], ["vendor/foo-bar"])

    def test_composer_psr4_namespaces_are_hints(self):
        document = resolver.resolve("composer", "guzzlehttp/psr7", None, _symbols("parse_header"), FIXTURES / "composer")
        self.assertEqual(_names(document), {("GuzzleHttp.Psr7", "parse_header")})
        self.assertTrue(any("hints only" in step for step in document["steps"]))


class GeneralTests(unittest.TestCase):
    def test_no_symbols_native_and_tier(self):
        self.assertEqual(resolver.resolve("pypi", "x", None, [], FIXTURES / "python")["gaps"], ["no-advisory-symbols"])
        native = resolver.resolve("conan", "zlib", "1.2.11", _symbols("inflate"), FIXTURES)
        self.assertEqual((native["language"], _names(native)), ("cpp", {("zlib", "inflate")}))
        self.assertEqual(resolver.tier("site-packages/yaml/constructor.py", ["site-packages/yaml"]), "through-dependency")
        self.assertEqual(resolver.tier("site-packages/yamlx/a.py", ["site-packages/yaml"]), "direct")
        self.assertEqual(resolver.tier("app.py", []), "direct")

    def test_links_are_never_followed_and_names_are_validated(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            shutil.copytree(FIXTURES / "npm", root / "app")
            outside = root / "outside"; outside.mkdir()
            (outside / "package.json").write_text('{"name": "evil", "exports": {"./x": "./x.js"}}')
            (root / "app" / "node_modules" / "evil").symlink_to(outside, target_is_directory=True)
            document = resolver.resolve("npm", "evil", None, _symbols("x"), root / "app")
            self.assertIn("dependency-source-absent:npm:evil", document["gaps"])
            self.assertIsNone(resolver.Checkout(root / "app").read("node_modules/evil/package.json"))
        result = resolver.Resolution("npm", "p", None, "javascript")
        result.add("bad package\n", "x", "via"); result.add("p", "not a symbol!", "via")
        self.assertEqual(result.names, [])


if __name__ == "__main__":
    unittest.main()
