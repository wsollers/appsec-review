"""V15 (ADR-0010 G10 = B): language/size metrics of the evidence index.

Runs on every platform. The pure rules need no index at all; the lifecycle tests drive the real
`run`/`collect`/`validate` with real SQLite FTS5 and a stand-in for libfuzzy, because ssdeep is a
retrieval hint that no metric reads (the pinned-runtime ssdeep tests stay in test_evidence_store).
Every input is generated at test time as bytes: no fixture depends on Git newline conversion.
"""
import hashlib
import inspect
import json
import os
from pathlib import Path
import random
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import evidence_redaction
import evidence_store as store
import execution_state as state
from schema_validate import SCHEMAS_DIR, validate_document
from validate_job_output import NO_ORCHESTRATION_FACTS, validate_job_output
from worker_result import artifact_records, terminal_envelope

# Located the way the worker locates them, never by the repository's directory names: in the Linux
# code-server this tree is mounted as /opt/process beside /opt/schemas, and a path built from
# '<repo>/appsec-review-process' made this module fail to import there (found by the requalification).
SCHEMA = json.loads((SCHEMAS_DIR / store.METRICS_SCHEMA_FILE).read_text(encoding='utf-8'))
CONTRACT = json.loads((store.ROOT / 'registry' / 'output-contracts' / 'evidence-index.json')
                      .read_text(encoding='utf-8'))
FINGERPRINT = hashlib.sha256(b'v15 fixture source').hexdigest()
SUPPORTED_KEYWORDS = {'$schema', '$id', 'title', 'description', 'type', 'required', 'properties',
                      'additionalProperties', 'enum', 'const', 'pattern', 'items', 'minItems', '$ref'}

# One golden snapshot: (indexed path, bytes). Expected numbers below are worked by hand.
GOLDEN = [
    ('source/src/main.c', b'int main(void) {\n\n  return 0;\n}\n'),                 # 4 lines, 1 blank
    ('source/src/win.c', b'\xef\xbb\xbfint a;\r\n\r\nint b;'),                       # BOM, CRLF, no final EOL: 3, 1
    ('source/src/old.c', b'a\rb\r\r'),                                              # lone CR, 5 bytes: 3, 1
    ('source/include/api.h', b''),                                                  # empty: 0, 0
    ('source/src/latin1.c', b'caf\xe9\n'),                                          # undecodable
    ('source/assets/logo.png', b'\x89PNG\x00\x01'),                                 # binary
    ('source/LICENSE', b'text\n'),                                                  # unclassified
    ('source/vendor/lib/x.py', b'x = 1\n \t\n'),                                    # vendored: 2, 1
    ('source/third_party/generated/y.pb.go', b'package y\n'),                       # vendored wins
    ('source/api/generated/z.ts', b'export {}\n'),                                  # generated dir
    ('source/web/app.min.js', b'!function(){}()'),                                  # generated suffix: 1, 0
    ('source/package-lock.json', b'{}\n'),                                          # generated name
    ('evidence/intake/outputs/intake.json', b'{}\n'),                               # review-evidence
]
GOLDEN_SHA256 = 'b16b80659913c1a7cc4fc2999464bb2b58a2412fef53c171e631f0b9dbd77e96'  # sha256 of the canonical golden bytes


def tally_of(items, order=None):
    tally = store.MetricsTally()
    for name, content in (order or items):
        tally.add(name, hashlib.sha256(content).hexdigest(), content)
    return tally


def naive_lines(content):
    """Independent byte-at-a-time statement of the rule, to cross-check the fast implementation."""
    if content[:3] == b'\xef\xbb\xbf':
        content = content[3:]
    lines = blank = 0
    current, index = bytearray(), 0
    while index < len(content):
        byte = content[index]
        if byte in (0x0a, 0x0d):
            if byte == 0x0d and index + 1 < len(content) and content[index + 1] == 0x0a:
                index += 1
            lines += 1
            blank += all(b in b' \t\x0b\x0c' for b in current)
            current = bytearray()
        else:
            current.append(byte)
        index += 1
    if current:
        lines += 1
        blank += all(b in b' \t\x0b\x0c' for b in current)
    return lines, blank


class LineRuleTests(unittest.TestCase):
    def test_every_terminator_case_by_bytes(self):
        cases = {
            b'': (0, 0), b'\n': (1, 1), b'a': (1, 0), b'a\n': (1, 0), b'a\nb': (2, 0),
            b'a\r\nb\r\n': (2, 0), b'a\rb\r': (2, 0), b'a\rb': (2, 0), b'\r\n': (1, 1), b'\r': (1, 1),
            b'\n\r': (2, 2), b'\r\r\n': (2, 2), b'a\n\n\nb\n': (4, 2), b' \t\x0b\x0c\n': (1, 1),
            b'a\n  ': (2, 1), b'\xef\xbb\xbf': (0, 0), b'\xef\xbb\xbf\n': (1, 1),
            b'\xef\xbb\xbfa': (1, 0), b'a\xef\xbb\xbf\n': (1, 0), b'\xc2\xa0\n': (1, 0),
            b'a\x0bb\x0cc\x1cd\xc2\x85e\xe2\x80\xa8f\n': (1, 0),
        }
        for content, expected in cases.items():
            with self.subTest(content=content):
                self.assertEqual(store.count_lines(content), expected)
                self.assertEqual(naive_lines(content), expected)

    def test_fast_rule_equals_the_bytewise_rule_on_generated_inputs(self):
        rng = random.Random(15)
        alphabet = [b'\n', b'\r', b'\r\n', b' ', b'\t', b'a', b'\x0c', b'\xef\xbb\xbf', b'\xc3\xa9']
        for _ in range(2000):
            content = b''.join(rng.choice(alphabet) for _ in range(rng.randrange(0, 24)))
            self.assertEqual(store.count_lines(content), naive_lines(content), content)

    def test_line_counting_is_defined_on_bytes_only(self):
        for bad in ('text', bytearray(b'a\n'), None):
            with self.subTest(bad=type(bad).__name__), self.assertRaises(TypeError):
                store.count_lines(bad)

    def test_content_kind(self):
        self.assertEqual(store.content_kind(b''), 'text')
        self.assertEqual(store.content_kind(b'\xef\xbb\xbfok\n'), 'text')
        self.assertEqual(store.content_kind(b'a\x00b'), 'binary')
        self.assertEqual(store.content_kind('a'.encode('utf-16')), 'binary')
        self.assertEqual(store.content_kind(b'caf\xe9'), 'undecodable')
        self.assertEqual(store.content_kind(b'\xed\xa0\x80'), 'undecodable')  # encoded surrogate


class ClassificationTests(unittest.TestCase):
    def test_language_table(self):
        cases = {
            'source/a.c': 'C', 'source/A.C': 'C', 'source/a.H': 'C/C++ Header', 'source/a.cpp': 'C++',
            'source/x/CMakeLists.txt': 'CMake', 'source/Makefile': 'Make', 'source/Dockerfile': 'Dockerfile',
            'source/Dockerfile.dev': 'Dockerfile', 'source/ci/app.dockerfile': 'Dockerfile',
            'source/go.mod': 'Go Module', 'source/a.tar.gz': 'unclassified', 'source/a.py': 'Python',
            'source/.gitignore': 'unclassified', 'source/.eslintrc.json': 'JSON', 'source/README': 'unclassified',
            'source/a.': 'unclassified', 'source/a.unknownext': 'unclassified', 'source/notes.TXT': 'Text',
            'source/\u0130.PY': 'Python', 'source/a.p\u0131': 'unclassified', 'source/py': 'unclassified',
            'evidence/build_discovery/output.json': 'JSON',
        }
        for name, language in cases.items():
            with self.subTest(name=name):
                self.assertEqual(store.classify_path(name)[1], language)
                self.assertIn(language, store.METRICS_LANGUAGES)

    def test_scope_table_and_precedence(self):
        cases = {
            'source/src/a.c': 'first-party', 'source/vendor/a.c': 'vendored', 'source/x/Vendor/y/a.c': 'vendored',
            'source/node_modules/p/index.js': 'vendored', 'source/third_party/generated/a.pb.go': 'vendored',
            'source/generated/a.c': 'generated', 'source/a.pb.go': 'generated', 'source/a_pb2.py': 'generated',
            'source/Cargo.lock': 'generated', 'source/web/app.min.js': 'generated',
            'source/vendor': 'first-party', 'source/generated': 'first-party', 'source/myvendor/a.c': 'first-party',
            'evidence/intake/vendor/a.c': 'review-evidence', 'evidence/intake/outputs/intake.json': 'review-evidence',
        }
        for name, scope in cases.items():
            with self.subTest(name=name):
                self.assertEqual(store.classify_path(name)[0], scope)
                self.assertIn(scope, store.METRICS_SCOPES)

    def test_one_spelling_per_path_and_no_echo(self):
        marker = 'planted' + 'marker'
        for bad in ('', 'source', 'source/', '/source/a.c', 'source//a.c', 'source/./a.c', 'source/../a.c',
                    'source/a/..', '../source/a.c', 'other/a.c', 'Source/a.c', './source/a.c',
                    f'source/{marker}/../a.c', None, b'source/a.c', 7):
            with self.subTest(bad=bad):
                with self.assertRaises(state.Blocked) as caught:
                    store.classify_path(bad)
                self.assertEqual(str(caught.exception),
                                 'an indexed path is not a normalized source/ or evidence/ relative path')

    def test_tables_are_closed_disjoint_and_match_the_schema(self):
        extensions = [ext for exts in store._LANGUAGE_EXTENSIONS.values() for ext in exts.split()]
        self.assertEqual(len(extensions), len(set(extensions)), 'an extension maps to two languages')
        self.assertTrue(all(ext == ext.lower() and '.' not in ext for ext in extensions))
        self.assertTrue(all(name == name.lower() for name in store._LANGUAGE_BY_FILENAME))
        groups = SCHEMA['properties']['groups']['items']['properties']
        self.assertEqual(groups['language']['enum'], list(store.METRICS_LANGUAGES))
        self.assertEqual(SCHEMA['properties']['by_language']['items']['properties']['language']['enum'],
                         list(store.METRICS_LANGUAGES))
        self.assertEqual(groups['scope']['enum'], list(store.METRICS_SCOPES))
        self.assertEqual(SCHEMA['properties']['by_scope']['items']['properties']['scope']['enum'],
                         list(store.METRICS_SCOPES))
        self.assertEqual(groups['content']['enum'], list(store.METRICS_CONTENT_KINDS))
        self.assertEqual(list(store.METRICS_LANGUAGES), sorted(store.METRICS_LANGUAGES))
        self.assertEqual(SCHEMA['properties']['rules_version']['const'], store.METRICS_RULES_VERSION)
        self.assertEqual(SCHEMA['properties']['schema']['const'], store.METRICS_SCHEMA_ID)
        self.assertEqual(SCHEMA['properties']['line_rule']['const'], store.METRICS_LINE_RULE)

    def test_no_label_or_property_is_secret_shaped_for_the_redactor(self):
        def names(node):
            if isinstance(node, dict):
                for key, value in node.get('properties', {}).items():
                    yield key
                    yield from names(value)
                if 'items' in node:
                    yield from names(node['items'])
        for word in list(names(SCHEMA)) + list(store.METRICS_LANGUAGES) + list(store.METRICS_SCOPES) + \
                list(store.METRICS_CONTENT_KINDS) + ['metrics', 'metrics_sha256']:
            with self.subTest(word=word):
                self.assertIsNone(evidence_redaction._KEYWORD_RE.search(word))


class SchemaConventionTests(unittest.TestCase):
    def walk(self, node, path='$'):
        yield path, node
        for key, value in node.get('properties', {}).items():
            yield from self.walk(value, f'{path}.{key}')
        if isinstance(node.get('items'), dict):
            yield from self.walk(node['items'], path + '[]')

    def test_only_supported_keywords_closed_objects_and_anchored_patterns(self):
        for path, node in self.walk(SCHEMA):
            with self.subTest(path=path):
                self.assertLessEqual(set(node), SUPPORTED_KEYWORDS)
                if node.get('type') == 'object':
                    self.assertIs(node['additionalProperties'], False)
                    self.assertEqual(sorted(node['required']), sorted(node['properties']))
                if 'pattern' in node:
                    self.assertTrue(node['pattern'].startswith('^') and node['pattern'].endswith('\\Z'))

    def test_schema_rejects_unknown_members_newline_digests_and_wrong_types(self):
        good = tally_of(GOLDEN).document(FINGERPRINT, 0)
        self.assertEqual(validate_document(good, store.METRICS_SCHEMA_FILE), [])
        edits = {
            'extra member': lambda d: d.update(analyzed=True),
            'per-file path': lambda d: d['groups'][0].update(path='source/a.c'),
            'digest with newline': lambda d: d['snapshot'].update(source_fingerprint=FINGERPRINT + '\n'),
            'uppercase digest': lambda d: d['snapshot'].update(file_set_sha256=FINGERPRINT.upper()),
            'float count': lambda d: d['overall'].update(lines=1.5),
            'string count': lambda d: d['groups'][0].update(files='1'),
            'unknown language': lambda d: d['groups'][0].update(language='Klingon'),
            'unknown scope': lambda d: d['by_scope'][0].update(scope='ignored'),
            'unknown content': lambda d: d['groups'][0].update(content='skipped'),
            'not descriptive': lambda d: d.update(descriptive_only=False),
            'other rules': lambda d: d.update(rules_version='2'),
            'missing member': lambda d: d.pop('excluded_files'),
        }
        for label, edit in edits.items():
            with self.subTest(label=label):
                document = json.loads(json.dumps(good))
                edit(document)
                self.assertTrue(validate_document(document, store.METRICS_SCHEMA_FILE))

    def test_contract_declares_the_member_additively_and_descriptively(self):
        self.assertEqual(CONTRACT['required_files'], ['manifest.json', 'index.sqlite', 'ssdeep.csv', 'status.json'])
        self.assertEqual(CONTRACT['claim_types'], ['evidence_index'])
        self.assertNotIn('claim_class', CONTRACT)
        self.assertNotIn('result_schema', CONTRACT)  # parity manifest still says schema_file: null
        self.assertEqual(CONTRACT['member_schemas'], [{
            'artifact': 'manifest.json', 'member': 'metrics', 'schema_file': store.METRICS_SCHEMA_FILE,
            'digest_member': 'metrics_sha256',
            'verifier': 'appsec-review-process/evidence_store.py:check_metrics'}])
        rules = '\n'.join(CONTRACT['validation_rules'])
        self.assertIn('descriptive only', rules)
        self.assertIn('not evidence of coverage, quality, reachability or analysis', rules)
        self.assertEqual(validate_document(CONTRACT, 'output-contract.schema.json'), [])


class TallyTests(unittest.TestCase):
    def test_golden_document_is_hand_checked_and_byte_stable(self):
        document = tally_of(GOLDEN).document(FINGERPRINT, 2)
        self.assertEqual(document['overall'], {'files': 13, 'bytes': 122, 'text_files': 11, 'lines': 18,
                                               'blank_lines': 4})
        self.assertEqual(document['by_scope'], [
            {'scope': 'first-party', 'files': 7, 'bytes': 72, 'text_files': 5, 'lines': 11, 'blank_lines': 3},
            {'scope': 'generated', 'files': 3, 'bytes': 28, 'text_files': 3, 'lines': 3, 'blank_lines': 0},
            {'scope': 'review-evidence', 'files': 1, 'bytes': 3, 'text_files': 1, 'lines': 1, 'blank_lines': 0},
            {'scope': 'vendored', 'files': 2, 'bytes': 19, 'text_files': 2, 'lines': 3, 'blank_lines': 1}])
        c = [g for g in document['groups'] if g['language'] == 'C']
        self.assertEqual(c, [
            {'scope': 'first-party', 'language': 'C', 'content': 'text', 'files': 3, 'bytes': 56,
             'lines': 10, 'blank_lines': 3},
            {'scope': 'first-party', 'language': 'C', 'content': 'undecodable', 'files': 1, 'bytes': 5,
             'lines': None, 'blank_lines': None}])
        self.assertIn({'scope': 'first-party', 'language': 'unclassified', 'content': 'binary', 'files': 1,
                       'bytes': 6, 'lines': None, 'blank_lines': None}, document['groups'])
        self.assertIn({'language': 'C/C++ Header', 'files': 1, 'bytes': 0, 'text_files': 1, 'lines': 0,
                       'blank_lines': 0}, document['by_language'])
        self.assertEqual(document['excluded_files'], 2)
        self.assertEqual(document['snapshot']['files'], 13)
        self.assertEqual(validate_document(document, store.METRICS_SCHEMA_FILE), [])
        data = store.metrics_bytes(document)
        self.assertNotIn(b'\r', data)
        self.assertTrue(data.endswith(b'}\n'))
        self.assertEqual(data, data.decode('ascii').encode('ascii'))
        # The cross-platform anchor: any host that computes another digest has diverged.
        self.assertEqual(hashlib.sha256(data).hexdigest(), GOLDEN_SHA256)

    def test_projections_agree_and_every_file_is_counted_once(self):
        document = tally_of(GOLDEN).document(FINGERPRINT, 0)
        fields = ('files', 'bytes', 'text_files', 'lines', 'blank_lines')
        for projection in ('by_scope', 'by_language'):
            for field in fields:
                self.assertEqual(sum(row[field] for row in document[projection]), document['overall'][field])
        groups = document['groups']
        self.assertEqual(sum(g['files'] for g in groups), len(GOLDEN))
        self.assertEqual(sum(g['bytes'] for g in groups), sum(len(content) for _, content in GOLDEN))
        self.assertEqual(sum(g['lines'] or 0 for g in groups), document['overall']['lines'])
        self.assertEqual(sum(g['files'] for g in groups if g['content'] == 'text'),
                         document['overall']['text_files'])
        for group in groups:
            self.assertEqual(group['lines'] is None, group['content'] != 'text')
            self.assertEqual(group['blank_lines'] is None, group['content'] != 'text')
        self.assertEqual([r['language'] for r in document['by_language']],
                         sorted(r['language'] for r in document['by_language']))
        self.assertEqual([r['scope'] for r in document['by_scope']], sorted(r['scope'] for r in document['by_scope']))

    def test_order_locale_and_platform_separator_do_not_reach_the_document(self):
        expected = store.metrics_bytes(tally_of(GOLDEN).document(FINGERPRINT, 0))
        rng = random.Random(7)
        for _ in range(5):
            shuffled = GOLDEN[:]
            rng.shuffle(shuffled)
            self.assertEqual(store.metrics_bytes(tally_of(GOLDEN, shuffled).document(FINGERPRINT, 0)), expected)
        with patch.object(os, 'linesep', '\r\n'), patch.object(os, 'sep', '\\'):
            self.assertEqual(store.metrics_bytes(tally_of(GOLDEN).document(FINGERPRINT, 0)), expected)

    def test_snapshot_identity_tracks_paths_and_bytes_but_never_publishes_them(self):
        base = tally_of(GOLDEN).document(FINGERPRINT, 0)
        renamed = [('source/src/renamed.c', GOLDEN[0][1])] + GOLDEN[1:]
        edited = [(GOLDEN[0][0], GOLDEN[0][1].replace(b'0', b'1'))] + GOLDEN[1:]
        for other in (renamed, edited):
            document = tally_of(other).document(FINGERPRINT, 0)
            self.assertNotEqual(document['snapshot']['file_set_sha256'], base['snapshot']['file_set_sha256'])
            self.assertEqual(document['groups'], base['groups'])
        planted = 'ghp_' + ''.join(random.Random(3).choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(36))
        hostile = GOLDEN + [(f'source/{planted}/{planted}.c', f'// {planted}\n'.encode())]
        data = store.metrics_bytes(tally_of(hostile).document(FINGERPRINT, 0))
        self.assertNotIn(planted.encode(), data)
        for name, _ in GOLDEN:
            self.assertNotIn(name.split('/')[-1].encode(), data)

    def test_duplicate_path_is_refused(self):
        tally = tally_of(GOLDEN + [GOLDEN[0]])
        with self.assertRaises(state.Blocked) as caught:
            tally.document(FINGERPRINT, 0)
        self.assertEqual(str(caught.exception), 'an indexed path was measured more than once')

    def test_safety_inputs_are_required(self):
        tally = tally_of(GOLDEN)
        for call in (lambda: tally.document(), lambda: tally.document(FINGERPRINT),
                     lambda: tally.add('source/a.c'), lambda: tally.add('source/a.c', 'x'),
                     lambda: store.check_metrics(), lambda: store.check_metrics(Path('.')),
                     lambda: store.check_metrics(Path('.'), 1), lambda: store.check_metrics(Path('.'), None)):
            with self.assertRaises(TypeError):
                call()
        for function in (store.check_metrics, store.MetricsTally.document, store.MetricsTally.add,
                         store.count_lines, store.classify_path, store.content_kind, store.file_set_sha256):
            for parameter in inspect.signature(function).parameters.values():
                self.assertIs(parameter.default, inspect.Parameter.empty, f'{function.__name__}.{parameter.name}')

    def test_v06_redactor_changes_nothing_in_the_golden(self):
        data = store.metrics_bytes(tally_of(GOLDEN).document(FINGERPRINT, 2))
        with tempfile.TemporaryDirectory() as folder:
            private, published = Path(folder) / 'private', Path(folder) / 'published'
            private.mkdir()
            (private / 'metrics.json').write_bytes(data)
            (private / 'manifest.json').write_bytes(
                (json.dumps({'metrics': json.loads(data), 'metrics_sha256': hashlib.sha256(data).hexdigest()},
                            indent=2, sort_keys=True) + '\n').encode())
            receipt = evidence_redaction.redact_tree(private, published, on_unhandled='refuse',
                                                     limits=evidence_redaction.DEFAULT_LIMITS)
            self.assertEqual([(r['path'], r['disposition']) for r in receipt['files']],
                             [('manifest.json', 'unchanged'), ('metrics.json', 'unchanged')])
            self.assertEqual((published / 'metrics.json').read_bytes(), data)
            self.assertEqual((published / 'manifest.json').read_bytes(), (private / 'manifest.json').read_bytes())


class FakeFuzzy:
    """Stand-in for libfuzzy: ssdeep is a retrieval hint and no metric reads it."""

    def hash(self, content):
        return '3:' + hashlib.sha256(content).hexdigest()[:32] + ':' + hashlib.sha256(content).hexdigest()[32:]

    def compare(self, left, right):
        return 100 if left == right else 0


class LifecycleCase(unittest.TestCase):
    FILES = [(name.split('/', 1)[1], content) for name, content in GOLDEN if name.startswith('source/')]

    def setUp(self):
        location = Path(os.environ['PHASE1_TEST_DATA']) if os.environ.get('PHASE1_TEST_DATA') else None
        if location:
            (location / 'evidence-metrics').mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=location / 'evidence-metrics' if location else None)
        self.base = Path(self.tmp.name).resolve()
        self.patches = [patch.object(state, 'RUNS', self.base / 'runs')]
        self.intake = self.base / 'intake' / 'attempts' / 'producer'
        self.source = self.base / 'source'
        files = {}
        for name, content in self.FILES:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            files[name] = {'kind': 'file', 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()}
        state.atomic_json(self.intake / 'evidence/source.json', {'target': str(self.source), 'files': files,
                          'fingerprint': FINGERPRINT, 'revision': 'fixture'})
        state.atomic_json(self.intake / 'outputs/intake.json', {'scope': {'excluded_paths': []}})
        state.atomic_bytes(self.intake / 'outputs/build-discovery.md', b'no build executed\n')
        self.plan = {'producers': [{'kind': 'intake', 'pointer': {'attempt_id': 'producer'}}],
                     'worker_sha256': store.LOADED_WORKER_SHA256}
        self.patches += [patch.object(store, 'inputs', side_effect=lambda _: json.loads(json.dumps(self.plan))),
                         patch.object(store.phase1, 'job_root', return_value=self.base / 'intake'),
                         patch.object(store, 'execute', side_effect=self.execute),
                         patch.object(store, 'Fuzzy', FakeFuzzy)]
        for item in self.patches:
            item.start()
        self.after_collect = None

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.tmp.cleanup()

    def execute(self, argv, attempt, logs, timeout, **kwargs):
        state.atomic_bytes(logs / 'stdout.log', b'fixture work\n')
        state.atomic_bytes(logs / 'stderr.log', b'fixture separate stream\n')
        store.collect('fixture', attempt)
        if self.after_collect:
            self.after_collect(attempt)
        return {'exit_code': 0}

    def attempt(self, pointer):
        return store.root('fixture') / 'attempts' / pointer['attempt_id']

    def indexed(self, attempt):
        db = sqlite3.connect(attempt / 'index.sqlite')
        try:
            return db.execute('SELECT path, sha256, bytes FROM files ORDER BY path').fetchall()
        finally:
            db.close()


def rewrite(attempt, edit, rehash):
    """Edit manifest.json in place. rehash=True models a forger who also fixes metrics_sha256."""
    manifest = state.read_json(attempt / 'manifest.json')
    edit(manifest)
    if rehash:
        manifest['metrics_sha256'] = hashlib.sha256(store.metrics_bytes(manifest['metrics'])).hexdigest()
    (attempt / 'manifest.json').write_bytes((json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode())


class PublishedMetricsTests(LifecycleCase):
    def test_metrics_are_published_in_the_manifest_from_the_indexed_snapshot(self):
        pointer = store.run('fixture', 'launch1')
        attempt = self.attempt(pointer)
        manifest = state.read_json(attempt / 'manifest.json')
        metrics = manifest['metrics']
        rows = self.indexed(attempt)
        self.assertEqual(metrics['snapshot']['files'], len(rows))
        self.assertEqual(metrics['snapshot']['files'], manifest['files'])
        self.assertEqual(metrics['overall']['files'], len(rows))
        self.assertEqual(metrics['overall']['bytes'], sum(row[2] for row in rows))
        self.assertEqual(metrics['overall']['bytes'], manifest['snapshot_bytes'])
        self.assertEqual(metrics['snapshot']['file_set_sha256'], store.file_set_sha256(rows))
        self.assertEqual(metrics['snapshot']['source_fingerprint'], manifest['source_fingerprint'])
        self.assertEqual(manifest['metrics_sha256'], hashlib.sha256(store.metrics_bytes(metrics)).hexdigest())
        self.assertEqual([r for r in metrics['by_scope'] if r['scope'] == 'review-evidence'][0]['files'], 2)
        # Same source files as the golden: the source-only projection must equal the pure tally.
        expected = tally_of([(n, c) for n, c in GOLDEN if n.startswith('source/')]).document(FINGERPRINT, 0)
        self.assertEqual([g for g in metrics['groups'] if g['scope'] != 'review-evidence'], expected['groups'])
        self.assertEqual(store.check_metrics(attempt, True), metrics)
        self.assertEqual(store.check_metrics(attempt, False), metrics)
        # Existing keys are untouched: the enrichment is additive.
        for key in ('status', 'source_fingerprint', 'source_revision', 'files', 'chunks', 'snapshot_bytes',
                    'text_status_counts', 'excluded', 'untrusted_content', 'scope', 'producers', 'limits'):
            self.assertIn(key, manifest)
        for forbidden in ('analyzed', 'coverage', 'reviewed', 'scanned', 'code_lines', 'comment_lines', 'sloc'):
            self.assertNotIn(forbidden, json.dumps(metrics))

    def test_identical_snapshot_gives_identical_metrics_across_attempts(self):
        first = store.run('fixture', 'launch1')
        second = store.run('fixture', 'launch2', True)
        self.assertNotEqual(first['attempt_id'], second['attempt_id'])
        one, two = (state.read_json(self.attempt(p) / 'manifest.json') for p in (first, second))
        self.assertEqual(store.metrics_bytes(one['metrics']), store.metrics_bytes(two['metrics']))
        self.assertEqual(one['metrics_sha256'], two['metrics_sha256'])

    def test_returned_metrics_are_a_copy_not_an_authority(self):
        attempt = self.attempt(store.run('fixture', 'launch1'))
        first = store.check_metrics(attempt, True)
        first['overall']['lines'] = 10 ** 9
        first['groups'].clear()
        self.assertNotEqual(store.check_metrics(attempt, True), first)
        self.assertEqual(store.check_metrics(attempt, True)['overall']['files'], len(self.indexed(attempt)))

    def test_excluded_and_limit_skipped_files_are_labelled_not_measured(self):
        state.atomic_json(self.intake / 'outputs/intake.json', {'scope': {'excluded_paths': ['LICENSE']}})
        limits = dict(store.LIMITS, max_file_bytes=20, max_text_bytes=8)
        with patch.object(store, 'LIMITS', limits):
            attempt = self.attempt(store.run('fixture', 'launch1'))
            manifest = state.read_json(attempt / 'manifest.json')
            self.assertEqual(manifest['metrics']['excluded_files'], len(manifest['excluded']))
            self.assertGreaterEqual(len(manifest['excluded']), 2)  # LICENSE by scope, main.c by byte limit
            self.assertEqual(manifest['metrics']['snapshot']['files'], manifest['files'])
            # win.c (19 bytes) is over the text limit, so it is not full-text indexed, yet it is still
            # measured as text from the bytes already in hand.
            self.assertIn('text byte limit', manifest['text_status_counts'])
            c_text = [g for g in manifest['metrics']['groups']
                      if (g['scope'], g['language'], g['content']) == ('first-party', 'C', 'text')][0]
            self.assertEqual((c_text['files'], c_text['lines'], c_text['blank_lines']), (2, 6, 2))
            store.check_metrics(attempt, True)

    def test_existing_job_output_validator_accepts_the_attempt_unchanged(self):
        pointer = store.run('fixture', 'launch1')
        attempt = self.attempt(pointer)
        envelope = terminal_envelope(
            run_id='fixture', job_id=store.JOB, attempt_id=pointer['attempt_id'],
            worker_kind='deterministic_python', execution_status='OK', acceptance_status='CURRENT',
            input_fingerprint='sha256:' + pointer['fingerprint'], output_contract='evidence-index',
            started_at='2026-09-20T10:00:00Z', finished_at='2026-09-20T10:01:00Z', summary='indexed',
            artifacts=artifact_records(attempt, CONTRACT['required_files']))
        self.assertEqual(validate_job_output(attempt, envelope, 'sha256:' + pointer['fingerprint'],
                                             expected_run_id='fixture', expected_job_id=store.JOB,
                                             orchestration=NO_ORCHESTRATION_FACTS), [])


class TamperTests(LifecycleCase):
    def accepted(self):
        pointer = store.run('fixture', 'launch1')
        return pointer, self.attempt(pointer)

    def rejected(self, attempt, rederive, message):
        with self.assertRaises(state.Blocked) as caught:
            store.check_metrics(attempt, rederive)
        self.assertEqual(str(caught.exception), message)

    def test_editing_only_one_bound_field_is_rejected(self):
        """Each edit changes one field and nothing else (no re-hash): the honest-mistake case."""
        other = hashlib.sha256(b'other').hexdigest()
        edits = {
            'metrics_sha256': (lambda m: m.update(metrics_sha256=other),
                               'manifest.json metrics member does not match metrics_sha256'),
            'metrics removed': (lambda m: m.pop('metrics'), 'manifest.json has no metrics member'),
            'metrics not an object': (lambda m: m.update(metrics=[]), 'manifest.json has no metrics member'),
            'manifest source_fingerprint': (lambda m: m.update(source_fingerprint=other),
                'metrics snapshot source_fingerprint differs from manifest.json source_fingerprint'),
            'manifest files': (lambda m: m.update(files=m['files'] + 1),
                               'metrics file count differs from the number of indexed files'),
            'manifest excluded': (lambda m: m['excluded'].append({'path': 'source/x', 'reason': 'planted'}),
                                  'metrics excluded_files differs from the length of manifest.json excluded'),
        }
        for field in ('schema', 'rules_version', 'descriptive_only', 'line_rule', 'excluded_files'):
            edits['metrics ' + field] = (lambda m, f=field: m['metrics'].update({f: 9}),
                                         'manifest.json metrics member does not match metrics_sha256')
        for label, (edit, message) in edits.items():
            with self.subTest(label=label):
                pointer, attempt = self.accepted()
                rewrite(attempt, edit, False)
                self.rejected(attempt, False, message)
                self.rejected(attempt, True, message)
                with self.assertRaises(state.Blocked) as caught:   # the store's existing verifier
                    store.validate('fixture')
                self.assertEqual(str(caught.exception), 'index artifact integrity mismatch')
                store.run('fixture', 'recover-' + hashlib.sha256(label.encode()).hexdigest()[:8], True)

    def test_a_forger_who_fixes_the_digest_is_still_rejected_field_by_field(self):
        other = hashlib.sha256(b'other').hexdigest()
        schema_message = 'manifest.json metrics member does not satisfy ' + store.METRICS_SCHEMA_FILE
        projections = 'metrics overall, by_scope and by_language must be projections of groups'
        edits = {
            'snapshot.source_fingerprint': (lambda d: d['snapshot'].update(source_fingerprint=other),
                'metrics snapshot source_fingerprint differs from manifest.json source_fingerprint'),
            'snapshot.file_set_sha256': (lambda d: d['snapshot'].update(file_set_sha256=other),
                'metrics snapshot file_set_sha256 or files differs from the files table of index.sqlite'),
            'snapshot.files': (lambda d: d['snapshot'].update(files=d['snapshot']['files'] + 1),
                               'metrics file count differs from the number of indexed files'),
            'excluded_files': (lambda d: d.update(excluded_files=5),
                               'metrics excluded_files differs from the length of manifest.json excluded'),
            'rules_version': (lambda d: d.update(rules_version='2'), schema_message),
            'schema': (lambda d: d.update(schema='appsec-review/evidence-index-metrics/9'), schema_message),
            'line_rule': (lambda d: d.update(line_rule='splitlines'), schema_message),
            'descriptive_only false': (lambda d: d.update(descriptive_only=False), schema_message),
            'descriptive_only 1': (lambda d: d.update(descriptive_only=1),
                                   'metrics descriptive_only must be the JSON literal true'),
            'claim of analysis': (lambda d: d.update(analyzed=True), schema_message),
            'per-file path': (lambda d: d['groups'][0].update(path='source/x'), schema_message),
            'overall.lines': (lambda d: d['overall'].update(lines=d['overall']['lines'] + 1), projections),
            'by_scope': (lambda d: d['by_scope'][0].update(bytes=0), projections),
            'by_language dropped row': (lambda d: d['by_language'].pop(), projections),
            'groups reordered': (lambda d: d['groups'].reverse(),
                                 'metrics groups are not unique and sorted by scope, language, content'),
            'groups duplicated': (lambda d: d['groups'].append(dict(d['groups'][-1])),
                                  'metrics groups are not unique and sorted by scope, language, content'),
            'negative count': (lambda d: d['groups'][0].update(bytes=-1),
                               'a metrics count is not a non-negative integer'),
            'boolean count': (lambda d: d['groups'][0].update(files=True), schema_message),
            'lines of binary': (lambda d: [g for g in d['groups'] if g['content'] == 'binary'][0].update(lines=3),
                                'a metrics group counts lines of content that is not text'),
            'null lines of text': (lambda d: [g for g in d['groups'] if g['content'] == 'text'][0].update(lines=None),
                                   'a metrics count is not a non-negative integer'),
        }
        pointer, attempt = self.accepted()
        pristine = (attempt / 'manifest.json').read_bytes()
        for label, (edit, message) in edits.items():
            with self.subTest(label=label):
                (attempt / 'manifest.json').write_bytes(pristine)
                rewrite(attempt, lambda m: edit(m['metrics']), True)
                self.rejected(attempt, False, message)
                self.rejected(attempt, True, message)
        (attempt / 'manifest.json').write_bytes(pristine)
        store.check_metrics(attempt, True)

    def test_a_self_consistent_forgery_needs_rederivation_and_the_store_rejects_it_anyway(self):
        pointer, attempt = self.accepted()

        def inflate(manifest):
            document = manifest['metrics']
            text = [g for g in document['groups'] if g['content'] == 'text'][0]
            text['lines'] += 1000
            for key, field in (('overall', None), ('by_scope', 'scope'), ('by_language', 'language')):
                document[key] = store._projection(document['groups'], field)
        rewrite(attempt, inflate, True)
        store.check_metrics(attempt, False)   # stated limit of the cheap check: projections still agree
        self.rejected(attempt, True, 'manifest.json metrics are not what the indexed snapshot produces '
                                     'under rules version ' + store.METRICS_RULES_VERSION)
        with self.assertRaises(state.Blocked):
            store.validate('fixture')
        with self.assertRaises(state.Blocked):
            store.query('fixture', 'search', text='main')

    def test_rederivation_rejects_a_changed_object_and_a_changed_index_row(self):
        pointer, attempt = self.accepted()
        sha = hashlib.sha256(GOLDEN[0][1]).hexdigest()
        original = (attempt / 'objects' / sha).read_bytes()
        (attempt / 'objects' / sha).write_bytes(original + b'\n\n\n')
        store.check_metrics(attempt, False)
        self.rejected(attempt, True, 'a snapshot object does not match its indexed sha256 and size')
        (attempt / 'objects' / sha).write_bytes(original)
        store.check_metrics(attempt, True)
        db = sqlite3.connect(attempt / 'index.sqlite')
        db.execute("UPDATE files SET path='source/src/main.py' WHERE path='source/src/main.c'")
        db.commit()
        db.close()
        for rederive in (False, True):
            self.rejected(attempt, rederive,
                          'metrics snapshot file_set_sha256 or files differs from the files table of index.sqlite')

    def test_every_file_of_the_attempt_tampered_one_at_a_time_is_rejected_without_echo(self):
        pointer, attempt = self.accepted()
        planted = b'planted-' + hashlib.sha256(b'v15').hexdigest()[:12].encode()
        paths = sorted(p for p in attempt.rglob('*') if p.is_file())
        self.assertIn(attempt / 'manifest.json', paths)
        for path in paths:
            with self.subTest(path=path.relative_to(attempt).as_posix()):
                original = path.read_bytes()
                path.write_bytes(original + planted)
                try:
                    for call in (lambda: store.validate('fixture'), lambda: store.validate('fixture', fresh=False),
                                 lambda: store.query('fixture', 'search', text='main')):
                        with self.assertRaises(state.Blocked) as caught:
                            call()
                        self.assertNotIn(planted.decode(), str(caught.exception))
                finally:
                    path.write_bytes(original)
        store.validate('fixture')

    def test_bad_metrics_block_publication_in_the_post_phase(self):
        def corrupt(attempt):
            rewrite(attempt, lambda m: m['metrics']['overall'].update(lines=10 ** 6), True)
        self.after_collect = corrupt
        with self.assertRaises(state.Blocked) as caught:
            store.run('fixture', 'launch1')
        self.assertEqual(str(caught.exception),
                         'metrics overall, by_scope and by_language must be projections of groups')
        base = store.root('fixture')
        accepted = state.read_json(base / 'accepted.json')
        self.assertEqual(accepted['status'], 'FAILED')
        failure = state.read_json(base / 'attempts' / accepted['attempt_id'] / 'validation/failure.json')
        self.assertEqual(failure['phase'], 'post')
        with self.assertRaises(state.Blocked):
            store.query('fixture', 'search', text='main')

        def strip(attempt):
            rewrite(attempt, lambda m: (m.pop('metrics'), m.pop('metrics_sha256')), False)
        self.after_collect = strip
        with self.assertRaises(state.Blocked) as caught:
            store.run('fixture', 'launch2')
        self.assertEqual(str(caught.exception), 'manifest.json has no metrics member')

    def test_an_unnormalized_indexed_path_fails_the_attempt_without_echo(self):
        source = state.read_json(self.intake / 'evidence/source.json')
        planted = 'planted' + 'segment'
        (self.source / planted).mkdir()
        (self.source / planted / 'a.c').write_bytes(b'x\n')
        source['files'][f'{planted}/./a.c'] = {'kind': 'file', 'bytes': 2,
                                               'sha256': hashlib.sha256(b'x\n').hexdigest()}
        (self.intake / 'evidence/source.json').unlink()
        state.atomic_json(self.intake / 'evidence/source.json', source)
        with self.assertRaises(state.Blocked) as caught:
            store.run('fixture', 'launch1')
        self.assertEqual(str(caught.exception),
                         'an indexed path is not a normalized source/ or evidence/ relative path')
        self.assertEqual(state.read_json(store.root('fixture') / 'accepted.json')['status'], 'FAILED')


class IdentityChangeTests(LifecycleCase):
    """Acceptance: prior accepted pointers stay integrity-readable but are not reused as current."""

    def prior_identity_attempt(self):
        """An attempt exactly as the pre-V15 worker left it: no metrics members, prior worker hash."""
        self.plan['worker_sha256'] = hashlib.sha256(b'evidence_store.py before V15').hexdigest()
        with patch.object(store, 'check_metrics'):
            self.after_collect = lambda attempt: rewrite(
                attempt, lambda m: (m.pop('metrics'), m.pop('metrics_sha256')), False)
            pointer = store.run('fixture', 'prior-launch')
        self.after_collect = None
        self.assertNotIn('metrics', state.read_json(self.attempt(pointer) / 'manifest.json'))
        self.assertEqual(state.read_json(self.attempt(pointer) / 'inputs.json')['worker_sha256'],
                         self.plan['worker_sha256'])
        return pointer

    def test_prior_pointer_is_integrity_readable_but_not_current_and_not_reused(self):
        prior = self.prior_identity_attempt()
        before = state.tree_hashes(self.attempt(prior))
        store.validate('fixture')                                    # current under the prior identity
        self.plan['worker_sha256'] = store.LOADED_WORKER_SHA256      # this change is deployed
        # (a) integrity-readable: verifies and can be read when freshness is explicitly not claimed
        pointer, attempt = store.validate('fixture', fresh=False)
        self.assertEqual(pointer, prior)
        read = store.query('fixture', 'read', path='source/src/main.c', fresh=False)
        self.assertFalse(read['freshness_checked'])
        self.assertIn('int main', read['results'][0]['excerpt'])
        # (b) not current
        for call in (lambda: store.validate('fixture'), lambda: store.query('fixture', 'search', text='main')):
            with self.assertRaises(state.Blocked) as caught:
                call()
            self.assertEqual(str(caught.exception), 'index is stale; rerun evidence_index')
        # a prior-identity attempt has no metrics and is never presented as having any
        with self.assertRaises(state.Blocked) as caught:
            store.check_metrics(attempt, True)
        self.assertEqual(str(caught.exception), 'manifest.json has no metrics member')
        # (b) not reused: a run without force allocates a new attempt under the new identity
        current = store.run('fixture', 'new-launch')
        self.assertNotEqual(current['attempt_id'], prior['attempt_id'])
        self.assertNotEqual(current['fingerprint'], prior['fingerprint'])
        self.assertFalse((state.data_path('fixture', 'orchestration', 'dagster', 'new-launch',
                                          'evidence-index-reuse.json')).exists())
        self.assertIn('metrics', state.read_json(self.attempt(current) / 'manifest.json'))
        store.check_metrics(self.attempt(current), True)
        self.assertEqual(before, state.tree_hashes(self.attempt(prior)))   # history is not rewritten
        # and the new identity IS reused by the next launch
        self.assertEqual(store.run('fixture', 'third-launch'), current)

    def test_input_fingerprint_is_a_function_of_the_worker_file_bytes(self):
        for item in self.patches:
            if getattr(item, 'attribute', None) == 'inputs':
                item.stop()
                self.patches.remove(item)
                break
        discovery = state.data_path('fixture', 'jobs', '00-workflow-preparation', 'build_discovery', 'accepted.json')
        state.atomic_json(discovery, {'upstream': 'intake-generation', 'attempt_id': 'd'})
        real_hash = store.file_hash
        worker = store.ROOT / 'evidence_store.py'

        def plan_for(worker_hash):
            def fake_hash(path):
                path = Path(path)
                if path == worker:
                    return worker_hash
                return real_hash(path) if path.is_relative_to(store.ROOT) else 'runtime-library'
            import workflow
            with patch.object(store, 'file_hash', side_effect=fake_hash), \
                    patch.object(store, 'LOADED_WORKER_SHA256', worker_hash), \
                    patch.object(store.phase1, 'accepted', return_value={'status': 'OK', 'fingerprint': 'intake-generation'}), \
                    patch.object(workflow, 'validate_branch'):
                return store.inputs('fixture')
        prior, current = plan_for('a' * 64), plan_for(real_hash(worker))
        self.assertEqual(current['worker_sha256'], store.LOADED_WORKER_SHA256)
        self.assertEqual({k: v for k, v in prior.items() if k != 'worker_sha256'},
                         {k: v for k, v in current.items() if k != 'worker_sha256'})
        self.assertNotEqual(state.digest(prior), state.digest(current))
        # the contract record is part of the fingerprint too, so its additive text also changed identity
        self.assertIn('member_schemas', json.dumps(current['composition']))
        with patch.object(store, 'LOADED_WORKER_SHA256', 'b' * 64), self.assertRaises(state.Blocked):
            store.inputs('fixture')


if __name__ == '__main__':
    unittest.main()
