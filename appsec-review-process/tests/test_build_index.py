"""Focused tests for 02-build-index (build_index.py; TODO Phase 5g item 2).

Fixture-driven and model-free: each test writes a small checkout, fingerprints it with intake's own
``source_identity`` and indexes it. Covers the hello-autotools answer key (units only), a polyglot
monorepo (nested, workspace, vendored, example and deferred roots), bounds and truncation, freshness,
determinism and the validator's tamper checks.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import build_index as bi
import intake
from execution_state import Blocked

INPUTS = [
    {'job': '00-intake', 'artifact': 'intake.json', 'attempt_id': '0' * 32, 'sha256': 'a' * 64},
    {'job': '02-repository-partition-discovery', 'artifact': 'repository-partition-map.json',
     'attempt_id': '1' * 32, 'sha256': 'b' * 64},
]

HELLO = {
    'configure.ac': 'AC_PREREQ([2.69])\nAC_INIT([hello], [1.0])\nAM_INIT_AUTOMAKE([foreign subdir-objects])\n'
                    'AC_PROG_CXX\nAC_PROG_CC\nAM_PROG_AR\nAC_PROG_RANLIB\nAC_CONFIG_FILES([Makefile])\nAC_OUTPUT\n',
    'Makefile.am': '# Vendored dependency (see vendor/cJSON-1.7.18/VENDORED.md)\n'
                   'noinst_LIBRARIES = libcjson.a\nlibcjson_a_SOURCES = \\\n\tvendor/cJSON-1.7.18/cJSON.c \\\n'
                   '\tvendor/cJSON-1.7.18/cJSON.h\nbin_PROGRAMS = hello\nhello_SOURCES = src/main.cpp\n'
                   'hello_CXXFLAGS = -std=c++11\nhello_LDADD = libcjson.a\n',
    'Dockerfile': 'FROM debian:bookworm-slim AS build\nRUN apt-get update && apt-get install -y autoconf\n'
                  'COPY . /src\nRUN autoreconf -fi && ./configure && make\n',
    'src/main.cpp': 'int main() { return 0; }\n',
    'vendor/cJSON-1.7.18/cJSON.c': '/* c */\n',
    'vendor/cJSON-1.7.18/cJSON.h': '/* h */\n',
    'vendor/cJSON-1.7.18/VENDORED.md': '# Vendored\nBuild it with make.\n',
    'README.md': '# hello\n\nA demo.\n\n## Building\n\nRun autoreconf -fi, ./configure and make.\n',
    'docs/BUILDING.md': '# Building\n\nautoreconf -fi\n',
}
HELLO_MAP = [
    {'partition_id': 'app', 'kinds': ['other'], 'include_paths': ['src/**'], 'disposition': 'review'},
    {'partition_id': 'vendored-cjson', 'kinds': ['vendored'], 'include_paths': ['vendor/cJSON-1.7.18/**'],
     'disposition': 'review'},
    {'partition_id': 'docs', 'kinds': ['documentation'], 'include_paths': ['README.md', 'docs/**'],
     'disposition': 'deferred'},
]

POLY = {
    'package.json': '{\n  "name": "mono",\n  "private": true,\n  "workspaces": ["packages/*"],\n'
                    '  "devDependencies": {\n    "typescript": "5.4.0"\n  }\n}\n',
    'package-lock.json': '{\n  "lockfileVersion": 3\n}\n',
    'tsconfig.json': '{ "compilerOptions": { "strict": true } }\n',
    'packages/web/package.json': '{\n  "name": "web",\n  "dependencies": {\n    "vite": "5.0.0"\n  }\n}\n',
    'packages/web/src/app.ts': 'export const x = 1;\n',
    'services/api/go.mod': 'module example.com/api\n\ngo 1.22\n\nrequire (\n\tgithub.com/x/y v1.0.0\n)\n',
    'services/api/go.sum': 'github.com/x/y v1.0.0 h1:abc=\n',
    'services/api/main.go': 'package main\n',
    'services/api/Dockerfile': 'FROM golang:1.22 AS build\nRUN go build ./...\n',
    'crates/Cargo.toml': '[workspace]\nmembers = ["core"]\n',
    'crates/core/Cargo.toml': '[package]\nname = "core"\nedition = "2021"\n\n[dependencies]\nlibc = "0.2"\n',
    'crates/core/build.rs': 'fn main() {}\n',
    'crates/core/src/lib.rs': 'pub fn f() {}\n',
    'third_party/zlib/CMakeLists.txt': 'cmake_minimum_required(VERSION 3.10)\nproject(zlib C)\n',
    'third_party/zlib/zlib.c': 'int z;\n',
    'examples/demo/package.json': '{ "name": "demo" }\n',
    'legacy/setup.py': 'from setuptools import setup\nsetup(name="legacy", install_requires=["six"])\n',
    'legacy/requirements.txt': 'six==1.16.0\n',
    'legacy/README.md': '# Legacy\n\n## Install\n\npip install .\n',
    'infra/main.tf': 'terraform {\n  required_version = ">= 1.5"\n}\n',
    'tools/Makefile': 'all:\n\techo tools\n',
    'Makefile': '# tools is built on its own\nall:\n\tnpm run build\n',
    '.github/workflows/ci.yml': 'on: push\njobs:\n  b:\n    steps:\n      - run: npm ci\n',
    'excluded/package.json': '{ "name": "out-of-scope" }\n',
}
POLY_MAP = [
    {'partition_id': 'legacy', 'kinds': ['other'], 'include_paths': ['legacy/**'], 'disposition': 'deferred'},
    {'partition_id': 'web', 'kinds': ['client'], 'include_paths': ['packages/**'], 'disposition': 'review'},
]


def write_tree(root, files):
    for rel, text in files.items():
        path = Path(root) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode('utf-8'))


def records(root, partitions, excluded=()):
    source = intake.source_identity(str(root))
    result = {'source_revision': source['revision'], 'source_fingerprint': source['fingerprint'],
              'scope': {'excluded_paths': sorted(excluded)}}
    partition_map = {'schema': 'appsec-review/repository-partition-map/0.1', 'target': 'fixture',
                     'source_revision': source['revision'], 'partitions': partitions, 'coverage': {}}
    return source, result, partition_map


class Checkout(unittest.TestCase):
    files = HELLO
    partitions = HELLO_MAP
    excluded = ()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / 'target'
        write_tree(self.root, self.files)
        self.source, self.intake, self.map = records(self.root, self.partitions, self.excluded)

    def tearDown(self):
        self.tmp.cleanup()

    def index(self, cross=None):
        return bi.build_index(self.root, self.source, self.intake, self.map, INPUTS, cross)

    def check(self, index, **kw):
        return bi.check(index, self.root, intake_result=self.intake, inputs=INPUTS, partition_map=self.map,
                        raw=bi.serialize(index), **kw)

    def signal(self, index, **match):
        return [s for s in index['signals'] if all(s[k] == v for k, v in match.items())]


class HelloAutotools(Checkout):
    def test_answer_key_units(self):
        index = self.index()
        self.assertEqual([u['unit_id'] for u in index['units']], ['dir:.', 'file:Dockerfile'])
        root = index['units'][0]
        self.assertEqual([m['path'] for m in root['defining_manifests']], ['Makefile.am', 'configure.ac'])
        self.assertEqual([(m['path'], m['reason'], m['manifests']) for m in root['members']],
                         [('vendor/cJSON-1.7.18', 'referenced-by-parent-build', [])])
        self.assertEqual(index['not_units'], [])
        self.assertEqual(self.check(index), [])

    def test_no_class_or_plan_anywhere(self):
        text = bi.serialize(self.index()).decode()
        for word in ('"class"', 'compiled-native', '"plan"', 'feasibility', '"argv"'):
            self.assertNotIn(word, text)

    def test_member_reference_is_code_not_comment(self):
        index = self.index()
        refs = self.signal(index, kind='nested-root-reference')
        self.assertEqual([(r['path'], r['line_start'], r['line_end'], r['label']) for r in refs],
                         [('Makefile.am', 3, 5, 'libcjson_a_SOURCES')])
        self.assertEqual(index['units'][0]['members'][0]['signal_ids'], [refs[0]['signal_id']])

    def test_signals_cover_toolchain_container_and_docs(self):
        index = self.index()
        labels = {(s['kind'], s['label']) for s in index['signals']}
        for expected in [('toolchain-declaration', 'AC_PROG_CXX'), ('toolchain-declaration', 'hello_CXXFLAGS'),
                         ('dependency-declaration', 'hello_LDADD'), ('container-recipe', 'FROM'),
                         ('build-manifest', 'Dockerfile'), ('human-instructions', 'README.md#building'),
                         ('human-instructions', 'BUILDING.md#building')]:
            self.assertIn(expected, labels)
        # vendored tree: counted, not indexed
        self.assertFalse(any(s['path'].startswith('vendor/') for s in index['signals']))
        self.assertEqual(index['units'][0]['file_count'], 8)
        self.assertEqual(self.signal(index, label='FROM')[0]['unit_ids'], ['file:Dockerfile'])

    def test_deterministic(self):
        first, second = self.index(), self.index()
        self.assertEqual(bi.serialize(first), bi.serialize(second))
        self.assertEqual(self.check(first, expected=second), [])

    def test_every_excerpt_is_marked_and_bounded(self):
        index = self.index()
        self.assertEqual(index['trust_notice'], bi.TRUST_NOTICE)
        for s in index['signals']:
            self.assertLessEqual(len(s['excerpt'].encode()), bi.MAX_EXCERPT_BYTES)

    def test_markdown_carries_no_excerpt(self):
        index = self.index()
        md = bi.render_markdown(index)
        self.assertIn('`dir:.`', md)
        self.assertIn('`file:Dockerfile`', md)
        self.assertNotIn('bookworm', md)

    def test_stale_checkout_blocks(self):
        (self.root / 'configure.ac').write_text('AC_INIT([changed])\n')
        with self.assertRaisesRegex(Blocked, 'changed since intake'):
            self.index()

    def test_partition_revision_mismatch_blocks(self):
        self.map['source_revision'] = 'other'
        with self.assertRaisesRegex(Blocked, 'source_revision'):
            self.index()

    def test_cross_check(self):
        index = self.index({'02-devops-project-discovery': {'projects': [
            {'project_id': 'container-image', 'root': './'}, {'project_id': 'ghost', 'root': 'nope/'}]}})
        dev, devops = index['cross_check']
        self.assertEqual(dev, {'job': '02-dev-project-discovery', 'status': 'not-available', 'roots': []})
        self.assertEqual(devops['roots'], [
            {'project_id': 'container-image', 'root': '.', 'unit_ids': ['dir:.', 'file:Dockerfile']},
            {'project_id': 'ghost', 'root': 'nope', 'unit_ids': []}])


class Tamper(Checkout):
    def assertRejected(self, mutate, message):
        index = self.index()
        bad = copy.deepcopy(index)
        mutate(bad)
        errors = self.check(bad)
        self.assertTrue(any(message in e for e in errors), errors)

    def test_excerpt_edit(self):
        self.assertRejected(lambda i: i['signals'][0].update(excerpt='FROM evil'), 'excerpt does not equal')

    def test_sha_edit(self):
        self.assertRejected(lambda i: i['signals'][0].update(sha256='0' * 64), 'sha256 does not match')

    def test_line_range_outside_file(self):
        self.assertRejected(lambda i: i['signals'][0].update(line_end=999), 'outside the file')

    def test_traversal_path(self):
        self.assertRejected(lambda i: i['signals'][0].update(path='../outside'), 'does not match pattern')

    def test_duplicate_signal_id(self):
        self.assertRejected(lambda i: i['signals'][1].update(signal_id=i['signals'][0]['signal_id']), 'not unique')

    def test_unit_without_manifest_signal(self):
        def strip(i):
            unit = i['units'][1]
            for s in i['signals']:
                if unit['unit_id'] in s['unit_ids']:
                    s['unit_ids'] = []
            unit['signal_ids'] = []
        self.assertRejected(strip, 'minItems')

    def test_unit_signal_disagreement(self):
        self.assertRejected(lambda i: i['units'][0]['signal_ids'].pop(), 'disagree')

    def test_member_without_reference(self):
        self.assertRejected(lambda i: i['units'][0]['members'][0].update(
            signal_ids=[i['units'][0]['signal_ids'][0]]), 'nested-root-reference')

    def test_inputs_mismatch(self):
        self.assertRejected(lambda i: i['inputs'][0].update(sha256='c' * 64), 'inputs do not name')

    def test_revision_mismatch(self):
        self.assertRejected(lambda i: i.update(source_revision='x'), 'source_revision differs')

    def test_partition_context_edit(self):
        self.assertRejected(lambda i: i['partition_context'].pop(), 'partition_context does not match')

    def test_truncation_counts(self):
        self.assertRejected(lambda i: i['truncated'].update(any=True), 'truncated.any')

    def test_class_field_rejected(self):
        self.assertRejected(lambda i: i['units'][0].update({'class': 'compiled-native'}), 'unexpected property')

    def test_checkout_changed_after_indexing(self):
        index = self.index()
        (self.root / 'Dockerfile').write_text('FROM scratch\n')
        self.assertTrue(any('sha256 does not match' in e for e in self.check(index)))

    def test_rebuild_difference(self):
        index = self.index()
        other = copy.deepcopy(index)
        other['limitations'] = other['limitations'][:-1]
        self.assertTrue(any('deterministic rebuild' in e for e in self.check(index, expected=other)))


class Polyglot(Checkout):
    files = POLY
    partitions = POLY_MAP
    excluded = ('excluded/package.json',)

    def test_units(self):
        index = self.index()
        self.assertEqual([u['unit_id'] for u in index['units']], [
            'dir:.', 'dir:crates', 'dir:infra', 'dir:services/api', 'dir:tools', 'file:services/api/Dockerfile'])
        self.assertEqual(self.check(index), [])

    def test_members_and_not_units(self):
        index = self.index()
        units = {u['unit_id']: u for u in index['units']}
        self.assertEqual([(m['path'], m['reason']) for m in units['dir:.']['members']],
                         [('packages/web', 'parent-workspace-member')])
        self.assertEqual([(m['path'], m['reason']) for m in units['dir:crates']['members']],
                         [('crates/core', 'parent-workspace-member')])
        self.assertEqual([(n['path'], n['reason'], n['partition_id']) for n in index['not_units']], [
            ('examples/demo', 'unreferenced-example-copy', None),
            ('legacy', 'in-deferred-partition', 'legacy'),
            ('third_party/zlib', 'unreferenced-vendored-copy', None)])

    def test_comment_is_not_a_reference(self):
        index = self.index()
        self.assertIn('dir:tools', [u['unit_id'] for u in index['units']])
        self.assertEqual(self.signal(index, kind='nested-root-reference', path='Makefile'), [])

    def test_language_markers_and_lockfiles(self):
        index = self.index()
        units = {u['unit_id']: u for u in index['units']}
        marker = lambda label: {tuple(s['unit_ids']) for s in self.signal(index, kind='language-marker', label=label)}
        self.assertEqual(marker('typescript'), {('dir:.',)})
        self.assertEqual(marker('tsconfig.json'), {('dir:.',)})
        self.assertEqual(marker('vite'), {('dir:.',)})
        self.assertEqual(marker('build.rs'), {('dir:crates',)})
        self.assertEqual([l['path'] for l in units['dir:.']['lockfiles']], ['package-lock.json'])
        self.assertEqual([l['path'] for l in units['dir:services/api']['lockfiles']], ['services/api/go.sum'])
        self.assertEqual({tuple(s['unit_ids']) for s in self.signal(index, kind='ci-recipe')}, {('dir:.',)})
        exts = {e['extension']: e['count'] for e in units['dir:.']['extension_counts']}
        self.assertEqual(exts.get('.ts'), 1)

    def test_deferred_partition_gives_names_not_excerpts(self):
        index = self.index()
        legacy = [s for s in index['signals'] if s['path'].startswith('legacy/')]
        self.assertEqual({s['kind'] for s in legacy}, set())  # not a unit: no signals at all
        self.assertEqual(index['partition_context'][0], {'partition_id': 'legacy', 'kinds': ['other'],
                                                          'disposition': 'deferred', 'include_paths': ['legacy/**']})

    def test_excluded_paths_absent(self):
        text = bi.serialize(self.index()).decode()
        self.assertNotIn('excluded/package.json', text)
        self.assertEqual(self.index()['layout']['files_excluded'], 1)


class Bounds(Checkout):
    # 12 independent CMake units x (manifest + 2 toolchain + 38 find_package) = 492 signals, plus
    # the Dockerfile's 2, against the 400 bound; plus one file over the 40-per-file cap.
    files = dict({f'lib{n:02d}/CMakeLists.txt': 'cmake_minimum_required(VERSION 3.20)\nproject(l CXX)\n'
                  + ''.join(f'find_package(Dep{i:03d} REQUIRED)\n' for i in range(38)) for n in range(12)},
                 **{'Dockerfile': 'FROM debian\n',
                    'big/CMakeLists.txt': 'project(big)\n' + ''.join(f'find_package(B{i:03d})\n' for i in range(300))})
    partitions = []

    def test_signal_cap_and_counts(self):
        index = self.index()
        self.assertEqual(len(index['signals']), bi.MAX_SIGNALS)
        t = index['truncated']
        self.assertTrue(t['any'])
        produced = 12 * 41 + 2 + 302  # Dockerfile: manifest + FROM; big/: manifest + project + 300
        self.assertEqual(t['signals_omitted'], produced - bi.MAX_SIGNALS)
        # lowest priority goes first: the FROM line (container-recipe) is dropped before any dependency
        self.assertEqual([k['kind'] for k in t['omitted_by_kind']], ['dependency-declaration', 'container-recipe'])
        self.assertEqual(t['excerpts_clipped'], 1)  # big/CMakeLists.txt's whole-file excerpt
        self.assertTrue(self.signal(index, kind='build-manifest', path='big/CMakeLists.txt')[0]['excerpt_clipped'])
        self.assertEqual(len(index['units']), 14)
        self.assertTrue(all(u['signal_ids'] for u in index['units']))
        self.assertEqual(self.check(index), [])

    def test_index_size_bound(self):
        with patch.object(bi, 'MAX_INDEX_BYTES', 40000):
            index = self.index()
            self.assertLessEqual(len(bi.serialize(index)), 40000)
            self.assertTrue(index['truncated']['index_size_limited'])
            # only the schema's pinned limit notices the patched bound; every other check passes
            self.assertEqual(self.check(index), ['$.limits.max_index_bytes: expected const 524288, got 40000'])
            self.assertTrue(self.signal(index, kind='build-manifest', path='Dockerfile'))


class Symlinks(Checkout):
    files = {'configure.ac': 'AC_INIT([x])\n'}
    partitions = []

    def setUp(self):
        super().setUp()
        outside = Path(self.tmp.name) / 'outside'
        outside.mkdir()
        (outside / 'package.json').write_text('{}\n')
        try:
            os.symlink(outside / 'package.json', self.root / 'package.json')
            os.symlink(outside, self.root / 'linked', target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('symlinks unavailable on this host')
        self.source, self.intake, self.map = records(self.root, [])

    def test_links_are_not_followed(self):
        index = self.index()
        self.assertEqual([u['unit_id'] for u in index['units']], ['dir:.'])
        self.assertFalse(any(s['path'] in ('package.json',) or s['path'].startswith('linked/')
                             for s in index['signals']))


FIXTURE = ROOT.parent / 'fixtures' / 'targets' / 'hello-autotools'


@unittest.skipUnless((FIXTURE / 'configure.ac').is_file(), 'fixtures/populate-targets.sh not run')
class RealFixture(unittest.TestCase):
    def test_answer_key(self):
        source, result, partition_map = records(FIXTURE, HELLO_MAP)
        index = bi.build_index(FIXTURE, source, result, partition_map, INPUTS)
        self.assertEqual([u['unit_id'] for u in index['units']], ['dir:.', 'file:Dockerfile'])
        self.assertEqual([m['path'] for m in index['units'][0]['members']], ['vendor/cJSON-1.7.18'])
        self.assertEqual(bi.check(index, FIXTURE, intake_result=result, inputs=INPUTS,
                                  raw=bi.serialize(index)), [])


if __name__ == '__main__':
    unittest.main()
