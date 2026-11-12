"""Locked grammars parse the sample definitions and calls in the pinned Tree-sitter image.

Skips, naming the gap, when Docker or the image is missing. The projection and retrieval checks
that run on recorded nodes stay in ``tests/test_syntax_retrieval.py``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from appsec_review.jobs.job_tree_sitter_ast.projection import project


SAMPLES = [
    ("c", "#include <stdio.h>\nint dispatch(){ return sink(); }", "dispatch", "sink"),
    ("cpp", "#include <string>\nclass C { int dispatch(){ return sink(); } };", "dispatch", "sink"),
    ("csharp", "using System;\nclass C { int Dispatch(){ return Sink(); } }", "Dispatch", "Sink"),
    ("go", 'package p\nimport "os"\nfunc dispatch() { sink() }', "dispatch", "sink"),
    ("java", "import java.util.List;\nclass C { int dispatch(){ return sink(); } }", "dispatch", "sink"),
    ("javascript", 'import lib from "lib";\nexport function dispatch(){ return lib.sink(); }', "dispatch", "lib.sink"),
    ("typescript", 'import lib from "lib";\nfunction dispatch(): number { return sink(); }', "dispatch", "sink"),
    ("tsx", 'import lib from "lib";\nfunction dispatch(){ return sink(); }', "dispatch", "sink"),
    ("kotlin", "import java.io.File\nfun dispatch() { sink() }", "dispatch", "sink"),
    ("python", "import os\ndef dispatch():\n    return sink()\n", "dispatch", "sink"),
    ("ruby", "require 'dep'\ndef dispatch\n  sink()\nend\n", "dispatch", "sink"),
    ("rust", "use std::fs;\nfn dispatch() { sink(); }", "dispatch", "sink"),
    ("php", "<?php use Foo\\Bar;\nfunction dispatch() { return sink(); }", "dispatch", "sink"),
]

# No host mounts or network are needed: feed only repository-owned fixture bytes over stdin to the
# already installed image, using its pinned parser and grammars unchanged.
_PARSE_FIXTURES = """
import json, runpy, sys
p = runpy.run_path('/opt/appsec/parser.py')
p['configure'](p['PackConfig'](cache_dir='/opt/grammars'))
result = {}
for grammar, text, _, _ in json.load(sys.stdin):
    tree = p['get_parser'](grammar).parse(text.encode())
    stack, nodes = [(tree.root_node, (), None)], []
    while stack:
        node, ordinal, field = stack.pop()
        nodes.append(p['_node'](node, ordinal, field))
        stack.extend((child, (*ordinal, i), node.field_name_for_child(i))
                     for i, child in reversed(list(enumerate(node.children))))
    result[grammar] = {'error': tree.root_node.has_error, 'nodes': nodes}
json.dump(result, sys.stdout)
"""


@pytest.fixture(scope="module")
def live_nodes():
    if not shutil.which("docker"):
        pytest.skip("pinned Tree-sitter image unavailable")
    from appsec_review.container_runtime import load_catalog
    root = Path(__file__).resolve().parents[1]
    tool = load_catalog(root).tools["tool-tree-sitter"]
    probe = subprocess.run(["docker", "image", "inspect", tool.tag, "--format", "{{.Id}}"],
                           capture_output=True, text=True, timeout=15)
    if probe.returncode != 0:
        pytest.skip("pinned Tree-sitter image unavailable")
    assert probe.stdout.strip() == tool.expected_image_id
    parsed = subprocess.run(["docker", "run", "--rm", "-i", "--network", "none", "--read-only",
                             "--user", "10001:10001", "--entrypoint", "python", tool.expected_image_id, "-c", _PARSE_FIXTURES],
                            input=json.dumps(SAMPLES), capture_output=True, text=True, timeout=60)
    assert parsed.returncode == 0, parsed.stderr
    return json.loads(parsed.stdout)


@pytest.mark.parametrize(("grammar", "source", "definition", "call"), SAMPLES)
def test_locked_grammar_definition_and_call_shapes(live_nodes, grammar, source, definition, call):
    parsed = live_nodes[grammar]
    assert not parsed["error"]
    nodes = parsed["nodes"]
    identities = {tuple(node["ordinal_path"]): "asr:ast_node:" + hashlib.sha256(
                  json.dumps(node).encode()).hexdigest() for node in nodes}
    data = source.encode()
    projected = project(nodes, data, grammar=grammar, source_identity="asr:source_file:" + "f" * 64,
                        identities=identities)
    assert definition in {value["written_name"] for value in projected.values() if value["category"] == "definition"}
    assert call in {value["written_name"] for value in projected.values() if value["category"] == "call_expression"}
    assert any(value.get("import_expression") for value in projected.values())
    for value in projected.values():
        span = value["name_span"]
        assert data[span["start_byte"]:span["end_byte"]].decode() == value["written_name"]
        assert value["syntax_only"] and value["resolution"] == "unresolved"
