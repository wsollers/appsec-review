from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from tools.quality.baseline import baseline_json, compare, decode_baseline, finding, prune, require_shrink_only
from tools.quality.boundaries import scan_boundaries
from tools.quality.config import GateError, load_config
from tests.quality.support import repository, write


def scan(root: Path, module: str, source: str):
    path = f"src/{module.replace('.', '/')}.py"
    write(root, path, source)
    return scan_boundaries(root, (path,), load_config(root))


@pytest.mark.parametrize("source", [
    "from appsec_review.jobs.producer.api import receipt\n",
    "from appsec_review.storage.atomic import canonical_json\n",
    "from appsec_review.inference import infer\n",
    "import hashlib, json, subprocess, datetime\n",
    "from ._internal import helper\n",
    "from appsec_review.jobs.consumer._internal import helper\n",
    "from appsec_review.config import AppConfig\nfields = AppConfig.__dataclass_fields__\n",
    "from appsec_review.retrieval.observations import SEVERITY_ORDER\nkey = SEVERITY_ORDER.__getitem__\n",
])
def test_legitimate_producer_and_same_owner_dependencies_are_allowed(tmp_path: Path, source: str) -> None:
    root = repository(tmp_path / "repo")
    assert scan(root, "appsec_review.jobs.consumer.handler", source) == ()


@pytest.mark.parametrize("source", [
    "from appsec_review.jobs.producer.impl import _private\n",
    "import appsec_review.jobs.producer._internal\n",
    "from ..producer.impl import _private\n",
    "from appsec_review.jobs.producer import impl as producer\nproducer._private()\n",
    "import importlib as loader\nloader.import_module('appsec_review.jobs.producer._internal')\n",
    "from appsec_review.storage.atomic import *\n",
])
def test_private_cross_owner_dependencies_are_forbidden(tmp_path: Path, source: str) -> None:
    root = repository(tmp_path / "repo")
    assert {item.rule for item in scan(root, "appsec_review.jobs.consumer.handler", source)} == {"ARCH:private-import"}


@pytest.mark.parametrize("source", [
    "from appsec_review.storage import atomic\n",
    "from appsec_review.signing import core\n",
    "from . import core\n",
    "import requests\n",
    "import importlib\nimportlib.import_module('appsec_review.config')\n",
    "from importlib import import_module as load\nload(name)\n",
    "__import__('appsec_review')\n",
    "if __import__('appsec_review'):\n    pass\n",
])
def test_bootstrap_cannot_import_the_application_or_external_dependencies(tmp_path: Path, source: str) -> None:
    root = repository(tmp_path / "repo")
    assert {item.rule for item in scan(root, "appsec_review.signing.bootstrap", source)} == {"ARCH:bootstrap-isolation"}


def test_bootstrap_dependency_closure_requires_guarded_trusted_siblings(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo")
    assert scan(root, "appsec_review.signing.bootstrap", "import sys, pathlib, importlib.util\n") == ()
    assert scan(root, "appsec_review.signing.modules", "if __package__:\n    from . import core\n") == ()
    assert scan(root, "appsec_review.signing.modules",
                "if __package__:\n    from . import core\ncore._read_regular_file('x')\n") == ()
    assert scan(root, "appsec_review.signing.modules", "from . import core\n")[0].rule == "ARCH:bootstrap-isolation"
    assert scan(root, "appsec_review.signing.core", "from appsec_review.storage.atomic import canonical_json\n")
    assert scan(root, "appsec_review.signing.modules", "if __package__:\n    from . import untrusted\n")


def test_runtime_and_public_contract_direction(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo")
    assert scan(root, "appsec_review.runtime.contract", "from appsec_review.jobs import producer\n")[0].rule == "ARCH:contract-direction"
    assert scan(root, "appsec_review.runtime.contract", "from tools.quality import config\n")[0].rule == "ARCH:runtime-development"
    assert scan(root, "appsec_review.jobs.consumer", "from appsec_review.inference.claude_cli import send\n")[0].rule == "ARCH:inference-api"


def test_fingerprint_survives_line_shifts_but_not_changed_statements(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo")
    path = "src/appsec_review/legacy.py"
    write(root, path, "value = undefined\n")
    before = finding(root, path, "ruff:F821", "Undefined name", 1)
    write(root, path, "\n# shifted\nvalue = undefined\n")
    shifted = finding(root, path, "ruff:F821", "Undefined name", 3)
    assert before.key == shifted.key
    assert compare((shifted,), (before,)) == ()
    write(root, path, "other = undefined\n")
    changed = finding(root, path, "ruff:F821", "Undefined name", 1)
    assert changed.key != before.key
    assert len(compare((changed,), (before,))) == 2


def test_ratcheting_counts_removal_and_pruning(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo")
    path = "src/appsec_review/legacy.py"
    write(root, path, "value = undefined\n")
    item = finding(root, path, "ruff:F821", "Undefined name", 1)
    assert compare((item, item), (item,))[0].startswith("NEW")
    assert compare((), (item,))[0].startswith("STALE")
    assert prune((item, item), (item,)) == (item,)
    assert prune((), (item,)) == ()
    require_shrink_only((), (item,))
    with pytest.raises(GateError, match="baseline-growth"):
        require_shrink_only((item, item), (item,))
    assert decode_baseline(baseline_json((item,), "Reviewed fixture")) == (item,)


def test_self_scan_baseline_binds_security_relevant_enclosing_scope(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo")
    path = "src/appsec_review/legacy.py"
    template = "def load(text):\n    class Loader(yaml.%s):\n        pass\n    return yaml.load(text, Loader=Loader)\n"
    write(root, path, template % "SafeLoader")
    before = finding(root, path, "bandit:B506", "yaml load", 4)
    write(root, path, template % "UnsafeLoader")
    after = finding(root, path, "bandit:B506", "yaml load", 4)
    assert before.key != after.key


def test_baseline_rejects_unreviewed_and_bootstrap_exemptions(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo")
    path = "src/appsec_review/legacy.py"
    write(root, path, "value = 1\n")
    item = finding(root, path, "ARCH:private-import", "fixture", 1)
    for bad in (replace(item, path="tools/quality/check.py"), replace(item, rule="ARCH:bootstrap-isolation")):
        with pytest.raises(GateError):
            decode_baseline(baseline_json((bad,), "review"))
    with pytest.raises(GateError):
        decode_baseline(baseline_json((item,), ""))
    with pytest.raises(GateError):
        decode_baseline('{"version": 1, "reason": "review", "findings": [{}]}')
    document = json.loads(baseline_json((item,), "review"))
    document["findings"][0]["fingerprint"] = "not-a-digest"
    with pytest.raises(GateError):
        decode_baseline(json.dumps(document))


def test_syntax_errors_are_resolving_findings_not_skipped_coverage(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo")
    values = scan(root, "appsec_review.runtime.contract", "def broken(:\n")
    assert len(values) == 1 and values[0].rule == "ARCH:syntax" and values[0].line == 1


def test_distinct_canonical_json_public_contracts_are_not_interchangeable() -> None:
    from appsec_review.retrieval.model import canonical_json as retrieval_json
    from appsec_review.signing.core import canonical_json as signing_json
    from appsec_review.storage.atomic import canonical_json as storage_json

    value = {"z": "\u00e9", "a": [True, None, 2]}
    compact = b'{"a":[true,null,2],"z":"\xc3\xa9"}'
    assert storage_json(value) == compact + b"\n"
    assert retrieval_json(value) == signing_json(value) == compact
    for invalid in ({"a": 1.5}, {1: "invalid key"}):
        with pytest.raises(ValueError):
            signing_json(invalid)
