"""declare_releases sets release ids without duplicating keys the shipped configuration declares."""
import tomllib
from pathlib import Path

from tests.release_support import declare_releases

ROOT = Path(__file__).resolve().parents[1]


def test_declared_keys_are_replaced_and_new_keys_inserted_once() -> None:
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    assert "platform = " in text, "the shipped configuration declares platform; this test relies on it"
    patched = declare_releases(text, platform="fixture-platform", build_toolchain="fixture-build",
                               validation="fixture-validation")
    releases = tomllib.loads(patched)["review_policy"]["releases"]
    assert releases["platform"] == "fixture-platform"
    assert releases["validation"] == "fixture-validation"
    assert releases["build_toolchain"] == "fixture-build"
    assert releases["codeql"] == tomllib.loads(text)["review_policy"]["releases"]["codeql"]
    again = declare_releases(patched, platform="fixture-platform-2")
    assert tomllib.loads(again)["review_policy"]["releases"]["platform"] == "fixture-platform-2"


def test_other_tables_are_untouched() -> None:
    text = ("[runtime]\nruns_dir = \"runs\"\n\n[review_policy.releases]\ncodeql = \"x\"\n\n"
            "[jobs]\nplatform = \"not-a-release\"\n")
    patched = declare_releases(text, platform="p", **{"tool-syft": "fixture/1"})
    document = tomllib.loads(patched)
    assert document["review_policy"]["releases"] == {"codeql": "x", "platform": "p", "tool-syft": "fixture/1"}
    assert document["jobs"]["platform"] == "not-a-release"
