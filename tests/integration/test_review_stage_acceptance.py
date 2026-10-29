"""Each collected producer node is exactly one bounded application phase."""
import pytest

from tests.acceptance_review_stages import VARIANTS, produce


@pytest.mark.parametrize("variant", list(VARIANTS))
def test_prepare_stage(variant):
    produce("prepare", variant)


@pytest.mark.parametrize("variant", list(VARIANTS))
def test_review_stage(variant):
    produce("review", variant)


@pytest.mark.parametrize("variant", ["ci-positive", "ci-benign", "ci-blocked"])
def test_gate_stage(variant):
    produce("gate", variant)


@pytest.mark.parametrize("variant", ["ci-positive", "ci-benign", "ci-blocked"])
def test_report_stage(variant):
    produce("report", variant)


@pytest.mark.parametrize("variant", ["native-positive"])
def test_poc_stage(variant):
    produce("poc", variant)
