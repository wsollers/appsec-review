"""Manual host oracle for the running Linux interpreter's dynamic ELF loader facts.

Preserved from the unit tier: the host must supply a dynamic executable with a /lib
interpreter and a libc dependency. Run only on explicit request, never as a unit gate.
"""

from __future__ import annotations

from pathlib import Path
import sys

import pytest

from appsec_review.jobs.job_language_build import elf


@pytest.mark.skipif(sys.platform != "linux", reason="reads the running ELF interpreter")
def test_loader_facts_agree_with_a_real_dynamic_executable() -> None:
    facts = elf.loader_facts(Path(sys.executable).resolve())
    assert facts["linkage"] == "dynamic" and facts["interpreter"].startswith("/lib")
    assert any(name.startswith("libc.so") for name in facts["needed"])
