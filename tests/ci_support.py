"""A container executor double for the CI job tests: the external boundary only (image resolution
and tool execution); everything else — discovery, static rules, normalization, indexing, publication —
is the real code."""
from __future__ import annotations

from pathlib import Path

from appsec_review.container_runtime import load_catalog
from appsec_review.container_runtime.executor import ExecutionResult

DIGEST = "sha256:" + "c" * 64


class FakeExecutor:
    """Records every request and answers with an empty JSON document on stdout (exit 0).

    ``stdout`` is the bytes every tool prints, or a ``{tool_id: bytes}`` mapping (tools not named
    print ``{}``), so a test can make exactly one linter speak.
    """

    def __init__(self, repository: Path, run_root: Path, calls: list[tuple[str, tuple[str, ...]]],
                 *, stdout: bytes | dict[str, bytes] = b"{}", exit_code: int = 0):
        self.catalog = load_catalog(repository)
        self.run_root = run_root
        self.calls = calls
        self.stdout_bytes = stdout
        self.exit_code = exit_code

    def _stdout(self, tool_id: str) -> bytes:
        if isinstance(self.stdout_bytes, dict):
            return self.stdout_bytes.get(tool_id, b"{}")
        return self.stdout_bytes

    def resolve_image(self, tool):
        return DIGEST

    def execute(self, request):
        self.calls.append((request.tool_id, request.argv))
        raw = request.scratch_root / "raw"
        raw.mkdir(parents=True, exist_ok=True)
        stdout, stderr = raw / "stdout.bin", raw / "stderr.bin"
        stdout.write_bytes(self._stdout(request.tool_id))
        stderr.write_bytes(b"")
        receipt = request.scratch_root / "execution.json"
        receipt.write_text("{}", encoding="utf-8")
        relative = lambda path: path.relative_to(self.run_root).as_posix()
        return ExecutionResult(
            "appsec-review/container-execution/1", request.tool_id, "fixture:1", DIGEST, DIGEST,
            "argv", (), {"network": "none", "target_mount": "read-only"}, "start", "end",
            self.exit_code, False, False, False, False, relative(stdout), relative(stderr), relative(receipt),
        )
