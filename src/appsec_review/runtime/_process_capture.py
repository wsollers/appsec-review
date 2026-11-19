"""Incremental pipe draining for local Linux CLI execution."""
from __future__ import annotations

import os
import selectors
import subprocess
import time


class PipeCapture:
    """Retain a prefix plus one overflow byte, without blocking either output pipe."""

    def __init__(self, process: subprocess.Popen, output_bytes: int | None):
        if output_bytes is not None and (type(output_bytes) is not int or output_bytes < 0):
            raise ValueError("output byte limit must be a nonnegative integer")
        self.process = process
        self.limit = None if output_bytes is None else output_bytes + 1
        self.buffers = (bytearray(), bytearray())
        self.selector = selectors.DefaultSelector()
        try:
            for stream, buffer in zip((process.stdout, process.stderr), self.buffers):
                if stream is not None:
                    self.selector.register(stream, selectors.EVENT_READ, buffer)
        except BaseException:
            self.close()
            raise

    def wait(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while self.selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(self.process.args, timeout)
            for key, _ in self.selector.select(remaining):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    self.selector.unregister(key.fileobj)
                    continue
                buffer = key.data
                if self.limit is None:
                    buffer.extend(chunk)
                else:
                    buffer.extend(chunk[:max(0, self.limit - len(buffer))])
        self.process.wait(timeout=max(0, deadline - time.monotonic()))

    def output(self) -> tuple[bytes, bytes]:
        return bytes(self.buffers[0]), bytes(self.buffers[1])

    def close(self) -> None:
        self.selector.close()
