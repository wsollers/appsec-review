"""Local TLS inputs and declared run-owned work paths for the feed boundaries."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
from pathlib import Path
import ssl
import threading
from urllib.parse import urlsplit
import zipfile

from appsec_review.jobs.job_third_party_data_sync.datasets import DATASETS
from appsec_review.jobs.job_third_party_data_sync.job import build_job
from appsec_review.jobs.job_third_party_data_sync.publication import HttpDownloader
from appsec_review.indexing.inventory import compile_glob


ROOT = Path(__file__).resolve().parents[3]
TLS = ROOT / "tests/fixtures/acceptance_feeds"
JOB_ID = "job_third_party_data_sync"


@dataclass(frozen=True)
class Response:
    body: bytes
    status: int = 200
    headers: tuple[tuple[str, str], ...] = ()


@contextmanager
def https_server(routes, monkeypatch):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = urlsplit(self.path).path
            requests.append((self.path, dict(self.headers), self.connection.version()))
            response = routes[path]
            if callable(response):
                response = response(self)
            self.send_response(response.status)
            headers = dict(response.headers)
            self.send_header("Content-Length", headers.pop("Content-Length", str(len(response.body))))
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(response.body)
            self.close_connection = True

        def log_message(self, *_args):
            pass

    class Server(ThreadingHTTPServer):
        daemon_threads = False

        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(2)
            return connection, address

    server = Server(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(TLS / "localhost.crt.pem", TLS / "localhost.test-key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    monkeypatch.setenv("SSL_CERT_FILE", str(TLS / "localhost.crt.pem"))
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    worker.start()
    try:
        assert worker.is_alive()
        yield f"https://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
        assert not worker.is_alive(), "owned TLS fixture did not stop"


class LoopbackDownloader(HttpDownloader):
    """Map fixed upstream endpoints to the fixture server, keeping the real HTTP transport."""

    def __init__(self, base: str):
        super().__init__(timeout_seconds=2, allow_redirects=False)
        self.base = base

    def download(self, url, destination, *, max_bytes, allowed_hosts):
        parsed = urlsplit(url)
        assert parsed.scheme == "https" and parsed.hostname in allowed_hosts
        return super().download(self.base + parsed.path, destination, max_bytes=max_bytes,
                                allowed_hosts=("127.0.0.1",))


def zip_bytes(name: str, body: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0)), body)
    return output.getvalue()


def work_path(run_root: Path, unit_id: str) -> Path:
    step, task = unit_id.split(".")
    return run_root / f"data/jobs/{JOB_ID}/attempts/attempt_0001/steps/{step}/tasks/{task}/work"


def assert_work_contract(run_root: Path, unit_id: str, result: dict) -> None:
    unit = next(unit for unit in build_job().units if unit.unit_id == unit_id)
    for validate in unit.output_validators:
        validate(None, result)
    work = work_path(run_root, unit_id)
    paths = sorted(path for path in work.rglob("*") if path.is_file())
    assert paths, f"{unit_id} produced no boundary artifacts"
    dataset, = DATASETS
    assert dataset.output_kind == "feed_sync_work"
    assert dataset.schema == "appsec-review/job-result/third-party-data-sync/1"
    for path in paths:
        relative = path.relative_to(run_root).as_posix()
        assert any(compile_glob(pattern).fullmatch(relative) for pattern in dataset.artifacts), relative
