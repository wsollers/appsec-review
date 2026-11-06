"""Manual-only loopback GraphQL interoperability; not part of the offline unit gate.

Run explicitly with the Dagster optional dependencies installed. These tests start only
an owned loopback fixture, never a real review or Dagster deployment.
"""
from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import threading
from types import SimpleNamespace

import pytest

from appsec_review.mcp.dagster import DagsterReader, RUN_STATE_QUERY


APPLICATION_ID = "2026-11-06-0001"
DISPATCH_ID = "e8321e18-38a9-4d41-a456-df451c4d4827"
TLS = Path(__file__).resolve().parents[1] / "fixtures" / "acceptance_feeds"


def _document(application_id=APPLICATION_ID):
    return {"data": {"runOrError": {
        "__typename": "Run", "runId": DISPATCH_ID, "status": "FAILURE",
        "tags": [{"key": "appsec/application_run_id", "value": application_id},
                 {"key": "private", "value": "must-not-escape"}],
        "stats": {"__typename": "RunStatsSnapshot", "stepsSucceeded": 2, "stepsFailed": 1},
    }}}


@contextmanager
def _service(*, tls=False):
    state = SimpleNamespace(document=_document(), status=200, requests=[], errors=[], redirect=None)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                state.errors.append("unbounded request")
                self.send_error(400)
                return
            request = json.loads(self.rfile.read(length))
            state.requests.append((self.path, request))
            if self.path != "/graphql" or request != {
                    "operationName": "OperatorRunState", "query": RUN_STATE_QUERY,
                    "variables": {"dispatchId": DISPATCH_ID}}:
                state.errors.append("operation outside the fixed read allowlist")
                self.send_error(403)
                return
            body = json.dumps(state.document).encode()
            self.send_response(state.status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            if state.redirect is not None:
                self.send_header("Location", state.redirect)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            state.errors.append("unexpected GET")
            self.send_error(405)

        def log_message(self, *_args):
            pass

    class Server(ThreadingHTTPServer):
        daemon_threads = False

        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(2)
            return connection, address

    server = Server(("127.0.0.1", 0), Handler)
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(TLS / "localhost.crt.pem", TLS / "localhost.test-key.pem")
        server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02},
                              name="operator-dagster-integration", daemon=True)
    worker.start()
    try:
        assert worker.is_alive()
        scheme = "https" if tls else "http"
        yield f"{scheme}://127.0.0.1:{server.server_port}/graphql", state
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
        assert not worker.is_alive(), "owned GraphQL fixture did not stop"


@pytest.mark.parametrize("tls", [False, True])
def test_real_transport_executes_only_bound_read_and_ignores_proxy_environment(monkeypatch, tls):
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(key, "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    if tls:
        monkeypatch.setenv("SSL_CERT_FILE", str(TLS / "localhost.crt.pem"))
    with _service(tls=tls) as (endpoint, service):
        if tls:
            endpoint = endpoint.replace("127.0.0.1", "localhost")
        result = DagsterReader(endpoint, APPLICATION_ID).inspect(DISPATCH_ID)
        assert result["application_run_id"] == APPLICATION_ID
        assert result["dagster_dispatch_id"] == DISPATCH_ID
        assert result["availability"] == "available" and result["status"] == "FAILURE"
        assert result["step_counts"] == {"succeeded": 2, "failed": 1}
        assert result["gaps"] == []
        assert "must-not-escape" not in json.dumps(result)
        assert len(service.requests) == 1 and service.errors == []


def test_real_transport_rejects_cross_application_dispatch():
    with _service() as (endpoint, service):
        service.document = _document("2026-11-06-0002")
        with pytest.raises(ValueError, match="application identity"):
            DagsterReader(endpoint, APPLICATION_ID).inspect(DISPATCH_ID)
        assert len(service.requests) == 1 and service.errors == []


def test_real_transport_preserves_missing_dispatch_gap():
    with _service() as (endpoint, service):
        service.document = {"data": {"runOrError": {"__typename": "RunNotFoundError"}}}
        result = DagsterReader(endpoint, APPLICATION_ID).inspect(DISPATCH_ID)
        assert result["availability"] == "missing"
        assert result["gaps"] == ["dagster_dispatch_missing"]
        assert result["status"] is None and result["step_counts"] is None


def test_real_transport_never_follows_redirect_to_another_operation():
    with _service() as (endpoint, service):
        service.status = 307
        service.redirect = endpoint.replace("/graphql", "/mutation")
        with pytest.raises(RuntimeError, match="unavailable"):
            DagsterReader(endpoint, APPLICATION_ID).inspect(DISPATCH_ID)
        assert len(service.requests) == 1 and service.errors == []


def test_fixed_read_operation_matches_the_installed_dagster_graphql_schema():
    from dagster_graphql.schema import create_schema
    from graphql import parse, validate

    document = parse(RUN_STATE_QUERY)
    assert len(document.definitions) == 1
    assert document.definitions[0].operation.value == "query"
    assert validate(create_schema().graphql_schema, document) == []
