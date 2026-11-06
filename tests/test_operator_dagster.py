"""Offline Dagster authorization/serialization tests; only network boundaries are faked."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import inspect
import json
import socket
import ssl
import threading
import time

import pytest

from appsec_review.mcp import dagster


APPLICATION_ID = "2026-11-06-0001"
DISPATCH_ID = "e8321e18-38a9-4d41-a456-df451c4d4827"
OTHER_DISPATCH_ID = "e8321e18-38a9-4d41-a456-df451c4d4828"
ENDPOINT = "http://127.0.0.1:3000/graphql"
SECRET = "sensitive-auth-token-and-raw-trace"


def _run():
    return {
        "__typename": "Run", "runId": DISPATCH_ID, "status": "FAILURE",
        "tags": [{"key": "appsec/application_run_id", "value": APPLICATION_ID},
                 {"key": "private/token", "value": SECRET}],
        "stats": {"__typename": "RunStatsSnapshot", "stepsSucceeded": 4, "stepsFailed": 1},
    }


def _document(run=None):
    return {"data": {"runOrError": _run() if run is None else run}}


class _Socket:
    def __init__(self):
        self.timeouts = []
        self.shutdowns = []
        self.closed = False
        self.address = None

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def shutdown(self, how):
        self.shutdowns.append(how)

    def connect(self, address):
        self.address = address

    def close(self):
        self.closed = True


class _Response:
    def __init__(self, document=None, *, body=None, status=200, headers=None):
        self.body = (json.dumps(_document() if document is None else document).encode()
                     if body is None else body)
        self.status = status
        self.headers = ([("Content-Type", "application/json"),
                         ("Content-Length", str(len(self.body)))] if headers is None else headers)
        self.offset = 0
        self.read_sizes = []
        self.closed = False
        self.read_error = None

    def getheaders(self):
        return self.headers

    def read1(self, size):
        self.read_sizes.append(size)
        if self.read_error is not None:
            raise self.read_error
        data = self.body[self.offset:self.offset + size]
        self.offset += len(data)
        return data

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True


@pytest.fixture
def network(monkeypatch):
    class Network:
        def __init__(self):
            self.connections = []
            self.requests = []
            self.response = _Response()
            self.connect_error = None
            self.request_error = None

        def factory(self, protocol):
            owner = self

            class Connection:
                def __init__(self, host, port, *, timeout, context=None):
                    self.host, self.port = host, port
                    self.timeout, self.context = timeout, context
                    self.protocol = protocol
                    self.sock = None
                    self.closed = False
                    owner.connections.append(self)

                def connect(self):
                    if owner.connect_error is not None:
                        raise owner.connect_error
                    self.sock = _Socket()

                def request(self, method, path, *, body, headers):
                    if owner.request_error is not None:
                        raise owner.request_error
                    owner.requests.append((method, path, json.loads(body), headers))

                def getresponse(self):
                    return owner.response

                def close(self):
                    self.closed = True

            return Connection

    transport = Network()
    monkeypatch.setattr(dagster.http.client, "HTTPConnection", transport.factory("http"))
    monkeypatch.setattr(dagster.http.client, "HTTPSConnection", transport.factory("https"))
    return transport


def test_exact_application_and_dispatch_binding_with_sanitized_projection(network):
    reader = dagster.DagsterReader(ENDPOINT, APPLICATION_ID)
    assert not network.connections, "startup configuration must not contact a service"
    assert reader.inspect(DISPATCH_ID) == {
        "schema": "appsec-review/operator-dagster-state/1",
        "application_run_id": APPLICATION_ID, "dagster_dispatch_id": DISPATCH_ID,
        "availability": "available", "status": "FAILURE",
        "step_counts": {"succeeded": 4, "failed": 1}, "gaps": [],
    }
    method, path, body, headers = network.requests[0]
    assert method == "POST" and path == "/graphql"
    assert set(body) == {"query", "operationName", "variables"}
    assert body["operationName"] == "OperatorRunState"
    assert body["variables"] == {"dispatchId": DISPATCH_ID}
    assert body["query"] == dagster.RUN_STATE_QUERY
    assert body["query"].startswith("query OperatorRunState($dispatchId: ID!)")
    assert "runOrError(runId: $dispatchId)" in body["query"]
    assert "stepsSucceeded stepsFailed" in body["query"]
    assert all(word not in body["query"] for word in (
        "mutation", "subscription", "runConfig", "logs", "message", "stack", "terminate"))
    assert headers["Accept-Encoding"] == "identity"
    assert "Authorization" not in headers and "Cookie" not in headers
    assert network.connections[0].timeout == dagster.REQUEST_TIMEOUT_SECONDS
    assert 0 < network.connections[0].sock.timeouts[0] <= dagster.REQUEST_TIMEOUT_SECONDS
    assert network.connections[0].closed and network.response.closed


@pytest.mark.parametrize(("endpoint", "protocol", "host", "port"), [
    ("http://127.0.0.1:3000/graphql", "http", "127.0.0.1", 3000),
    ("http://localhost/graphql", "http", "127.0.0.1", 80),
    ("http://127.5.6.7/graphql", "http", "127.5.6.7", 80),
    ("http://[::1]:3000/graphql", "http", "::1", 3000),
    ("https://dagster.example/graphql", "https", "dagster.example", 443),
    ("https://dagster.example:8443/graphql", "https", "dagster.example", 8443),
    ("https://[2001:db8::1]/graphql", "https", "2001:db8::1", 443),
])
def test_only_explicit_canonical_endpoints_are_contacted(network, endpoint, protocol, host, port):
    dagster.DagsterReader(endpoint, APPLICATION_ID).inspect(DISPATCH_ID)
    connection = network.connections[0]
    assert (connection.protocol, connection.host, connection.port) == (protocol, host, port)
    if protocol == "https":
        assert connection.context.verify_mode == ssl.CERT_REQUIRED
        assert connection.context.check_hostname is True


@pytest.mark.parametrize("endpoint", [
    None, "", False, "graphql", "/graphql", "//127.0.0.1/graphql",
    "ftp://127.0.0.1/graphql", "file:///graphql", "ws://127.0.0.1/graphql",
    "http://dagster.example/graphql", "http://192.168.1.1/graphql",
    "http://169.254.169.254/graphql", "http://0.0.0.0/graphql",
    "http://127.1/graphql", "http://2130706433/graphql", "http://0177.0.0.1/graphql",
    "http://[::ffff:127.0.0.1]/graphql", "http://[::ffff:7f00:1]/graphql",
    "https://[::ffff:127.0.0.1]/graphql", "https://[::ffff:7f00:1]/graphql",
    "http://[::ffff:192.0.2.1]/graphql", "http://localhost.example/graphql",
    "https://user:password@dagster.example/graphql",
    "https://user@dagster.example/graphql", "https://dagster.example/graphql?query=mutation",
    "https://dagster.example/graphql?", "https://dagster.example/graphql#",
    "https://dagster.example/graphql#fragment", "https://dagster.example/gr%61phql",
    "https://dagster.example\\evil/graphql", "https://dagster.example//graphql",
    "https://dagster.example/a/../graphql", "https://dagster.example/graphql/",
    "https://dagster.example/", "https://dagster.example", "https://dagster.example:0/graphql",
    "https://dagster.example:65536/graphql", "https://dagster.example:bad/graphql",
    "https://dagster.example:0443/graphql", "https://dagster.example:/graphql",
    "HTTPS://dagster.example/graphql", "https://DAGSTER.example/graphql",
    "https://dagster.example./graphql", "https://-dagster.example/graphql",
    "https://[0:0:0:0:0:0:0:1]/graphql", "http://[::1%25eth0]/graphql",
    "https://dagster.example/\ngraphql", " https://dagster.example/graphql",
    "https://dagster.example/graphql ", "https://dägster.example/graphql",
])
def test_endpoint_authorization_is_not_faked(network, endpoint):
    with pytest.raises(ValueError):
        dagster.DagsterReader(endpoint, APPLICATION_ID)
    assert network.connections == [] and network.requests == []


@pytest.mark.parametrize("application_id", [
    None, "", False, 123, DISPATCH_ID, "latest", "../2026-11-06-0001",
    "2026-11-06-0001\n", "２０２６-11-06-0001", "2026-11-06-1",
])
def test_application_id_is_explicit_and_separate_from_dispatch_uuid(network, application_id):
    with pytest.raises(ValueError, match="explicit application run ID"):
        dagster.DagsterReader(ENDPOINT, application_id)
    assert network.connections == []


@pytest.mark.parametrize("dispatch_id", [
    None, "", False, 123, APPLICATION_ID, DISPATCH_ID.upper(),
    DISPATCH_ID.replace("-", ""), "{" + DISPATCH_ID + "}", DISPATCH_ID + "\n",
    "00000000-0000-0000-0000-not-a-uuid!!",
])
def test_invalid_dispatch_ids_never_reach_the_network(network, dispatch_id):
    with pytest.raises(ValueError, match="dispatch ID"):
        dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(dispatch_id)
    assert network.connections == []


def test_no_query_url_or_mutation_parameters_and_startup_scope_is_immutable(network):
    reader = dagster.DagsterReader(ENDPOINT, APPLICATION_ID)
    assert set(inspect.signature(dagster.DagsterReader.inspect).parameters) == {
        "self", "dispatch_id"}
    for field, value in (("endpoint", "https://other.example/graphql"),
                         ("application_run_id", "2026-11-06-0002")):
        with pytest.raises(FrozenInstanceError):
            setattr(reader, field, value)
    with pytest.raises(TypeError):
        reader.inspect(DISPATCH_ID, query="mutation { terminateRun }")
    with pytest.raises(TypeError):
        reader.inspect(DISPATCH_ID, endpoint="https://other.example/graphql")
    assert network.requests == []


@pytest.mark.parametrize("environment", ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                                          "http_proxy", "https_proxy", "all_proxy"])
def test_environment_proxies_cannot_change_the_destination(network, monkeypatch, environment):
    monkeypatch.setenv(environment, "http://credentials:secret@proxy.example:8888")
    dagster.DagsterReader("https://dagster.example/graphql", APPLICATION_ID).inspect(DISPATCH_ID)
    assert len(network.connections) == 1
    assert network.connections[0].host == "dagster.example"
    assert network.connections[0].port == 443


@pytest.mark.parametrize("status", sorted(dagster._RUN_STATUSES))
def test_closed_known_run_statuses(network, status):
    run = _run()
    run["status"] = status
    network.response = _Response(_document(run))
    result = dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)
    assert result["status"] == status and result["availability"] == "available"


@pytest.mark.parametrize(("run", "availability", "gap"), [
    ({"__typename": "RunNotFoundError"}, "missing", "dagster_dispatch_missing"),
    ({"__typename": "FutureRunResult"}, "unsupported", "dagster_response_type_unsupported"),
])
def test_missing_and_unsupported_are_not_empty_success(network, run, availability, gap):
    network.response = _Response(_document(run))
    result = dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)
    assert result["availability"] == availability and result["gaps"] == [gap]
    assert result["status"] is None and result["step_counts"] is None
    assert result["application_run_id"] == APPLICATION_ID
    assert result["dagster_dispatch_id"] == DISPATCH_ID


@pytest.mark.parametrize(("kind", "gap"), [
    ("PythonError", "dagster_step_counts_unavailable"),
    ("FutureStats", "dagster_step_counts_unsupported"),
])
def test_unavailable_statistics_are_not_zero_counts(network, kind, gap):
    run = _run()
    run["stats"] = {"__typename": kind}
    network.response = _Response(_document(run))
    result = dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)
    assert result["availability"] == "available" and result["status"] == "FAILURE"
    assert result["step_counts"] is None and result["gaps"] == [gap]


def test_unknown_status_is_explicit_without_returning_untrusted_enum(network):
    run = _run()
    run["status"] = "FUTURE_STATUS"
    network.response = _Response(_document(run))
    result = dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)
    assert result["availability"] == "unsupported"
    assert result["gaps"] == ["dagster_status_unsupported"]
    assert result["status"] is None and result["step_counts"] is None
    assert "FUTURE_STATUS" not in json.dumps(result)


@pytest.mark.parametrize("change", [
    lambda run: run.update(runId=OTHER_DISPATCH_ID),
    lambda run: run.update(runId=DISPATCH_ID.upper()),
    lambda run: run.update(runId=APPLICATION_ID),
    lambda run: run.update(runId=None),
    lambda run: run.update(tags=[]),
    lambda run: run["tags"][0].update(value="2026-11-06-0002"),
    lambda run: run["tags"][0].update(value=APPLICATION_ID + "\n"),
    lambda run: run["tags"][0].update(key="appsec/run_id"),
    lambda run: run["tags"].append(dict(run["tags"][0])),
    lambda run: run["tags"].append({"key": "appsec/application_run_id", "value": SECRET}),
])
def test_identity_mismatch_unbound_dispatch_and_duplicate_tags_fail_closed(network, change):
    run = _run()
    change(run)
    network.response = _Response(_document(run))
    with pytest.raises(ValueError) as error:
        dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)
    assert SECRET not in str(error.value)
    assert network.connections[0].closed and network.response.closed


def test_unsupported_status_does_not_bypass_application_authorization(network):
    run = _run()
    run.update(status="FUTURE_STATUS", tags=[])
    network.response = _Response(_document(run))
    with pytest.raises(ValueError, match="application identity"):
        dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)


@pytest.mark.parametrize("change", [
    lambda run: run.update(message=SECRET),
    lambda run: run.pop("stats"),
    lambda run: run.update(tags=None),
    lambda run: run.update(tags={"appsec/application_run_id": APPLICATION_ID}),
    lambda run: run["tags"][0].update(extra=SECRET),
    lambda run: run["tags"][0].update(key=False),
    lambda run: run["tags"][0].update(value=False),
    lambda run: run["tags"].append({"key": "x", "value": "x" * (dagster.MAX_TAG_VALUE_LENGTH + 1)}),
    lambda run: run["tags"].append({"key": "x" * (dagster.MAX_TAG_KEY_LENGTH + 1), "value": ""}),
    lambda run: run.update(tags=[{"key": str(i), "value": ""} for i in range(dagster.MAX_TAGS + 1)]),
    lambda run: run.update(status=SECRET),
    lambda run: run.update(status=None),
    lambda run: run.update(stats=None),
    lambda run: run["stats"].update(stack=SECRET),
    lambda run: run["stats"].update(stepsSucceeded=True),
    lambda run: run["stats"].update(stepsFailed=-1),
    lambda run: run["stats"].update(stepsFailed=1.0),
    lambda run: run["stats"].update(stepsFailed="1"),
    lambda run: run["stats"].update(stepsFailed=dagster.MAX_STEP_COUNT + 1),
    lambda run: run.update(stats={"__typename": "PythonError", "message": SECRET}),
])
def test_closed_response_schema_rejects_extra_or_invalid_metadata(network, change):
    run = _run()
    change(run)
    network.response = _Response(_document(run))
    with pytest.raises(ValueError) as error:
        dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)
    assert SECRET not in str(error.value)


@pytest.mark.parametrize("body", [
    b"null", b"[]", b"false", b"{}", b'{"data": null}', b'{"data": []}',
    b'{"data": {"runOrError": null}}', b'{"data": {"runOrError": []}}',
    b'{"data": {"runOrError": {"__typename": false}}}',
    b'{"data": {"runOrError": {"__typename": "RunNotFoundError", "message": "secret"}}}',
    b'{"data": {"runOrError": {"__typename": "RunNotFoundError"}}, "extensions": {}}',
    b'{"data": {"runOrError": {"__typename": "RunNotFoundError"}, "other": {}}}',
    b'{"data": {"runOrError": {"__typename": "RunNotFoundError"}}, "data": null}',
    b'{"data": {"runOrError": {"__typename": "RunNotFoundError", "__typename": "Run"}}}',
    b'{"data": NaN}', b'{"data": Infinity}', b'{"data": -Infinity}',
    b'{"data": "\xff"}', b'{"data":', b"\xef\xbb\xbf{}",
    b"[" * 1500 + b"]" * 1500,
])
def test_malformed_json_and_open_envelopes_are_not_accepted(network, body):
    network.response = _Response(body=body)
    with pytest.raises(ValueError):
        dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)


@pytest.mark.parametrize("document", [
    {"data": {"runOrError": {"__typename": "PythonError"}}},
    {"errors": [{"message": SECRET}]},
    {"data": None, "errors": [{"message": SECRET, "locations": [{"line": 1, "column": 2}]}]},
    {**_document(), "errors": [{"message": SECRET, "path": ["runOrError", "stats"]}]},
])
def test_unavailable_graphql_never_returns_raw_errors_or_partial_state(network, document):
    network.response = _Response(document)
    with pytest.raises(RuntimeError, match="unavailable") as error:
        dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)
    assert SECRET not in str(error.value)


@pytest.mark.parametrize("errors", [
    [], {}, None, [None], [{"message": 7}], [{"message": SECRET, "stack": SECRET}],
    [{"message": SECRET, "extensions": {"secret": SECRET}}],
    [{"message": "x" * 8193}], [{"message": SECRET}] * 33,
    [{"message": SECRET, "locations": [{"line": True, "column": 1}]}],
    [{"message": SECRET, "locations": {}}],
    [{"message": SECRET, "path": ["runOrError", -1]}],
    [{"message": SECRET, "path": [False]}],
])
def test_graphql_errors_also_have_a_closed_schema(network, errors):
    network.response = _Response({"errors": errors})
    with pytest.raises(ValueError) as error:
        dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)
    assert SECRET not in str(error.value)


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308, 400, 401, 403, 404, 500, 503])
def test_http_errors_and_redirects_are_never_followed(network, status):
    network.response = _Response(status=status, headers=[
        ("Location", "https://other.example/graphql"), ("Content-Type", "text/html")],
        body=SECRET.encode())
    with pytest.raises(RuntimeError, match="unavailable") as error:
        dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)
    assert SECRET not in str(error.value)
    assert len(network.connections) == 1 and len(network.requests) == 1
    assert network.response.read_sizes == []
    assert network.connections[0].closed and network.response.closed


@pytest.mark.parametrize("headers", [
    [], [("Content-Type", "text/html")],
    [("Content-Type", "application/json; charset=latin1")],
    [("Content-Type", "application/json"), ("content-type", "application/json")],
    [("Content-Type", "application/json"), ("Content-Encoding", "gzip")],
    [("Content-Type", "application/json"), ("Content-Length", "-1")],
    [("Content-Type", "application/json"), ("Content-Length", "01")],
    [("Content-Type", "application/json"), ("Content-Length", "1.0")],
    [("Content-Type", "application/json"), ("Content-Length", "9" * 200)],
    [("Content-Type", "application/json"), ("Content-Length", "2"), ("content-length", "2")],
    [("Content-Type", "application/json"), ("Transfer-Encoding", "gzip")],
    [("Content-Type", "application/json"), ("Transfer-Encoding", "chunked"), ("Content-Length", "2")],
    [("Content-Type", "application/json"), ("X-Large", "x" * dagster.MAX_HEADER_BYTES)],
])
def test_ambiguous_or_unsupported_transport_metadata_is_rejected(network, headers):
    network.response = _Response(headers=headers)
    with pytest.raises(ValueError):
        dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)
    assert network.response.read_sizes == []


@pytest.mark.parametrize("content_type", [
    "application/json", "application/json; charset=utf-8",
    "application/graphql-response+json", "application/graphql-response+json; charset=utf-8",
])
def test_utf8_json_mime_types_and_headerless_length_are_supported(network, content_type):
    network.response = _Response(headers=[("Content-Type", content_type)])
    assert dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)["status"] == "FAILURE"


def test_chunked_transport_is_supported_without_content_length(network):
    network.response = _Response(headers=[
        ("Content-Type", "application/json"), ("Transfer-Encoding", "chunked")])
    assert dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)["status"] == "FAILURE"


def test_declared_oversize_is_rejected_without_reading_the_body(network):
    network.response = _Response(headers=[
        ("Content-Type", "application/json"), ("Content-Length", str(dagster.MAX_RESPONSE_BYTES + 1))])
    with pytest.raises(ValueError, match="bound"):
        dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)
    assert network.response.read_sizes == []


def test_headerless_stream_is_read_only_to_the_byte_bound_plus_one(network):
    network.response = _Response(body=b"x" * (dagster.MAX_RESPONSE_BYTES + 100),
                                 headers=[("Content-Type", "application/json")])
    with pytest.raises(ValueError, match="byte bound"):
        dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)
    assert network.response.offset == dagster.MAX_RESPONSE_BYTES + 1
    assert all(0 < size <= 16 * 1024 for size in network.response.read_sizes)


def test_valid_json_prefix_cannot_hide_a_truncated_response(network):
    network.response.headers[-1] = ("Content-Length", str(len(network.response.body) + 1))
    with pytest.raises(ValueError, match="does not match"):
        dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)


@pytest.mark.parametrize("boundary", ["connect_error", "request_error", "read_error"])
def test_network_failures_are_predictable_sanitized_and_close_connections(network, boundary):
    failure = OSError(SECRET)
    if boundary == "read_error":
        network.response.read_error = failure
    else:
        setattr(network, boundary, failure)
    with pytest.raises(RuntimeError, match="unavailable") as error:
        dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)
    assert SECRET not in str(error.value)
    assert network.connections[0].closed


def test_expired_deadline_is_not_reset_by_a_slow_stream(network, monkeypatch):
    now = [10.0]
    monkeypatch.setattr(dagster.time, "monotonic", lambda: now[0])
    original_read = network.response.read1

    def slow_read(size):
        now[0] += dagster.REQUEST_TIMEOUT_SECONDS + 1
        return original_read(size)

    network.response.read1 = slow_read
    with pytest.raises(RuntimeError, match="unavailable"):
        dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)
    assert network.connections[0].closed and network.response.closed


def test_socket_abort_shuts_down_blocking_reads():
    connection = _Socket()
    dagster._abort_socket(connection)
    assert connection.shutdowns == [socket.SHUT_RDWR]


def test_literal_loopback_does_not_consult_dns(monkeypatch):
    def unexpected_dns(*_args, **_kwargs):
        pytest.fail("literal endpoint must not use a resolver")

    connection = _Socket()
    monkeypatch.setattr(dagster.socket, "getaddrinfo", unexpected_dns)
    monkeypatch.setattr(dagster.socket, "socket", lambda *_args: connection)
    assert dagster._connect_socket("127.0.0.1", 3000, time.monotonic() + 5) is connection
    assert connection.address == ("127.0.0.1", 3000)
    assert len(connection.timeouts) == 2 and all(0 < value <= 5 for value in connection.timeouts)


def test_configured_hostname_resolution_is_bounded_and_connection_uses_resolved_address(monkeypatch):
    calls = []

    def resolve(host, port, *, type):
        calls.append((host, port, type))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", port))]

    connection = _Socket()
    monkeypatch.setattr(dagster.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(dagster.socket, "socket", lambda *_args: connection)
    assert dagster._connect_socket("dagster.example", 443, time.monotonic() + 5) is connection
    assert calls == [("dagster.example", 443, socket.SOCK_STREAM)]
    assert connection.address == ("192.0.2.1", 443)


def test_dns_failure_is_sanitized_without_opening_a_socket(monkeypatch):
    def resolve(*_args, **_kwargs):
        raise OSError(SECRET)

    def unexpected_socket(*_args):
        pytest.fail("failed DNS must not open a socket")

    monkeypatch.setattr(dagster.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(dagster.socket, "socket", unexpected_socket)
    with pytest.raises(RuntimeError, match="name resolution is unavailable") as error:
        dagster._connect_socket("dagster.example", 443, time.monotonic() + 5)
    assert SECRET not in str(error.value)


def test_blocked_dns_has_a_deadline_and_cannot_create_unbounded_workers(monkeypatch):
    release = threading.Event()
    finished = threading.Event()
    calls = []

    def resolve(*_args, **_kwargs):
        calls.append(1)
        try:
            release.wait(2)
            return []
        finally:
            finished.set()

    monkeypatch.setattr(dagster.socket, "getaddrinfo", resolve)
    try:
        with pytest.raises(TimeoutError):
            dagster._addresses("dagster.example", 443, time.monotonic() + 0.02)
        with pytest.raises(RuntimeError, match="name resolution is unavailable"):
            dagster._addresses("dagster.example", 443, time.monotonic() + 5)
        assert len(calls) <= 1
    finally:
        release.set()
        assert finished.wait(2), "fake resolver did not finish"
        assert dagster._DNS_SLOT.acquire(timeout=2), "resolver slot was not released"
        dagster._DNS_SLOT.release()


def test_endpoint_connection_callback_cannot_select_another_host(network, monkeypatch):
    dagster.DagsterReader(ENDPOINT, APPLICATION_ID).inspect(DISPATCH_ID)
    calls = []

    def connect(host, port, deadline):
        calls.append((host, port, deadline))
        return "socket-boundary"

    monkeypatch.setattr(dagster, "_connect_socket", connect)
    assert network.connections[0]._create_connection(
        ("other.example", 444), 999, None) == "socket-boundary"
    assert calls[0][:2] == ("127.0.0.1", 3000)
