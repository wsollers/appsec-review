"""One read-only Dagster operation, bound to an explicitly selected application run.

Live dispatch state is not accepted application evidence. The operator adapter owns
accepted-manifest admission; this reader verifies the dispatch UUID and the application
tag written by both the Dagster adapter and the native launcher before returning state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID


SCHEMA = "appsec-review/operator-dagster-state/1"
APPLICATION_RUN_TAG = "appsec/application_run_id"
REQUEST_TIMEOUT_SECONDS = 5.0
MAX_RESPONSE_BYTES = 256 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_TAGS = 128
MAX_TAG_KEY_LENGTH = 256
MAX_TAG_VALUE_LENGTH = 4096
MAX_STEP_COUNT = 2**31 - 1
MAX_ENDPOINT_ADDRESSES = 16
OPERATION_NAME = "OperatorRunState"
RUN_STATE_QUERY = """query OperatorRunState($dispatchId: ID!) {
  runOrError(runId: $dispatchId) {
    __typename
    ... on Run {
      runId
      status
      tags { key value }
      stats {
        __typename
        ... on RunStatsSnapshot { stepsSucceeded stepsFailed }
      }
    }
  }
}"""

_APPLICATION_ID = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4}")
_GRAPHQL_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]{0,127}")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_RUN_STATUSES = frozenset({
    "QUEUED", "NOT_STARTED", "MANAGED", "STARTING", "STARTED",
    "SUCCESS", "FAILURE", "CANCELING", "CANCELED",
})
_DNS_SLOT = threading.BoundedSemaphore(1)


@dataclass(frozen=True)
class _Endpoint:
    scheme: str
    host: str
    port: int


def _endpoint(value: str) -> _Endpoint:
    error = "Dagster endpoint must be a canonical trusted HTTP(S) /graphql URL"
    if (not isinstance(value, str) or not value or len(value) > 2048
            or any(ord(char) <= 32 or ord(char) >= 127 for char in value)
            or any(char in value for char in ("\\", "%", "?", "#", "@"))):
        raise ValueError(error)
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ValueError(error) from None
    if (parsed.scheme not in {"http", "https"} or not host
            or parsed.path != "/graphql" or parsed.query or parsed.fragment):
        raise ValueError(error)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
        if (len(host) > 253 or not all(_DNS_LABEL.fullmatch(part) for part in host.split("."))
                or re.fullmatch(r"[0-9.]+", host)):
            raise ValueError(error) from None
    # Mapped-address canonicalization and loopback classification differ between Python versions.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        raise ValueError("IPv4-mapped IPv6 Dagster endpoints are not supported")
    canonical_host = f"[{address.compressed}]" if address and address.version == 6 else host
    if address and address.version == 4 and str(address) != host:
        raise ValueError(error)
    authority = canonical_host + (f":{port}" if port is not None else "")
    if (value != f"{parsed.scheme}://{authority}/graphql"
            or port is not None and not 1 <= port <= 65535):
        raise ValueError(error)
    if parsed.scheme == "http":
        if host == "localhost":
            # Do not let hosts-file or DNS configuration turn plaintext localhost into a remote peer.
            host = "127.0.0.1"
        elif address is None or not address.is_loopback:
            raise ValueError("plaintext Dagster endpoints must use a loopback address")
    return _Endpoint(parsed.scheme, host, port if port is not None else (
        443 if parsed.scheme == "https" else 80))


def _dispatch_id(value: str) -> str:
    if not isinstance(value, str) or len(value) != 36:
        raise ValueError("Dagster dispatch ID must be a canonical UUID, not an application run ID")
    try:
        canonical = str(UUID(value))
    except ValueError:
        raise ValueError("Dagster dispatch ID must be a canonical UUID") from None
    if canonical != value:
        raise ValueError("Dagster dispatch ID must be a canonical UUID")
    return value


def _object(value: Any, keys: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise ValueError("Dagster response does not match the closed state schema")
    return value


def _typename(value: Any) -> str:
    if not isinstance(value, str) or not _GRAPHQL_NAME.fullmatch(value):
        raise ValueError("Dagster response has an invalid type discriminator")
    return value


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON member")
        value[key] = item
    return value


def _invalid_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _decode(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_json_object,
                           parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Dagster returned invalid JSON") from None
    if type(value) is not dict or set(value) not in ({"data"}, {"errors"}, {"data", "errors"}):
        raise ValueError("Dagster response does not match the closed state schema")
    if "errors" in value:
        errors = value["errors"]
        if type(errors) is not list or not 1 <= len(errors) <= 32:
            raise ValueError("Dagster returned invalid GraphQL errors")
        for error in errors:
            if (type(error) is not dict or "message" not in error
                    or set(error) - {"message", "locations", "path"}
                    or not isinstance(error["message"], str) or len(error["message"]) > 8192):
                raise ValueError("Dagster returned invalid GraphQL errors")
            if "locations" in error:
                if type(error["locations"]) is not list or len(error["locations"]) > 32:
                    raise ValueError("Dagster returned invalid GraphQL errors")
                for location in error["locations"]:
                    _object(location, {"line", "column"})
                    if any(type(item) is not int or not 1 <= item <= MAX_STEP_COUNT
                           for item in location.values()):
                        raise ValueError("Dagster returned invalid GraphQL errors")
            if "path" in error and (
                    type(error["path"]) is not list or len(error["path"]) > 32
                    or any(not (type(item) is int and 0 <= item <= MAX_STEP_COUNT
                                or isinstance(item, str) and _GRAPHQL_NAME.fullmatch(item))
                           for item in error["path"])):
                raise ValueError("Dagster returned invalid GraphQL errors")
        # Even partial GraphQL data is not admitted when the operation reports errors.
        raise RuntimeError("Dagster state query is unavailable or unsupported")
    return _object(value["data"], {"runOrError"})


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


def _abort_socket(connection_socket: socket.socket) -> None:
    try:
        connection_socket.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def _addresses(host: str, port: int, deadline: float) -> list[tuple[int, tuple]]:
    _remaining(deadline)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        return [(socket.AF_INET6, (host, port, 0, 0))] if address.version == 6 else [
            (socket.AF_INET, (host, port))]
    slot = _DNS_SLOT
    if not slot.acquire(blocking=False):
        raise RuntimeError("Dagster endpoint name resolution is unavailable")
    done = threading.Event()
    resolved: list[tuple[int, tuple]] = []

    def resolve() -> None:
        try:
            records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            resolved.extend((record[0], record[4]) for record in records[:MAX_ENDPOINT_ADDRESSES]
                            if record[0] in {socket.AF_INET, socket.AF_INET6})
        except OSError:
            pass
        finally:
            slot.release()
            done.set()

    # OS DNS resolution has no socket timeout. At most one daemon resolver can remain
    # blocked; it cannot connect or send a late request, and further DNS reads fail closed.
    worker = threading.Thread(target=resolve, name="operator-dagster-dns", daemon=True)
    try:
        worker.start()
    except RuntimeError:
        slot.release()
        raise RuntimeError("Dagster endpoint name resolution is unavailable") from None
    if not done.wait(_remaining(deadline)):
        raise TimeoutError
    _remaining(deadline)
    if not resolved:
        raise RuntimeError("Dagster endpoint name resolution is unavailable")
    return resolved


def _connect_socket(host: str, port: int, deadline: float) -> socket.socket:
    for family, address in _addresses(host, port, deadline):
        connection_socket = socket.socket(family, socket.SOCK_STREAM)
        try:
            connection_socket.settimeout(_remaining(deadline))
            connection_socket.connect(address)
            connection_socket.settimeout(_remaining(deadline))
            return connection_socket
        except (OSError, TimeoutError):
            connection_socket.close()
    raise RuntimeError("Dagster endpoint is unavailable")


def _response_bytes(response: http.client.HTTPResponse, deadline: float) -> bytes:
    if response.status != 200:
        raise RuntimeError("Dagster endpoint is unavailable")
    headers = response.getheaders()
    if sum(len(key) + len(value) for key, value in headers) > MAX_HEADER_BYTES:
        raise ValueError("Dagster response headers exceed the bound")
    selected: dict[str, str] = {}
    for key, value in headers:
        name = key.lower()
        if name in {"content-type", "content-length", "content-encoding", "transfer-encoding"}:
            if name in selected:
                raise ValueError("Dagster response has ambiguous transport headers")
            selected[name] = value
    content_type = selected.get("content-type", "").lower().replace(" ", "")
    if content_type not in {
            "application/json", "application/json;charset=utf-8",
            "application/graphql-response+json", "application/graphql-response+json;charset=utf-8"}:
        raise ValueError("Dagster response must be UTF-8 JSON")
    if selected.get("content-encoding", "identity").lower() != "identity":
        raise ValueError("compressed Dagster responses are not supported")
    if ("transfer-encoding" in selected and (
            selected["transfer-encoding"].lower() != "chunked" or "content-length" in selected)):
        raise ValueError("Dagster response has ambiguous transport headers")
    length = selected.get("content-length")
    if length is not None and (
            not re.fullmatch(r"0|[1-9][0-9]{0,9}", length) or int(length) > MAX_RESPONSE_BYTES):
        raise ValueError("Dagster response length exceeds the bound or is invalid")
    data = bytearray()
    while True:
        _remaining(deadline)
        chunk = response.read1(min(16 * 1024, MAX_RESPONSE_BYTES + 1 - len(data)))
        _remaining(deadline)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > MAX_RESPONSE_BYTES:
            raise ValueError("Dagster response exceeds the byte bound")
    if length is not None and len(data) != int(length):
        raise ValueError("Dagster response length does not match its declaration")
    return bytes(data)


def _post(endpoint: _Endpoint, dispatch_id: str) -> bytes:
    body = json.dumps({"operationName": OPERATION_NAME, "query": RUN_STATE_QUERY,
                       "variables": {"dispatchId": dispatch_id}},
                      separators=(",", ":")).encode("utf-8")
    deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
    connection = None
    timer = None
    try:
        # http.client neither reads environment proxy settings nor follows redirects.
        connection = (http.client.HTTPSConnection(
            endpoint.host, endpoint.port, timeout=REQUEST_TIMEOUT_SECONDS,
            context=ssl.create_default_context()) if endpoint.scheme == "https"
            else http.client.HTTPConnection(
                endpoint.host, endpoint.port, timeout=REQUEST_TIMEOUT_SECONDS))
        # Keep HTTPS hostname/certificate verification while replacing unbounded OS DNS.
        connection._create_connection = lambda _address, _timeout, _source: _connect_socket(
            endpoint.host, endpoint.port, deadline)
        connection.connect()
        remaining = _remaining(deadline)
        if connection.sock is None:
            raise RuntimeError("Dagster endpoint is unavailable")
        connection.sock.settimeout(remaining)
        # A socket timeout alone resets on each read. Shutdown bounds trickling headers/bodies too.
        timer = threading.Timer(remaining, _abort_socket, (connection.sock,))
        timer.daemon = True
        timer.start()
        connection.request("POST", "/graphql", body=body, headers={
            "Content-Type": "application/json", "Accept": "application/json",
            "Accept-Encoding": "identity", "Connection": "close",
        })
        with connection.getresponse() as response:
            result = _response_bytes(response, deadline)
        _remaining(deadline)
        return result
    except (OSError, http.client.HTTPException):
        raise RuntimeError("Dagster endpoint is unavailable") from None
    finally:
        if timer is not None:
            timer.cancel()
        if connection is not None:
            connection.close()


def _step_counts(value: Any) -> tuple[dict[str, int] | None, list[str]]:
    if type(value) is not dict or "__typename" not in value:
        raise ValueError("Dagster response has invalid step statistics")
    kind = _typename(value["__typename"])
    if kind == "RunStatsSnapshot":
        _object(value, {"__typename", "stepsSucceeded", "stepsFailed"})
        if any(type(value[key]) is not int or not 0 <= value[key] <= MAX_STEP_COUNT
               for key in ("stepsSucceeded", "stepsFailed")):
            raise ValueError("Dagster response has invalid step counts")
        return {"succeeded": value["stepsSucceeded"], "failed": value["stepsFailed"]}, []
    _object(value, {"__typename"})
    return None, ["dagster_step_counts_unavailable" if kind == "PythonError"
                  else "dagster_step_counts_unsupported"]


@dataclass(frozen=True)
class DagsterReader:
    """Startup-only configuration; ``inspect`` accepts a dispatch UUID, never a URL or query."""

    endpoint: str = field(repr=False)
    application_run_id: str
    _trusted_endpoint: _Endpoint = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (not isinstance(self.application_run_id, str)
                or not _APPLICATION_ID.fullmatch(self.application_run_id)):
            raise ValueError("an explicit application run ID in YYYY-MM-DD-NNNN form is required")
        object.__setattr__(self, "_trusted_endpoint", _endpoint(self.endpoint))

    def inspect(self, dispatch_id: str) -> dict[str, Any]:
        dispatch_id = _dispatch_id(dispatch_id)
        data = _decode(_post(self._trusted_endpoint, dispatch_id))
        run = data["runOrError"]
        if type(run) is not dict or "__typename" not in run:
            raise ValueError("Dagster response has an invalid dispatch result")
        kind = _typename(run["__typename"])
        result: dict[str, Any] = {
            "schema": SCHEMA, "application_run_id": self.application_run_id,
            "dagster_dispatch_id": dispatch_id, "availability": "available",
            "status": None, "step_counts": None, "gaps": [],
        }
        if kind != "Run":
            _object(run, {"__typename"})
            if kind == "PythonError":
                raise RuntimeError("Dagster dispatch state is unavailable")
            result["availability"] = "missing" if kind == "RunNotFoundError" else "unsupported"
            result["gaps"] = ["dagster_dispatch_missing" if kind == "RunNotFoundError"
                              else "dagster_response_type_unsupported"]
            return result
        _object(run, {"__typename", "runId", "status", "tags", "stats"})
        if _dispatch_id(run["runId"]) != dispatch_id:
            raise ValueError("Dagster dispatch identity does not match the requested dispatch")
        tags = run["tags"]
        if type(tags) is not list or len(tags) > MAX_TAGS:
            raise ValueError("Dagster response has invalid application identity tags")
        tag_values: dict[str, str] = {}
        for tag in tags:
            _object(tag, {"key", "value"})
            key, value = tag["key"], tag["value"]
            if (not isinstance(key, str) or not 1 <= len(key) <= MAX_TAG_KEY_LENGTH
                    or not isinstance(value, str) or len(value) > MAX_TAG_VALUE_LENGTH
                    or key in tag_values):
                raise ValueError("Dagster response has invalid application identity tags")
            tag_values[key] = value
        if tag_values.get(APPLICATION_RUN_TAG) != self.application_run_id:
            raise ValueError("Dagster application identity is missing or does not match the selected run")
        status = _typename(run["status"])
        counts, gaps = _step_counts(run["stats"])
        if status not in _RUN_STATUSES:
            result["availability"] = "unsupported"
            result["gaps"] = ["dagster_status_unsupported", *gaps]
            return result
        result.update(status=status, step_counts=counts, gaps=gaps)
        return result
