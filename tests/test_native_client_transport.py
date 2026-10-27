import json
from pathlib import Path
import socket
import stat
import struct
from types import SimpleNamespace

import pytest

from appsec_review.container_runtime import native_client
from tests.test_native_engine_broker import native, lease  # noqa: F401
from tests.test_bounded_image_build_service import forbid_real_execution  # noqa: F401


@pytest.mark.parametrize("failure", [None, "peer-uid", "peer-pid", "socket-replacement",
                                    "oversize", "wrong-binding", "wrong-budget", "disconnect"])
def test_native_transport_authenticates_peer_and_bounded_bound_response(native, monkeypatch, failure):
    endpoint = Path(native.client.contract.endpoint)
    calls = []
    original_lstat = Path.lstat

    def socket_stat(path, *args, **kwargs):
        if path != endpoint:
            return original_lstat(path, *args, **kwargs)
        calls.append("stat")
        return SimpleNamespace(
            st_mode=stat.S_IFSOCK | 0o600, st_uid=native.peer.uid, st_dev=1,
            st_ino=2 if failure == "socket-replacement" and len(calls) > 1 else 1)

    class Channel:
        output = b""

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, timeout):
            assert 0 < timeout <= 60

        def connect(self, path):
            assert path == str(endpoint)

        def getsockopt(self, level, option, length):
            assert (level, option, length) == (socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            return struct.pack("3i", native.peer.pid + (failure == "peer-pid"),
                               native.peer.uid if failure == "peer-uid" else 0, 0)

        def sendall(self, data):
            self.output = native.broker.dispatch(data, native.peer)
            if failure in {"wrong-binding", "wrong-budget"}:
                document = json.loads(self.output)
                if failure == "wrong-binding":
                    document["binding"]["engine_generation"] = "wrong"
                else:
                    document["result"]["resource_budget"]["cpu"] = 999
                self.output = json.dumps(document).encode() + b"\n"
            if failure == "oversize":
                self.output = b"x" * (native_client.MAX_RESPONSE + 1) + b"\n"
            if failure == "disconnect":
                self.output = b""

        def recv(self, maximum):
            result, self.output = self.output[:maximum], self.output[maximum:]
            return result

    monkeypatch.setattr(native_client, "private_path", lambda path, **kw: None)
    monkeypatch.setattr(Path, "lstat", socket_stat)
    monkeypatch.setattr(native_client.socket, "socket", lambda *args: Channel())
    with lease(native):
        if failure:
            with pytest.raises((PermissionError, ValueError, RuntimeError)):
                native.client.request("image.inspect", {"reference": "base:release"})
        else:
            result = native.client.request("image.inspect", {"reference": "base:release"})
            assert result["state"] == "PRESENT"
            assert result["broker_process"]["pid"] == native.peer.pid


def test_client_deadline_caps_each_exchange_and_refuses_expired_work(native, monkeypatch):
    calls = []
    monkeypatch.setattr(native_client.time, "monotonic", lambda: 10)
    monkeypatch.setattr(native.client, "request",
                        lambda action, payload, **kw: calls.append(kw) or {})
    native.client._until("image.inspect", {"reference": "base:release"}, 12)
    assert calls == [{"timeout": 2}]
    with pytest.raises(TimeoutError):
        native.client._until("image.inspect", {"reference": "base:release"}, 10)
    assert len(calls) == 1
