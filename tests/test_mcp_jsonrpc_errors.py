from io import StringIO
import json

import pytest

from appsec_review.mcp import stdio


@pytest.mark.parametrize("prefix", ["", '{"jsonrpc":"2.0","id":7,"method":"ping"}\n'])
def test_malformed_message_has_no_stale_id_and_next_request_succeeds(prefix, monkeypatch, capsys):
    monkeypatch.setattr(stdio, "RetrievalCore", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(stdio, "RetrievalMcpAdapter", lambda _core: object())
    monkeypatch.setattr(stdio.sys, "stdin", StringIO(
        prefix + "{\n" + '{"jsonrpc":"2.0","id":9,"method":"ping"}\n'))
    assert stdio.main(["--run-id", "isolated-protocol"]) == 0
    responses = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    error, recovered = responses[-2:]
    assert error["id"] is None
    assert error["error"]["code"] == -32700
    assert recovered == {"jsonrpc": "2.0", "id": 9, "result": {}}
