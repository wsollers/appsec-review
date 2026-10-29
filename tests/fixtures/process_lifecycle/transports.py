from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading


@contextmanager
def submission_server():
    state = {"launches": [], "status": "STARTED", "acknowledge": threading.Event(),
             "accepted": threading.Event(), "disconnected": threading.Event()}
    state["acknowledge"].set()

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(3)

        def log_message(self, *args):
            pass

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if request.get("run_id"):
                state["launches"].append(request)
                state["accepted"].set()
                if not state["acknowledge"].wait(15):
                    self.send_error(504)
                    return
                result = {"accepted": request["run_id"]}
            else:
                wanted = request["variables"]["runId"]
                launches = [item for item in state["launches"] if item["run_id"] == wanted]
                run = {"__typename": "RunNotFoundError", "message": "no submitted run"}
                if launches:
                    run = {"__typename": "Run", "runId": wanted, "pipelineName": "wave1_review",
                           "status": state["status"], "tags": [{
                               "key": "appsec/submission_identity",
                               "value": launches[0]["identity_sha256"]}]}
                result = {"data": {"runOrError": run}}
            payload = json.dumps(result).encode()
            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                state["disconnected"].set()

    class Server(ThreadingHTTPServer):
        daemon_threads = False

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/graphql", state
    finally:
        state["acknowledge"].set()
        server.shutdown()
        server.server_close()
        thread.join(5)
        assert not thread.is_alive(), "owned loopback server did not stop"
