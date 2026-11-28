from contextlib import contextmanager
from hashlib import sha256
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, HTTPServer
from secrets import compare_digest, token_urlsafe
from threading import Thread

from .fixtures import OBJECT, READER
from .policy import evaluate
from .storage import CANARY, guard, storage

PATH = "/classroom/canary.txt"


@contextmanager
def sandbox(state: dict, backend: str):
    token = token_urlsafe(32)
    with storage(backend) as fetch:
        class Gate(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                pass

            def do_GET(self) -> None:
                if self.path != PATH:
                    self.send_error(404)
                    return
                actor = "Internet"
                supplied = self.headers.get("Authorization")
                if supplied is not None:
                    if not compare_digest(supplied, "Bearer " + token):
                        self.send_error(401)
                        return
                    actor = READER
                result = evaluate(state["bucket_statements"], "s3:GetObject", OBJECT, actor)
                code = {"ALLOW": 200, "IMPLICIT_DENY": 403, "EXPLICIT_DENY": 403, "UNKNOWN": 409}[result]
                try:
                    data = fetch() if code == 200 else b""
                except Exception:
                    self.send_error(502)
                    return
                self.send_response(code)
                self.send_header("X-PathProof-Gate", result)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        with HTTPServer(("127.0.0.1", 0), Gate) as server:
            worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
            worker.start()
            try:
                yield server.server_port, token
            finally:
                server.shutdown()
                worker.join()


def read(port: int, token: str, actor: str, backend: str) -> dict:
    if actor not in ("Internet", READER):
        raise ValueError("Unregistered canary reader.")
    guard(f"http://127.0.0.1:{port}{PATH}", port)
    headers = {} if actor == "Internet" else {"Authorization": "Bearer " + token}
    connection = HTTPConnection("127.0.0.1", port, timeout=4)
    result = {"actor": actor, "method": "GET", "path": PATH, "backend": backend, "gate": None,
              "http_status": None, "digest_match": None, "verdict": None, "control": None}
    try:
        connection.request("GET", PATH, headers=headers)
        response = connection.getresponse()
        gate = response.getheader("X-PathProof-Gate")
        result.update(http_status=response.status, gate=gate)
        if response.status == 200 and gate == "ALLOW":
            body = response.read(len(CANARY) + 1)
            expected = sha256(CANARY).hexdigest()
            observed = sha256(body).hexdigest()
            result.update(digest_match=expected == observed, expected_sha256=expected, observed_sha256=observed)
            if result["digest_match"]:
                result["verdict"] = "PROVEN"
        elif response.status == 403 and gate in ("IMPLICIT_DENY", "EXPLICIT_DENY"):
            result.update(verdict="BLOCKED", control="canary bucket policy: " + gate)
    except (OSError, HTTPException):
        result["error"] = "transport_error"
    finally:
        connection.close()
    return result
