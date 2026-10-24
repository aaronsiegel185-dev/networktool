"""A stand-in for Ollama, so the client can be tested without a model.

Speaks the parts of the OpenAI chat-completions API that Assist uses, records
what it was sent, and can stream. Having this means the request shape - and in
particular that images arrive as inline data URLs rather than paths - is
checked on every run instead of only when someone has a 7 GB model pulled.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path.endswith("/models"):
            self._json({"data": [{"id": name} for name in self.server.models]})
        else:
            self._json({"error": "not found"}, status=404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length) or b"{}")
        self.server.requests.append(payload)
        if payload.get("stream"):
            return self._stream()
        self._json({"choices": [{"message": {"role": "assistant",
                                             "content": self.server.reply}}]})

    def _stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for piece in self.server.reply.split(" "):
            chunk = {"choices": [{"delta": {"content": piece + " "}}]}
            self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")

    def _json(self, payload, status=200):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class StubModelServer(object):
    def __init__(self, reply="Check the interference on channel 48 first.",
                 models=("llama3.1:8b", "llama3.2-vision:11b")):
        self.httpd = HTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.requests = []
        self.httpd.reply = reply
        self.httpd.models = list(models)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def endpoint(self):
        return "http://127.0.0.1:%d/v1" % self.httpd.server_address[1]

    @property
    def requests(self):
        return self.httpd.requests

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        return False
