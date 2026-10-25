"""Stand-ins for Hudu, NetBox and BookStack.

These speak the documented request and response shapes so the connectors can be
tested without anyone owning an instance of each. They also record every
request, which is how the tests check the things that actually matter: that the
right auth header went, that paging stopped, and - most of all - that a sync
never sent a notebook's contents anywhere.

They are not the real products. A stub proves the client is self-consistent and
handles the documented shapes; it cannot prove a vendor has not changed them.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        self.server.requests.append({
            "path": parsed.path,
            "query": query,
            "headers": dict(self.headers),
        })
        if self.server.fail_with:
            self._send(self.server.fail_with, {"error": "nope"})
            return
        handler = self.server.route(parsed.path, query)
        if handler is None:
            self._send(404, {"error": "not found"})
            return
        self._send(200, handler)

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class StubServer(object):
    def __init__(self):
        self.httpd = HTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.requests = []
        self.httpd.fail_with = None
        self.httpd.route = self.route
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.httpd.server_address[1]

    @property
    def requests(self):
        return self.httpd.requests

    def fail_with(self, status):
        self.httpd.fail_with = status

    def auth_headers(self):
        """The auth header of every request, lowercased keys."""
        out = []
        for request in self.requests:
            lowered = {k.lower(): v for k, v in request["headers"].items()}
            out.append({k: v for k, v in lowered.items()
                        if k in ("x-api-key", "authorization")})
        return out

    def route(self, path, query):
        raise NotImplementedError

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        return False


class HuduStub(StubServer):
    """Hudu: /api/v1, x-api-key, lists wrapped in a named key, HTML content."""

    COMPANIES = [{"id": 1, "name": "Acme Corp"}, {"id": 2, "name": "Northwind Ltd"}]

    def route(self, path, query):
        page = int(query.get("page", 1))
        if path == "/api/v1/companies":
            return {"companies": self.COMPANIES if page == 1 else []}
        if path == "/api/v1/articles":
            if page != 1 or query.get("company_id") != "1":
                return {"articles": []}
            return {"articles": [{
                "id": 10,
                "name": "Acme HQ Firewall",
                "url": "https://hudu.example.com/a/10",
                "content": "<h2>Edge</h2><p>Fortigate 100F.</p>"
                           "<ul><li>WAN: 203.0.113.1</li></ul>",
            }]}
        if path == "/api/v1/companies/1/assets":
            if page != 1:
                return {"assets": []}
            return {"assets": [{
                "id": 7,
                "name": "fw-hq-01",
                "asset_type": "Firewall",
                "url": "https://hudu.example.com/as/7",
                "fields": [
                    {"label": "WAN IP", "value": "203.0.113.1", "field_type": "Text"},
                    {"label": "Model", "value": "Fortigate 100F", "field_type": "Text"},
                    {"label": "Admin Password", "value": "hunter2",
                     "field_type": "Password"},
                    {"label": "Notes", "value": "Replaced 2025", "field_type": "Text"},
                ],
            }]}
        return None


class NetBoxStub(StubServer):
    """NetBox: /api, Token auth, {count, next, results} with next as a URL."""

    def route(self, path, query):
        if path == "/api/status/":
            return {"netbox-version": "4.1.0"}
        if path == "/api/tenancy/tenants/":
            return _page([{"id": 3, "name": "Acme Corp"}])
        if path == "/api/dcim/devices/":
            return _page([
                {"name": "fw-hq-01",
                 "role": {"name": "Firewall"},
                 "device_type": {"display": "Fortigate 100F"},
                 "site": {"name": "HQ"},
                 "primary_ip4": {"address": "10.20.0.1/24"}},
                {"name": "sw-core-01",
                 "role": {"name": "Core Switch"},
                 "device_type": {"display": "EX4300"},
                 "site": {"name": "HQ"},
                 "primary_ip4": {"address": "10.20.0.2/24"}},
            ])
        if path == "/api/ipam/prefixes/":
            return _page([
                {"prefix": "10.20.0.0/16", "site": {"name": "HQ"}, "description": ""},
                {"prefix": "10.30.0.0/16", "site": {"name": "Warehouse"},
                 "description": ""},
            ])
        if path == "/api/ipam/vlans/":
            return _page([{"vid": 20, "name": "voice"}])
        if path == "/api/dcim/sites/":
            return _page([{"name": "HQ"}, {"name": "Warehouse"}])
        return None


class BookStackStub(StubServer):
    """BookStack: /api, Authorization: Token id:secret, {data, total}."""

    def route(self, path, query):
        if path == "/api/books":
            return {"data": [{"id": 4, "name": "Acme Corp", "slug": "acme-corp"}],
                    "total": 1}
        if path == "/api/pages":
            return {"data": [{"id": 9, "name": "VPN runbook", "book_slug": "acme-corp"}],
                    "total": 1}
        if path == "/api/pages/9":
            return {"id": 9, "name": "VPN runbook", "slug": "vpn-runbook",
                    "html": "<h2>Tunnel</h2><p>Peer is 198.51.100.7.</p>"}
        return None


def _page(rows):
    return {"count": len(rows), "next": None, "previous": None, "results": rows}
