"""A local JSON API, so the iOS app can use a Mac's radios and wires.

The phone can do a lot on its own - read a capture, decode it, ping, scan a
port range - but iOS will not hand any app a raw socket or a monitor-mode
radio. Anything that needs one has to be asked of a real computer, so nettool
can act as that computer: this serves the same reports the CLI prints, over
HTTP on the local network, and advertises itself over Bonjour so the phone can
find it without anyone typing an address.

Deliberately small and deliberately closed:

* bound to localhost unless `--lan` is passed, so it is not exposed by accident;
* every request needs a token, printed once at startup for pairing;
* read-only - the endpoints run diagnostics, and nothing accepts a path,
  command or filename from the client that is not checked against a whitelist.
"""

import json
import os
import re
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__
from .util import NetToolError, run_cmd

API_VERSION = "v1"
SERVICE_TYPE = "_nettool._tcp"

# Anything a phone could ask for that would take longer than this is not worth
# holding a socket open for.
MAX_DURATION = 120


class Api(object):
    """The endpoint table, kept apart from HTTP so it can be tested directly."""

    def __init__(self, token, capture_dir=None):
        self.token = token
        self.capture_dir = capture_dir or os.getcwd()
        self.started = time.time()

    # --- helpers ---------------------------------------------------------

    @staticmethod
    def _int(params, name, default, low, high):
        raw = params.get(name, [None])[0]
        try:
            value = int(raw) if raw is not None else default
        except (TypeError, ValueError):
            raise NetToolError("%s must be a whole number" % name)
        return max(low, min(high, value))

    @staticmethod
    def _host(params, name="host"):
        host = (params.get(name, [""])[0] or "").strip()
        if not host:
            raise NetToolError("%s is required" % name)
        if not re.match(r"^[A-Za-z0-9._:\-]+$", host):
            raise NetToolError("%s is not a hostname or address" % name)
        return host

    def _iface(self, params):
        name = (params.get("interface", [""])[0] or "").strip()
        if name and not re.match(r"^[A-Za-z0-9._\-]+$", name):
            raise NetToolError("interface is not a valid name")
        return name or None

    # --- endpoints -------------------------------------------------------

    def hello(self, params):
        """What this server is, so the app can show it before pairing."""
        from . import iface as ifmod

        try:
            interfaces = [i["name"] for i in ifmod.inventory(include_down=False)]
        except NetToolError:
            interfaces = []
        return {
            "service": "nettool",
            "version": __version__,
            "api": API_VERSION,
            "host": socket.gethostname(),
            "platform": os.uname().sysname if hasattr(os, "uname") else "unknown",
            "uptime_s": round(time.time() - self.started, 1),
            "interfaces": interfaces,
            "capabilities": self.capabilities(),
        }

    def capabilities(self):
        """What this machine can actually be asked to do.

        The app greys out what is unavailable rather than offering a button that
        will fail - a Mac without the BPF helper cannot capture, and saying so up
        front is kinder than an error three taps later.
        """
        from .link import capturable_interfaces
        from .util import is_elevated

        try:
            capturable = capturable_interfaces()
        except Exception:
            capturable = []
        return {
            "capture": bool(capturable),
            "capturable_interfaces": capturable,
            "monitor_mode": os.uname().sysname == "Darwin" if hasattr(os, "uname") else False,
            "elevated": is_elevated(),
        }

    def interfaces(self, params):
        from . import iface as ifmod

        return {"interfaces": ifmod.inventory()}

    def routes(self, params):
        from . import iface as ifmod

        return {"routes": ifmod.routes()}

    def arp(self, params):
        from . import iface as ifmod

        return {"arp": ifmod.arp_table()}

    def dns(self, params):
        from . import iface as ifmod

        servers, search = ifmod.dns_servers()
        return {"servers": servers, "search": search}

    def discover(self, params):
        from . import discover as discmod

        subnet = params.get("subnet", [""])[0] or None
        if subnet and not re.match(r"^[0-9a-fA-F.:/]+$", subnet):
            raise NetToolError("subnet must be a CIDR range")
        method = params.get("method", ["auto"])[0]
        if method not in ("auto", "arp", "icmp", "tcp"):
            raise NetToolError("method must be auto, arp, icmp or tcp")
        hosts, used = discmod.discover(self._iface(params), subnet, method,
                                       timeout=self._int(params, "timeout", 2, 1, 10))
        return {"hosts": hosts, "method": used,
                "duplicates": discmod.find_duplicate_ips(hosts)}

    def portscan(self, params):
        from . import portscan
        from .util import parse_ports, parse_targets

        results = portscan.scan(
            parse_targets(self._host(params)),
            parse_ports(params.get("ports", ["1-1024"])[0]),
            proto=params.get("proto", ["tcp"])[0],
            timeout=self._int(params, "timeout", 1, 1, 10),
            workers=self._int(params, "workers", 64, 1, 256),
            banner=params.get("banner", ["0"])[0] in ("1", "true", "yes"),
            open_only=params.get("all", ["0"])[0] not in ("1", "true", "yes"),
        )
        return {"results": results}

    def wifi_scan(self, params):
        from . import wifi as wifimod

        networks, source = wifimod.scan(self._iface(params))
        return {"networks": networks, "source": source}

    def wifi_link(self, params):
        from . import wifi as wifimod

        return wifimod.link(self._iface(params))

    def wifi_analyze(self, params):
        from . import wifi as wifimod

        networks, source = wifimod.scan(self._iface(params))
        current = wifimod.link(self._iface(params))
        try:
            survey = wifimod.survey_dump(self._iface(params))
        except NetToolError:
            survey = []
        return {"source": source, "networks": networks, "current": current,
                "survey": survey, "report": wifimod.analyze(networks, current, survey)}

    def ping(self, params):
        from . import ping as pingmod

        stats = pingmod.ping(
            self._host(params),
            count=self._int(params, "count", 5, 1, 30),
            timeout=self._int(params, "timeout", 1, 1, 10),
            quiet=True,
        )
        return {k: v for k, v in stats.items() if k != "rtts"}

    def trace(self, params):
        from . import ping as pingmod

        return {"hops": pingmod.traceroute(
            self._host(params),
            max_hops=self._int(params, "max_hops", 20, 1, 40),
            probes=self._int(params, "probes", 2, 1, 5),
            sink=None)}

    def captures(self, params):
        """Captures on this machine the phone may fetch.

        Only .pcap files directly inside the capture directory - no traversal, no
        recursion, nothing the client names.
        """
        found = []
        try:
            for name in sorted(os.listdir(self.capture_dir)):
                if not name.endswith((".pcap", ".pcapng")):
                    continue
                path = os.path.join(self.capture_dir, name)
                if not os.path.isfile(path):
                    continue
                found.append({"name": name, "bytes": os.path.getsize(path),
                              "modified": os.path.getmtime(path)})
        except OSError as exc:
            raise NetToolError("cannot list captures: %s" % exc)
        return {"directory": self.capture_dir, "captures": found}

    def capture(self, params):
        """Run a capture and report where it landed; the file is fetched after."""
        from . import capture as capmod

        name = params.get("name", ["phone"])[0]
        if not re.match(r"^[A-Za-z0-9._\-]{1,60}$", name):
            raise NetToolError("name may only contain letters, digits, dot, dash "
                               "and underscore")
        target = os.path.join(self.capture_dir, "%s.pcap" % name)
        stats = capmod.live_capture(
            ifname=self._iface(params),
            outfile=target,
            duration=self._int(params, "duration", 10, 1, MAX_DURATION),
            count=self._int(params, "count", 0, 0, 200000),
            filter_expr=params.get("filter", [""])[0] or None,
            monitor=params.get("monitor", ["0"])[0] in ("1", "true", "yes"),
            show=False,
            quiet=True,
        )
        report = {"file": os.path.basename(target),
                  "packets": getattr(stats, "packets", 0),
                  "bytes": getattr(stats, "bytes", 0)}
        if getattr(stats, "wireless", False):
            report["wireless"] = stats.survey.report()
        return report

    def analyze(self, params):
        from . import analyze as analyzemod

        analysis = analyzemod.analyze_pcap(
            self._capture_path(params),
            filter_expr=params.get("filter", [""])[0] or None)
        return analysis.report(top=self._int(params, "top", 20, 1, 200))

    def _capture_path(self, params):
        """Resolve a client-named capture, refusing anything outside the directory."""
        name = params.get("file", [""])[0]
        if not name:
            raise NetToolError("file is required")
        if os.path.basename(name) != name or name.startswith("."):
            raise NetToolError("file must be a plain name in the capture directory")
        path = os.path.join(self.capture_dir, name)
        if not os.path.isfile(path):
            raise NetToolError("no such capture: %s" % name)
        return path


ROUTES = {
    "hello": "hello",
    "capabilities": lambda api, params: api.capabilities(),
    "iface": "interfaces",
    "routes": "routes",
    "arp": "arp",
    "dns": "dns",
    "discover": "discover",
    "scan": "portscan",
    "wifi/scan": "wifi_scan",
    "wifi/link": "wifi_link",
    "wifi/analyze": "wifi_analyze",
    "ping": "ping",
    "trace": "trace",
    "captures": "captures",
    "capture": "capture",
    "analyze": "analyze",
}


class Handler(BaseHTTPRequestHandler):
    """HTTP in front of Api. Every route is GET; nothing here changes state."""

    server_version = "nettool/%s" % __version__
    api = None                      # set by serve()

    def log_message(self, fmt, *args):
        if self.server.verbose:
            BaseHTTPRequestHandler.log_message(self, fmt, *args)

    def _send(self, status, payload):
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # The app is the only intended client; no browser should be able to
        # reach these from a page the user happens to have open.
        self.send_header("Access-Control-Allow-Origin", "null")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _authorised(self, params):
        supplied = ""
        header = self.headers.get("Authorization", "")
        if header.lower().startswith("bearer "):
            supplied = header[7:].strip()
        supplied = supplied or (params.get("token", [""])[0])
        return secrets.compare_digest(supplied, self.api.token)

    def _download(self, params):
        """Send a capture file. The path is resolved by Api, which refuses
        anything that is not a plain name inside the capture directory."""
        try:
            path = self.api._capture_path(params)
        except NetToolError as exc:
            return self._send(400, {"error": str(exc)})
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as fh:
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
                self.send_header("Content-Length", str(size))
                self.send_header("Content-Disposition",
                                 'attachment; filename="%s"' % os.path.basename(path))
                self.end_headers()
                # Streamed: a mirror capture can be hundreds of megabytes, and
                # the phone should not wait for the server to hold it all first.
                while True:
                    chunk = fh.read(256 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except OSError as exc:
            return self._send(500, {"error": "cannot read capture: %s" % exc})

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        path = parsed.path.strip("/")
        prefix = "api/%s/" % API_VERSION
        if not path.startswith(prefix):
            return self._send(404, {"error": "unknown path; the API lives under /%s"
                                             % prefix})
        route = path[len(prefix):]

        # /hello is deliberately open: the app shows what it found before the
        # user has pasted a token, and it reveals only a hostname and version.
        if route != "hello" and not self._authorised(params):
            return self._send(401, {"error": "a pairing token is required"})

        # The one endpoint that answers with bytes rather than JSON.
        if route == "download":
            return self._download(params)

        handler = ROUTES.get(route)
        if handler is None:
            return self._send(404, {"error": "unknown endpoint",
                                    "endpoints": sorted(ROUTES) + ["download"]})
        try:
            if callable(handler):
                payload = handler(self.api, params)
            else:
                payload = getattr(self.api, handler)(params)
        except NetToolError as exc:
            return self._send(400, {"error": str(exc)})
        except Exception as exc:                       # never leak a traceback
            return self._send(500, {"error": "%s: %s" % (type(exc).__name__, exc)})
        return self._send(200, payload)


def _lan_address():
    """The address a phone on the same network should use to reach us."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Never actually sends: connecting a UDP socket just picks the route.
        probe.connect(("192.0.2.1", 9))
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


def advertise(port, name=None):
    """Publish over Bonjour, so the app finds this Mac without an address typed.

    Uses whichever registration tool the platform ships - dns-sd on macOS,
    avahi-publish on Linux - as a child process, because binding mDNS ourselves
    would mean either a dependency or a second-rate reimplementation. Returns
    the process, or None if neither is present; the server runs regardless and
    the app can still be pointed at an address by hand.
    """
    import subprocess

    label = name or ("nettool on %s" % socket.gethostname().split(".")[0])
    for argv in (
        ["dns-sd", "-R", label, SERVICE_TYPE, "local", str(port),
         "version=%s" % __version__],
        ["avahi-publish-service", label, SERVICE_TYPE, str(port),
         "version=%s" % __version__],
    ):
        try:
            return subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
        except (OSError, ValueError):
            continue
    return None


def read_token(path):
    """A pairing token from a file, checking it is not world-readable.

    A service reads its token from disk rather than taking it on the command
    line, because a command line is visible to every user on the machine
    through ps. That only helps if the file itself is not.
    """
    try:
        with open(path, "r") as handle:
            token = handle.read().strip()
    except OSError as exc:
        raise NetToolError("cannot read the token file %s: %s"
                           % (path, exc.strerror or exc))
    if not token:
        raise NetToolError("the token file %s is empty" % path)
    try:
        mode = os.stat(path).st_mode
    except OSError:
        mode = 0
    if mode & 0o077:
        raise NetToolError(
            "%s is readable by other users (mode %o). Anyone who can read it can "
            "drive this server, so tighten it first:\n    chmod 600 %s"
            % (path, mode & 0o777, path))
    return token


def serve(host="127.0.0.1", port=8765, token=None, capture_dir=None,
          announce=True, verbose=False, sink=None):
    """Run the API until interrupted. Returns the ThreadingHTTPServer."""
    import sys

    out = sink or sys.stdout
    token = token or os.environ.get("NETTOOL_TOKEN") or secrets.token_urlsafe(18)
    Handler.api = Api(token, capture_dir=capture_dir)

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.verbose = verbose
    port = httpd.server_address[1]

    reachable = _lan_address() if host not in ("127.0.0.1", "localhost") else host
    link = "nettool://%s:%d/?token=%s" % (reachable, port, token)
    local_only = host in ("127.0.0.1", "localhost")

    out.write("nettool API on http://%s:%d/api/%s/\n\n" % (reachable, port, API_VERSION))
    if local_only:
        # Said before the link, or it is read, tried, and only then explained.
        out.write("Bound to localhost, so no phone can reach it yet.\n"
                  "Restart with --lan to let one:\n\n"
                  "    nettool serve --lan\n\n")
        # Still worth printing: this is the form for poking at the API by hand.
        out.write("pairing token: %s\n" % token)
        out.write("    %s\n" % link)
    else:
        out.write("To pair, get this link to the phone and open it - the app\n"
                  "registers nettool:// so opening it pairs, with nothing typed:\n\n")
        out.write("    %s\n\n" % link)
        out.write("Any of these works:\n"
                  "  * copy it here and paste on the phone (Universal Clipboard,\n"
                  "    if both are signed into the same Apple ID)\n"
                  "  * message or AirDrop it to yourself and tap it\n"
                  "  * paste it into the Mac tab in the app by hand\n\n")
        out.write("Leave this running while you use the app. Ctrl-C stops it.\n")
    out.flush()

    publisher = advertise(port) if announce and host not in ("127.0.0.1", "localhost") else None
    if announce and publisher is None and host not in ("127.0.0.1", "localhost"):
        out.write("note: no dns-sd or avahi-publish here, so the app will not "
                  "discover this automatically - pair with the address above.\n")

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    httpd.pairing_token = token
    httpd.publisher = publisher
    return httpd


def shutdown(httpd):
    if getattr(httpd, "publisher", None):
        httpd.publisher.terminate()
    httpd.shutdown()
    httpd.server_close()
