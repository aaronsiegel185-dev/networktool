"""Shared helpers: privilege checks, formatting, tables, subprocess wrappers."""

import ipaddress
import os
import re
import shutil
import socket
import struct
import subprocess
import sys

IS_LINUX = sys.platform.startswith("linux")


class NetToolError(Exception):
    """User-facing error: printed without a traceback."""


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


IS_DARWIN = sys.platform == "darwin"


def require_root(what):
    """Raise a NetToolError naming the fix for *this* platform."""
    if is_root():
        return
    if IS_DARWIN:
        raise NetToolError(
            "%s needs access to /dev/bpf*. Either re-run with sudo, or install the "
            "BPF access helper once so your user can capture without sudo:\n"
            "    sudo ./gui/macos/install-bpf-access.sh   (then log out and back in)"
            % what
        )
    raise NetToolError(
        "%s needs root. Either re-run with sudo, or grant the capabilities once:\n"
        "    sudo setcap cap_net_raw,cap_net_admin=eip "
        "\"$(readlink -f \"$(which python3)\")\"" % what
    )


def require_linux(what):
    if not IS_LINUX:
        raise NetToolError("%s is only implemented on Linux (found %s)." % (what, sys.platform))


def run_cmd(argv, timeout=30, stdin=None):
    """Run a command, returning (rc, stdout, stderr). rc=-1 if the binary is missing.

    `stdin` is text fed to the command - some tools (scutil) only take a query
    that way.
    """
    exe = shutil.which(argv[0])
    if exe is None:
        return -1, "", "%s not found in PATH" % argv[0]
    try:
        proc = subprocess.run(
            [exe] + list(argv[1:]),
            input=None if stdin is None else stdin.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return -2, "", "%s timed out after %ss" % (argv[0], timeout)
    return (
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def have_cmd(name):
    return shutil.which(name) is not None


# --- formatting ------------------------------------------------------------


def mac_str(raw):
    """Bytes -> aa:bb:cc:dd:ee:ff."""
    return ":".join("%02x" % b for b in bytearray(raw))


def mac_bytes(text):
    parts = text.replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError("bad MAC: %r" % text)
    return bytes(int(p, 16) for p in parts)


def human_bytes(n):
    step = 1024.0
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < step or unit == "TiB":
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= step
    return "%.1f TiB" % n


def human_secs(s):
    if s < 1:
        return "%.2fs" % s
    s = int(s)
    if s < 60:
        return "%ds" % s
    if s < 3600:
        return "%dm%02ds" % (s // 60, s % 60)
    return "%dh%02dm" % (s // 3600, (s % 3600) // 60)


def table(rows, headers, sink=None):
    """Print an aligned text table. rows: list of sequences (values stringified)."""
    sink = sink or sys.stdout
    body = [[("" if c is None else str(c)) for c in r] for r in rows]
    widths = [len(str(h)) for h in headers]
    for r in body:
        for i, c in enumerate(r):
            if i < len(widths):
                widths[i] = max(widths[i], len(c))
    line = "  ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers))
    sink.write(line.rstrip() + "\n")
    sink.write("  ".join("-" * w for w in widths) + "\n")
    for r in body:
        sink.write("  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip() + "\n")
    if not body:
        sink.write("(none)\n")


def section(title, sink=None):
    sink = sink or sys.stdout
    sink.write("\n== %s ==\n" % title)


# --- addressing ------------------------------------------------------------


_RANGE_RE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})\s*$")


def parse_targets(spec):
    """Expand a target spec into a list of IPv4 address strings.

    Accepts comma-separated entries of: single IP, hostname, CIDR (10.0.0.0/24),
    dashed range (10.0.0.5-20 or 10.0.0.5-10.0.0.20).
    """
    out = []
    seen = set()

    def add(ip):
        if ip not in seen:
            seen.add(ip)
            out.append(ip)

    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            hosts = net.hosts() if net.prefixlen < 31 else net
            for host in hosts:
                add(str(host))
        elif _RANGE_RE.match(part):
            left, right = part.split("-", 1)
            left = left.strip()
            right = right.strip()
            start = ipaddress.ip_address(left)
            if "." in right:
                end = ipaddress.ip_address(right)
            else:
                base = left.rsplit(".", 1)[0]
                end = ipaddress.ip_address("%s.%s" % (base, right))
            if int(end) < int(start):
                raise NetToolError("range %r ends before it starts" % part)
            if int(end) - int(start) > 65535:
                raise NetToolError("range %r is larger than 65536 addresses" % part)
            for i in range(int(start), int(end) + 1):
                add(str(ipaddress.ip_address(i)))
        else:
            try:
                add(str(ipaddress.ip_address(part)))
            except ValueError:
                try:
                    add(socket.gethostbyname(part))
                except OSError as exc:
                    raise NetToolError("cannot resolve %r: %s" % (part, exc))
    return out


TOP_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143, 161,
    162, 389, 443, 445, 464, 465, 514, 515, 548, 587, 593, 623, 631, 636, 873, 902, 989,
    990, 993, 995, 1080, 1194, 1433, 1521, 1723, 1883, 1900, 2049, 2181, 2375, 2376, 3128,
    3268, 3269, 3306, 3389, 4369, 4786, 5000, 5060, 5061, 5222, 5353, 5432, 5555, 5601,
    5672, 5900, 5901, 5985, 5986, 6379, 6443, 7001, 8000, 8006, 8008, 8009, 8080, 8081,
    8088, 8090, 8123, 8443, 8500, 8600, 8883, 9000, 9090, 9092, 9100, 9200, 9300, 9418,
    10000, 11211, 15672, 27017, 32400, 47808, 49152, 50000, 51820,
]

EXTRA_SERVICES = {
    22: "ssh", 80: "http", 443: "https", 445: "microsoft-ds", 623: "ipmi", 902: "vmware",
    1883: "mqtt", 2375: "docker", 2376: "docker-tls", 3389: "ms-wbt", 5060: "sip",
    5900: "vnc", 5985: "winrm", 5986: "winrm-tls", 6379: "redis", 6443: "kubernetes",
    8006: "proxmox", 8080: "http-alt", 8443: "https-alt", 9100: "jetdirect",
    9200: "elasticsearch", 27017: "mongodb", 32400: "plex", 47808: "bacnet",
    51820: "wireguard", 4786: "cisco-smi",
}


def parse_ports(spec):
    """'22,80,8000-8100' | 'top' | 'all' -> sorted list of ints."""
    spec = str(spec).strip().lower()
    if spec in ("top", "common", "default"):
        return sorted(TOP_PORTS)
    if spec in ("all", "-", "1-65535"):
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi:
                lo, hi = hi, lo
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
                raise NetToolError("port range out of bounds: %r" % part)
            ports.update(range(lo, hi + 1))
        else:
            p = int(part)
            if not 1 <= p <= 65535:
                raise NetToolError("port out of bounds: %r" % part)
            ports.add(p)
    if not ports:
        raise NetToolError("no ports selected")
    return sorted(ports)


def service_name(port, proto="tcp"):
    if proto == "tcp" and port in EXTRA_SERVICES:
        return EXTRA_SERVICES[port]
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return ""


def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(value):
    return socket.inet_ntoa(struct.pack("!I", value))


def same_subnet(a, b, prefixlen):
    mask = (0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF
    return (ip_to_int(a) & mask) == (ip_to_int(b) & mask)


def reverse_dns(ip, timeout=1.0):
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""
    finally:
        socket.setdefaulttimeout(old)
