"""TCP connect and UDP probe port scanning."""

import errno
import re
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .util import NetToolError, service_name

TLS_PORTS = {443, 465, 636, 853, 989, 990, 993, 995, 8443, 9443, 5061, 6443, 4433, 2376}
HTTP_PORTS = {80, 81, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8090, 8123, 8888,
              9000, 9090, 5601, 15672, 32400}

# Probes that reliably provoke a reply from a live UDP service.
UDP_PROBES = {
    53: b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    123: b"\x1b" + b"\x00" * 47,
    161: bytes.fromhex("302602010104067075626c6963a019020400000001020100020100300b3009"
                       "06052b060102010500"),
    137: bytes.fromhex("a2480000000100000000000020434b4141414141414141414141414141414141"
                       "4141414141414141414100002100 01".replace(" ", "")),
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
          b"MX: 1\r\nST: ssdp:all\r\n\r\n",
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd"
          b"\x04_udp\x05local\x00\x00\x0c\x00\x01",
    500: bytes.fromhex("0000000000000000000000000000000001100200000000000000015000000134"),
    69: b"\x00\x01" + b"nettool-probe\x00" + b"octet\x00",
    111: bytes.fromhex("72fe1d1300000000000000020001862a00000002000000000000000000000000"
                       "0000000000000000"),
    5060: b"OPTIONS sip:probe SIP/2.0\r\nVia: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bKprobe\r\n"
          b"From: <sip:probe@0.0.0.0>;tag=1\r\nTo: <sip:probe>\r\nCall-ID: probe\r\n"
          b"CSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
}
UDP_DEFAULT_PROBE = b"\x00"


def _grab_banner(sock, port, timeout):
    """Best-effort service fingerprint from an already-connected socket."""
    sock.settimeout(timeout)
    try:
        if port in TLS_PORTS:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            except (AttributeError, ValueError):
                pass
            with ctx.wrap_socket(sock) as tls:
                proto = tls.version() or "TLS"
                cipher = (tls.cipher() or ("", "", ""))[0]
                return "%s %s" % (proto, cipher)
        if port in HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: probe\r\nUser-Agent: nettool\r\n\r\n")
            data = sock.recv(512)
        else:
            # SSH/SMTP/FTP/IMAP announce themselves; anything silent gets an HTTP nudge.
            sock.settimeout(max(0.3, timeout / 2))
            try:
                data = sock.recv(256)
            except socket.timeout:
                data = b""
            if not data:
                sock.settimeout(timeout)
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: probe\r\n"
                             b"User-Agent: nettool\r\n\r\n")
                data = sock.recv(512)
        if not data:
            return ""
        text = data.decode("utf-8", "replace")
        server = re.search(r"^Server:\s*(.+)$", text, re.I | re.M)
        if server:
            first = text.splitlines()[0].strip()
            return "%s | %s" % (first, server.group(1).strip())
        return " ".join(text.split())[:120]
    except (OSError, ssl.SSLError, ValueError):
        return ""


def scan_tcp_port(host, port, timeout=1.0, banner=False):
    """Return (state, detail): state is 'open', 'closed' or 'filtered'."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start = time.time()
    try:
        sock.connect((host, port))
    except socket.timeout:
        sock.close()
        return "filtered", ""
    except ConnectionRefusedError:
        sock.close()
        return "closed", ""
    except OSError as exc:
        sock.close()
        if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EACCES, errno.EPERM):
            return "filtered", exc.strerror or ""
        return "closed", exc.strerror or ""
    rtt = (time.time() - start) * 1000
    detail = _grab_banner(sock, port, timeout) if banner else ""
    try:
        sock.close()
    except OSError:
        pass
    return "open", detail or ("%.0f ms" % rtt)


def scan_udp_port(host, port, timeout=1.5):
    """UDP is unacknowledged: a reply proves 'open', silence is 'open|filtered'."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    payload = UDP_PROBES.get(port, UDP_DEFAULT_PROBE)
    try:
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(2048)
        return "open", "%d byte reply" % len(data)
    except socket.timeout:
        return "open|filtered", "no reply"
    except ConnectionRefusedError:
        return "closed", "ICMP port unreachable"
    except OSError as exc:
        return "closed", exc.strerror or ""
    finally:
        sock.close()


def scan(hosts, ports, proto="tcp", timeout=1.0, workers=256, banner=False,
         open_only=True, progress=None):
    """Scan every (host, port). Returns a list of result dicts.

    progress: optional callable(done, total) for UI feedback.
    """
    if proto not in ("tcp", "udp"):
        raise NetToolError("proto must be tcp or udp")
    jobs = [(h, p) for h in hosts for p in ports]
    total = len(jobs)
    if not total:
        raise NetToolError("nothing to scan")
    workers = max(1, min(workers, 1024, total))
    results = []
    lock = threading.Lock()
    done = [0]

    def work(job):
        host, port = job
        if proto == "tcp":
            state, detail = scan_tcp_port(host, port, timeout, banner)
        else:
            state, detail = scan_udp_port(host, port, timeout)
        return {"host": host, "port": port, "proto": proto, "state": state,
                "service": service_name(port, proto), "detail": detail}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(work, job) for job in jobs]
        for fut in as_completed(futures):
            res = fut.result()
            with lock:
                done[0] += 1
                if progress and (done[0] % 100 == 0 or done[0] == total):
                    progress(done[0], total)
            if open_only and not res["state"].startswith("open"):
                continue
            results.append(res)
    results.sort(key=lambda r: (tuple(int(x) for x in r["host"].split(".")
                                      if x.isdigit()) or (0,), r["port"]))
    return results


def tcp_ping(host, ports=(443, 80, 22, 3389, 445), timeout=0.7):
    """Is this host alive? Returns (alive, port, rtt_ms) using TCP handshakes."""
    for port in ports:
        start = time.time()
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return True, port, (time.time() - start) * 1000
        except ConnectionRefusedError:
            # A refusal still proves the host is up and reachable.
            return True, port, (time.time() - start) * 1000
        except OSError:
            continue
        finally:
            sock.close()
    return False, None, None


def summarize(results):
    """Group results by host for display."""
    by_host = {}
    for r in results:
        by_host.setdefault(r["host"], []).append(r)
    return by_host
