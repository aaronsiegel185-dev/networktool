"""ICMP echo, traceroute and path-MTU discovery (raw or unprivileged ICMP sockets)."""

import errno
import os
import select
import socket
import struct
import time

from .util import NetToolError, reverse_dns

ICMP_ECHO = 8
ICMP_ECHOREPLY = 0
ICMP_UNREACH = 3
ICMP_TIME_EXCEEDED = 11
IP_MTU_DISCOVER = 10
IP_PMTUDISC_DO = 2
IP_MTU = 14
IP_RECVERR = 11


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _open_icmp_socket():
    """Prefer a raw socket; fall back to Linux unprivileged ICMP sockets."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        return sock, True
    except PermissionError:
        pass
    except OSError as exc:
        if exc.errno not in (errno.EPERM, errno.EACCES):
            raise
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        return sock, False
    except OSError:
        raise NetToolError(
            "ICMP needs either root/CAP_NET_RAW or unprivileged ping sockets "
            "(sysctl net.ipv4.ping_group_range)."
        )


def _echo_packet(ident, seq, payload_size=32):
    payload = struct.pack("!d", time.time())
    pad = max(0, payload_size - len(payload))
    payload += bytes((i & 0xFF) for i in range(pad))
    header = struct.pack("!BBHHH", ICMP_ECHO, 0, 0, ident, seq)
    chk = checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO, 0, chk, ident, seq)
    return header + payload


def _parse_icmp(data, raw_mode):
    """Return (type, code, ident, seq, src_offset_payload)."""
    offset = 0
    if raw_mode:
        if len(data) < 20:
            return None
        offset = (data[0] & 0x0F) * 4
    if len(data) < offset + 8:
        return None
    itype, code, _chk, ident, seq = struct.unpack("!BBHHH", data[offset:offset + 8])
    return itype, code, ident, seq, data[offset + 8:]


def ping(host, count=4, interval=0.5, timeout=1.0, size=32, quiet=True, sink=None):
    """Send ICMP echoes. Returns a stats dict (sent/received/loss/rtt_min/avg/max/jitter)."""
    try:
        dest = socket.gethostbyname(host)
    except OSError as exc:
        raise NetToolError("cannot resolve %s: %s" % (host, exc))
    sock, raw_mode = _open_icmp_socket()
    sock.settimeout(timeout)
    ident = os.getpid() & 0xFFFF
    rtts = []
    sent = 0
    errors = []
    try:
        for seq in range(1, count + 1):
            pkt = _echo_packet(ident, seq, size)
            start = time.time()
            try:
                sock.sendto(pkt, (dest, 0))
                sent += 1
            except OSError as exc:
                errors.append(str(exc))
                continue
            deadline = start + timeout
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                ready = select.select([sock], [], [], remaining)[0]
                if not ready:
                    break
                data, addr = sock.recvfrom(2048)
                parsed = _parse_icmp(data, raw_mode)
                if not parsed:
                    continue
                itype, code, rid, rseq, _rest = parsed
                if itype == ICMP_ECHOREPLY and rseq == seq and (not raw_mode or rid == ident):
                    rtt = (time.time() - start) * 1000
                    rtts.append(rtt)
                    if not quiet and sink:
                        sink.write("%d bytes from %s: seq=%d time=%.2f ms\n" % (
                            len(data), addr[0], seq, rtt))
                    break
                if itype == ICMP_UNREACH:
                    errors.append("unreachable (code %d) from %s" % (code, addr[0]))
                    break
            if seq < count:
                time.sleep(max(0, interval - (time.time() - start)))
    finally:
        sock.close()
    received = len(rtts)
    stats = {
        "host": host, "address": dest, "sent": sent, "received": received,
        "loss_pct": 100.0 * (sent - received) / sent if sent else 100.0,
        "rtt_min": min(rtts) if rtts else None,
        "rtt_avg": sum(rtts) / received if received else None,
        "rtt_max": max(rtts) if rtts else None,
        "jitter": (max(rtts) - min(rtts)) if len(rtts) > 1 else None,
        "errors": errors,
        "rtts": rtts,
    }
    if len(rtts) > 1:
        mean = stats["rtt_avg"]
        stats["stdev"] = (sum((r - mean) ** 2 for r in rtts) / (len(rtts) - 1)) ** 0.5
    return stats


def traceroute(host, max_hops=30, probes=3, timeout=1.5, resolve=True, sink=None):
    """ICMP traceroute. Returns a list of hop dicts."""
    try:
        dest = socket.gethostbyname(host)
    except OSError as exc:
        raise NetToolError("cannot resolve %s: %s" % (host, exc))
    sock, raw_mode = _open_icmp_socket()
    ident = (os.getpid() + 1) & 0xFFFF
    hops = []
    try:
        for ttl in range(1, max_hops + 1):
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            hop = {"ttl": ttl, "address": None, "name": "", "rtts": [], "final": False}
            for probe in range(probes):
                seq = ttl * 100 + probe
                pkt = _echo_packet(ident, seq, 32)
                start = time.time()
                try:
                    sock.sendto(pkt, (dest, 0))
                except OSError as exc:
                    hop["error"] = str(exc)
                    break
                deadline = start + timeout
                while True:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    if not select.select([sock], [], [], remaining)[0]:
                        break
                    data, addr = sock.recvfrom(2048)
                    parsed = _parse_icmp(data, raw_mode)
                    if not parsed:
                        continue
                    itype, _code, _rid, _rseq, rest = parsed
                    if itype in (ICMP_TIME_EXCEEDED, ICMP_UNREACH, ICMP_ECHOREPLY):
                        hop["address"] = addr[0]
                        hop["rtts"].append((time.time() - start) * 1000)
                        if itype == ICMP_ECHOREPLY or addr[0] == dest:
                            hop["final"] = True
                        break
            if hop["address"] and resolve:
                hop["name"] = reverse_dns(hop["address"], timeout=0.6)
            hops.append(hop)
            if sink:
                sink.write(format_hop(hop) + "\n")
                sink.flush()
            if hop["final"]:
                break
    finally:
        sock.close()
    return hops


def format_hop(hop):
    if not hop["address"]:
        return "%2d  * * *" % hop["ttl"]
    times = "  ".join("%.2f ms" % r for r in hop["rtts"]) or "no reply"
    label = hop["address"] + (" (%s)" % hop["name"] if hop["name"] else "")
    return "%2d  %-45s %s" % (hop["ttl"], label, times)


def path_mtu(host, low=576, high=9000, timeout=1.0):
    """Binary-search the largest unfragmented ICMP payload that reaches `host`.

    Returns a dict with the discovered MTU, or an explanation when ICMP is filtered.
    """
    try:
        dest = socket.gethostbyname(host)
    except OSError as exc:
        raise NetToolError("cannot resolve %s: %s" % (host, exc))
    sock, raw_mode = _open_icmp_socket()
    ident = (os.getpid() + 2) & 0xFFFF
    try:
        try:
            sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
        except OSError as exc:
            raise NetToolError("cannot set DF bit: %s" % exc)
        sock.settimeout(timeout)

        def reaches(payload):
            pkt = _echo_packet(ident, payload & 0xFFFF, payload)
            try:
                sock.sendto(pkt, (dest, 0))
            except OSError as exc:
                if exc.errno == errno.EMSGSIZE:
                    return False, exc
                return False, exc
            deadline = time.time() + timeout
            while time.time() < deadline:
                if not select.select([sock], [], [], deadline - time.time())[0]:
                    continue
                data, addr = sock.recvfrom(2048)
                parsed = _parse_icmp(data, raw_mode)
                if parsed and parsed[0] == ICMP_ECHOREPLY:
                    return True, None
                if parsed and parsed[0] == ICMP_UNREACH and parsed[1] == 4:
                    return False, "fragmentation needed"
            return False, "timeout"

        ok_small, err = reaches(low - 28)
        if not ok_small:
            return {"host": host, "address": dest, "mtu": None,
                    "note": "no echo reply even at %d bytes (%s); ICMP may be blocked"
                            % (low, err)}
        best = low
        lo, hi = low, high
        while lo <= hi:
            mid = (lo + hi) // 2
            ok, _ = reaches(mid - 28)
            if ok:
                best = mid
                lo = mid + 1
            else:
                hi = mid - 1
        return {"host": host, "address": dest, "mtu": best,
                "note": "largest ICMP packet delivered with DF set"}
    finally:
        sock.close()
