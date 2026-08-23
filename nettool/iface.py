"""Interface, address, route, ARP and DNS inventory.

Linux reads /proc, /sys and ioctls directly; macOS gets the same shapes from the BSD
userland tools in `nettool.darwin`. Both return identical dictionaries so every other
module is platform agnostic.
"""

import fcntl
import os
import socket
import struct
import sys

from .util import NetToolError, mac_str

IS_DARWIN = sys.platform == "darwin"

SIOCGIFADDR = 0x8915
SIOCGIFBRDADDR = 0x8919
SIOCGIFNETMASK = 0x891B
SIOCGIFFLAGS = 0x8913
SIOCGIFHWADDR = 0x8927
SIOCGIFMTU = 0x8921
SIOCGIFINDEX = 0x8933

IFF_UP = 0x1
IFF_BROADCAST = 0x2
IFF_LOOPBACK = 0x8
IFF_POINTOPOINT = 0x10
IFF_RUNNING = 0x40
IFF_PROMISC = 0x100

SYS_NET = "/sys/class/net"


def _ioctl(sock, request, name):
    return fcntl.ioctl(sock.fileno(), request, struct.pack("256s", name.encode()[:15]))


def _read(path, default=""):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return default


def list_names():
    if IS_DARWIN:
        from . import darwin

        return sorted(darwin.interfaces())
    try:
        names = sorted(os.listdir(SYS_NET))
    except OSError:
        raise NetToolError("cannot read %s - this platform is not supported" % SYS_NET)
    return names


def is_wireless(name):
    if IS_DARWIN:
        from . import darwin

        return darwin.is_wireless(name)
    return os.path.exists(os.path.join(SYS_NET, name, "wireless")) or os.path.exists(
        os.path.join(SYS_NET, name, "phy80211")
    )


def ipv4_info(name):
    """(addr, netmask, prefixlen, broadcast) - empty strings when unset."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = mask = bcast = ""
    prefix = 0
    try:
        try:
            addr = socket.inet_ntoa(_ioctl(sock, SIOCGIFADDR, name)[20:24])
        except OSError:
            return "", "", 0, ""
        try:
            mask = socket.inet_ntoa(_ioctl(sock, SIOCGIFNETMASK, name)[20:24])
            prefix = bin(struct.unpack("!I", socket.inet_aton(mask))[0]).count("1")
        except OSError:
            pass
        try:
            bcast = socket.inet_ntoa(_ioctl(sock, SIOCGIFBRDADDR, name)[20:24])
        except OSError:
            pass
    finally:
        sock.close()
    return addr, mask, prefix, bcast


def ipv6_addrs(name):
    out = []
    for line in _read("/proc/net/if_inet6").splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[5] == name:
            raw = parts[0]
            grouped = ":".join(raw[i:i + 4] for i in range(0, 32, 4))
            try:
                addr = socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, grouped))
            except OSError:
                addr = grouped
            out.append("%s/%d" % (addr, int(parts[2], 16)))
    return out


def flags(name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        raw = _ioctl(sock, SIOCGIFFLAGS, name)
        return struct.unpack("H", raw[16:18])[0]
    except OSError:
        return 0
    finally:
        sock.close()


def mtu(name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return struct.unpack("i", _ioctl(sock, SIOCGIFMTU, name)[16:20])[0]
    except OSError:
        return int(_read(os.path.join(SYS_NET, name, "mtu"), "0") or 0)
    finally:
        sock.close()


def hwaddr(name):
    mac = _read(os.path.join(SYS_NET, name, "address"))
    if mac:
        return mac
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return mac_str(_ioctl(sock, SIOCGIFHWADDR, name)[18:24])
    except OSError:
        return ""
    finally:
        sock.close()


def ifindex(name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return struct.unpack("i", _ioctl(sock, SIOCGIFINDEX, name)[16:20])[0]
    except OSError:
        return int(_read(os.path.join(SYS_NET, name, "ifindex"), "0") or 0)
    finally:
        sock.close()


def counters(name):
    base = os.path.join(SYS_NET, name, "statistics")
    keys = ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors",
            "rx_dropped", "tx_dropped", "collisions")
    return {k: int(_read(os.path.join(base, k), "0") or 0) for k in keys}


def _from_darwin(record):
    """Normalise a nettool.darwin interface record into the shape describe() returns."""
    return {
        "name": record["name"],
        "index": record.get("index", 0),
        "mac": record.get("mac", ""),
        "ipv4": record.get("ipv4", ""),
        "netmask": record.get("netmask", ""),
        "prefixlen": record.get("prefixlen", 0),
        "broadcast": record.get("broadcast", ""),
        "ipv6": record.get("ipv6", []),
        "mtu": record.get("mtu", 0),
        "operstate": record.get("operstate", "unknown"),
        "carrier": record.get("carrier", ""),
        "speed_mbps": record.get("speed_mbps"),
        "duplex": record.get("duplex", ""),
        "wireless": record.get("wireless", False),
        "up": record.get("up", False),
        "running": record.get("running", False),
        "loopback": record.get("loopback", False),
        "promisc": record.get("promisc", False),
        "counters": record.get("counters", {}),
    }


def describe(name):
    if IS_DARWIN:
        from . import darwin

        records = darwin.interfaces()
        if name not in records:
            raise NetToolError("no such interface: %s" % name)
        return _from_darwin(records[name])
    addr, mask, prefix, bcast = ipv4_info(name)
    fl = flags(name)
    speed = _read(os.path.join(SYS_NET, name, "speed"))
    duplex = _read(os.path.join(SYS_NET, name, "duplex"))
    return {
        "name": name,
        "index": ifindex(name),
        "mac": hwaddr(name),
        "ipv4": addr,
        "netmask": mask,
        "prefixlen": prefix,
        "broadcast": bcast,
        "ipv6": ipv6_addrs(name),
        "mtu": mtu(name),
        "operstate": _read(os.path.join(SYS_NET, name, "operstate"), "unknown"),
        "carrier": _read(os.path.join(SYS_NET, name, "carrier"), ""),
        "speed_mbps": int(speed) if speed.lstrip("-").isdigit() else None,
        "duplex": duplex,
        "wireless": is_wireless(name),
        "up": bool(fl & IFF_UP),
        "running": bool(fl & IFF_RUNNING),
        "loopback": bool(fl & IFF_LOOPBACK),
        "promisc": bool(fl & IFF_PROMISC),
        "counters": counters(name),
    }


def inventory(include_down=True):
    out = []
    if IS_DARWIN:
        from . import darwin

        for name, record in sorted(darwin.interfaces().items()):
            info = _from_darwin(record)
            if not include_down and not info["up"]:
                continue
            out.append(info)
        return out
    for name in list_names():
        info = describe(name)
        if not include_down and not info["up"]:
            continue
        out.append(info)
    return out


def routes():
    """IPv4 routing table (from /proc/net/route, or netstat -rn on macOS)."""
    if IS_DARWIN:
        from . import darwin

        return darwin.routes()
    out = []
    lines = _read("/proc/net/route").splitlines()
    for line in lines[1:]:
        f = line.split()
        if len(f) < 11:
            continue
        def h2ip(x):
            return socket.inet_ntoa(struct.pack("<I", int(x, 16)))
        mask = int(f[7], 16)
        prefix = bin(mask).count("1")
        out.append({
            "iface": f[0],
            "dest": h2ip(f[1]),
            "gateway": h2ip(f[2]),
            "prefixlen": prefix,
            "flags": int(f[3], 16),
            "metric": int(f[6]),
        })
    return out


def default_gateway():
    """(gateway_ip, iface) for the lowest-metric default route, or (None, None)."""
    best = None
    for r in routes():
        if r["dest"] == "0.0.0.0" and r["prefixlen"] == 0:
            if best is None or r["metric"] < best["metric"]:
                best = r
    if best is None:
        return None, None
    return best["gateway"], best["iface"]


def primary_interface():
    """Best guess at the interface carrying traffic to the internet."""
    _, dev = default_gateway()
    if dev:
        return dev
    for info in inventory():
        if info["up"] and not info["loopback"] and info["ipv4"]:
            return info["name"]
    return None


def arp_table():
    if IS_DARWIN:
        from . import darwin

        return darwin.arp_table()
    out = []
    for line in _read("/proc/net/arp").splitlines()[1:]:
        f = line.split()
        if len(f) >= 6:
            out.append({
                "ip": f[0], "type": f[1], "flags": f[2],
                "mac": f[3], "mask": f[4], "iface": f[5],
                "incomplete": f[3] == "00:00:00:00:00:00" or f[2] == "0x0",
            })
    return out


def dns_servers():
    if IS_DARWIN:
        from . import darwin

        servers, search = darwin.dns_servers()
        if servers:
            return servers, search
    servers, search = [], []
    for path in ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"):
        text = _read(path)
        if not text:
            continue
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) > 1 and parts[1] not in servers:
                    servers.append(parts[1])
            elif line.startswith(("search", "domain")):
                search.extend(line.split()[1:])
        if servers:
            break
    return servers, search
