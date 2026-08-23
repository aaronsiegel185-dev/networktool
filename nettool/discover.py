"""LAN host discovery: ARP sweep (fast and accurate on a local subnet), with ICMP and
TCP fallbacks for routed targets or unprivileged runs."""

import ipaddress
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor

from . import iface as ifmod
from . import oui
from .link import open_link
from .ping import ping
from .portscan import tcp_ping
from .util import NetToolError, is_root, mac_bytes, mac_str, reverse_dns

ETH_P_ARP = 0x0806
BROADCAST = b"\xff" * 6


def _arp_request(src_mac, src_ip, target_ip):
    eth = BROADCAST + src_mac + struct.pack("!H", ETH_P_ARP)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
    arp += src_mac + socket.inet_aton(src_ip)
    arp += b"\x00" * 6 + socket.inet_aton(target_ip)
    frame = eth + arp
    return frame + b"\x00" * max(0, 60 - len(frame))


def arp_sweep(ifname=None, cidr=None, timeout=3.0, rate=600.0, on_host=None):
    """Broadcast ARP requests across a subnet and collect the replies.

    rate: requests per second (throttled so cheap switches don't drop the burst).
    """
    ifname = ifname or ifmod.primary_interface()
    if not ifname:
        raise NetToolError("no interface found; pass -i <iface>")
    info = ifmod.describe(ifname)
    if not info["ipv4"]:
        raise NetToolError("%s has no IPv4 address, cannot ARP sweep" % ifname)
    if cidr:
        network = ipaddress.ip_network(cidr, strict=False)
    else:
        network = ipaddress.ip_network("%s/%d" % (info["ipv4"], info["prefixlen"] or 24),
                                       strict=False)
    if network.num_addresses > 65536:
        raise NetToolError("%s is too large to sweep (%d addresses)"
                           % (network, network.num_addresses))
    src_mac = mac_bytes(info["mac"])
    src_ip = info["ipv4"]

    link = open_link(ifname, promisc=False, snaplen=2048)
    found = {}
    targets = [str(h) for h in network.hosts()] if network.prefixlen < 31 \
        else [str(h) for h in network]
    delay = 1.0 / rate if rate > 0 else 0

    def drain(deadline):
        while time.time() < deadline:
            batch = link.read(timeout=max(0.01, min(0.2, deadline - time.time())))
            if not batch:
                continue
            for data, _ts in batch:
                if len(data) < 42:
                    continue
                if struct.unpack("!H", data[12:14])[0] != ETH_P_ARP:
                    continue
                if struct.unpack("!H", data[20:22])[0] != 2:      # replies only
                    continue
                sha = mac_str(data[22:28])
                spa = socket.inet_ntoa(data[28:32])
                if spa in found:
                    continue
                entry = {"ip": spa, "mac": sha, "vendor": oui.lookup(sha),
                         "method": "arp", "iface": ifname}
                found[spa] = entry
                if on_host:
                    on_host(entry)

    try:
        for target in targets:
            if target == src_ip:
                continue
            try:
                link.write(_arp_request(src_mac, src_ip, target))
            except OSError as exc:
                raise NetToolError("ARP send failed on %s: %s" % (ifname, exc))
            if delay:
                drain(time.time() + delay)
        drain(time.time() + timeout)
    finally:
        link.close()
    return sorted(found.values(), key=lambda h: tuple(int(o) for o in h["ip"].split(".")))


def sweep_icmp(hosts, timeout=1.0, workers=64, on_host=None):
    """Ping sweep. Works across routers, but hosts commonly firewall ICMP."""
    alive = []

    def probe(ip):
        try:
            stats = ping(ip, count=1, interval=0, timeout=timeout)
        except NetToolError:
            return None
        if stats["received"]:
            return {"ip": ip, "mac": "", "vendor": "", "method": "icmp",
                    "rtt_ms": stats["rtt_avg"]}
        return None

    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(hosts)))) as pool:
        for res in pool.map(probe, hosts):
            if res:
                alive.append(res)
                if on_host:
                    on_host(res)
    return sorted(alive, key=lambda h: tuple(int(o) for o in h["ip"].split(".")))


def sweep_tcp(hosts, ports=(443, 80, 22, 445, 3389), timeout=0.7, workers=128,
              on_host=None):
    """Connect-probe sweep: the fallback that works without any privileges."""
    alive = []

    def probe(ip):
        ok, port, rtt = tcp_ping(ip, ports, timeout)
        if ok:
            return {"ip": ip, "mac": "", "vendor": "", "method": "tcp:%d" % port,
                    "rtt_ms": rtt}
        return None

    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(hosts)))) as pool:
        for res in pool.map(probe, hosts):
            if res:
                alive.append(res)
                if on_host:
                    on_host(res)
    return sorted(alive, key=lambda h: tuple(int(o) for o in h["ip"].split(".")))


def enrich(hosts, resolve=True, arp_fill=True):
    """Add reverse-DNS names, and MACs from the kernel ARP cache where missing."""
    arp = {e["ip"]: e for e in ifmod.arp_table()} if arp_fill else {}
    for host in hosts:
        if arp_fill and not host.get("mac"):
            entry = arp.get(host["ip"])
            if entry and not entry["incomplete"]:
                host["mac"] = entry["mac"]
                host["vendor"] = oui.lookup(entry["mac"])
        if resolve and not host.get("name"):
            host["name"] = reverse_dns(host["ip"], timeout=0.8)
    return hosts


def find_duplicate_ips(hosts):
    """Two MACs claiming one IP is a classic, hard-to-spot outage cause."""
    by_ip = {}
    for host in hosts:
        if host.get("mac"):
            by_ip.setdefault(host["ip"], set()).add(host["mac"])
    return {ip: sorted(macs) for ip, macs in by_ip.items() if len(macs) > 1}


def discover(ifname=None, cidr=None, method="auto", timeout=3.0, resolve=True,
             on_host=None):
    """Pick the best available discovery method and run it."""
    if method == "auto":
        method = "arp" if (is_root() and not cidr_is_remote(ifname, cidr)) else "tcp"
    if method == "arp":
        hosts = arp_sweep(ifname, cidr, timeout=timeout, on_host=on_host)
    elif method == "icmp":
        hosts = sweep_icmp(_expand(ifname, cidr), timeout=1.0, on_host=on_host)
    elif method == "tcp":
        hosts = sweep_tcp(_expand(ifname, cidr), on_host=on_host)
    else:
        raise NetToolError("unknown discovery method: %s" % method)
    return enrich(hosts, resolve=resolve), method


def _expand(ifname, cidr):
    if not cidr:
        ifname = ifname or ifmod.primary_interface()
        info = ifmod.describe(ifname) if ifname else None
        if not info or not info["ipv4"]:
            raise NetToolError("no subnet to scan; pass a CIDR")
        cidr = "%s/%d" % (info["ipv4"], info["prefixlen"] or 24)
    network = ipaddress.ip_network(cidr, strict=False)
    if network.num_addresses > 65536:
        raise NetToolError("%s is too large to sweep" % network)
    return [str(h) for h in network.hosts()]


def cidr_is_remote(ifname, cidr):
    """True when the target subnet is not on the given interface's link."""
    if not cidr:
        return False
    ifname = ifname or ifmod.primary_interface()
    if not ifname:
        return True
    info = ifmod.describe(ifname)
    if not info["ipv4"] or not info["prefixlen"]:
        return True
    local = ipaddress.ip_network("%s/%d" % (info["ipv4"], info["prefixlen"]), strict=False)
    try:
        target = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return True
    return not target.subnet_of(local)
