"""One-shot network health check: link, addressing, gateway, DNS, internet, MTU, Wi-Fi.

Each check appends findings as (severity, message) where severity is one of
ok / info / warn / critical, so the CLI can print a verdict and scripts can gate on it.
"""

import socket
import time

from . import iface as ifmod
from . import wifi as wifimod
from .ping import ping, path_mtu
from .portscan import tcp_ping
from .util import NetToolError, is_root

SEVERITY_ORDER = {"ok": 0, "info": 1, "warn": 2, "critical": 3}
DEFAULT_INTERNET_TARGETS = [("1.1.1.1", 443), ("8.8.8.8", 53), ("9.9.9.9", 443)]
DEFAULT_DNS_NAMES = ["example.com", "cloudflare.com"]


class Report(object):
    def __init__(self):
        self.checks = []
        self.data = {}

    def add(self, name, severity, message):
        self.checks.append({"check": name, "severity": severity, "message": message})

    def worst(self):
        if not self.checks:
            return "ok"
        return max((c["severity"] for c in self.checks), key=lambda s: SEVERITY_ORDER.get(s, 0))

    def verdict(self):
        worst = self.worst()
        return {
            "ok": "Network looks healthy.",
            "info": "Network looks healthy (notes below).",
            "warn": "Network works but has problems worth fixing.",
            "critical": "Network is broken or badly degraded.",
        }[worst]


def check_interfaces(report, ifname=None):
    interfaces = ifmod.inventory()
    usable = [i for i in interfaces
              if i["up"] and not i["loopback"] and (i["ipv4"] or i["ipv6"])]
    report.data["interfaces"] = interfaces
    if not usable:
        report.add("link", "critical", "No interface is up with an IP address.")
        return None
    chosen = ifname or ifmod.primary_interface() or usable[0]["name"]
    info = ifmod.describe(chosen)
    report.data["interface"] = info
    if not info["up"]:
        report.add("link", "critical", "%s is administratively down." % chosen)
    elif info["carrier"] == "0":
        report.add("link", "critical", "%s has no carrier - cable unplugged or port down."
                   % chosen)
    else:
        speed = "%s Mb/s %s" % (info["speed_mbps"], info["duplex"]) \
            if info["speed_mbps"] and info["speed_mbps"] > 0 else "link up"
        report.add("link", "ok", "%s is up (%s, MTU %d)." % (chosen, speed, info["mtu"]))
    if info["duplex"] == "half":
        report.add("link", "warn", "%s negotiated half duplex - expect collisions and "
                                   "terrible throughput." % chosen)
    if info["speed_mbps"] == 10:
        report.add("link", "warn", "%s negotiated 10 Mb/s - suspect a bad cable or a "
                                   "forced switch port setting." % chosen)
    counters = info["counters"]
    total_rx = max(1, counters["rx_packets"])
    total_tx = max(1, counters["tx_packets"])
    err_rx = 100.0 * counters["rx_errors"] / total_rx
    err_tx = 100.0 * counters["tx_errors"] / total_tx
    if err_rx > 0.1 or err_tx > 0.1:
        report.add("link", "warn", "%s error rate rx %.2f%% / tx %.2f%% - cabling, SFP or "
                                   "duplex mismatch." % (chosen, err_rx, err_tx))
    if counters["rx_dropped"] > 100 and counters["rx_dropped"] > 0.01 * total_rx:
        report.add("link", "info", "%s has dropped %d received packets."
                   % (chosen, counters["rx_dropped"]))
    return info


def check_addressing(report, info):
    if info is None:
        return
    if not info["ipv4"]:
        report.add("address", "critical", "%s has no IPv4 address (DHCP failure?)."
                   % info["name"])
    elif info["ipv4"].startswith("169.254."):
        report.add("address", "critical", "%s self-assigned %s - it never got a DHCP "
                                          "lease." % (info["name"], info["ipv4"]))
    else:
        report.add("address", "ok", "%s/%d on %s."
                   % (info["ipv4"], info["prefixlen"], info["name"]))
    if info["ipv6"]:
        report.add("address", "info", "IPv6: %s" % ", ".join(info["ipv6"]))
    arp = [e for e in ifmod.arp_table() if e["iface"] == info["name"]]
    report.data["arp"] = arp
    macs = {}
    for entry in arp:
        if not entry["incomplete"]:
            macs.setdefault(entry["mac"], []).append(entry["ip"])
    duplicates = {mac: ips for mac, ips in macs.items() if len(ips) > 3}
    if duplicates:
        report.add("address", "info", "One MAC answers for several IPs (router or proxy "
                                      "ARP): %s" % ", ".join(duplicates))


def check_gateway(report, info, count=5):
    gateway, dev = ifmod.default_gateway()
    report.data["gateway"] = gateway
    if not gateway or gateway == "0.0.0.0":
        report.add("gateway", "critical", "No default route - nothing off-subnet is "
                                          "reachable.")
        return None
    arp = {e["ip"]: e for e in ifmod.arp_table()}
    entry = arp.get(gateway)
    if entry and entry["incomplete"]:
        report.add("gateway", "warn", "Gateway %s is in the ARP table but unresolved - "
                                      "it may be down." % gateway)
    try:
        stats = ping(gateway, count=count, interval=0.2, timeout=1.0)
    except NetToolError as exc:
        report.add("gateway", "info", "Could not ICMP the gateway (%s); trying TCP." % exc)
        alive, port, rtt = tcp_ping(gateway, (80, 443, 22, 53))
        if alive:
            report.add("gateway", "ok", "Gateway %s answers on TCP/%d (%.1f ms)."
                       % (gateway, port, rtt))
        else:
            report.add("gateway", "warn", "Gateway %s did not answer ICMP or TCP." % gateway)
        return gateway
    report.data["gateway_ping"] = stats
    if stats["received"] == 0:
        report.add("gateway", "critical", "Gateway %s is not answering pings - the LAN "
                                          "path is down or ICMP is filtered." % gateway)
    else:
        msg = "Gateway %s: %.1f ms avg, %.0f%% loss" % (
            gateway, stats["rtt_avg"], stats["loss_pct"])
        if stats["loss_pct"] > 20:
            report.add("gateway", "critical", msg + " - heavy loss on the local link.")
        elif stats["loss_pct"] > 0:
            report.add("gateway", "warn", msg + " - any loss to the gateway is a local "
                                                "problem (cable, Wi-Fi, switch port).")
        elif stats["rtt_avg"] > 30:
            report.add("gateway", "warn", msg + " - unusually slow for a local hop.")
        else:
            report.add("gateway", "ok", msg + ".")
        if stats.get("jitter") and stats["jitter"] > 30:
            report.add("gateway", "warn", "Gateway jitter %.0f ms - congestion or a "
                                          "struggling radio link." % stats["jitter"])
    return gateway


def check_dns(report, names=None, timeout=3.0):
    servers, search = ifmod.dns_servers()
    report.data["dns_servers"] = servers
    if not servers:
        report.add("dns", "critical", "No DNS servers configured.")
        return
    report.add("dns", "ok", "DNS servers: %s%s"
               % (", ".join(servers), " (search: %s)" % " ".join(search) if search else ""))
    for server in servers[:3]:
        alive, port, rtt = tcp_ping(server, (53,), timeout=1.0)
        if not alive:
            report.add("dns", "info", "DNS %s does not answer TCP/53 (normal for many "
                                      "resolvers)." % server)
    results = {}
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        for name in (names or DEFAULT_DNS_NAMES):
            start = time.time()
            try:
                addr = socket.gethostbyname(name)
                elapsed = (time.time() - start) * 1000
                results[name] = {"address": addr, "ms": elapsed}
            except OSError as exc:
                results[name] = {"error": str(exc)}
    finally:
        socket.setdefaulttimeout(old)
    report.data["dns_lookups"] = results
    failed = [n for n, r in results.items() if "error" in r]
    slow = [n for n, r in results.items() if r.get("ms", 0) > 500]
    if failed and len(failed) == len(results):
        report.add("dns", "critical", "DNS resolution is failing for %s."
                   % ", ".join(failed))
    elif failed:
        report.add("dns", "warn", "DNS resolution failed for %s." % ", ".join(failed))
    elif slow:
        report.add("dns", "warn", "DNS is slow (%s)."
                   % ", ".join("%s %.0f ms" % (n, results[n]["ms"]) for n in slow))
    else:
        ok_name = next(iter(results))
        report.add("dns", "ok", "DNS resolves (%s -> %s in %.0f ms)."
                   % (ok_name, results[ok_name]["address"], results[ok_name]["ms"]))


def check_internet(report, targets=None):
    targets = targets or DEFAULT_INTERNET_TARGETS
    reached = []
    for host, port in targets:
        alive, hit_port, rtt = tcp_ping(host, (port,), timeout=2.0)
        if alive:
            reached.append((host, hit_port, rtt))
    report.data["internet"] = [{"host": h, "port": p, "ms": r} for h, p, r in reached]
    if not reached:
        report.add("internet", "critical", "No TCP connection to any of %s - no working "
                                           "internet path (or a captive portal)."
                   % ", ".join("%s:%d" % t for t in targets))
        return
    host, port, rtt = reached[0]
    report.add("internet", "ok", "Internet reachable (%s:%d in %.0f ms)." % (host, port, rtt))
    try:
        stats = ping(reached[0][0], count=5, interval=0.2, timeout=1.5)
        report.data["internet_ping"] = stats
        if stats["received"]:
            level = "warn" if stats["loss_pct"] > 5 or stats["rtt_avg"] > 150 else "ok"
            report.add("internet", level, "Upstream latency %.0f ms avg, %.0f%% loss to %s."
                       % (stats["rtt_avg"], stats["loss_pct"], stats["address"]))
    except NetToolError:
        pass


def check_mtu(report, info, target=None):
    if info is None or not is_root():
        return
    gateway, _dev = ifmod.default_gateway()
    probe = target or gateway
    if not probe:
        return
    try:
        result = path_mtu(probe, low=576, high=min(info["mtu"], 9000))
    except NetToolError as exc:
        report.add("mtu", "info", "Path MTU check skipped: %s" % exc)
        return
    report.data["path_mtu"] = result
    if result["mtu"] is None:
        report.add("mtu", "info", "Path MTU to %s could not be measured (ICMP filtered)."
                   % probe)
    elif result["mtu"] < info["mtu"]:
        report.add("mtu", "warn", "Path MTU to %s is %d but %s is set to %d - oversized "
                                  "packets will be dropped (PPPoE/VPN/tunnel?)."
                   % (probe, result["mtu"], info["name"], info["mtu"]))
    else:
        report.add("mtu", "ok", "Path MTU to %s is %d, matching the interface."
                   % (probe, result["mtu"]))


def check_wifi(report, info):
    if info is None or not info["wireless"]:
        return
    try:
        state = wifimod.link(info["name"])
    except NetToolError as exc:
        report.add("wifi", "info", "Wi-Fi state unavailable: %s" % exc)
        return
    report.data["wifi_link"] = state
    if not state.get("connected") and state.get("signal_dbm") is None:
        report.add("wifi", "critical", "%s is not associated with any network." % info["name"])
        return
    sig = state.get("signal_dbm")
    label = "%s ch %s, %s dBm (%s)" % (state.get("ssid", "?"), state.get("channel", "?"),
                                       sig, state.get("rating"))
    if sig is None:
        report.add("wifi", "info", "Associated: %s" % state.get("ssid", "?"))
    elif sig < -75:
        report.add("wifi", "critical", label + " - too weak to be reliable.")
    elif sig < -67:
        report.add("wifi", "warn", label + " - below the -67 dBm floor for voice/video.")
    else:
        report.add("wifi", "ok", label + ".")
    if state.get("snr_db") is not None and state["snr_db"] < 20:
        report.add("wifi", "warn", "SNR %.0f dB - noise floor is high for this signal."
                   % state["snr_db"])
    station = state.get("station") or {}
    if station.get("retry_pct") is not None and station["retry_pct"] > 15:
        report.add("wifi", "warn", "Wi-Fi TX retries %.1f%% - interference or a weak link."
                   % station["retry_pct"])
    try:
        survey = [s for s in wifimod.survey_dump(info["name"]) if s.get("in_use")]
    except NetToolError:
        survey = []
    if survey and survey[0].get("busy_pct") is not None:
        busy = survey[0]["busy_pct"]
        level = "critical" if busy > 70 else ("warn" if busy > 40 else "ok")
        report.add("wifi", level, "Channel %s is %.0f%% busy (%.0f%% of that is traffic we "
                                  "cannot decode)." % (survey[0].get("channel", "?"), busy,
                                                       survey[0].get("interference_pct", 0)))


def run(ifname=None, skip=(), dns_names=None, internet_targets=None):
    """Run the full battery. Returns a Report."""
    report = Report()
    info = check_interfaces(report, ifname)
    if "address" not in skip:
        check_addressing(report, info)
    if "gateway" not in skip:
        check_gateway(report, info)
    if "dns" not in skip:
        check_dns(report, dns_names)
    if "internet" not in skip:
        check_internet(report, internet_targets)
    if "wifi" not in skip:
        check_wifi(report, info)
    if "mtu" not in skip:
        check_mtu(report, info)
    report.data["verdict"] = report.verdict()
    report.data["worst_severity"] = report.worst()
    return report
