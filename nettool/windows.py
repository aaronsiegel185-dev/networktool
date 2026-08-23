"""Windows platform support, over the tools every install already has.

Windows has no /sys/class/net and no ifconfig, so the facts come from
`ipconfig /all`, `route print`, `arp -a`, `getmac` and `netsh wlan`. Parsing
console output is not elegant, but it holds nettool to its one rule - nothing
outside the standard library - and these commands are present on every edition
back to Windows 7.

`netsh wlan` is the happy surprise: it reports SSID, BSSID, channel, signal,
radio type, band and per-BSS detail for every network in range, with no driver
and no elevation. The Wi-Fi views therefore work fully here, which is more than
macOS gives without a permission grant.

Everything is parsed from text passed in, so the whole module is testable on any
platform - the recordings under tests/ are real output.
"""

import re
import socket
import sys

from .util import NetToolError, run_cmd

IS_WINDOWS = sys.platform == "win32"

_CACHE_TTL = 2.0
_cache = {"at": 0.0, "value": None}


# --- ipconfig -------------------------------------------------------------

def _mac(text):
    """Windows writes MACs as 3C-22-FB-11-22-33."""
    cleaned = text.strip().replace("-", ":").lower()
    return cleaned if re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", cleaned) else ""


def _prefix_from_mask(mask):
    try:
        packed = socket.inet_aton(mask)
    except OSError:
        return 0
    return sum(bin(byte).count("1") for byte in packed)


def parse_ipconfig(text):
    """`ipconfig /all` into {name: record}.

    Adapters are keyed by their connection name ("Wi-Fi", "Ethernet"), which is
    what every other Windows command takes as an argument, rather than by the
    long description.
    """
    adapters = {}
    current = None
    last_key = ""
    for raw in text.splitlines():
        if not raw.strip():
            continue
        header = re.match(r"^(\S.*?adapter)\s+(.*?):\s*$", raw, re.IGNORECASE)
        if header:
            kind = header.group(1).strip()
            name = header.group(2).strip()
            current = {
                "name": name,
                "kind": kind,
                "description": "",
                "mac": "",
                "ipv4": "",
                "netmask": "",
                "prefixlen": 0,
                "broadcast": "",
                "ipv6": [],
                "gateway": "",
                "dhcp": False,
                "dns": [],
                "up": False,
                "running": False,
                "media_disconnected": False,
                "wireless": "wireless" in kind.lower() or "wi-fi" in name.lower(),
                "loopback": "loopback" in kind.lower() or "loopback" in name.lower(),
                "mtu": 1500,
                "index": 0,
                "operstate": "unknown",
                "carrier": "",
                "speed_mbps": None,
                "duplex": "",
                "promisc": False,
                "counters": {},
            }
            adapters[name] = current
            last_key = ""
            continue
        if current is None:
            continue
        if ":" not in raw:
            # A second DNS server is written as a bare indented value with no
            # key of its own, so it only makes sense next to the line above it.
            if last_key.startswith("dns servers") and raw.strip():
                current["dns"].append(raw.strip())
            continue
        key, value = raw.split(":", 1)
        key = key.strip(" .").lower()
        value = value.strip()
        last_key = key
        if key.startswith("description"):
            current["description"] = value
        elif key.startswith("physical address"):
            current["mac"] = _mac(value)
        elif key.startswith("media state"):
            current["media_disconnected"] = "disconnected" in value.lower()
        elif key.startswith("dhcp enabled"):
            current["dhcp"] = value.lower().startswith("yes")
        elif key.startswith("ipv4 address") or key.startswith("autoconfiguration ipv4"):
            current["ipv4"] = value.split("(")[0].strip()
        elif key.startswith("subnet mask"):
            current["netmask"] = value
            current["prefixlen"] = _prefix_from_mask(value)
        elif key.startswith("default gateway"):
            if value:
                current["gateway"] = value
        elif "ipv6 address" in key:
            address = value.split("(")[0].strip()
            if address:
                current["ipv6"].append(address)
        elif key.startswith("dns servers"):
            if value:
                current["dns"].append(value)

    for record in adapters.values():
        # Windows reports "Media State . . . : Media disconnected" only when down,
        # and simply omits the line otherwise.
        record["up"] = not record["media_disconnected"]
        record["running"] = record["up"] and bool(record["ipv4"])
        record["operstate"] = "up" if record["up"] else "down"
        record["carrier"] = "1" if record["up"] else "0"
    return adapters


def parse_route_print(text):
    """IPv4 routes out of `route print`."""
    routes = []
    in_table = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.lower().startswith("network destination"):
            in_table = True
            continue
        if not in_table:
            continue
        if line.startswith("=") or not line:
            if routes:
                break
            continue
        fields = line.split()
        if len(fields) < 5:
            continue
        destination, mask, gateway, iface = fields[0], fields[1], fields[2], fields[3]
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", destination):
            continue
        routes.append({
            "destination": "default" if destination == "0.0.0.0" else destination,
            "gateway": "" if gateway.lower() == "on-link" else gateway,
            "netmask": mask,
            "prefixlen": _prefix_from_mask(mask),
            "iface": iface,
            "metric": int(fields[4]) if fields[4].isdigit() else None,
            "flags": "",
        })
    return routes


def parse_arp(text):
    """`arp -a` into nettool's ARP records, keeping the interface each came from."""
    entries = []
    iface = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        header = re.match(r"^Interface:\s+(\S+)", line, re.IGNORECASE)
        if header:
            iface = header.group(1)
            continue
        fields = line.split()
        if len(fields) < 3 or not re.match(r"^\d+\.\d+\.\d+\.\d+$", fields[0]):
            continue
        mac = _mac(fields[1])
        if not mac:
            continue
        entries.append({
            "ip": fields[0],
            "mac": mac,
            "type": fields[2].lower(),
            "flags": "",
            "mask": "*",
            "iface": iface,
            "incomplete": False,
        })
    return entries


# --- netsh wlan -----------------------------------------------------------

def _signal_to_dbm(percent):
    """Windows reports signal as a percentage; convert to the dBm nettool uses.

    The mapping is the one Microsoft's WLAN API documents: 0% is -100 dBm, 100%
    is -50 dBm, linear between. It is a quantised view of the real RSSI rather
    than a measurement, so it lands on 2 dB steps - accurate enough to rate a
    link, not accurate enough to argue about.
    """
    try:
        value = float(percent)
    except (TypeError, ValueError):
        return None
    return round(value / 2.0 - 100.0, 1)


def _band_of(channel):
    if 1 <= channel <= 14:
        return "2.4"
    if 15 <= channel <= 196:
        return "5"
    return "6"


def _phy_modes(radio):
    """The 802.11 letters in a "Radio type" string.

    Ordered alternation with a word boundary, because a plain substring test
    finds "802.11a" inside "802.11ac" and reports a network as both.
    """
    return re.findall(r"802\.11(be|ax|ac|n|g|a)\b", str(radio).lower())


def parse_wlan_interfaces(text):
    """The current association, from `netsh wlan show interfaces`."""
    info = {}
    for raw in text.splitlines():
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        info[key.strip().lower()] = value.strip()
    if not info:
        return {"connected": False}

    state = info.get("state", "").lower()
    channel = info.get("channel", "")
    channel = int(channel) if channel.isdigit() else None
    signal = info.get("signal", "").rstrip("%")
    link = {
        "interface": info.get("name", ""),
        "connected": state == "connected",
        "ssid": info.get("ssid", ""),
        "bssid": _mac(info.get("bssid", "")),
        "channel": channel,
        "band": _band_of(channel) if channel else "",
        "freq": None,
        "signal_dbm": _signal_to_dbm(signal),
        "quality_pct": int(signal) if signal.isdigit() else None,
        "noise_dbm": None,
        "snr_db": None,
        "tx_bitrate": "%s Mbit/s" % info["transmit rate (mbps)"]
                      if info.get("transmit rate (mbps)") else "",
        "rx_bitrate": "%s Mbit/s" % info["receive rate (mbps)"]
                      if info.get("receive rate (mbps)") else "",
        "security": info.get("authentication", ""),
        "phy_mode": info.get("radio type", ""),
        "mac": _mac(info.get("physical address", "")),
        "width_mhz": None,
        "redacted": False,
        "source": "netsh",
    }
    return link


def parse_wlan_networks(text):
    """Every BSS in range, from `netsh wlan show networks mode=bssid`.

    One SSID block holds many BSS blocks, and the interesting facts are split
    between them: the name and security come from the SSID, the address, signal
    and channel from each BSS. A network is only really a list of BSSes, so that
    is what this returns - one row each, which is what the analysis wants.
    """
    networks = []
    ssid = ""
    security = []
    radio = ""
    current = None

    def flush():
        if current is not None:
            networks.append(current)

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        head = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line)
        if head:
            flush()
            current = None
            ssid = head.group(1).strip()
            security = []
            radio = ""
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key in ("authentication", "encryption"):
            if value and value.lower() != "none":
                security.append(value)
            continue
        bss = re.match(r"^bssid\s+\d+$", key)
        if bss:
            flush()
            current = {
                "ssid": ssid,
                "bssid": _mac(value),
                "channel": None,
                "band": "",
                "freq": None,
                "signal_dbm": None,
                "quality_pct": None,
                "noise_dbm": None,
                "width_mhz": None,
                "utilization_pct": None,
                "stations": None,
                "standards": [],
                "security": list(security),
                "associated": False,
                "redacted": False,
            }
            continue
        if current is None:
            continue
        if key == "signal":
            percent = value.rstrip("%")
            current["quality_pct"] = int(percent) if percent.isdigit() else None
            current["signal_dbm"] = _signal_to_dbm(percent)
        elif key == "channel":
            channel = value.split()[0] if value else ""
            if channel.isdigit():
                current["channel"] = int(channel)
                current["band"] = _band_of(current["channel"])
        elif key == "radio type":
            radio = value
            current["standards"] = _phy_modes(value)
        elif key == "band":
            # Windows 11 states the band outright; trust it over the channel.
            if "2.4" in value:
                current["band"] = "2.4"
            elif value.strip().startswith("5"):
                current["band"] = "5"
            elif value.strip().startswith("6"):
                current["band"] = "6"
    flush()
    for network in networks:
        if not network["standards"]:
            network["standards"] = _phy_modes(radio)
    return networks


# --- running the commands -------------------------------------------------

def _run(argv, what, timeout=30):
    rc, out, err = run_cmd(argv, timeout=timeout)
    if rc == -1:
        raise NetToolError("%s is not available on this system" % argv[0])
    if rc != 0 and not out.strip():
        raise NetToolError("%s failed: %s" % (what, (err or out).strip() or "no output"))
    return out


def interfaces(max_age=_CACHE_TTL):
    """{name: record} for every adapter, cached briefly.

    `ipconfig /all` is one process for the whole inventory, and nettool asks for
    it several times per refresh, so a short cache keeps a Wi-Fi tab redraw from
    spawning a dozen of them.
    """
    import time

    now = time.time()
    if _cache["value"] is not None and now - _cache["at"] < max_age:
        return _cache["value"]
    adapters = parse_ipconfig(_run(["ipconfig", "/all"], "ipconfig"))
    for name, record in adapters.items():
        record["wireless"] = record["wireless"] or _is_wlan(name)
    _cache["value"] = adapters
    _cache["at"] = now
    return adapters


_wlan_names = {"at": 0.0, "value": None}


def wireless_interfaces():
    """Adapter names netsh reports as wireless."""
    import time

    now = time.time()
    if _wlan_names["value"] is not None and now - _wlan_names["at"] < _CACHE_TTL:
        return _wlan_names["value"]
    names = []
    rc, out, _err = run_cmd(["netsh", "wlan", "show", "interfaces"], timeout=30)
    if rc == 0:
        for raw in out.splitlines():
            if ":" not in raw:
                continue
            key, value = raw.split(":", 1)
            if key.strip().lower() == "name":
                names.append(value.strip())
    _wlan_names["value"] = names
    _wlan_names["at"] = now
    return names


def _is_wlan(name):
    return name in wireless_interfaces()


def is_wireless(name):
    record = interfaces().get(name)
    return bool(record and record["wireless"])


def routes():
    return parse_route_print(_run(["route", "print", "-4"], "route print"))


def arp_table():
    return parse_arp(_run(["arp", "-a"], "arp"))


def dns_servers():
    """(servers, search domains) merged across adapters, in adapter order."""
    servers, search = [], []
    for record in interfaces().values():
        for address in record["dns"]:
            if address not in servers:
                servers.append(address)
    text = _run(["ipconfig", "/all"], "ipconfig")
    for raw in text.splitlines():
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        if key.strip(" .").lower().startswith("primary dns suffix") and value.strip():
            if value.strip() not in search:
                search.append(value.strip())
    return servers, search


def wifi_link(ifname=None):
    text = _run(["netsh", "wlan", "show", "interfaces"], "netsh wlan show interfaces")
    return parse_wlan_interfaces(text)


def wifi_scan(refresh=True):
    """(networks, source). `refresh` asks the radio to sweep before reporting."""
    if refresh:
        # Not every build accepts it, and a failure here is not worth an error -
        # the scan below still returns the cached view.
        run_cmd(["netsh", "wlan", "refresh", "hostednetwork"], timeout=10)
    text = _run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                "netsh wlan show networks", timeout=45)
    networks = parse_wlan_networks(text)
    current = wifi_link()
    for network in networks:
        if current.get("bssid") and network["bssid"] == current["bssid"]:
            network["associated"] = True
    return networks, "netsh"


def is_admin():
    """Whether we hold the elevation raw capture needs."""
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
