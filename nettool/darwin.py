"""macOS (Darwin) implementations of the platform-specific inventory and Wi-Fi calls.

Linux exposes all of this through /proc, /sys and netlink. macOS does not, so the data
comes from the BSD userland tools that ship with every install - ifconfig, netstat, arp,
scutil - plus system_profiler and wdutil for the radio. Everything here is split into a
thin command wrapper and a pure parser so the parsers can be tested anywhere.
"""

import json
import re
import time

from .util import NetToolError, run_cmd

_CACHE_TTL = 2.0
_interface_cache = (0.0, None)

WIFI_CHANNEL_RE = re.compile(r"(?:(\d)g)?(\d+)(?:/(\d+))?")


# --- interfaces ------------------------------------------------------------


def parse_ifconfig(text):
    """Parse `ifconfig -a` into a dict of interface records."""
    interfaces = {}
    current = None
    for raw in text.splitlines():
        if not raw:
            continue
        if not raw[0].isspace():
            header = re.match(
                r"^([A-Za-z0-9._-]+):\s*flags=([0-9a-fA-F]+)<([^>]*)>(?:.*\bmtu\s+(\d+))?",
                raw)
            if not header:
                current = None
                continue
            name = header.group(1)
            # ifconfig prints the flag word in hex, without an 0x prefix.
            flags = int(header.group(2), 16)
            current = {
                "name": name,
                "flags": flags,
                "flag_names": [f for f in header.group(3).split(",") if f],
                "mtu": int(header.group(4)) if header.group(4) else 0,
                "mac": "",
                "ipv4": "",
                "netmask": "",
                "prefixlen": 0,
                "broadcast": "",
                "ipv6": [],
                "media": "",
                "status": "",
                "up": bool(flags & 0x1),
                "running": bool(flags & 0x40),
                "loopback": bool(flags & 0x8),
                "promisc": bool(flags & 0x100),
            }
            interfaces[name] = current
            continue
        if current is None:
            continue
        line = raw.strip()
        if line.startswith("ether "):
            current["mac"] = line.split()[1].lower()
        elif line.startswith("inet ") and "-->" not in line:
            fields = line.split()
            current["ipv4"] = fields[1]
            if "netmask" in fields:
                mask_hex = fields[fields.index("netmask") + 1]
                current["netmask"], current["prefixlen"] = _mask_from_hex(mask_hex)
            if "broadcast" in fields:
                current["broadcast"] = fields[fields.index("broadcast") + 1]
        elif line.startswith("inet6 "):
            addr = line.split()[1]
            prefix = 64
            fields = line.split()
            if "prefixlen" in fields:
                try:
                    prefix = int(fields[fields.index("prefixlen") + 1])
                except (ValueError, IndexError):
                    pass
            current["ipv6"].append("%s/%d" % (addr, prefix))
        elif line.startswith("media:"):
            current["media"] = line.split(":", 1)[1].strip()
        elif line.startswith("status:"):
            current["status"] = line.split(":", 1)[1].strip()
    return interfaces


def _mask_from_hex(value):
    """'0xffffff00' -> ('255.255.255.0', 24). Also accepts dotted masks."""
    text = value.strip()
    if text.startswith("0x") or text.startswith("0X"):
        try:
            mask = int(text, 16)
        except ValueError:
            return "", 0
    elif "." in text:
        parts = [int(p) for p in text.split(".")]
        mask = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    else:
        return "", 0
    dotted = "%d.%d.%d.%d" % ((mask >> 24) & 0xFF, (mask >> 16) & 0xFF,
                              (mask >> 8) & 0xFF, mask & 0xFF)
    return dotted, bin(mask).count("1")


def parse_media(media):
    """`media: autoselect (1000baseT <full-duplex>)` -> (speed_mbps, duplex)."""
    if not media:
        return None, ""
    speed = None
    match = re.search(r"(\d+)\s*(G|g)?base", media)
    if match:
        speed = int(match.group(1))
        if match.group(2):                       # 10Gbase-T and friends
            speed *= 1000
    duplex = ""
    if "full-duplex" in media:
        duplex = "full"
    elif "half-duplex" in media:
        duplex = "half"
    return speed, duplex


def parse_netstat_counters(text):
    """Parse `netstat -ibn` into {iface: counters}. The <Link#n> row carries the totals."""
    counters = {}
    indexes = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10 or fields[0] == "Name":
            continue
        name = fields[0]
        network = fields[2] if len(fields) > 2 else ""
        if not network.startswith("<Link#"):
            continue
        index = re.search(r"<Link#(\d+)>", network)
        if index:
            indexes[name] = int(index.group(1))
        # Layout: Name Mtu Network [Address] Ipkts Ierrs Ibytes Opkts Oerrs Obytes [Coll]
        # The Address column is empty on some rows, so read the trailing run of integers
        # rather than counting columns from the left.
        tail = []
        for field in reversed(fields):
            if field.isdigit():
                tail.append(int(field))
            else:
                break
        values = list(reversed(tail))
        if len(values) >= 7:
            values = values[-7:]
        if len(values) >= 6:
            rx_packets, rx_errors, rx_bytes, tx_packets, tx_errors, tx_bytes = values[:6]
            collisions = values[6] if len(values) > 6 else 0
            counters[name] = {
                "rx_packets": rx_packets,
                "rx_errors": rx_errors,
                "rx_bytes": rx_bytes,
                "tx_packets": tx_packets,
                "tx_errors": tx_errors,
                "tx_bytes": tx_bytes,
                "rx_dropped": 0,
                "tx_dropped": 0,
                "collisions": collisions,
            }
    return counters, indexes


def parse_netstat_routes(text):
    """Parse `netstat -rn -f inet` into the same shape as Linux /proc/net/route."""
    routes = []
    started = False
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "Destination":
            started = True
            continue
        if not started or len(fields) < 4:
            continue
        dest, gateway, flags = fields[0], fields[1], fields[2]
        iface = fields[3] if len(fields) > 3 else ""
        if not re.match(r"^[a-z]+\d", iface or ""):
            # Some rows carry an extra column before the interface name.
            iface = next((f for f in fields[3:] if re.match(r"^[a-z]+\d", f)), iface)
        dest_ip, prefixlen = _normalise_destination(dest)
        if dest_ip is None:
            continue
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", gateway):
            gateway = "0.0.0.0"           # link#12, or a MAC for a directly attached host
        routes.append({
            "iface": iface,
            "dest": dest_ip,
            "gateway": gateway,
            "prefixlen": prefixlen,
            "flags": flags,
            "metric": 0,
        })
    return routes


def _normalise_destination(dest):
    """netstat abbreviates: 'default', '192.168.1', '10.1/16', '192.168.1.1/32'."""
    if dest == "default":
        return "0.0.0.0", 0
    prefix = None
    if "/" in dest:
        dest, prefix_text = dest.split("/", 1)
        try:
            prefix = int(prefix_text)
        except ValueError:
            prefix = None
    if not re.match(r"^\d+(\.\d+){0,3}$", dest):
        return None, 0                     # link-local, IPv6 or a MAC address row
    octets = dest.split(".")
    if prefix is None:
        prefix = 8 * len(octets)
    while len(octets) < 4:
        octets.append("0")
    return ".".join(octets), prefix


def parse_arp(text):
    """Parse `arp -an`: '? (192.168.1.1) at 3c:22:fb:11:22:33 on en0 ifscope [ethernet]'."""
    entries = []
    for line in text.splitlines():
        match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)(?:\s+on\s+(\S+))?", line)
        if not match:
            continue
        mac = match.group(2)
        incomplete = "incomplete" in mac
        if not incomplete:
            # macOS prints 3c:22:fb:1:2:33 - pad each octet so it matches everywhere else.
            mac = ":".join("%02x" % int(part, 16) for part in mac.split(":"))
        else:
            mac = "00:00:00:00:00:00"
        entries.append({
            "ip": match.group(1),
            "mac": mac,
            "iface": match.group(3) or "",
            "type": "0x1",
            "flags": "0x0" if incomplete else "0x2",
            "mask": "*",
            "incomplete": incomplete,
        })
    return entries


def parse_scutil_dns(text):
    """Pull nameservers and search domains out of `scutil --dns`."""
    servers, search = [], []
    for line in text.splitlines():
        line = line.strip()
        match = re.match(r"nameserver\[\d+\]\s*:\s*(\S+)", line)
        if match and match.group(1) not in servers:
            servers.append(match.group(1))
            continue
        match = re.match(r"(?:search domain|domain)\[\d+\]\s*:\s*(\S+)", line)
        if match and match.group(1) not in search:
            search.append(match.group(1))
    return servers, search


# --- command wrappers ------------------------------------------------------


def _run(argv, what):
    rc, out, err = run_cmd(argv, timeout=20)
    if rc != 0:
        raise NetToolError("%s failed: %s" % (what, (err or out).strip() or "rc=%d" % rc))
    return out


def interfaces(max_age=_CACHE_TTL):
    """{name: record} for every interface, with counters and media merged in.

    Cached briefly: the inventory helpers ask for this repeatedly and each call would
    otherwise spawn ifconfig and netstat.
    """
    global _interface_cache
    stamp, cached = _interface_cache
    if cached is not None and time.time() - stamp < max_age:
        return cached
    records = parse_ifconfig(_run(["ifconfig", "-a"], "ifconfig"))
    try:
        counters, indexes = parse_netstat_counters(_run(["netstat", "-ibn"], "netstat -ibn"))
    except NetToolError:
        counters, indexes = {}, {}
    empty = {"rx_bytes": 0, "tx_bytes": 0, "rx_packets": 0, "tx_packets": 0,
             "rx_errors": 0, "tx_errors": 0, "rx_dropped": 0, "tx_dropped": 0,
             "collisions": 0}
    for name, record in records.items():
        record["counters"] = counters.get(name, dict(empty))
        record["index"] = indexes.get(name, 0)
        speed, duplex = parse_media(record.get("media", ""))
        record["speed_mbps"] = speed
        record["duplex"] = duplex
        record["operstate"] = "up" if record.get("status") == "active" else (
            "down" if record.get("status") == "inactive" else
            ("up" if record["running"] else "unknown"))
        record["carrier"] = "1" if record.get("status") == "active" else (
            "0" if record.get("status") == "inactive" else "")
        record["wireless"] = is_wireless(name)
    _interface_cache = (time.time(), records)
    return records


def routes():
    return parse_netstat_routes(_run(["netstat", "-rn", "-f", "inet"], "netstat -rn"))


def arp_table():
    rc, out, _err = run_cmd(["arp", "-an"], timeout=15)
    return parse_arp(out) if rc == 0 else []


def dns_servers():
    rc, out, _err = run_cmd(["scutil", "--dns"], timeout=15)
    if rc == 0:
        servers, search = parse_scutil_dns(out)
        if servers:
            return servers, search
    return [], []


_wireless_cache = None


def wireless_interfaces():
    """Wi-Fi interface names, from `networksetup -listallhardwareports`."""
    global _wireless_cache
    if _wireless_cache is not None:
        return list(_wireless_cache)
    names = []
    rc, out, _err = run_cmd(["networksetup", "-listallhardwareports"], timeout=20)
    if rc == 0:
        block_is_wifi = False
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Hardware Port:"):
                port = line.split(":", 1)[1].strip().lower()
                block_is_wifi = port in ("wi-fi", "airport")
            elif line.startswith("Device:") and block_is_wifi:
                names.append(line.split(":", 1)[1].strip())
    if not names:
        # Fall back to asking each interface whether it has a wireless PHY.
        rc, out, _err = run_cmd(["networksetup", "-listallnetworkservices"], timeout=20)
        if "Wi-Fi" in out:
            names.append("en0")
    _wireless_cache = names
    return list(names)


def is_wireless(name):
    return name in wireless_interfaces()


# --- Wi-Fi -----------------------------------------------------------------


def parse_channel_spec(spec):
    """'5g36/80' or '36 (5GHz, 80MHz)' -> (channel, band, width_mhz)."""
    if not spec:
        return None, "", None
    text = str(spec).strip()
    match = re.match(r"^\s*(\d+)\s*\(\s*([\d.]+)\s*GHz(?:,\s*(\d+)\s*MHz)?", text, re.I)
    if match:
        band = match.group(2)
        band = "2.4" if band.startswith("2") else band.rstrip(".0")
        return int(match.group(1)), band, int(match.group(3)) if match.group(3) else None
    match = re.match(r"^(?:(\d)g)?(\d+)(?:/(\d+))?$", text, re.I)
    if match:
        channel = int(match.group(2))
        band = match.group(1)
        if band == "2":
            band = "2.4"
        elif band == "5":
            band = "5"
        elif band == "6":
            band = "6"
        else:
            band = "2.4" if channel <= 14 else "5"
        width = int(match.group(3)) if match.group(3) else None
        return channel, band, width
    match = re.match(r"^(\d+)$", text)
    if match:
        channel = int(match.group(1))
        return channel, "2.4" if channel <= 14 else "5", None
    return None, "", None


def parse_signal_noise(text):
    """'-47 dBm / -92 dBm' -> (-47.0, -92.0)."""
    if not text:
        return None, None
    numbers = re.findall(r"(-?\d+)\s*dBm", str(text))
    signal = float(numbers[0]) if numbers else None
    noise = float(numbers[1]) if len(numbers) > 1 else None
    return signal, noise


def _security_label(raw):
    if not raw:
        return []
    text = str(raw).replace("spairport_security_mode_", "").replace("_", " ").strip()
    lookup = {
        "none": ["open"], "open": ["open"], "wep": ["WEP"],
        "wpa2 personal": ["WPA2"], "wpa2 enterprise": ["WPA2", "802.1X/Enterprise"],
        "wpa3 personal": ["WPA3-SAE"], "wpa3 transition": ["WPA2", "WPA3-SAE"],
        "wpa3 enterprise": ["WPA3-SAE", "802.1X/Enterprise"],
        "wpa personal": ["WPA"], "wpa enterprise": ["WPA", "802.1X/Enterprise"],
    }
    return lookup.get(text.lower(), [text])


def is_redacted(*values):
    """True if macOS blanked a Wi-Fi name.

    Since Sonoma, a process without Location Services permission is handed
    "<redacted>" in place of the SSID and BSSID - by both wdutil and
    system_profiler. It is not an error, and the radio numbers alongside it are
    still real, so we blank the name and say why rather than printing the
    placeholder.
    """
    return any("redacted" in str(value).lower() for value in values)


def _walk_networks(node, found):
    """system_profiler's schema moves between releases; find the network dicts anywhere."""
    if isinstance(node, dict):
        if "_name" in node and any(key.startswith("spairport_network") or
                                   key == "spairport_signal_noise" for key in node):
            found.append(node)
        for value in node.values():
            _walk_networks(value, found)
    elif isinstance(node, list):
        for item in node:
            _walk_networks(item, found)
    return found


def parse_airport_json(payload):
    """Parse `system_profiler -json SPAirPortDataType` into nettool BSS dicts."""
    if isinstance(payload, (str, bytes)):
        payload = json.loads(payload)
    entries = _walk_networks(payload, [])
    networks = []
    seen = set()
    for entry in entries:
        name = entry.get("_name", "")
        channel, band, width = parse_channel_spec(entry.get("spairport_network_channel", ""))
        signal, noise = parse_signal_noise(entry.get("spairport_signal_noise", ""))
        key = (name, channel)
        if key in seen:
            continue
        seen.add(key)
        bssid = entry.get("spairport_network_bssid", "")
        # Dedup on the name macOS gave us, but never show the placeholder itself.
        redacted = is_redacted(name, bssid)
        networks.append({
            "ssid": "" if redacted else name,
            # macOS does not expose neighbouring BSSIDs without extra entitlements.
            "bssid": "" if redacted else bssid,
            "channel": channel,
            "band": band,
            "freq": None,
            "signal_dbm": signal,
            "noise_dbm": noise,
            "width_mhz": width or 20,
            "utilization_pct": None,
            "stations": None,
            "standards": _phy_modes(entry.get("spairport_network_phymode", "")),
            "security": _security_label(entry.get("spairport_security_mode", "")),
            "associated": False,
            "redacted": redacted,
        })
    return networks


def _phy_modes(mode):
    text = str(mode).lower()
    modes = []
    for token, name in (("11be", "be"), ("11ax", "ax"), ("11ac", "ac"), ("11n", "n")):
        if token in text:
            modes.append(name)
    return modes


def parse_wdutil(text):
    """Parse the WIFI block of `sudo wdutil info`."""
    info = {}
    in_wifi = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.upper().startswith("WIFI"):
            in_wifi = True
            continue
        if re.match(r"^[A-Z][A-Z ]+$", line) and not line.upper().startswith("WIFI"):
            in_wifi = False
            continue
        if not in_wifi or ":" not in line:
            continue
        key, value = line.split(":", 1)
        info[key.strip().lower()] = value.strip()

    def num(key):
        match = re.search(r"(-?\d+(?:\.\d+)?)", info.get(key, ""))
        return float(match.group(1)) if match else None

    ssid = info.get("ssid", "")
    bssid = info.get("bssid", "")
    redacted = is_redacted(ssid, bssid)
    channel, band, width = parse_channel_spec(info.get("channel", ""))
    signal = num("rssi")
    noise = num("noise")
    link = {
        "interface": info.get("interface name", ""),
        "connected": bool(ssid) and "not associated" not in ssid.lower(),
        "ssid": "" if redacted else ssid,
        "bssid": "" if redacted else bssid.lower(),
        "channel": channel,
        "band": band,
        "width_mhz": width,
        "freq": None,
        "signal_dbm": signal,
        "noise_dbm": noise,
        "snr_db": round(signal - noise, 1) if signal is not None and noise is not None else None,
        "tx_bitrate": info.get("tx rate", ""),
        "security": info.get("security", ""),
        "phy_mode": info.get("phy mode", ""),
        "mac": info.get("mac address", ""),
        "redacted": redacted,
    }
    return link


def parse_airport_current(payload):
    """Current association from system_profiler, for when wdutil is unavailable."""
    if isinstance(payload, (str, bytes)):
        payload = json.loads(payload)
    found = []

    def walk(node):
        if isinstance(node, dict):
            current = node.get("spairport_current_network_information")
            if isinstance(current, dict):
                found.append((node.get("_name", ""), current))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    if not found:
        return {"connected": False}
    iface, current = found[0]
    channel, band, width = parse_channel_spec(current.get("spairport_network_channel", ""))
    signal, noise = parse_signal_noise(current.get("spairport_signal_noise", ""))
    rate = current.get("spairport_network_rate")
    ssid = current.get("_name", "")
    bssid = current.get("spairport_network_bssid", "")
    redacted = is_redacted(ssid, bssid)
    return {
        "interface": iface,
        "connected": True,
        "ssid": "" if redacted else ssid,
        "bssid": "" if redacted else bssid,
        "channel": channel,
        "band": band,
        "width_mhz": width,
        "freq": None,
        "signal_dbm": signal,
        "noise_dbm": noise,
        "snr_db": round(signal - noise, 1) if signal is not None and noise is not None else None,
        "tx_bitrate": "%s Mbit/s" % rate if rate else "",
        "security": " ".join(_security_label(current.get("spairport_security_mode", ""))),
        "redacted": redacted,
    }


def _system_profiler_wifi():
    rc, out, err = run_cmd(["system_profiler", "-json", "SPAirPortDataType"], timeout=60)
    if rc != 0 or not out.strip():
        raise NetToolError("system_profiler could not read the Wi-Fi state: %s"
                           % (err.strip() or "no output"))
    try:
        return json.loads(out)
    except ValueError as exc:
        raise NetToolError("could not parse system_profiler output: %s" % exc)


def wifi_scan():
    """Nearby networks. Returns (networks, source)."""
    networks = parse_airport_json(_system_profiler_wifi())
    current = wifi_link(quiet=True)
    for net in networks:
        if current.get("ssid") and net["ssid"] == current["ssid"]:
            net["associated"] = True
            if net["signal_dbm"] is None:
                net["signal_dbm"] = current.get("signal_dbm")
    blanked = current.get("redacted") or any(n.get("redacted") for n in networks)
    same_channel = [n for n in networks
                    if current.get("channel") and n["channel"] == current["channel"]]
    if blanked and len(same_channel) == 1 and not any(n["associated"] for n in networks):
        # macOS hid the names, so the channel is the only handle we have left.
        ours = same_channel[0]
        ours["associated"] = True
        if ours["signal_dbm"] is None:
            ours["signal_dbm"] = current.get("signal_dbm")
        if not ours["ssid"] and current.get("ssid"):
            # We recovered our own name; the neighbours' stay hidden.
            ours["ssid"] = current["ssid"]
            ours["redacted"] = False
    if current.get("connected") and not any(n["associated"] for n in networks):
        networks.insert(0, {
            "ssid": current.get("ssid", ""),
            "bssid": current.get("bssid", ""),
            "channel": current.get("channel"),
            "band": current.get("band", ""),
            "freq": None,
            "signal_dbm": current.get("signal_dbm"),
            "noise_dbm": current.get("noise_dbm"),
            "width_mhz": current.get("width_mhz") or 20,
            "utilization_pct": None,
            "stations": None,
            "standards": _phy_modes(current.get("phy_mode", "")),
            "security": [current.get("security", "")] if current.get("security") else [],
            "associated": True,
            "redacted": current.get("redacted", False),
        })
    return networks, "system_profiler"


def parse_networksetup_ssid(text):
    """SSID out of `networksetup -getairportnetwork <iface>`.

    This reads the interface's own configuration rather than scanning the air,
    so macOS does not gate it on Location Services.
    """
    for line in text.splitlines():
        if ":" not in line:
            continue
        label, value = line.split(":", 1)
        if "current" in label.lower() and "network" in label.lower():
            name = value.strip()
            return "" if is_redacted(name) else name
    return ""


def parse_scutil_airport(text):
    """SSID_STR and BSSID out of a `scutil` AirPort dictionary."""
    info = {"ssid": "", "bssid": ""}
    for raw in text.splitlines():
        line = raw.strip()
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().upper()
        value = value.strip()
        if key == "SSID_STR" and not is_redacted(value):
            info["ssid"] = value
        elif key == "BSSID" and not is_redacted(value):
            info["bssid"] = value.lower()
    return info


def recover_hidden_names(ifname):
    """Names macOS blanked, read back from sources it does not redact.

    `wdutil` and `system_profiler` hand "<redacted>" to a process without the
    Location Services permission. The interface's stored configuration and the
    SystemConfiguration store still hold the real name, so ask them instead of
    making the user go change a privacy setting. BSSID needs root even here.
    """
    names = {"ssid": "", "bssid": ""}
    if not ifname:
        return names
    rc, out, _err = run_cmd(["networksetup", "-getairportnetwork", ifname], timeout=15)
    if rc == 0:
        names["ssid"] = parse_networksetup_ssid(out)
    rc, out, _err = run_cmd(
        ["scutil"], timeout=15,
        stdin="show State:/Network/Interface/%s/AirPort\n" % ifname)
    if rc == 0:
        found = parse_scutil_airport(out)
        names["ssid"] = names["ssid"] or found["ssid"]
        names["bssid"] = found["bssid"]
    return names


def _unredact(link):
    """Fill a blanked name back in, and say where it came from."""
    if not link.get("redacted"):
        return link
    names = recover_hidden_names(link.get("interface", ""))
    if names["ssid"]:
        link["ssid"] = names["ssid"]
    if names["bssid"]:
        link["bssid"] = names["bssid"]
    # Still redacted only if we could not recover the name after all.
    link["redacted"] = not link.get("ssid")
    return link


def wifi_link(quiet=False):
    """Current association. Prefers `wdutil info` (needs root), falls back to
    system_profiler, which cannot see the BSSID and hides the SSID without the
    Location Services permission."""
    rc, out, _err = run_cmd(["wdutil", "info"], timeout=30)
    if rc == 0 and "WIFI" in out.upper():
        link = parse_wdutil(out)
        if link.get("signal_dbm") is not None or link.get("ssid") or link.get("redacted"):
            link["source"] = "wdutil"
            return _unredact(link)
    try:
        link = parse_airport_current(_system_profiler_wifi())
        link["source"] = "system_profiler"
        return _unredact(link)
    except NetToolError:
        if quiet:
            return {"connected": False}
        raise
