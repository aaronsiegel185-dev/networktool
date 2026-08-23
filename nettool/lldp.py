"""LLDP (802.1AB) and CDP neighbour discovery: listen on a link and decode what the
switch is advertising - switch name, port, VLAN, PoE, MTU, management IP.

That single answer ("which switch port am I plugged into, and what VLAN is it in?")
resolves a large share of on-site LAN problems.
"""

import socket
import struct
import time

from . import iface as ifmod
from . import oui
from .link import open_link
from .pcap import PcapReader, PcapWriter, LINKTYPE_ETHERNET
from .util import NetToolError, mac_str

LLDP_ETHERTYPE = 0x88CC
LLDP_MULTICAST = {"01:80:c2:00:00:0e", "01:80:c2:00:00:03", "01:80:c2:00:00:00"}
CDP_MULTICAST = "01:00:0c:cc:cc:cc"

CHASSIS_SUBTYPE = {1: "chassis-component", 2: "interface-alias", 3: "port-component",
                   4: "mac", 5: "network-address", 6: "interface-name",
                   7: "locally-assigned"}
PORT_SUBTYPE = {1: "interface-alias", 2: "port-component", 3: "mac",
                4: "network-address", 5: "interface-name", 6: "agent-circuit-id",
                7: "locally-assigned"}
CAPS = [(0x01, "Other"), (0x02, "Repeater"), (0x04, "Bridge"), (0x08, "WLAN-AP"),
        (0x10, "Router"), (0x20, "Telephone"), (0x40, "DOCSIS"), (0x80, "Station")]
CDP_CAPS = [(0x01, "Router"), (0x02, "TransparentBridge"), (0x04, "SourceRouteBridge"),
            (0x08, "Switch"), (0x10, "Host"), (0x20, "IGMP"), (0x40, "Repeater"),
            (0x80, "Phone")]

MAU_TYPES = {
    5: "10BASE-T half", 6: "10BASE-T full", 15: "100BASE-TX half", 16: "100BASE-TX full",
    29: "1000BASE-T half", 30: "1000BASE-T full", 31: "1000BASE-X",
    62: "2.5GBASE-T", 63: "5GBASE-T", 64: "10GBASE-T",
}


def _addr_from_bytes(family, raw):
    try:
        if family == 1 and len(raw) >= 4:
            return socket.inet_ntoa(raw[:4])
        if family == 2 and len(raw) >= 16:
            return socket.inet_ntop(socket.AF_INET6, raw[:16])
        if family == 6 and len(raw) >= 6:
            return mac_str(raw[:6])
    except OSError:
        pass
    return raw.hex()


def _text(raw):
    return raw.decode("utf-8", "replace").rstrip("\x00").strip()


def _id_value(subtype, raw, table):
    kind = table.get(subtype, "subtype-%d" % subtype)
    if kind == "mac" and len(raw) >= 6:
        return mac_str(raw[:6]), kind
    if kind == "network-address" and raw:
        return _addr_from_bytes(raw[0], raw[1:]), kind
    return _text(raw), kind


def parse_lldp(frame):
    """Decode an LLDP frame (full Ethernet frame) into a neighbour dict, or None."""
    if len(frame) < 16:
        return None
    etype = struct.unpack("!H", frame[12:14])[0]
    off = 14
    while etype == 0x8100 and len(frame) >= off + 4:
        etype = struct.unpack("!H", frame[off + 2:off + 4])[0]
        off += 4
    if etype != LLDP_ETHERTYPE:
        return None
    n = {"protocol": "LLDP", "src_mac": mac_str(frame[6:12]),
         "dst_mac": mac_str(frame[0:6]), "capabilities": [], "enabled_capabilities": [],
         "mgmt_addrs": [], "vlans": [], "raw_tlvs": []}
    n["vendor"] = oui.lookup(n["src_mac"])
    pos = off
    while pos + 2 <= len(frame):
        head = struct.unpack("!H", frame[pos:pos + 2])[0]
        ttype = head >> 9
        tlen = head & 0x01FF
        pos += 2
        if ttype == 0:
            break
        value = frame[pos:pos + tlen]
        if len(value) < tlen:
            break
        pos += tlen
        _lldp_tlv(n, ttype, value)
    if "chassis_id" not in n and "port_id" not in n:
        return None
    return n


def _lldp_tlv(n, ttype, value):
    if ttype == 1 and value:
        n["chassis_id"], n["chassis_id_type"] = _id_value(value[0], value[1:], CHASSIS_SUBTYPE)
    elif ttype == 2 and value:
        n["port_id"], n["port_id_type"] = _id_value(value[0], value[1:], PORT_SUBTYPE)
    elif ttype == 3 and len(value) >= 2:
        n["ttl"] = struct.unpack("!H", value[:2])[0]
    elif ttype == 4:
        n["port_description"] = _text(value)
    elif ttype == 5:
        n["system_name"] = _text(value)
    elif ttype == 6:
        n["system_description"] = _text(value)
    elif ttype == 7 and len(value) >= 4:
        supported, enabled = struct.unpack("!HH", value[:4])
        n["capabilities"] = [name for bit, name in CAPS if supported & bit]
        n["enabled_capabilities"] = [name for bit, name in CAPS if enabled & bit]
    elif ttype == 8 and len(value) >= 2:
        alen = value[0]
        if alen >= 1 and len(value) >= 1 + alen:
            family = value[1]
            addr = _addr_from_bytes(family, value[2:1 + alen])
            entry = {"address": addr}
            rest = value[1 + alen:]
            if len(rest) >= 5:
                iface_subtype = rest[0]
                iface_num = struct.unpack("!I", rest[1:5])[0]
                entry["interface"] = iface_num
                entry["interface_numbering"] = {1: "unknown", 2: "ifIndex",
                                                3: "system-port"}.get(iface_subtype, "?")
            if entry not in n["mgmt_addrs"]:
                n["mgmt_addrs"].append(entry)
    elif ttype == 127 and len(value) >= 4:
        _lldp_org_tlv(n, value[:3], value[3], value[4:])
    else:
        n["raw_tlvs"].append({"type": ttype, "hex": value.hex()})


def _lldp_org_tlv(n, oui_bytes, subtype, body):
    if oui_bytes == b"\x00\x80\xc2":  # IEEE 802.1
        if subtype == 1 and len(body) >= 2:
            n["port_vlan_id"] = struct.unpack("!H", body[:2])[0]
        elif subtype == 2 and len(body) >= 3:
            n.setdefault("protocol_vlans", []).append(struct.unpack("!H", body[1:3])[0])
        elif subtype == 3 and len(body) >= 3:
            vid = struct.unpack("!H", body[:2])[0]
            name_len = body[2]
            name = _text(body[3:3 + name_len])
            entry = {"vlan": vid, "name": name}
            if entry not in n["vlans"]:
                n["vlans"].append(entry)
    elif oui_bytes == b"\x00\x12\x0f":  # IEEE 802.3
        if subtype == 1 and len(body) >= 5:
            autoneg = body[0]
            mau = struct.unpack("!H", body[3:5])[0]
            n["autoneg_supported"] = bool(autoneg & 0x01)
            n["autoneg_enabled"] = bool(autoneg & 0x02)
            n["mau_type"] = MAU_TYPES.get(mau, "MAU type %d" % mau)
        elif subtype == 2 and len(body) >= 3:
            n["poe"] = {
                "port_class": "PSE" if body[0] & 0x01 else "PD",
                "supported": bool(body[0] & 0x02),
                "enabled": bool(body[0] & 0x04),
                "pair_control": bool(body[0] & 0x08),
                "power_pairs": body[1],
                "power_class": body[2],
            }
            if len(body) >= 7:
                n["poe"]["requested_mw"] = struct.unpack("!H", body[3:5])[0] * 100
                n["poe"]["allocated_mw"] = struct.unpack("!H", body[5:7])[0] * 100
        elif subtype == 3 and len(body) >= 5:
            n["link_aggregation"] = {
                "capable": bool(body[0] & 0x01),
                "enabled": bool(body[0] & 0x02),
                "port_id": struct.unpack("!I", body[1:5])[0],
            }
        elif subtype == 4 and len(body) >= 2:
            n["max_frame_size"] = struct.unpack("!H", body[:2])[0]
    elif oui_bytes == b"\x00\x12\xbb":  # TIA LLDP-MED
        if subtype == 2 and len(body) >= 4:
            app = body[0]
            bits = struct.unpack("!I", b"\x00" + body[1:4])[0]
            n.setdefault("med_policies", []).append({
                "application": {1: "voice", 2: "voice-signaling", 3: "guest-voice",
                                4: "guest-voice-signaling", 5: "softphone-voice",
                                6: "video-conferencing", 7: "streaming-video",
                                8: "video-signaling"}.get(app, "app-%d" % app),
                "tagged": not bool(bits & 0x800000),
                "vlan": (bits >> 11) & 0x0FFF,
                "priority": (bits >> 8) & 0x07,
                "dscp": bits & 0x3F,
            })
        elif subtype == 4 and len(body) >= 3:
            n["med_power_mw"] = struct.unpack("!H", body[1:3])[0] * 100


def parse_cdp(frame):
    """Decode a CDP frame (full Ethernet frame with LLC/SNAP) into a dict, or None."""
    if len(frame) < 26:
        return None
    if mac_str(frame[0:6]) != CDP_MULTICAST:
        return None
    body = frame[14:]
    if len(body) < 8 or body[0:3] != b"\xaa\xaa\x03" or body[3:6] != b"\x00\x00\x0c":
        return None
    if struct.unpack("!H", body[6:8])[0] != 0x2000:
        return None
    cdp = body[8:]
    if len(cdp) < 4:
        return None
    n = {"protocol": "CDP", "src_mac": mac_str(frame[6:12]),
         "dst_mac": mac_str(frame[0:6]), "cdp_version": cdp[0], "ttl": cdp[1],
         "capabilities": [], "mgmt_addrs": [], "vlans": [], "raw_tlvs": []}
    n["vendor"] = oui.lookup(n["src_mac"])
    pos = 4
    while pos + 4 <= len(cdp):
        ttype, tlen = struct.unpack("!HH", cdp[pos:pos + 4])
        if tlen < 4 or pos + tlen > len(cdp):
            break
        value = cdp[pos + 4:pos + tlen]
        pos += tlen
        _cdp_tlv(n, ttype, value)
    return n if ("chassis_id" in n or "port_id" in n) else None


def _cdp_addresses(value):
    out = []
    if len(value) < 4:
        return out
    count = struct.unpack("!I", value[:4])[0]
    pos = 4
    for _ in range(min(count, 16)):
        if pos + 2 > len(value):
            break
        proto_len = value[pos + 1]
        pos += 2 + proto_len
        if pos + 2 > len(value):
            break
        addr_len = struct.unpack("!H", value[pos:pos + 2])[0]
        pos += 2
        raw = value[pos:pos + addr_len]
        pos += addr_len
        if addr_len == 4:
            out.append({"address": socket.inet_ntoa(raw)})
        elif addr_len == 16:
            out.append({"address": socket.inet_ntop(socket.AF_INET6, raw)})
    return out


def _cdp_tlv(n, ttype, value):
    if ttype == 0x0001:
        n["chassis_id"] = _text(value)
        n["system_name"] = n["chassis_id"]
        n["chassis_id_type"] = "device-id"
    elif ttype == 0x0002:
        for entry in _cdp_addresses(value):
            if entry not in n["mgmt_addrs"]:
                n["mgmt_addrs"].append(entry)
    elif ttype == 0x0003:
        n["port_id"] = _text(value)
        n["port_id_type"] = "interface-name"
    elif ttype == 0x0004 and len(value) >= 4:
        bits = struct.unpack("!I", value[:4])[0]
        n["capabilities"] = [name for bit, name in CDP_CAPS if bits & bit]
        n["enabled_capabilities"] = list(n["capabilities"])
    elif ttype == 0x0005:
        n["system_description"] = _text(value)
    elif ttype == 0x0006:
        n["platform"] = _text(value)
    elif ttype == 0x0009:
        n["vtp_domain"] = _text(value)
    elif ttype == 0x000A and len(value) >= 2:
        n["port_vlan_id"] = struct.unpack("!H", value[:2])[0]
    elif ttype == 0x000B and value:
        n["duplex"] = "full" if value[0] else "half"
    elif ttype == 0x000E and len(value) >= 3:
        n["voice_vlan"] = struct.unpack("!H", value[1:3])[0]
    elif ttype == 0x0010 and len(value) >= 2:
        n["poe"] = {"consumption_mw": struct.unpack("!H", value[:2])[0]}
    elif ttype == 0x0011 and len(value) >= 4:
        n["mtu"] = struct.unpack("!I", value[:4])[0]
    elif ttype == 0x0016:
        for entry in _cdp_addresses(value):
            if entry not in n["mgmt_addrs"]:
                n["mgmt_addrs"].append(entry)
    else:
        n["raw_tlvs"].append({"type": "0x%04x" % ttype, "hex": value.hex()})


def parse_frame(frame):
    """Try LLDP then CDP."""
    return parse_lldp(frame) or parse_cdp(frame)


def neighbor_key(n):
    return (n.get("protocol"), n.get("src_mac"), n.get("chassis_id"), n.get("port_id"))


def listen(ifname=None, timeout=65, stop_after=0, save_pcap=None, on_neighbor=None):
    """Listen for LLDP/CDP frames. Returns a list of neighbour dicts.

    Switches advertise every 30s (LLDP) / 60s (CDP), so the default 65s window
    catches at least one of each on a normal switch port.
    """
    ifname = ifname or ifmod.primary_interface()
    if not ifname:
        raise NetToolError("no interface to listen on; pass -i <iface>")
    link = open_link(ifname, promisc=True, snaplen=2048)
    writer = PcapWriter(save_pcap, LINKTYPE_ETHERNET, 2048) if save_pcap else None
    found = {}
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            for data, ts in link.read(timeout=0.5):
                dst = mac_str(data[0:6]) if len(data) >= 6 else ""
                if dst not in LLDP_MULTICAST and dst != CDP_MULTICAST:
                    continue
                n = parse_frame(data)
                if not n:
                    continue
                n["seen_at"] = ts
                n["interface"] = ifname
                key = neighbor_key(n)
                fresh = key not in found
                found[key] = n
                if writer:
                    writer.write(data, ts)
                if fresh and on_neighbor:
                    on_neighbor(n)
            if stop_after and len(found) >= stop_after:
                break
    finally:
        link.close()
        if writer:
            writer.close()
    return list(found.values())


def from_pcap(path):
    """Extract LLDP/CDP neighbours from an existing capture file."""
    out = {}
    with PcapReader(path) as reader:
        for ts, data, _orig in reader:
            n = parse_frame(data)
            if n:
                n["seen_at"] = ts
                out[neighbor_key(n)] = n
    return list(out.values())


def describe(n):
    """Human-readable multi-line rendering of one neighbour."""
    lines = []
    title = n.get("system_name") or n.get("chassis_id") or n.get("src_mac")
    lines.append("%s  (%s from %s%s)" % (
        title, n.get("protocol"), n.get("src_mac"),
        ", " + n["vendor"] if n.get("vendor") else ""))
    def add(label, value):
        if value not in (None, "", [], {}):
            lines.append("  %-18s %s" % (label + ":", value))
    add("chassis", "%s (%s)" % (n.get("chassis_id", "?"), n.get("chassis_id_type", "?")))
    add("port", "%s (%s)" % (n.get("port_id", "?"), n.get("port_id_type", "?")))
    add("port desc", n.get("port_description"))
    add("platform", n.get("platform"))
    add("system desc", (n.get("system_description") or "").replace("\n", " ")[:160] or None)
    add("capabilities", ", ".join(n.get("enabled_capabilities") or n.get("capabilities") or []))
    add("native VLAN", n.get("port_vlan_id"))
    add("voice VLAN", n.get("voice_vlan"))
    if n.get("vlans"):
        add("VLANs", ", ".join("%s(%s)" % (v["vlan"], v["name"]) for v in n["vlans"]))
    if n.get("med_policies"):
        for p in n["med_policies"]:
            add("MED policy", "%s vlan %s prio %s dscp %s%s" % (
                p["application"], p["vlan"], p["priority"], p["dscp"],
                "" if p["tagged"] else " (untagged)"))
    add("mgmt address", ", ".join(a["address"] for a in n.get("mgmt_addrs", [])))
    add("MAU/link", n.get("mau_type"))
    add("autoneg", None if n.get("autoneg_supported") is None else
        ("enabled" if n.get("autoneg_enabled") else "supported but OFF"))
    add("duplex", n.get("duplex"))
    add("max frame", n.get("max_frame_size") or n.get("mtu"))
    add("VTP domain", n.get("vtp_domain"))
    if n.get("poe"):
        poe = n["poe"]
        bits = []
        if "port_class" in poe:
            bits.append("%s class %s" % (poe["port_class"], poe.get("power_class")))
        if poe.get("allocated_mw"):
            bits.append("allocated %.1f W" % (poe["allocated_mw"] / 1000.0))
        if poe.get("requested_mw"):
            bits.append("requested %.1f W" % (poe["requested_mw"] / 1000.0))
        if poe.get("consumption_mw"):
            bits.append("draw %.1f W" % (poe["consumption_mw"] / 1000.0))
        add("PoE", ", ".join(bits))
    add("TTL", n.get("ttl"))
    return "\n".join(lines)
