"""Lightweight Ethernet/IP/TCP/UDP/ICMP/ARP decoder for capture summaries and filtering."""

import socket
import struct

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_IPV6 = 0x86DD
ETH_P_VLAN = 0x8100
ETH_P_QINQ = 0x88A8
ETH_P_QINQ_LEGACY = 0x9100
ETH_P_LLDP = 0x88CC
ETH_P_EAPOL = 0x888E
ETH_P_PPPOE_DISC = 0x8863
ETH_P_PPPOE_SESS = 0x8864
ETH_P_MPLS = 0x8847
ETH_P_PROFINET = 0x8892
ETH_P_LOOP = 0x9000

ETHERTYPE_NAMES = {
    ETH_P_IP: "IPv4", ETH_P_ARP: "ARP", ETH_P_IPV6: "IPv6", ETH_P_VLAN: "802.1Q",
    ETH_P_QINQ: "802.1ad", ETH_P_QINQ_LEGACY: "QinQ", ETH_P_LLDP: "LLDP", ETH_P_EAPOL: "EAPOL",
    ETH_P_PPPOE_DISC: "PPPoE-Disc", ETH_P_PPPOE_SESS: "PPPoE", ETH_P_MPLS: "MPLS",
    ETH_P_PROFINET: "PROFINET", ETH_P_LOOP: "Loopback/CDP-keepalive", 0x8035: "RARP",
    0x88E5: "MACsec", 0x8906: "FCoE", 0x22EA: "SRP", 0x88F7: "PTP",
}

IP_PROTO_NAMES = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE",
                  50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 103: "PIM", 112: "VRRP",
                  132: "SCTP"}

TCP_FLAG_NAMES = [(0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"),
                  (0x10, "A"), (0x20, "U"), (0x40, "E"), (0x80, "C")]


def _mac(raw):
    return ":".join("%02x" % b for b in bytearray(raw))


def decode(data):
    """Decode an Ethernet frame into a flat dict. Never raises on short/odd frames."""
    pkt = {"len": len(data), "l2": "", "l3": "", "l4": "", "proto": "", "info": "",
           "src": "", "dst": "", "sport": None, "dport": None, "vlan": None,
           "eth_src": "", "eth_dst": "", "ethertype": None, "tcp_flags": ""}
    if len(data) < 14:
        pkt["proto"] = "runt"
        return pkt
    pkt["eth_dst"] = _mac(data[0:6])
    pkt["eth_src"] = _mac(data[6:12])
    etype = struct.unpack("!H", data[12:14])[0]
    off = 14
    while etype in (ETH_P_VLAN, ETH_P_QINQ, ETH_P_QINQ_LEGACY) and len(data) >= off + 4:
        tci = struct.unpack("!H", data[off:off + 2])[0]
        vlan = tci & 0x0FFF
        pkt["vlan"] = vlan                      # innermost tag: the one traffic rides on
        pkt["pcp"] = (tci >> 13) & 0x7
        pkt["dei"] = bool((tci >> 12) & 0x1)
        pkt.setdefault("outer_vlan", vlan)      # first tag seen: the QinQ service tag
        pkt.setdefault("vlan_stack", []).append(vlan)
        etype = struct.unpack("!H", data[off + 2:off + 4])[0]
        off += 4
    pkt["ethertype"] = etype
    if etype <= 1500:
        pkt["l2"] = "802.3/LLC"
        pkt["proto"] = _llc_name(data, off)
        pkt["info"] = pkt["proto"]
        return pkt
    pkt["l2"] = ETHERTYPE_NAMES.get(etype, "0x%04x" % etype)
    pkt["proto"] = pkt["l2"]

    if etype == ETH_P_ARP:
        _decode_arp(pkt, data, off)
    elif etype == ETH_P_IP:
        _decode_ipv4(pkt, data, off)
    elif etype == ETH_P_IPV6:
        _decode_ipv6(pkt, data, off)
    else:
        pkt["info"] = pkt["l2"]
    return pkt


def _llc_name(data, off):
    if len(data) < off + 3:
        return "802.3"
    dsap, ssap = data[off], data[off + 1]
    if dsap == 0xAA and ssap == 0xAA and len(data) >= off + 8:
        oui = data[off + 3:off + 6]
        pid = struct.unpack("!H", data[off + 6:off + 8])[0]
        if oui == b"\x00\x00\x0c":
            if pid == 0x2000:
                return "CDP"
            if pid == 0x2004:
                return "DTP"
            if pid == 0x010B:
                return "PVSTP+"
            return "Cisco-SNAP"
        return "SNAP"
    if dsap == 0x42 and ssap == 0x42:
        return "STP"
    return "LLC"


def _decode_arp(pkt, data, off):
    if len(data) < off + 28:
        pkt["info"] = "ARP (truncated)"
        return
    op = struct.unpack("!H", data[off + 6:off + 8])[0]
    sha = _mac(data[off + 8:off + 14])
    spa = socket.inet_ntoa(data[off + 14:off + 18])
    tha = _mac(data[off + 18:off + 24])
    tpa = socket.inet_ntoa(data[off + 24:off + 28])
    pkt.update({"l3": "ARP", "src": spa, "dst": tpa, "arp_op": op,
                "arp_sha": sha, "arp_tha": tha})
    if op == 1:
        pkt["info"] = "who-has %s tell %s" % (tpa, spa)
    elif op == 2:
        pkt["info"] = "%s is-at %s" % (spa, sha)
    else:
        pkt["info"] = "ARP op %d" % op


def _decode_ipv4(pkt, data, off):
    if len(data) < off + 20:
        pkt["info"] = "IPv4 (truncated)"
        return
    ihl = (data[off] & 0x0F) * 4
    total_len = struct.unpack("!H", data[off + 2:off + 4])[0]
    frag = struct.unpack("!H", data[off + 6:off + 8])[0]
    proto = data[off + 9]
    pkt.update({
        "l3": "IPv4",
        "src": socket.inet_ntoa(data[off + 12:off + 16]),
        "dst": socket.inet_ntoa(data[off + 16:off + 20]),
        "ttl": data[off + 8],
        "ip_proto": proto,
        "ip_len": total_len,
        "df": bool(frag & 0x4000),
        "mf": bool(frag & 0x2000),
        "frag_offset": (frag & 0x1FFF) * 8,
        "dscp": data[off + 1] >> 2,
    })
    pkt["proto"] = IP_PROTO_NAMES.get(proto, "IP proto %d" % proto)
    payload = off + ihl
    if pkt["frag_offset"]:
        pkt["info"] = "%s fragment offset %d" % (pkt["proto"], pkt["frag_offset"])
        return
    if proto == 6:
        _decode_tcp(pkt, data, payload, total_len - ihl)
    elif proto == 17:
        _decode_udp(pkt, data, payload)
    elif proto == 1:
        _decode_icmp(pkt, data, payload)
    else:
        pkt["info"] = "%s %s > %s" % (pkt["proto"], pkt["src"], pkt["dst"])


def _decode_ipv6(pkt, data, off):
    if len(data) < off + 40:
        pkt["info"] = "IPv6 (truncated)"
        return
    nxt = data[off + 6]
    pkt.update({
        "l3": "IPv6",
        "src": socket.inet_ntop(socket.AF_INET6, data[off + 8:off + 24]),
        "dst": socket.inet_ntop(socket.AF_INET6, data[off + 24:off + 40]),
        "ttl": data[off + 7],
        "ip_proto": nxt,
    })
    pkt["proto"] = IP_PROTO_NAMES.get(nxt, "IPv6 nh %d" % nxt)
    payload = off + 40
    if nxt == 6:
        _decode_tcp(pkt, data, payload, len(data) - payload)
    elif nxt == 17:
        _decode_udp(pkt, data, payload)
    elif nxt == 58:
        if len(data) > payload:
            pkt["icmp_type"] = data[payload]
            pkt["info"] = "ICMPv6 type %d" % data[payload]
    else:
        pkt["info"] = "%s %s > %s" % (pkt["proto"], pkt["src"], pkt["dst"])


def _decode_tcp(pkt, data, off, seg_len):
    if len(data) < off + 20:
        pkt["info"] = "TCP (truncated)"
        return
    sport, dport, seq, ack = struct.unpack("!HHII", data[off:off + 12])
    doff = (data[off + 12] >> 4) * 4
    flags = data[off + 13]
    win = struct.unpack("!H", data[off + 14:off + 16])[0]
    names = "".join(ch for bit, ch in TCP_FLAG_NAMES if flags & bit) or "."
    pkt.update({"l4": "TCP", "sport": sport, "dport": dport, "tcp_flags": names,
                "seq": seq, "ack": ack, "window": win})
    plen = max(0, seg_len - doff) if seg_len else max(0, len(data) - off - doff)
    pkt["payload_len"] = plen
    pkt["info"] = "%s:%d > %s:%d [%s] seq=%u win=%u len=%d" % (
        pkt["src"], sport, pkt["dst"], dport, names, seq, win, plen)


def _decode_udp(pkt, data, off):
    if len(data) < off + 8:
        pkt["info"] = "UDP (truncated)"
        return
    sport, dport, ulen = struct.unpack("!HHH", data[off:off + 6])
    pkt.update({"l4": "UDP", "sport": sport, "dport": dport,
                "payload_len": max(0, ulen - 8)})
    hint = ""
    if 67 in (sport, dport) or 68 in (sport, dport):
        hint = " (DHCP)"
    elif 53 in (sport, dport):
        hint = " (DNS)"
    elif 5353 in (sport, dport):
        hint = " (mDNS)"
    elif 1900 in (sport, dport):
        hint = " (SSDP)"
    elif 123 in (sport, dport):
        hint = " (NTP)"
    elif 137 in (sport, dport) or 138 in (sport, dport):
        hint = " (NetBIOS)"
    pkt["info"] = "%s:%d > %s:%d UDP len=%d%s" % (
        pkt["src"], sport, pkt["dst"], dport, pkt["payload_len"], hint)


ICMP_TYPES = {0: "echo-reply", 3: "dest-unreachable", 5: "redirect", 8: "echo-request",
              11: "ttl-exceeded", 13: "timestamp", 14: "timestamp-reply"}
ICMP_UNREACH = {0: "net", 1: "host", 2: "protocol", 3: "port", 4: "frag-needed(DF set)",
                9: "net-admin-prohibited", 10: "host-admin-prohibited",
                13: "communication-administratively-filtered"}


def _decode_icmp(pkt, data, off):
    if len(data) < off + 4:
        pkt["info"] = "ICMP (truncated)"
        return
    itype, code = data[off], data[off + 1]
    pkt.update({"l4": "ICMP", "icmp_type": itype, "icmp_code": code})
    label = ICMP_TYPES.get(itype, "type %d" % itype)
    if itype == 3:
        label += "/" + ICMP_UNREACH.get(code, "code %d" % code)
    pkt["info"] = "%s > %s ICMP %s" % (pkt["src"], pkt["dst"], label)


def summary(pkt):
    """One-line tcpdump-ish summary."""
    vlan = " vlan%d" % pkt["vlan"] if pkt.get("vlan") is not None else ""
    if pkt.get("info"):
        return "%s%s %s" % (pkt["l2"] or "?", vlan, pkt["info"])
    return "%s%s %s > %s" % (pkt["l2"] or "?", vlan, pkt["eth_src"], pkt["eth_dst"])
