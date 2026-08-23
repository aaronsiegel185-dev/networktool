"""Wireshark-style analysis of a capture: conversations, endpoints, protocol hierarchy,
TCP health and service latency.

Everything here is computed in a single streaming pass so a multi-gigabyte mirror capture
can be summarised without loading it into memory.
"""

import collections

from . import decode as dec
from .pcap import PcapReader

TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10


def _key(a, b):
    """Canonical, direction-independent conversation key."""
    return (a, b) if a <= b else (b, a)


class Conversation(object):
    """One pair of endpoints, counted separately in each direction."""

    __slots__ = ("kind", "a", "b", "packets_ab", "packets_ba", "bytes_ab", "bytes_ba",
                 "first_ts", "last_ts", "protocols", "ports")

    def __init__(self, kind, a, b):
        self.kind = kind
        self.a = a
        self.b = b
        self.packets_ab = 0
        self.packets_ba = 0
        self.bytes_ab = 0
        self.bytes_ba = 0
        self.first_ts = None
        self.last_ts = None
        self.protocols = collections.Counter()
        self.ports = collections.Counter()

    def add(self, source, length, timestamp, protocol=None, port=None):
        if source == self.a:
            self.packets_ab += 1
            self.bytes_ab += length
        else:
            self.packets_ba += 1
            self.bytes_ba += length
        if self.first_ts is None:
            self.first_ts = timestamp
        self.last_ts = timestamp
        if protocol:
            self.protocols[protocol] += 1
        if port is not None:
            self.ports[port] += 1

    @property
    def packets(self):
        return self.packets_ab + self.packets_ba

    @property
    def bytes(self):
        return self.bytes_ab + self.bytes_ba

    def duration(self):
        if self.first_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)

    def bits_per_second(self, packets_bytes):
        duration = self.duration()
        return (packets_bytes * 8 / duration) if duration > 0.05 else 0.0

    def report(self, epoch=None):
        return {
            "kind": self.kind,
            "a": self.a,
            "b": self.b,
            "packets": self.packets,
            "bytes": self.bytes,
            "packets_ab": self.packets_ab,
            "bytes_ab": self.bytes_ab,
            "packets_ba": self.packets_ba,
            "bytes_ba": self.bytes_ba,
            "start": round(self.first_ts - epoch, 3) if epoch and self.first_ts else 0.0,
            "duration": round(self.duration(), 3),
            "bps_ab": round(self.bits_per_second(self.bytes_ab), 1),
            "bps_ba": round(self.bits_per_second(self.bytes_ba), 1),
            "protocol": self.protocols.most_common(1)[0][0] if self.protocols else "",
            "service": self.ports.most_common(1)[0][0] if self.ports else None,
        }


class Endpoint(object):
    __slots__ = ("address", "packets_tx", "packets_rx", "bytes_tx", "bytes_rx", "peers",
                 "ports")

    def __init__(self, address):
        self.address = address
        self.packets_tx = 0
        self.packets_rx = 0
        self.bytes_tx = 0
        self.bytes_rx = 0
        self.peers = set()
        self.ports = collections.Counter()

    def report(self):
        return {
            "address": self.address,
            "packets": self.packets_tx + self.packets_rx,
            "bytes": self.bytes_tx + self.bytes_rx,
            "packets_tx": self.packets_tx,
            "bytes_tx": self.bytes_tx,
            "packets_rx": self.packets_rx,
            "bytes_rx": self.bytes_rx,
            "peers": len(self.peers),
            "top_ports": [port for port, _ in self.ports.most_common(4)],
        }


class TcpFlow(object):
    """Per-direction sequence tracking, which is what exposes retransmissions."""

    __slots__ = ("next_seq", "last_ack", "dup_ack_count", "zero_window", "retransmits",
                 "out_of_order", "packets", "bytes", "syn_ts", "synack_ts", "fin", "rst",
                 "max_seq")

    def __init__(self):
        self.next_seq = {}
        self.last_ack = {}
        self.dup_ack_count = collections.Counter()
        self.zero_window = 0
        self.retransmits = 0
        self.out_of_order = 0
        self.packets = 0
        self.bytes = 0
        self.syn_ts = None
        self.synack_ts = None
        self.fin = False
        self.rst = False
        self.max_seq = {}


class Analysis(object):
    """Streaming analysis of decoded packets."""

    MAX_FLOWS = 50000

    def __init__(self, bucket_seconds=1.0):
        self.packets = 0
        self.bytes = 0
        self.first_ts = None
        self.last_ts = None
        self.conversations = {}
        self.endpoints = {}
        self.mac_endpoints = {}
        self.protocols = collections.Counter()
        self.protocol_bytes = collections.Counter()
        self.hierarchy = collections.Counter()
        self.hierarchy_bytes = collections.Counter()
        self.vlans = collections.Counter()
        self.flows = {}
        self.tcp_segments = 0
        self.tcp_retransmits = 0
        self.tcp_out_of_order = 0
        self.tcp_dup_acks = 0
        self.tcp_zero_window = 0
        self.tcp_resets = 0
        self.tcp_syns = 0
        self.tcp_handshakes = []
        self.failed_connects = {}
        self.dns_queries = {}
        self.dns_latencies = []
        self.dns_failures = collections.Counter()
        self.dns_names = collections.Counter()
        self.arp_claims = collections.defaultdict(set)
        self.icmp_errors = collections.Counter()
        self.ttl_by_host = {}
        self.bucket_seconds = bucket_seconds
        self.buckets = collections.Counter()
        self.bucket_bytes = collections.Counter()

    # -- ingestion --

    def add(self, pkt, timestamp):
        self.packets += 1
        length = pkt.get("len", 0)
        self.bytes += length
        if self.first_ts is None:
            self.first_ts = timestamp
        self.last_ts = timestamp
        bucket = int((timestamp - self.first_ts) / self.bucket_seconds)
        self.buckets[bucket] += 1
        self.bucket_bytes[bucket] += length

        protocol = pkt.get("proto") or pkt.get("l2") or "?"
        self.protocols[protocol] += 1
        self.protocol_bytes[protocol] += length
        self.hierarchy[self._layers(pkt)] += 1
        self.hierarchy_bytes[self._layers(pkt)] += length
        if pkt.get("vlan") is not None:
            self.vlans[pkt["vlan"]] += 1

        source_mac, dest_mac = pkt.get("eth_src"), pkt.get("eth_dst")
        if source_mac and dest_mac:
            self._add_conversation("ethernet", source_mac, dest_mac, length, timestamp,
                                   protocol)
            self._add_endpoint(self.mac_endpoints, source_mac, dest_mac, length, True)
            self._add_endpoint(self.mac_endpoints, dest_mac, source_mac, length, False)

        source, dest = pkt.get("src"), pkt.get("dst")
        if source and dest:
            kind = "ipv6" if pkt.get("l3") == "IPv6" else "ip"
            self._add_conversation(kind, source, dest, length, timestamp, protocol)
            self._add_endpoint(self.endpoints, source, dest, length, True,
                               port=pkt.get("dport"))
            self._add_endpoint(self.endpoints, dest, source, length, False,
                               port=pkt.get("sport"))
            if pkt.get("ttl") is not None:
                self.ttl_by_host.setdefault(source, set()).add(pkt["ttl"])

        layer4 = pkt.get("l4")
        if layer4 in ("TCP", "UDP") and source and dest:
            a = "%s:%s" % (source, pkt.get("sport"))
            b = "%s:%s" % (dest, pkt.get("dport"))
            service = self._service_port(pkt)
            self._add_conversation(layer4.lower(), a, b, length, timestamp, protocol,
                                   port=service)
        if layer4 == "TCP":
            self._tcp(pkt, timestamp, source, dest)
        elif layer4 == "UDP":
            self._dns(pkt, timestamp)
        if pkt.get("l3") == "ARP":
            self._arp(pkt)
        if pkt.get("l4") == "ICMP" and pkt.get("icmp_type") == 3:
            self.icmp_errors[pkt.get("info", "unreachable")] += 1

    @staticmethod
    def _layers(pkt):
        layers = [pkt.get("l2") or "eth"]
        for layer in (pkt.get("l3"), pkt.get("l4")):
            if layer and layer != layers[-1]:
                layers.append(layer)
        if pkt.get("dns_name") is not None:
            layers.append("DNS")
        return " > ".join(layers)

    @staticmethod
    def _service_port(pkt):
        """The lower port is nearly always the service."""
        source, dest = pkt.get("sport"), pkt.get("dport")
        if source is None or dest is None:
            return None
        return min(source, dest)

    def _add_conversation(self, kind, a, b, length, timestamp, protocol, port=None):
        key = (kind,) + _key(a, b)
        conversation = self.conversations.get(key)
        if conversation is None:
            if len(self.conversations) >= self.MAX_FLOWS * 2:
                return
            first, second = _key(a, b)
            conversation = self.conversations[key] = Conversation(kind, first, second)
        conversation.add(a, length, timestamp, protocol, port)

    @staticmethod
    def _add_endpoint(table, address, peer, length, sending, port=None):
        endpoint = table.get(address)
        if endpoint is None:
            if len(table) >= 100000:
                return
            endpoint = table[address] = Endpoint(address)
        if sending:
            endpoint.packets_tx += 1
            endpoint.bytes_tx += length
        else:
            endpoint.packets_rx += 1
            endpoint.bytes_rx += length
        endpoint.peers.add(peer)
        if port is not None and port < 1024:
            endpoint.ports[port] += 1

    # -- protocol specifics --

    def _tcp(self, pkt, timestamp, source, dest):
        self.tcp_segments += 1
        flags = pkt.get("tcp_flags", "")
        key = (source, pkt.get("sport"), dest, pkt.get("dport"))
        reverse = (dest, pkt.get("dport"), source, pkt.get("sport"))
        flow_key = key if key <= reverse else reverse
        flow = self.flows.get(flow_key)
        if flow is None:
            if len(self.flows) >= self.MAX_FLOWS:
                return
            flow = self.flows[flow_key] = TcpFlow()
        flow.packets += 1
        flow.bytes += pkt.get("len", 0)

        direction = key
        seq = pkt.get("seq")
        payload = pkt.get("payload_len", 0) or 0
        if "S" in flags and "A" not in flags:
            self.tcp_syns += 1
            flow.syn_ts = timestamp
            self.failed_connects[key] = timestamp
        elif "S" in flags and "A" in flags:
            flow.synack_ts = timestamp
            self.failed_connects.pop(reverse, None)
            if flow.syn_ts is not None:
                self.tcp_handshakes.append((dest, pkt.get("sport"),
                                            (timestamp - flow.syn_ts) * 1000.0))
        if "R" in flags:
            self.tcp_resets += 1
            flow.rst = True
            self.failed_connects.pop(reverse, None)
            self.failed_connects.pop(key, None)
        if "F" in flags:
            flow.fin = True

        if payload and seq is not None:
            highest = flow.max_seq.get(direction)
            end = seq + payload
            if highest is not None:
                if end <= highest:
                    flow.retransmits += 1
                    self.tcp_retransmits += 1
                elif seq > highest:
                    flow.out_of_order += 1
                    self.tcp_out_of_order += 1
            flow.max_seq[direction] = max(end, highest or 0)

        window = pkt.get("window")
        if window == 0 and "R" not in flags and "S" not in flags:
            flow.zero_window += 1
            self.tcp_zero_window += 1

        ack = pkt.get("ack")
        if "A" in flags and ack is not None and payload == 0:
            previous = flow.last_ack.get(direction)
            if previous == ack:
                flow.dup_ack_count[direction] += 1
                self.tcp_dup_acks += 1
            else:
                flow.last_ack[direction] = ack
                flow.dup_ack_count[direction] = 0

    def _dns(self, pkt, timestamp):
        name = pkt.get("dns_name")
        if name is None:
            return
        ident = pkt.get("dns_id")
        if not pkt.get("dns_response"):
            self.dns_names[name] += 1
            if len(self.dns_queries) < self.MAX_FLOWS:
                self.dns_queries[(ident, name)] = timestamp
            return
        asked = self.dns_queries.pop((ident, name), None)
        if asked is not None:
            self.dns_latencies.append((name, (timestamp - asked) * 1000.0))
        if pkt.get("dns_rcode"):
            self.dns_failures["%s: %s" % (name, pkt.get("dns_rcode_name"))] += 1

    def _arp(self, pkt):
        if pkt.get("arp_op") == 2 and pkt.get("src") and pkt.get("arp_sha"):
            self.arp_claims[pkt["src"]].add(pkt["arp_sha"])

    # -- reporting --

    def duration(self):
        if self.first_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)

    def conversation_list(self, kind=None, top=20):
        items = [c for c in self.conversations.values() if kind is None or c.kind == kind]
        items.sort(key=lambda c: c.bytes, reverse=True)
        return [c.report(self.first_ts) for c in items[:top]]

    def endpoint_list(self, top=20, macs=False):
        table = self.mac_endpoints if macs else self.endpoints
        items = sorted(table.values(), key=lambda e: e.bytes_tx + e.bytes_rx, reverse=True)
        return [e.report() for e in items[:top]]

    def protocol_hierarchy(self):
        total = float(self.packets) or 1.0
        total_bytes = float(self.bytes) or 1.0
        return [
            {"layers": layers, "packets": count,
             "packets_pct": round(100.0 * count / total, 1),
             "bytes": self.hierarchy_bytes[layers],
             "bytes_pct": round(100.0 * self.hierarchy_bytes[layers] / total_bytes, 1)}
            for layers, count in self.hierarchy.most_common(30)
        ]

    def tcp_report(self):
        handshakes = [ms for _host, _port, ms in self.tcp_handshakes]
        complete = sum(1 for flow in self.flows.values() if flow.synack_ts is not None)
        return {
            "segments": self.tcp_segments,
            "flows": len(self.flows),
            "completed_handshakes": complete,
            "syns": self.tcp_syns,
            "retransmissions": self.tcp_retransmits,
            "retransmission_pct": round(100.0 * self.tcp_retransmits /
                                        max(1, self.tcp_segments), 2),
            "out_of_order": self.tcp_out_of_order,
            "duplicate_acks": self.tcp_dup_acks,
            "zero_window": self.tcp_zero_window,
            "resets": self.tcp_resets,
            "handshake_ms_avg": round(sum(handshakes) / len(handshakes), 2)
            if handshakes else None,
            "handshake_ms_max": round(max(handshakes), 2) if handshakes else None,
            "unanswered_syns": [
                {"to": "%s:%s" % (destination, port)}
                for (_source, _sport, destination, port) in list(self.failed_connects)[:20]
            ],
        }

    def dns_report(self):
        latencies = [ms for _name, ms in self.dns_latencies]
        slow = sorted(self.dns_latencies, key=lambda item: item[1], reverse=True)[:5]
        return {
            "queries": sum(self.dns_names.values()),
            "answered": len(self.dns_latencies),
            "unanswered": len(self.dns_queries),
            "latency_ms_avg": round(sum(latencies) / len(latencies), 2) if latencies else None,
            "latency_ms_max": round(max(latencies), 2) if latencies else None,
            "slowest": [{"name": name, "ms": round(ms, 2)} for name, ms in slow],
            "failures": dict(self.dns_failures.most_common(10)),
            "top_names": dict(self.dns_names.most_common(10)),
        }

    def throughput(self, buckets=60):
        if not self.buckets:
            return []
        last = max(self.buckets)
        step = max(1, (last + 1) // buckets)
        out = []
        for start in range(0, last + 1, step):
            packets = sum(self.buckets[b] for b in range(start, start + step))
            byte_count = sum(self.bucket_bytes[b] for b in range(start, start + step))
            window = step * self.bucket_seconds
            out.append({
                "t": round(start * self.bucket_seconds, 2),
                "packets": packets,
                "bytes": byte_count,
                "bps": round(byte_count * 8 / window, 1) if window else 0.0,
            })
        return out

    def findings(self):
        """Plain-language problems, in the spirit of Wireshark's expert info."""
        out = []
        tcp = self.tcp_report()
        if self.tcp_segments >= 50:
            if tcp["retransmission_pct"] > 5:
                out.append(("critical", "%.1f%% of TCP segments are retransmissions - "
                                        "packet loss on the path."
                            % tcp["retransmission_pct"]))
            elif tcp["retransmission_pct"] > 1:
                out.append(("warn", "%.1f%% of TCP segments are retransmissions."
                            % tcp["retransmission_pct"]))
        if tcp["zero_window"]:
            out.append(("warn", "%d zero-window advertisements - a receiver could not keep "
                                "up with the sender." % tcp["zero_window"]))
        if tcp["duplicate_acks"] > 20:
            out.append(("warn", "%d duplicate ACKs - segments are arriving out of order or "
                                "going missing." % tcp["duplicate_acks"]))
        if tcp["unanswered_syns"]:
            targets = ", ".join(entry["to"] for entry in tcp["unanswered_syns"][:5])
            out.append(("warn", "%d connection attempt(s) got no SYN/ACK: %s"
                        % (len(tcp["unanswered_syns"]), targets)))
        if tcp["resets"] and tcp["flows"]:
            share = 100.0 * tcp["resets"] / max(1, tcp["flows"])
            if share > 30:
                out.append(("warn", "%d resets across %d TCP flows - services refusing or "
                                    "dropping connections." % (tcp["resets"], tcp["flows"])))
        if tcp["handshake_ms_avg"] is not None and tcp["handshake_ms_avg"] > 200:
            out.append(("warn", "TCP handshakes average %.0f ms - a slow or distant path."
                        % tcp["handshake_ms_avg"]))

        dns = self.dns_report()
        if dns["failures"]:
            out.append(("warn", "DNS failures: %s"
                        % ", ".join(list(dns["failures"])[:3])))
        if dns["unanswered"]:
            out.append(("warn", "%d DNS queries were never answered." % dns["unanswered"]))
        if dns["latency_ms_avg"] is not None and dns["latency_ms_avg"] > 200:
            out.append(("warn", "DNS answers average %.0f ms." % dns["latency_ms_avg"]))

        duplicates = {ip: macs for ip, macs in self.arp_claims.items() if len(macs) > 1}
        if duplicates:
            for ip, macs in list(duplicates.items())[:3]:
                out.append(("critical", "%s is claimed by %d MAC addresses (%s) - a "
                                        "duplicate IP." % (ip, len(macs),
                                                           ", ".join(sorted(macs)))))
        if self.icmp_errors:
            common = self.icmp_errors.most_common(1)[0]
            out.append(("info", "%d ICMP unreachable messages, most commonly: %s"
                        % (sum(self.icmp_errors.values()), common[0])))
        fragmentation = [info for info in self.icmp_errors if "frag-needed" in info]
        if fragmentation:
            out.append(("warn", "ICMP fragmentation-needed seen - an MTU mismatch on the "
                                "path."))
        if not out:
            out.append(("ok", "No protocol-level problems stood out."))
        return out

    def report(self, top=20):
        return {
            "packets": self.packets,
            "bytes": self.bytes,
            "duration": round(self.duration(), 3),
            "start": self.first_ts,
            "protocols": dict(self.protocols.most_common(15)),
            "protocol_bytes": dict(self.protocol_bytes.most_common(15)),
            "hierarchy": self.protocol_hierarchy(),
            "vlans": dict(self.vlans.most_common(20)),
            "conversations": {
                "tcp": self.conversation_list("tcp", top),
                "udp": self.conversation_list("udp", top),
                "ip": self.conversation_list("ip", top),
                "ipv6": self.conversation_list("ipv6", top),
                "ethernet": self.conversation_list("ethernet", top),
            },
            "endpoints": self.endpoint_list(top),
            "mac_endpoints": self.endpoint_list(top, macs=True),
            "tcp": self.tcp_report(),
            "dns": self.dns_report(),
            "throughput": self.throughput(),
            "findings": self.findings(),
        }


def analyze_pcap(path, filter_expr=None, bucket_seconds=1.0):
    """Run the analysis over a capture file."""
    from .pfilter import compile_filter

    match = compile_filter(filter_expr)
    analysis = Analysis(bucket_seconds=bucket_seconds)
    with PcapReader(path) as reader:
        linktype = reader.linktype
        for timestamp, data, _orig in reader:
            if linktype != 1:
                continue
            pkt = dec.decode(data)
            if not match(pkt):
                continue
            analysis.add(pkt, timestamp)
    analysis.linktype = linktype
    return analysis


def follow_stream(path, index=0, kind="tcp", max_bytes=64 * 1024):
    """Reassemble one TCP/UDP conversation's payload, in capture order.

    Returns (metadata, [(direction, bytes), ...]) where direction is "a" or "b".
    """
    analysis = analyze_pcap(path)
    conversations = analysis.conversation_list(kind, top=index + 1)
    if index >= len(conversations):
        raise IndexError("only %d %s conversations in %s" % (len(conversations), kind, path))
    wanted = conversations[index]
    endpoints = {wanted["a"], wanted["b"]}
    chunks = []
    total = 0
    with PcapReader(path) as reader:
        for _timestamp, data, _orig in reader:
            pkt = dec.decode(data)
            if pkt.get("l4", "").lower() != kind:
                continue
            source = "%s:%s" % (pkt.get("src"), pkt.get("sport"))
            dest = "%s:%s" % (pkt.get("dst"), pkt.get("dport"))
            if {source, dest} != endpoints:
                continue
            payload_len = pkt.get("payload_len", 0) or 0
            if not payload_len:
                continue
            start = len(data) - payload_len
            if start < 0:
                continue
            payload = data[start:start + payload_len]
            chunks.append(("a" if source == wanted["a"] else "b", payload))
            total += len(payload)
            if total >= max_bytes:
                break
    return wanted, chunks


def format_stream(chunks, as_hex=False, width=16):
    """Render a followed stream, direction by direction."""
    lines = []
    for direction, payload in chunks:
        prefix = "->" if direction == "a" else "<-"
        if as_hex:
            for offset in range(0, len(payload), width):
                row = payload[offset:offset + width]
                hex_part = " ".join("%02x" % b for b in row)
                text = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
                lines.append("%s %04x  %-*s  %s" % (prefix, offset, width * 3, hex_part, text))
        else:
            text = payload.decode("utf-8", "replace")
            for line in text.splitlines() or [""]:
                lines.append("%s %s" % (prefix, line))
    return "\n".join(lines)
