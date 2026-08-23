"""Conversations, endpoints, protocol hierarchy, TCP health and DNS timing."""

import os
import socket
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nettool import analyze, decode
from nettool.pcap import PcapWriter

CLIENT = "10.0.0.5"
SERVER = "93.184.216.34"
RESOLVER = "10.0.0.1"
MACS = {CLIENT: "00:1b:21:aa:00:05", SERVER: "00:0c:29:cc:00:01",
        RESOLVER: "00:0c:29:cc:00:02", "10.0.0.9": "b8:27:eb:dd:00:09",
        "10.0.0.250": "3c:22:fb:bb:00:06"}


def eth(dst, src, etype, payload):
    return (bytes.fromhex(dst.replace(":", "")) + bytes.fromhex(src.replace(":", ""))
            + struct.pack("!H", etype) + payload)


def ip(src, dst, proto, payload, ttl=64):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0x4000, ttl,
                       proto, 0, socket.inet_aton(src), socket.inet_aton(dst)) + payload


def tcp(sport, dport, seq, ack, flags, window=64240, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, window,
                       0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_message(name, ident, response=False, rcode=0):
    flags = (0x8000 | rcode) if response else 0x0100
    body = struct.pack("!HHHHHH", ident, flags, 1, 1 if response else 0, 0, 0)
    for part in name.split("."):
        body += bytes([len(part)]) + part.encode()
    return body + b"\x00" + struct.pack("!HH", 1, 1)


def frame(src, dst, payload, proto=6, ttl=64):
    return eth(MACS[dst], MACS[src], 0x0800, ip(src, dst, proto, payload, ttl))


def arp_reply(claimed_ip, mac):
    body = (struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
            + bytes.fromhex(mac.replace(":", "")) + socket.inet_aton(claimed_ip)
            + b"\x00" * 6 + socket.inet_aton(CLIENT))
    return eth("ff:ff:ff:ff:ff:ff", mac, 0x0806, body)


def build_capture():
    """A session with a clean handshake, retransmissions, dup ACKs, a reset,
    a dead connection attempt, four DNS lookups and a duplicate IP."""
    packets = []
    now = [1700000000.0]

    def add(raw, gap=0.01):
        now[0] += gap
        packets.append((now[0], raw))

    add(frame(CLIENT, SERVER, tcp(51000, 443, 1000, 0, 0x02)))
    add(frame(SERVER, CLIENT, tcp(443, 51000, 5000, 1001, 0x12)), 0.020)
    add(frame(CLIENT, SERVER, tcp(51000, 443, 1001, 5001, 0x10)))
    for index in range(20):
        add(frame(CLIENT, SERVER, tcp(51000, 443, 1001 + index * 100, 5001, 0x18,
                                      payload=b"x" * 100)))
        add(frame(SERVER, CLIENT, tcp(443, 51000, 5001 + index * 500, 1101 + index * 100,
                                      0x18, payload=b"y" * 500)))
    for index in range(6):                        # same segments again: retransmissions
        add(frame(CLIENT, SERVER, tcp(51000, 443, 1001 + index * 100, 5001, 0x18,
                                      payload=b"x" * 100)), 0.3)
    for _ in range(5):                            # duplicate ACKs
        add(frame(SERVER, CLIENT, tcp(443, 51000, 15001, 3001, 0x10)), 0.002)
    add(frame(SERVER, CLIENT, tcp(443, 51000, 15001, 3001, 0x10, window=0)), 0.05)
    add(frame(SERVER, CLIENT, tcp(443, 51000, 15001, 3001, 0x14)), 0.05)
    for _ in range(3):                            # SYNs nobody answers
        add(frame("10.0.0.9", "10.0.0.250", tcp(52000, 445, 900, 0, 0x02)), 1.0)
    add(frame(CLIENT, RESOLVER, udp(51001, 53, dns_message("example.com", 0x1111)), proto=17))
    add(frame(RESOLVER, CLIENT, udp(53, 51001, dns_message("example.com", 0x1111, True)),
              proto=17), 0.015)
    add(frame(CLIENT, RESOLVER, udp(51002, 53, dns_message("slow.internal", 0x2222)), proto=17))
    add(frame(RESOLVER, CLIENT, udp(53, 51002, dns_message("slow.internal", 0x2222, True)),
              proto=17), 0.9)
    add(frame(CLIENT, RESOLVER, udp(51003, 53, dns_message("typo.exampel", 0x3333)), proto=17))
    add(frame(RESOLVER, CLIENT,
              udp(53, 51003, dns_message("typo.exampel", 0x3333, True, rcode=3)), proto=17),
        0.02)
    add(frame(CLIENT, RESOLVER, udp(51004, 53, dns_message("lost.query", 0x4444)), proto=17))
    add(arp_reply("10.0.0.77", "00:11:22:33:44:55"), 0.1)
    add(arp_reply("10.0.0.77", "aa:bb:cc:dd:ee:ff"), 0.1)
    return packets


def write_capture(packets=None):
    packets = packets or build_capture()
    path = os.path.join(tempfile.mkdtemp(), "analyze.pcap")
    with PcapWriter(path) as writer:
        for timestamp, raw in packets:
            writer.write(raw, timestamp)
    return path


def analysis_of(packets=None):
    result = analyze.Analysis()
    for timestamp, raw in (packets or build_capture()):
        result.add(decode.decode(raw), timestamp)
    return result


class TestConversations(unittest.TestCase):
    def setUp(self):
        self.report = analysis_of().report()

    def test_tcp_conversations_count_each_direction(self):
        conversations = self.report["conversations"]["tcp"]
        busiest = conversations[0]
        self.assertEqual({busiest["a"], busiest["b"]},
                         {"%s:51000" % CLIENT, "%s:443" % SERVER})
        self.assertGreater(busiest["packets_ab"], 0)
        self.assertGreater(busiest["packets_ba"], 0)
        self.assertEqual(busiest["packets"], busiest["packets_ab"] + busiest["packets_ba"])
        self.assertEqual(busiest["bytes"], busiest["bytes_ab"] + busiest["bytes_ba"])
        self.assertGreater(busiest["duration"], 0)

    def test_conversations_are_sorted_by_volume(self):
        volumes = [c["bytes"] for c in self.report["conversations"]["ip"]]
        self.assertEqual(volumes, sorted(volumes, reverse=True))

    def test_one_way_conversation_shows_zero_in_the_other_direction(self):
        dead = [c for c in self.report["conversations"]["tcp"]
                if "10.0.0.250:445" in (c["a"], c["b"])][0]
        self.assertTrue(dead["packets_ab"] == 0 or dead["packets_ba"] == 0)

    def test_every_layer_has_its_own_table(self):
        for kind in ("tcp", "udp", "ip", "ethernet"):
            self.assertTrue(self.report["conversations"][kind], kind)

    def test_direction_is_stable_regardless_of_who_speaks_first(self):
        packets = [
            (1.0, frame(SERVER, CLIENT, tcp(443, 51000, 1, 1, 0x18, payload=b"a" * 10))),
            (1.1, frame(CLIENT, SERVER, tcp(51000, 443, 1, 11, 0x18, payload=b"b" * 20))),
        ]
        conversation = analysis_of(packets).report()["conversations"]["tcp"][0]
        self.assertEqual(conversation["packets_ab"], 1)
        self.assertEqual(conversation["packets_ba"], 1)
        self.assertEqual(conversation["bytes"], conversation["bytes_ab"] + conversation["bytes_ba"])


class TestEndpointsAndHierarchy(unittest.TestCase):
    def setUp(self):
        self.report = analysis_of().report()

    def test_endpoints_split_transmit_and_receive(self):
        endpoints = {entry["address"]: entry for entry in self.report["endpoints"]}
        client = endpoints[CLIENT]
        self.assertGreater(client["packets_tx"], 0)
        self.assertGreater(client["packets_rx"], 0)
        self.assertEqual(client["packets"], client["packets_tx"] + client["packets_rx"])
        self.assertGreaterEqual(client["peers"], 2)
        self.assertIn(443, client["top_ports"])

    def test_mac_endpoints_are_tracked_too(self):
        macs = {entry["address"] for entry in self.report["mac_endpoints"]}
        self.assertIn(MACS[CLIENT], macs)

    def test_protocol_hierarchy_percentages(self):
        hierarchy = {entry["layers"]: entry for entry in self.report["hierarchy"]}
        self.assertIn("IPv4 > TCP", hierarchy)
        self.assertIn("IPv4 > UDP > DNS", hierarchy)
        total = sum(entry["packets"] for entry in self.report["hierarchy"])
        self.assertEqual(total, self.report["packets"])
        self.assertLessEqual(hierarchy["IPv4 > TCP"]["packets_pct"], 100.0)


class TestTcpHealth(unittest.TestCase):
    def setUp(self):
        self.tcp = analysis_of().report()["tcp"]

    def test_retransmissions_are_detected(self):
        self.assertEqual(self.tcp["retransmissions"], 6)
        self.assertGreater(self.tcp["retransmission_pct"], 5)

    def test_duplicate_acks(self):
        self.assertGreaterEqual(self.tcp["duplicate_acks"], 4)

    def test_zero_window_and_resets(self):
        self.assertEqual(self.tcp["zero_window"], 1)
        self.assertEqual(self.tcp["resets"], 1)

    def test_handshake_timing(self):
        self.assertAlmostEqual(self.tcp["handshake_ms_avg"], 20.0, delta=1.0)
        self.assertEqual(self.tcp["completed_handshakes"], 1)

    def test_unanswered_syn_is_listed(self):
        targets = {entry["to"] for entry in self.tcp["unanswered_syns"]}
        self.assertIn("10.0.0.250:445", targets)

    def test_clean_session_reports_no_problems(self):
        packets = [
            (1.0, frame(CLIENT, SERVER, tcp(51000, 443, 1, 0, 0x02))),
            (1.01, frame(SERVER, CLIENT, tcp(443, 51000, 100, 2, 0x12))),
            (1.02, frame(CLIENT, SERVER, tcp(51000, 443, 2, 101, 0x10))),
        ]
        for index in range(30):
            packets.append((1.1 + index * 0.01,
                            frame(CLIENT, SERVER, tcp(51000, 443, 2 + index * 50, 101,
                                                      0x18, payload=b"z" * 50))))
        tcp_report = analysis_of(packets).report()["tcp"]
        self.assertEqual(tcp_report["retransmissions"], 0)
        self.assertEqual(tcp_report["resets"], 0)


class TestDnsAndExpert(unittest.TestCase):
    def setUp(self):
        self.report = analysis_of().report()

    def test_dns_latency_and_failures(self):
        dns = self.report["dns"]
        self.assertEqual(dns["queries"], 4)
        self.assertEqual(dns["answered"], 3)
        self.assertEqual(dns["unanswered"], 1)
        self.assertAlmostEqual(dns["latency_ms_max"], 900.0, delta=5.0)
        self.assertTrue(any("NXDOMAIN" in failure for failure in dns["failures"]))
        self.assertEqual(dns["slowest"][0]["name"], "slow.internal")

    def test_findings_cover_every_planted_problem(self):
        text = " ".join(message for _level, message in self.report["findings"]).lower()
        for expected in ("retransmission", "zero-window", "syn/ack", "reset", "nxdomain",
                         "never answered", "duplicate ip"):
            self.assertIn(expected, text, expected)

    def test_duplicate_ip_is_critical(self):
        levels = {level for level, message in self.report["findings"]
                  if "duplicate ip" in message.lower()}
        self.assertEqual(levels, {"critical"})

    def test_quiet_capture_has_nothing_to_report(self):
        packets = [(1.0 + index * 0.1,
                    frame(CLIENT, SERVER, tcp(51000, 443, 1 + index * 10, 1, 0x18,
                                              payload=b"q" * 10)))
                   for index in range(5)]
        findings = analysis_of(packets).report()["findings"]
        self.assertEqual(findings[0][0], "ok")


class TestThroughputAndFiles(unittest.TestCase):
    def test_throughput_buckets(self):
        report = analysis_of().report()
        throughput = report["throughput"]
        self.assertTrue(throughput)
        self.assertEqual(throughput[0]["t"], 0.0)
        self.assertEqual(sum(entry["packets"] for entry in throughput), report["packets"])

    def test_analyze_a_capture_file(self):
        report = analyze.analyze_pcap(write_capture()).report()
        self.assertGreater(report["packets"], 60)
        self.assertTrue(report["conversations"]["tcp"])

    def test_filter_is_applied(self):
        path = write_capture()
        report = analyze.analyze_pcap(path, filter_expr="udp and port 53").report()
        self.assertEqual(report["conversations"]["tcp"], [])
        self.assertEqual(report["dns"]["queries"], 4)

    def test_follow_stream_returns_both_directions(self):
        path = write_capture()
        conversation, chunks = analyze.follow_stream(path, index=0)
        self.assertEqual({conversation["a"], conversation["b"]},
                         {"%s:51000" % CLIENT, "%s:443" % SERVER})
        directions = {direction for direction, _payload in chunks}
        self.assertEqual(directions, {"a", "b"})
        self.assertTrue(all(payload for _direction, payload in chunks))

    def test_follow_stream_out_of_range(self):
        with self.assertRaises(IndexError):
            analyze.follow_stream(write_capture(), index=99)

    def test_stream_formatting(self):
        _conversation, chunks = analyze.follow_stream(write_capture(), index=0)
        text = analyze.format_stream(chunks[:2])
        self.assertIn("->", text)
        hex_dump = analyze.format_stream(chunks[:1], as_hex=True)
        self.assertIn("0000", hex_dump)
        self.assertIn("78 78", hex_dump)          # 'x' payload

    def test_empty_analysis(self):
        report = analyze.Analysis().report()
        self.assertEqual(report["packets"], 0)
        self.assertEqual(report["findings"][0][0], "ok")
        self.assertEqual(report["throughput"], [])


if __name__ == "__main__":
    unittest.main()
