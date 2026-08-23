"""Mirror-port capture: per-VLAN inventory, health checks and switch configuration."""

import os
import socket
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nettool import decode, mirror
from nettool.pcap import PcapWriter

LOCAL_MAC = "02:fc:00:00:00:01"
CLIENT = "00:1b:21:aa:00:05"
SERVER = "3c:22:fb:bb:00:06"
GATEWAY = "00:0c:29:cc:00:01"


def eth(dst, src, vlan, etype, payload, tpid=0x8100):
    frame = bytes.fromhex(dst.replace(":", "")) + bytes.fromhex(src.replace(":", ""))
    if vlan is not None:
        frame += struct.pack("!HH", tpid, vlan)
    frame += struct.pack("!H", etype) + payload
    return frame + b"\x00" * max(0, 60 - len(frame))


def ipv4(src, dst, proto, payload):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0x4000, 64,
                         proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return header + payload


def tcp(sport, dport, flags=0x18):
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 0x50, flags, 8192, 0, 0) + b"x" * 60


def udp(sport, dport):
    return struct.pack("!HHHH", sport, dport, 48, 0) + b"\x00" * 40


def conversation(vlan=30):
    """A two-way TCP flow plus a DHCP offer and a broadcast, all on one VLAN."""
    return [
        eth(SERVER, CLIENT, vlan, 0x0800, ipv4("10.10.30.5", "10.10.30.6", 6, tcp(51000, 443))),
        eth(CLIENT, SERVER, vlan, 0x0800, ipv4("10.10.30.6", "10.10.30.5", 6, tcp(443, 51000, 0x10))),
        eth("ff:ff:ff:ff:ff:ff", GATEWAY, vlan, 0x0800,
            ipv4("10.10.30.1", "255.255.255.255", 17, udp(67, 68))),
    ]


def survey_from(frames, local_macs=None, start=1000.0):
    survey = mirror.MirrorSurvey(local_macs=local_macs or [LOCAL_MAC])
    for index, raw in enumerate(frames):
        survey.add(decode.decode(raw), start + index * 0.01)
    return survey


class TestVlanInventory(unittest.TestCase):
    def test_groups_traffic_by_vlan(self):
        frames = conversation(30) * 3 + conversation(40) * 2
        report = survey_from(frames).report()
        vlans = {entry["vlan"]: entry for entry in report["vlans"]}
        self.assertEqual(sorted(vlans), [30, 40])
        self.assertEqual(vlans[30]["packets"], 9)
        self.assertEqual(vlans[40]["packets"], 6)
        self.assertEqual(report["tagged"], 15)
        self.assertEqual(report["untagged"], 0)

    def test_hosts_and_services_per_vlan(self):
        report = survey_from(conversation(30) * 2).report()
        vlan = report["vlans"][0]
        addresses = {host["ip"] for host in vlan["hosts"]}
        self.assertIn("10.10.30.5", addresses)
        self.assertIn("10.10.30.6", addresses)
        self.assertEqual(vlan["dhcp_servers"], ["10.10.30.1"])
        self.assertIn("443/tcp", vlan["services"])
        self.assertEqual(vlan["unique_macs"], 3)

    def test_untagged_frames_get_their_own_bucket(self):
        frames = conversation(30) + [eth(SERVER, CLIENT, None, 0x0800,
                                         ipv4("192.168.1.2", "192.168.1.3", 6, tcp(1, 2)))]
        report = survey_from(frames).report()
        vlans = [entry["vlan"] for entry in report["vlans"]]
        self.assertIn(None, vlans)
        self.assertEqual(vlans[-1], None)          # untagged sorts last
        self.assertEqual(report["untagged"], 1)

    def test_qinq_is_counted_and_keyed_on_the_inner_vlan(self):
        frame = bytes.fromhex(SERVER.replace(":", "")) + bytes.fromhex(CLIENT.replace(":", ""))
        frame += struct.pack("!HHHH", 0x88A8, 100, 0x8100, 30)
        frame += struct.pack("!H", 0x0800) + ipv4("10.0.0.1", "10.0.0.2", 6, tcp(80, 80))
        report = survey_from([frame]).report()
        self.assertEqual(report["qinq"], 1)
        self.assertEqual(report["vlans"][0]["vlan"], 30)

    def test_broadcast_and_multicast_counts(self):
        frames = conversation(30)
        report = survey_from(frames).report()
        self.assertEqual(report["vlans"][0]["broadcast"], 1)


class TestMirrorHealth(unittest.TestCase):
    def test_no_traffic_at_all(self):
        findings = mirror.MirrorSurvey().findings()
        self.assertEqual(findings[0][0], "critical")
        self.assertIn("No frames", findings[0][1])

    def test_only_our_own_traffic_means_it_is_not_a_mirror(self):
        frames = [eth(SERVER, LOCAL_MAC, 30, 0x0800,
                      ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2)))] * 5
        findings = survey_from(frames).findings()
        self.assertEqual(findings[0][0], "critical")
        self.assertIn("not a mirror port", findings[0][1])

    def test_mostly_our_own_traffic_is_a_warning(self):
        frames = [eth(SERVER, LOCAL_MAC, 30, 0x0800,
                      ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2)))] * 8
        frames += conversation(30)
        levels = {level for level, _ in survey_from(frames).findings()}
        self.assertIn("warn", levels)

    def test_missing_vlan_tags_are_called_out(self):
        frames = [eth(SERVER, CLIENT, None, 0x0800,
                      ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2)))] * 4
        text = " ".join(message for _level, message in survey_from(frames).findings())
        self.assertIn("stripping VLAN tags", text)

    def test_one_directional_mirror_is_detected(self):
        frames = []
        for index in range(120):
            frames.append(eth(SERVER, CLIENT, 30, 0x0800,
                              ipv4("10.10.30.%d" % (index % 50 + 5), "10.10.30.200", 6,
                                   tcp(1000 + index, 443))))
        text = " ".join(message for _level, message in survey_from(frames).findings())
        self.assertIn("one direction", text)

    def test_both_directions_is_reported_as_healthy(self):
        survey = survey_from(conversation(30) * 40)
        self.assertGreater(survey.bidirectional_share(), 0.6)
        text = " ".join(message for _level, message in survey.findings())
        self.assertIn("Both directions", text)

    def test_kernel_drops_are_surfaced(self):
        survey = survey_from(conversation(30))
        survey.kernel_dropped = 1234
        text = " ".join(message for _level, message in survey.findings())
        self.assertIn("1234", text)
        self.assertIn("--vlan", text)

    def test_broadcast_storm(self):
        frames = [eth("ff:ff:ff:ff:ff:ff", CLIENT, 30, 0x0806, b"\x00" * 28)] * 10
        text = " ".join(message for _level, message in survey_from(frames).findings())
        self.assertIn("broadcast", text)


class TestVendorDetection(unittest.TestCase):
    def test_recognises_common_platforms(self):
        cases = [
            ({"system_description": "Cisco IOS Software, C9300"}, "cisco-ios"),
            ({"system_description": "Cisco Nexus Operating System (NX-OS)"}, "cisco-nxos"),
            ({"platform": "Aruba JL658A 6300M"}, "aruba-cx"),
            ({"system_description": "ProCurve J9085A Switch 2610"}, "aruba-procurve"),
            ({"system_description": "Juniper Networks EX2300, JUNOS 21.4"}, "juniper"),
            ({"platform": "MikroTik CRS326-24G"}, "mikrotik"),
            ({"system_description": "UniFi Switch 24 PoE"}, "ubiquiti"),
            ({"system_description": "Extreme Networks X440-G2, EXOS"}, "extreme"),
        ]
        for neighbor, expected in cases:
            self.assertEqual(mirror.detect_vendor(neighbor), expected, neighbor)

    def test_unknown_platform(self):
        self.assertIsNone(mirror.detect_vendor({"system_description": "Acme Switch 9000"}))
        self.assertIsNone(mirror.detect_vendor({}))
        self.assertIsNone(mirror.detect_vendor(None))


class TestSpanConfig(unittest.TestCase):
    def test_cisco_ios_vlan_source_keeps_tags(self):
        config = mirror.span_config("cisco-ios", source_vlan=30, dest_port="Gi1/0/24")
        self.assertIn("monitor session 1 source vlan 30 both", config)
        self.assertIn("destination interface Gi1/0/24", config)
        self.assertIn("encapsulation dot1q", config)

    def test_cisco_ios_port_source(self):
        config = mirror.span_config("cisco-ios", source_port="Gi1/0/5", dest_port="Gi1/0/24")
        self.assertIn("source interface Gi1/0/5 both", config)

    def test_every_vendor_produces_something_usable(self):
        for vendor in ("cisco-ios", "cisco-nxos", "aruba-cx", "aruba-procurve", "juniper",
                       "mikrotik", "ubiquiti", "extreme", "unknown"):
            config = mirror.span_config(vendor, source_vlan=30, dest_port="port24")
            self.assertTrue(config.strip(), vendor)
            self.assertIn("port24", config, vendor)

    def test_session_number_is_honoured(self):
        config = mirror.span_config("cisco-ios", source_vlan=10, dest_port="Gi1/0/2",
                                    session=4)
        self.assertIn("monitor session 4", config)

    def test_plan_uses_the_lldp_neighbour(self):
        neighbor = {
            "system_name": "sw-idf3-01",
            "system_description": "Cisco IOS Software, C9300",
            "port_id": "GigabitEthernet1/0/24",
            "port_vlan_id": 30,
            "mgmt_addrs": [{"address": "10.20.0.5"}],
        }
        plan = mirror.plan(neighbor, source_vlan=30)
        self.assertEqual(plan["vendor"], "cisco-ios")
        self.assertEqual(plan["switch"], "sw-idf3-01")
        self.assertEqual(plan["destination_port"], "GigabitEthernet1/0/24")
        self.assertEqual(plan["management_ip"], "10.20.0.5")
        self.assertEqual(plan["native_vlan"], 30)
        self.assertIn("GigabitEthernet1/0/24", plan["config"])

    def test_plan_without_a_neighbour_still_explains_itself(self):
        plan = mirror.plan(None, source_vlan=50)
        self.assertEqual(plan["vendor"], "unknown")
        self.assertIn("VLAN 50", plan["config"])


class TestFileHandling(unittest.TestCase):
    def test_split_file_naming(self):
        self.assertEqual(mirror._writer_path("span.pcap", "vlan30"), "span-vlan30.pcap")
        self.assertEqual(mirror._writer_path("/tmp/span", "vlan30"), "/tmp/span-vlan30.pcap")
        self.assertEqual(mirror._writer_path("/tmp/a.b/span.pcap", "untagged"),
                         "/tmp/a.b/span-untagged.pcap")

    def test_survey_from_a_capture_file(self):
        path = os.path.join(tempfile.mkdtemp(), "span.pcap")
        with PcapWriter(path) as writer:
            for index, raw in enumerate(conversation(30) * 3 + conversation(40)):
                writer.write(raw, 1000.0 + index)
        report = mirror.survey_pcap(path).report()
        self.assertEqual({entry["vlan"] for entry in report["vlans"]}, {30, 40})
        self.assertEqual(report["packets"], 12)

    def test_survey_from_a_file_can_filter_vlans(self):
        path = os.path.join(tempfile.mkdtemp(), "span.pcap")
        with PcapWriter(path) as writer:
            for index, raw in enumerate(conversation(30) + conversation(40)):
                writer.write(raw, 1000.0 + index)
        report = mirror.survey_pcap(path, vlans=[40]).report()
        self.assertEqual([entry["vlan"] for entry in report["vlans"]], [40])
        self.assertEqual(report["packets"], 3)


if __name__ == "__main__":
    unittest.main()
