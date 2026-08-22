import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nettool import lldp


def tlv(ttype, value):
    return struct.pack("!H", (ttype << 9) | len(value)) + value


def build_lldp():
    chassis = tlv(1, bytes([4]) + bytes.fromhex("aabbccddeeff"))          # MAC subtype
    port = tlv(2, bytes([5]) + b"GigabitEthernet1/0/24")                  # iface name
    ttl = tlv(3, struct.pack("!H", 120))
    portdesc = tlv(4, b"uplink to lab bench")
    sysname = tlv(5, b"sw-idf3-01")
    sysdesc = tlv(6, b"Cisco IOS Software, C9300")
    caps = tlv(7, struct.pack("!HH", 0x0014, 0x0004))                     # bridge+router / bridge
    mgmt = tlv(8, bytes([5, 1]) + bytes([10, 20, 0, 5]) + bytes([2]) + struct.pack("!I", 42) + bytes([0]))
    pvid = tlv(127, b"\x00\x80\xc2" + bytes([1]) + struct.pack("!H", 30))
    vlanname = tlv(127, b"\x00\x80\xc2" + bytes([3]) + struct.pack("!H", 30) + bytes([4]) + b"LABS")
    macphy = tlv(127, b"\x00\x12\x0f" + bytes([1]) + bytes([0x03]) + struct.pack("!H", 0x6C00) + struct.pack("!H", 30))
    poe = tlv(127, b"\x00\x12\x0f" + bytes([2]) + bytes([0x07, 0x01, 0x04]) + struct.pack("!HH", 154, 154))
    maxframe = tlv(127, b"\x00\x12\x0f" + bytes([4]) + struct.pack("!H", 9216))
    med = tlv(127, b"\x00\x12\xbb" + bytes([2]) + bytes([1]) + bytes([0x05, 0x82, 0x2e]))
    end = tlv(0, b"")
    payload = (chassis + port + ttl + portdesc + sysname + sysdesc + caps + mgmt +
               pvid + vlanname + macphy + poe + maxframe + med + end)
    return (bytes.fromhex("0180c200000e") + bytes.fromhex("aabbccddeeff") +
            struct.pack("!H", 0x88CC) + payload)


def build_cdp():
    def ctlv(t, v):
        return struct.pack("!HH", t, len(v) + 4) + v
    body = (ctlv(0x0001, b"sw-core-1.example.net") +
            ctlv(0x0003, b"FastEthernet0/12") +
            ctlv(0x0004, struct.pack("!I", 0x00000029)) +
            ctlv(0x0005, b"Cisco IOS 15.2") +
            ctlv(0x0006, b"cisco WS-C2960X") +
            ctlv(0x0009, b"LAB-VTP") +
            ctlv(0x000A, struct.pack("!H", 77)) +
            ctlv(0x000B, bytes([1])) +
            ctlv(0x0002, struct.pack("!I", 1) + bytes([1, 1, 0xcc]) +
                 struct.pack("!H", 4) + bytes([10, 20, 0, 6])) +
            ctlv(0x0010, struct.pack("!H", 6300)))
    cdp = bytes([2, 180, 0, 0]) + body
    snap = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + cdp
    return (bytes.fromhex("01000ccccccc") + bytes.fromhex("112233445566") +
            struct.pack("!H", len(snap)) + snap)


class TestLLDP(unittest.TestCase):
    def setUp(self):
        self.n = lldp.parse_lldp(build_lldp())

    def test_core_fields(self):
        n = self.n
        self.assertEqual(n["protocol"], "LLDP")
        self.assertEqual(n["chassis_id"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(n["chassis_id_type"], "mac")
        self.assertEqual(n["port_id"], "GigabitEthernet1/0/24")
        self.assertEqual(n["system_name"], "sw-idf3-01")
        self.assertEqual(n["port_description"], "uplink to lab bench")
        self.assertEqual(n["ttl"], 120)

    def test_capabilities_and_mgmt(self):
        self.assertIn("Bridge", self.n["capabilities"])
        self.assertIn("Router", self.n["capabilities"])
        self.assertEqual(self.n["enabled_capabilities"], ["Bridge"])
        self.assertEqual(self.n["mgmt_addrs"][0]["address"], "10.20.0.5")
        self.assertEqual(self.n["mgmt_addrs"][0]["interface"], 42)

    def test_org_tlvs(self):
        n = self.n
        self.assertEqual(n["port_vlan_id"], 30)
        self.assertEqual(n["vlans"], [{"vlan": 30, "name": "LABS"}])
        self.assertEqual(n["max_frame_size"], 9216)
        self.assertTrue(n["autoneg_supported"])
        self.assertTrue(n["autoneg_enabled"])
        self.assertEqual(n["mau_type"], "1000BASE-T full")
        self.assertEqual(n["poe"]["port_class"], "PSE")
        self.assertEqual(n["poe"]["allocated_mw"], 15400)
        policy = n["med_policies"][0]
        self.assertEqual(policy["application"], "voice")
        self.assertEqual(policy["vlan"], 176)
        self.assertTrue(policy["tagged"])

    def test_describe_mentions_key_facts(self):
        text = lldp.describe(self.n)
        self.assertIn("sw-idf3-01", text)
        self.assertIn("GigabitEthernet1/0/24", text)
        self.assertIn("30", text)
        self.assertIn("15.4 W", text)

    def test_rejects_non_lldp(self):
        self.assertIsNone(lldp.parse_lldp(b"\x00" * 60))
        self.assertIsNone(lldp.parse_frame(b"\xff" * 14 + b"junk"))

    def test_truncated_frame_does_not_crash(self):
        frame = build_lldp()
        for cut in range(14, len(frame), 7):
            lldp.parse_frame(frame[:cut])


class TestCDP(unittest.TestCase):
    def setUp(self):
        self.n = lldp.parse_cdp(build_cdp())

    def test_fields(self):
        n = self.n
        self.assertEqual(n["protocol"], "CDP")
        self.assertEqual(n["chassis_id"], "sw-core-1.example.net")
        self.assertEqual(n["port_id"], "FastEthernet0/12")
        self.assertEqual(n["platform"], "cisco WS-C2960X")
        self.assertEqual(n["port_vlan_id"], 77)
        self.assertEqual(n["duplex"], "full")
        self.assertEqual(n["vtp_domain"], "LAB-VTP")
        self.assertIn("Switch", n["capabilities"])
        self.assertIn("Router", n["capabilities"])
        self.assertEqual(n["mgmt_addrs"][0]["address"], "10.20.0.6")
        self.assertEqual(n["poe"]["consumption_mw"], 6300)

    def test_parse_frame_dispatch(self):
        self.assertEqual(lldp.parse_frame(build_cdp())["protocol"], "CDP")
        self.assertEqual(lldp.parse_frame(build_lldp())["protocol"], "LLDP")

    def test_describe(self):
        text = lldp.describe(self.n)
        self.assertIn("sw-core-1", text)
        self.assertIn("6.3 W", text)


class TestFromPcap(unittest.TestCase):
    def test_extract_from_capture(self):
        import tempfile
        from nettool.pcap import PcapWriter
        path = os.path.join(tempfile.mkdtemp(), "n.pcap")
        with PcapWriter(path) as w:
            w.write(build_lldp(), 1000.0)
            w.write(build_cdp(), 1001.0)
            w.write(b"\x00" * 60, 1002.0)
        found = lldp.from_pcap(path)
        self.assertEqual(sorted(n["protocol"] for n in found), ["CDP", "LLDP"])


if __name__ == "__main__":
    unittest.main()
