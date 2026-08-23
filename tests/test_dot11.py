"""802.11 / radiotap decoding, exercised with synthetic frames."""

import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nettool import dot11
from nettool.pcap import PcapWriter

BSSID = "3c:22:fb:11:22:33"
CLIENT = "b8:27:eb:aa:bb:cc"


def mac(text):
    return bytes(int(part, 16) for part in text.split(":"))


def radiotap(signal=-47, freq=2437, rate_mbps=54.0, flags=0, noise=None):
    """Build a radiotap header with flags, rate, channel and antenna signal."""
    present = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5)
    body = struct.pack("<BB", flags, int(rate_mbps * 2))          # flags, rate
    body += struct.pack("<HH", freq, 0x0080 if freq < 2500 else 0x0100)
    body += struct.pack("<b", signal)
    if noise is not None:
        present |= 1 << 6
        body += struct.pack("<b", noise)
    length = 8 + len(body)
    return struct.pack("<BBHI", 0, 0, length, present) + body


def frame_control(ftype, subtype, flags=0):
    return struct.pack("<H", (flags << 8) | (subtype << 4) | (ftype << 2))


def element(eid, payload):
    return bytes([eid, len(payload)]) + payload


def beacon(ssid="HomeNet", channel=6, stations=7, utilization=128, privacy=True,
           bssid=BSSID, sequence=1):
    header = frame_control(0, 8) + struct.pack("<H", 0)
    header += mac("ff:ff:ff:ff:ff:ff") + mac(bssid) + mac(bssid)
    header += struct.pack("<H", sequence << 4)
    capability = 0x0001 | (0x0010 if privacy else 0) | 0x0020
    body = struct.pack("<QHH", 0x1122334455667788, 100, capability)
    body += element(0, ssid.encode())
    body += element(1, b"\x82\x84\x8b\x96")
    body += element(3, bytes([channel]))
    body += element(11, struct.pack("<HBH", stations, utilization, 0))
    # RSN: version, group CCMP, one pairwise CCMP, one AKM PSK
    rsn = struct.pack("<H", 1) + b"\x00\x0f\xac\x04"
    rsn += struct.pack("<H", 1) + b"\x00\x0f\xac\x04"
    rsn += struct.pack("<H", 1) + b"\x00\x0f\xac\x02"
    body += element(48, rsn)
    body += element(61, bytes([channel, 0x05, 0x00, 0x00, 0x00]))
    return header + body


def deauth(reason=7, src=BSSID, dst=CLIENT):
    header = frame_control(0, 12) + struct.pack("<H", 0)
    header += mac(dst) + mac(src) + mac(src) + struct.pack("<H", 0)
    return header + struct.pack("<H", reason)


def probe_request(ssid="HomeNet", src=CLIENT):
    header = frame_control(0, 4) + struct.pack("<H", 0)
    header += mac("ff:ff:ff:ff:ff:ff") + mac(src) + mac("ff:ff:ff:ff:ff:ff")
    header += struct.pack("<H", 0)
    return header + element(0, ssid.encode()) + element(1, b"\x82\x84")


def data_frame(retry=False, to_ds=True, src=CLIENT, bssid=BSSID,
               dst="00:11:22:33:44:55", qos=True):
    flags = (0x01 if to_ds else 0) | (0x08 if retry else 0)
    header = frame_control(2, 8 if qos else 0, flags) + struct.pack("<H", 0)
    header += mac(bssid) + mac(src) + mac(dst) + struct.pack("<H", 0)
    if qos:
        header += struct.pack("<H", 0)
    return header + b"\x00" * 40


class TestRadiotap(unittest.TestCase):
    def test_parses_signal_channel_and_rate(self):
        fields, offset = dot11.parse_radiotap(radiotap(signal=-53, freq=5180, rate_mbps=24.0))
        self.assertEqual(fields["signal_dbm"], -53)
        self.assertEqual(fields["freq"], 5180)
        self.assertEqual(fields["channel"], 36)
        self.assertEqual(fields["band"], "5")
        self.assertEqual(fields["rate_mbps"], 24.0)
        self.assertEqual(offset, fields["radiotap_len"])

    def test_noise_field_shifts_later_fields(self):
        fields, _ = dot11.parse_radiotap(radiotap(signal=-60, noise=-92))
        self.assertEqual(fields["signal_dbm"], -60)
        self.assertEqual(fields["noise_dbm"], -92)

    def test_fcs_flag(self):
        fields, _ = dot11.parse_radiotap(radiotap(flags=dot11.RADIOTAP_FLAG_FCS))
        self.assertTrue(fields["has_fcs"])
        fields, _ = dot11.parse_radiotap(radiotap(flags=dot11.RADIOTAP_FLAG_BADFCS))
        self.assertTrue(fields["bad_fcs"])

    def test_rejects_junk(self):
        self.assertEqual(dot11.parse_radiotap(b"")[1], 0)
        self.assertEqual(dot11.parse_radiotap(b"\x01\x00\x08\x00" + b"\x00" * 8)[1], 0)


class TestFrameDecoding(unittest.TestCase):
    def test_beacon(self):
        info = dot11.parse_dot11(beacon())
        self.assertEqual(info["type"], "management")
        self.assertEqual(info["subtype"], "beacon")
        self.assertEqual(info["bssid"], BSSID)
        self.assertEqual(info["ssid"], "HomeNet")
        self.assertEqual(info["channel"], 6)
        self.assertEqual(info["stations"], 7)
        self.assertAlmostEqual(info["utilization_pct"], 50.2, places=1)
        self.assertEqual(info["beacon_interval"], 100)
        self.assertTrue(info["privacy"])
        self.assertIn("WPA2/WPA3", info["security"])
        self.assertEqual(info["akm_suites"], ["PSK"])
        self.assertEqual(info["pairwise_ciphers"], ["CCMP-128"])
        self.assertIn("n", info["standards"])

    def test_hidden_ssid(self):
        info = dot11.parse_dot11(beacon(ssid=""))
        self.assertTrue(info["hidden"])

    def test_open_network(self):
        frame = frame_control(0, 8) + struct.pack("<H", 0)
        frame += mac("ff:ff:ff:ff:ff:ff") + mac(BSSID) + mac(BSSID) + struct.pack("<H", 0)
        frame += struct.pack("<QHH", 0, 100, 0x0001)
        frame += element(0, b"GuestWiFi") + element(3, bytes([11]))
        info = dot11.parse_dot11(frame)
        self.assertEqual(info["security"], ["open"])

    def test_deauthentication_reason(self):
        info = dot11.parse_dot11(deauth(reason=7))
        self.assertEqual(info["subtype"], "deauthentication")
        self.assertEqual(info["reason_code"], 7)
        self.assertIn("non-associated", info["reason"])
        self.assertEqual(info["src"], BSSID)
        self.assertEqual(info["dst"], CLIENT)

    def test_probe_request(self):
        info = dot11.parse_dot11(probe_request("CorpWiFi"))
        self.assertEqual(info["subtype"], "probe-request")
        self.assertEqual(info["ssid"], "CorpWiFi")
        self.assertEqual(info["src"], CLIENT)

    def test_data_frame_addressing_and_retry(self):
        info = dot11.parse_dot11(data_frame(retry=True))
        self.assertEqual(info["type"], "data")
        self.assertEqual(info["subtype"], "qos-data")
        self.assertTrue(info["retry"])
        self.assertTrue(info["to_ds"])
        self.assertEqual(info["bssid"], BSSID)
        self.assertEqual(info["src"], CLIENT)

    def test_from_ds_swaps_the_addresses(self):
        info = dot11.parse_dot11(data_frame(to_ds=False, qos=False))
        self.assertEqual(info["dst"], BSSID)          # addr1 with neither DS bit set

    def test_control_frames_have_one_address(self):
        frame = frame_control(1, 13) + struct.pack("<H", 0) + mac(CLIENT)
        info = dot11.parse_dot11(frame)
        self.assertEqual(info["type"], "control")
        self.assertEqual(info["subtype"], "ack")
        self.assertEqual(info["addr1"], CLIENT)

    def test_vendor_lookup_on_source(self):
        info = dot11.parse_dot11(probe_request())
        self.assertEqual(info["src_vendor"], "Raspberry Pi")

    def test_truncated_frames_do_not_raise(self):
        full = radiotap() + beacon()
        for cut in range(0, len(full), 5):
            dot11.decode(full[:cut], 127)

    def test_decode_strips_radiotap_and_fcs(self):
        payload = beacon()
        frame = radiotap(signal=-47, flags=dot11.RADIOTAP_FLAG_FCS) + payload + b"\xde\xad\xbe\xef"
        info = dot11.decode(frame, 127)
        self.assertEqual(info["ssid"], "HomeNet")
        self.assertEqual(info["signal_dbm"], -47)
        self.assertEqual(info["length"], len(payload))

    def test_decode_rejects_non_wireless_linktype(self):
        self.assertIsNone(dot11.decode(b"\x00" * 60, 1))

    def test_summary_line(self):
        info = dot11.decode(radiotap() + beacon(), 127)
        text = dot11.summary(info)
        self.assertIn("beacon", text)
        self.assertIn("HomeNet", text)
        self.assertIn("ch 6", text)


class TestSurvey(unittest.TestCase):
    def build(self):
        survey = dot11.Survey()
        timestamp = 1000.0
        for index in range(10):
            survey.add(dot11.decode(radiotap(signal=-47) + beacon(sequence=index), 127),
                       timestamp + index * 0.1)
        for index in range(4):
            survey.add(dot11.decode(
                radiotap(signal=-72, freq=2412) + beacon(ssid="NeighborNet", channel=1,
                                                         bssid="60:22:32:aa:bb:cc"), 127),
                timestamp + index)
        for index in range(20):
            survey.add(dot11.decode(radiotap(signal=-55) + data_frame(retry=index % 3 == 0), 127),
                       timestamp + index * 0.05)
        survey.add(dot11.decode(radiotap() + probe_request("CorpWiFi"), 127), timestamp)
        for _ in range(3):
            survey.add(dot11.decode(radiotap() + deauth(reason=15), 127), timestamp)
        return survey

    def test_access_point_inventory(self):
        report = self.build().report()
        aps = {ap["bssid"]: ap for ap in report["access_points"]}
        self.assertEqual(len(aps), 2)
        home = aps[BSSID]
        self.assertEqual(home["ssid"], "HomeNet")
        self.assertEqual(home["beacons"], 10)
        self.assertEqual(home["channel"], 6)
        self.assertEqual(home["signal_dbm"], -47)
        self.assertEqual(home["stations"], 7)
        self.assertEqual(aps["60:22:32:aa:bb:cc"]["ssid"], "NeighborNet")
        # Strongest first.
        self.assertEqual(report["access_points"][0]["bssid"], BSSID)

    def test_clients_and_probes(self):
        report = self.build().report()
        clients = {c["mac"]: c for c in report["clients"]}
        self.assertIn(CLIENT, clients)
        self.assertEqual(clients[CLIENT]["vendor"], "Raspberry Pi")
        self.assertIn("CorpWiFi", clients[CLIENT]["probes"])
        self.assertIn(BSSID, clients[CLIENT]["bssids"])
        self.assertGreater(clients[CLIENT]["retry_pct"], 0)

    def test_retries_and_deauths_surface_as_findings(self):
        report = self.build().report()
        self.assertGreater(report["retry_pct"], 0)
        self.assertEqual(sum(d["count"] for d in report["deauths"]), 3)
        text = " ".join(message for _level, message in report["findings"])
        self.assertIn("deauth", text.lower())
        self.assertIn("handshake timeout", text)

    def test_channel_histogram(self):
        report = self.build().report()
        self.assertIn(6, report["channels"])
        self.assertIn(1, report["channels"])
        self.assertEqual(report["channels"][1]["bssids"], 1)

    def test_feeds_the_existing_channel_analysis(self):
        from nettool import wifi

        networks = self.build().to_networks()
        self.assertEqual(len(networks), 2)
        analysis = wifi.analyze(networks, {})
        self.assertIn("2.4", analysis["bands"])
        self.assertIn(analysis["recommendations"]["2.4"]["channel"], [1, 6, 11])

    def test_empty_survey_is_clean(self):
        report = dot11.Survey().report()
        self.assertEqual(report["frames"], 0)
        self.assertEqual(report["findings"][0][0], "ok")

    def test_survey_from_a_capture_file(self):
        from nettool.pcap import LINKTYPE_IEEE802_11_RADIOTAP

        path = os.path.join(tempfile.mkdtemp(), "air.pcap")
        with PcapWriter(path, LINKTYPE_IEEE802_11_RADIOTAP) as writer:
            for index in range(5):
                writer.write(radiotap(signal=-50) + beacon(), 2000.0 + index)
            writer.write(radiotap() + deauth(), 2005.0)
        survey = dot11.survey_pcap(path)
        report = survey.report()
        self.assertEqual(report["frames"], 6)
        self.assertEqual(len(report["access_points"]), 1)
        self.assertEqual(report["access_points"][0]["beacons"], 5)
        self.assertAlmostEqual(report["duration"], 5.0, places=1)

    def test_rejects_a_wired_capture(self):
        path = os.path.join(tempfile.mkdtemp(), "wired.pcap")
        with PcapWriter(path) as writer:
            writer.write(b"\x00" * 60, 1.0)
        with self.assertRaises(ValueError):
            dot11.survey_pcap(path)


if __name__ == "__main__":
    unittest.main()
