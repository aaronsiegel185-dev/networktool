import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nettool import wifi

IW_SCAN = """BSS 3c:37:86:11:22:33(on wlan0) -- associated
\tTSF: 128374652 usec (1d, 11:39:34)
\tfreq: 2437
\tbeacon interval: 100 TUs
\tcapability: ESS Privacy ShortSlotTime (0x0431)
\tsignal: -47.00 dBm
\tlast seen: 120 ms ago
\tSSID: HomeNet
\tSupported rates: 1.0* 2.0* 5.5* 11.0*
\tDS Parameter set: channel 6
\tERP: <no flags>
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: PSK
\tBSS Load:
\t\t * station count: 7
\t\t * channel utilisation: 128/255
\t\t * available admission capacity: 0 [*32us]
\tHT operation:
\t\t * primary channel: 6
\t\t * secondary channel offset: above
\t\t * STA channel width: any
\tCountry: US\tEnvironment: Indoor
BSS 60:22:32:aa:bb:cc(on wlan0)
\tfreq: 2412
\tsignal: -72.00 dBm
\tSSID: NeighborWifi
\tDS Parameter set: channel 1
\tRSN:\t * Version: 1
\t\t * Authentication suites: PSK SAE
BSS 04:18:d6:de:ad:01(on wlan0)
\tfreq: 5180
\tsignal: -58.00 dBm
\tSSID: HomeNet-5G
\tDS Parameter set: channel 36
\tRSN:\t * Version: 1
\t\t * Authentication suites: PSK
\tVHT operation:
\t\t * channel width: 1 (80 MHz)
\t\t * center freq segment 1: 42
\tHE capabilities:
\t\t * HE MAC Capabilities
BSS 04:18:d6:de:ad:02(on wlan0)
\tfreq: 5745
\tsignal: -80.00 dBm
\tSSID:
\tDS Parameter set: channel 149
"""

IW_LINK = """Connected to 3c:37:86:11:22:33 (on wlan0)
\tSSID: HomeNet
\tfreq: 2437
\tRX: 91827364 bytes (123456 packets)
\tTX: 1827364 bytes (23456 packets)
\tsignal: -47 dBm
\trx bitrate: 130.0 MBit/s MCS 15
\ttx bitrate: 144.4 MBit/s MCS 15 short GI
\tbss flags:\tshort-slot-time
"""

IW_STATION = """Station 3c:37:86:11:22:33 (on wlan0)
\tinactive time:\t20 ms
\trx bytes:\t91827364
\trx packets:\t123456
\ttx bytes:\t1827364
\ttx packets:\t10000
\ttx retries:\t2500
\ttx failed:\t250
\tbeacon loss:\t3
\tsignal:  \t-47 [-49, -52] dBm
\tsignal avg:\t-48 dBm
\ttx bitrate:\t144.4 MBit/s MCS 15 short GI
\tconnected time:\t3600 seconds
"""

IW_SURVEY = """Survey data from wlan0
\tfrequency:\t\t\t2412 MHz
Survey data from wlan0
\tfrequency:\t\t\t2437 MHz [in use]
\tnoise:\t\t\t\t-89 dBm
\tchannel active time:\t\t10000 ms
\tchannel busy time:\t\t7500 ms
\tchannel receive time:\t\t1000 ms
\tchannel transmit time:\t\t500 ms
"""

NMCLI = """HomeNet:3C\\:37\\:86\\:11\\:22\\:33:6:2437 MHz:82:WPA2
NeighborWifi:60\\:22\\:32\\:AA\\:BB\\:CC:1:2412 MHz:37:WPA2
"""


class TestFrequencyMath(unittest.TestCase):
    def test_channels(self):
        self.assertEqual(wifi.freq_to_channel(2412), 1)
        self.assertEqual(wifi.freq_to_channel(2437), 6)
        self.assertEqual(wifi.freq_to_channel(2484), 14)
        self.assertEqual(wifi.freq_to_channel(5180), 36)
        self.assertEqual(wifi.freq_to_channel(5745), 149)
        self.assertEqual(wifi.freq_to_channel(6135), 37)
        self.assertEqual(wifi.channel_to_freq(11, "2.4"), 2462)
        self.assertEqual(wifi.channel_to_freq(36, "5"), 5180)

    def test_bands(self):
        self.assertEqual(wifi.band_of(2437), "2.4")
        self.assertEqual(wifi.band_of(5500), "5")
        self.assertEqual(wifi.band_of(6115), "6")

    def test_overlap(self):
        self.assertEqual(wifi.overlap_factor(6, 6, "2.4"), 1.0)
        self.assertEqual(wifi.overlap_factor(1, 6, "2.4"), 0.0)
        self.assertAlmostEqual(wifi.overlap_factor(6, 8, "2.4"), 0.6)
        self.assertEqual(wifi.overlap_factor(36, 40, "5"), 0.0)

    def test_rating(self):
        self.assertEqual(wifi.signal_rating(-45), "excellent")
        self.assertEqual(wifi.signal_rating(-85), "unusable")
        self.assertEqual(wifi.quality_percent(-90), 0)
        self.assertEqual(wifi.quality_percent(-30), 100)


class TestScanParsing(unittest.TestCase):
    def setUp(self):
        self.nets = wifi.parse_iw_scan(IW_SCAN)

    def test_count_and_fields(self):
        self.assertEqual(len(self.nets), 4)
        home = self.nets[0]
        self.assertEqual(home["ssid"], "HomeNet")
        self.assertEqual(home["bssid"], "3c:37:86:11:22:33")
        self.assertEqual(home["channel"], 6)
        self.assertEqual(home["band"], "2.4")
        self.assertEqual(home["signal_dbm"], -47.0)
        self.assertTrue(home["associated"])
        self.assertEqual(home["stations"], 7)
        self.assertAlmostEqual(home["utilization_pct"], 50.2, places=1)
        self.assertEqual(home["width_mhz"], 40)
        self.assertEqual(home["country"], "US")
        self.assertIn("n", home["standards"])
        self.assertEqual(home["rating"], "excellent")

    def test_security(self):
        self.assertIn("WPA2/WPA3", self.nets[0]["security"])
        self.assertIn("WPA3-SAE", self.nets[1]["security"])

    def test_5ghz_entry(self):
        five = self.nets[2]
        self.assertEqual(five["channel"], 36)
        self.assertEqual(five["band"], "5")
        self.assertEqual(five["width_mhz"], 80)
        self.assertIn("ac", five["standards"])
        self.assertIn("ax", five["standards"])

    def test_hidden_ssid(self):
        self.assertEqual(self.nets[3]["ssid"], "")

    def test_empty_input(self):
        self.assertEqual(wifi.parse_iw_scan(""), [])


class TestLinkAndStation(unittest.TestCase):
    def test_link(self):
        info = wifi.parse_iw_link(IW_LINK)
        self.assertTrue(info["connected"])
        self.assertEqual(info["ssid"], "HomeNet")
        self.assertEqual(info["channel"], 6)
        self.assertEqual(info["signal_dbm"], -47)
        self.assertIn("144.4", info["tx_bitrate"])

    def test_not_connected(self):
        self.assertFalse(wifi.parse_iw_link("Not connected.")["connected"])

    def test_station(self):
        st = wifi.parse_iw_station(IW_STATION)[0]
        self.assertEqual(st["tx_retries"], 2500)
        self.assertEqual(st["retry_pct"], 25.0)
        self.assertEqual(st["fail_pct"], 2.5)
        self.assertEqual(st["signal_dbm"], -47)
        self.assertEqual(st["signal_avg_dbm"], -48)

    def test_survey(self):
        surveys = wifi.parse_iw_survey(IW_SURVEY)
        self.assertEqual(len(surveys), 2)
        used = [s for s in surveys if s["in_use"]][0]
        self.assertEqual(used["channel"], 6)
        self.assertEqual(used["noise_dbm"], -89)
        self.assertEqual(used["busy_pct"], 75.0)
        self.assertEqual(used["rx_pct"], 10.0)
        self.assertEqual(used["tx_pct"], 5.0)
        self.assertEqual(used["interference_pct"], 60.0)

    def test_nmcli_fallback(self):
        nets = wifi.parse_nmcli_scan(NMCLI)
        self.assertEqual(len(nets), 2)
        self.assertEqual(nets[0]["bssid"], "3c:37:86:11:22:33")
        self.assertEqual(nets[0]["channel"], 6)
        self.assertLess(nets[0]["signal_dbm"], 0)


class TestAnalysis(unittest.TestCase):
    def setUp(self):
        self.nets = wifi.parse_iw_scan(IW_SCAN)
        self.current = {"signal_dbm": -47, "channel": 6, "band": "2.4", "noise_dbm": -89,
                        "snr_db": 42, "station": wifi.parse_iw_station(IW_STATION)[0],
                        "proc": {"missed_beacons": 4}}
        self.survey = wifi.parse_iw_survey(IW_SURVEY)

    def test_bands_and_recommendation(self):
        report = wifi.analyze(self.nets, self.current, self.survey)
        self.assertEqual(report["total_bss"], 4)
        self.assertIn("2.4", report["bands"])
        self.assertIn("5", report["bands"])
        rec24 = report["recommendations"]["2.4"]["channel"]
        self.assertIn(rec24, [1, 6, 11])
        self.assertEqual(rec24, 11)   # 1 and 6 are occupied in the sample
        self.assertIn(report["recommendations"]["5"]["channel"], [36, 149])

    def test_channel_stats(self):
        report = wifi.analyze(self.nets, self.current, self.survey)
        ch6 = report["bands"]["2.4"]["channels"][6]
        self.assertEqual(ch6["bss"], 1)
        self.assertEqual(ch6["strongest_ssid"], "HomeNet")
        self.assertEqual(ch6["utilization_pct"], 50.2)

    def test_findings_flag_retries_and_airtime(self):
        report = wifi.analyze(self.nets, self.current, self.survey)
        text = " ".join(msg for _lvl, msg in report["findings"])
        self.assertIn("retry", text.lower())
        self.assertIn("airtime", text.lower())
        self.assertIn("interference", text.lower())
        self.assertTrue(any(lvl == "critical" for lvl, _ in report["findings"]))

    def test_weak_signal_finding(self):
        report = wifi.analyze(self.nets, {"signal_dbm": -80, "channel": 6, "band": "2.4"})
        levels = [lvl for lvl, _ in report["findings"]]
        self.assertIn("critical", levels)

    def test_clean_report_when_nothing_wrong(self):
        report = wifi.analyze([], {})
        self.assertEqual(report["findings"][0][0], "ok")


if __name__ == "__main__":
    unittest.main()
