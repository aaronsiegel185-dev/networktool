"""macOS platform parsers, exercised against recorded command output."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nettool import darwin

IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\toptions=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
\tnd6 options=201<PERFORMNUD,DAD>
gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\toptions=6463<RXCSUM,TXCSUM,TSO4,TSO6,CHANNEL_IO>
\tether 3c:22:fb:aa:bb:cc
\tinet6 fe80::14cd:1234:5678:9abc%en0 prefixlen 64 secured scopeid 0xc
\tinet 192.168.1.42 netmask 0xffffff00 broadcast 192.168.1.255
\tnd6 options=201<PERFORMNUD,DAD>
\tmedia: autoselect
\tstatus: active
en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 00:e0:4c:68:12:34
\tinet 10.0.7.9 netmask 0xfffffe00 broadcast 10.0.7.255
\tmedia: autoselect (1000baseT <full-duplex,flow-control>)
\tstatus: active
en6: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500
\tether 00:e0:4c:99:88:77
\tmedia: none
\tstatus: inactive
"""

NETSTAT_ROUTES = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
127                127.0.0.1          UCS                   lo0
127.0.0.1          127.0.0.1          UH                    lo0
169.254            link#12            UCS                   en0      !
192.168.1          link#12            UCS                   en0      !
192.168.1.1/32     link#12            UCS                   en0      !
192.168.1.1        3c:22:fb:11:22:33  UHLWIir               en0   1183
224.0.0/4          link#12            UmCS                  en0      !
"""

NETSTAT_COUNTERS = """Name  Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
lo0   16384 <Link#1>                            21254     0    5410992    21254     0    5410992     0
en0   1500  <Link#12>     3c:22:fb:aa:bb:cc   1234567     3 1234567890   987654     1  987654321     0
en0   1500  192.168.1     192.168.1.42        1234000     -    1230000   987000     -  987000000     -
"""

ARP = """? (192.168.1.1) at 3c:22:fb:11:22:33 on en0 ifscope [ethernet]
? (192.168.1.77) at 8:0:27:1:2:3 on en0 ifscope [ethernet]
? (192.168.1.90) at (incomplete) on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
"""

SCUTIL_DNS = """DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : 8.8.8.8
  if_index : 12 (en0)
  flags    : Request A records, Request AAAA records
  reach    : 0x00000002 (Reachable)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
"""

WDUTIL = """NETWORK
———————
    Primary IPv4          : en0 (192.168.1.42)

WIFI
————
    MAC Address          : 3c:22:fb:aa:bb:cc
    Interface Name       : en0
    Power                : On [On]
    SSID                 : HomeNet
    BSSID                : 3C:22:FB:11:22:33
    RSSI                 : -47 dBm
    Noise                : -92 dBm
    Tx Rate              : 1200.0 Mbps
    Security             : WPA2 Personal
    PHY Mode             : 11ax
    Channel              : 5g36/80
    Country Code         : US

BLUETOOTH
—————————
    Power                : On
"""

WDUTIL_REDACTED = """WIFI
————
    Interface Name       : en0
    SSID                 : <redacted>
    BSSID                : <redacted>
    RSSI                 : -61 dBm
    Noise                : -89 dBm
    Channel              : 2g6/20
"""

AIRPORT_JSON = json.dumps({
    "SPAirPortDataType": [{
        "spairport_airport_interfaces": [{
            "_name": "en0",
            "spairport_current_network_information": {
                "_name": "HomeNet",
                "spairport_network_channel": "36 (5GHz, 80MHz)",
                "spairport_network_phymode": "802.11ax",
                "spairport_network_rate": 1200,
                "spairport_security_mode": "spairport_security_mode_wpa2_personal",
                "spairport_signal_noise": "-47 dBm / -92 dBm",
            },
            "spairport_airport_other_local_wireless_networks": [
                {
                    "_name": "NeighborNet",
                    "spairport_network_channel": "6 (2GHz, 20MHz)",
                    "spairport_network_phymode": "802.11n",
                    "spairport_security_mode": "spairport_security_mode_wpa2_personal",
                    "spairport_signal_noise": "-72 dBm / -90 dBm",
                },
                {
                    "_name": "CoffeeShop",
                    "spairport_network_channel": "11 (2GHz, 20MHz)",
                    "spairport_security_mode": "spairport_security_mode_none",
                    "spairport_signal_noise": "-80 dBm / -90 dBm",
                },
            ],
        }]
    }]
})


class TestIfconfig(unittest.TestCase):
    def setUp(self):
        self.records = darwin.parse_ifconfig(IFCONFIG)

    def test_finds_every_interface(self):
        self.assertEqual(sorted(self.records), ["en0", "en5", "en6", "gif0", "lo0"])

    def test_wifi_interface_fields(self):
        en0 = self.records["en0"]
        self.assertEqual(en0["mac"], "3c:22:fb:aa:bb:cc")
        self.assertEqual(en0["ipv4"], "192.168.1.42")
        self.assertEqual(en0["netmask"], "255.255.255.0")
        self.assertEqual(en0["prefixlen"], 24)
        self.assertEqual(en0["broadcast"], "192.168.1.255")
        self.assertEqual(en0["mtu"], 1500)
        self.assertTrue(en0["up"])
        self.assertTrue(en0["running"])
        self.assertFalse(en0["loopback"])
        self.assertEqual(en0["status"], "active")
        self.assertEqual(len(en0["ipv6"]), 1)
        self.assertTrue(en0["ipv6"][0].endswith("/64"))

    def test_non_standard_prefix_length(self):
        self.assertEqual(self.records["en5"]["prefixlen"], 23)
        self.assertEqual(self.records["en5"]["netmask"], "255.255.254.0")

    def test_loopback_and_down_interfaces(self):
        self.assertTrue(self.records["lo0"]["loopback"])
        self.assertFalse(self.records["en6"]["up"])
        self.assertEqual(self.records["en6"]["status"], "inactive")
        self.assertEqual(self.records["gif0"]["ipv4"], "")

    def test_media_parsing(self):
        self.assertEqual(darwin.parse_media("autoselect (1000baseT <full-duplex>)"),
                         (1000, "full"))
        self.assertEqual(darwin.parse_media("autoselect (100baseTX <half-duplex>)"),
                         (100, "half"))
        self.assertEqual(darwin.parse_media("autoselect (10Gbase-T <full-duplex>)"),
                         (10000, "full"))
        self.assertEqual(darwin.parse_media("autoselect"), (None, ""))
        self.assertEqual(darwin.parse_media(""), (None, ""))


class TestRoutes(unittest.TestCase):
    def setUp(self):
        self.routes = darwin.parse_netstat_routes(NETSTAT_ROUTES)

    def test_default_route(self):
        default = [r for r in self.routes if r["prefixlen"] == 0]
        self.assertEqual(len(default), 1)
        self.assertEqual(default[0]["dest"], "0.0.0.0")
        self.assertEqual(default[0]["gateway"], "192.168.1.1")
        self.assertEqual(default[0]["iface"], "en0")

    def test_abbreviated_destinations_expand(self):
        subnet = [r for r in self.routes if r["dest"] == "192.168.1.0"]
        self.assertTrue(subnet)
        self.assertEqual(subnet[0]["prefixlen"], 24)
        self.assertEqual(subnet[0]["gateway"], "0.0.0.0")
        loop = [r for r in self.routes if r["dest"] == "127.0.0.0"]
        self.assertEqual(loop[0]["prefixlen"], 8)

    def test_explicit_prefix_is_kept(self):
        host = [r for r in self.routes if r["dest"] == "192.168.1.1" and r["prefixlen"] == 32]
        self.assertTrue(host)

    def test_multicast_prefix(self):
        mcast = [r for r in self.routes if r["dest"] == "224.0.0.0"]
        self.assertEqual(mcast[0]["prefixlen"], 4)


class TestCountersArpDns(unittest.TestCase):
    def test_counters_use_the_link_row(self):
        counters, indexes = darwin.parse_netstat_counters(NETSTAT_COUNTERS)
        self.assertEqual(counters["en0"]["rx_bytes"], 1234567890)
        self.assertEqual(counters["en0"]["tx_bytes"], 987654321)
        self.assertEqual(counters["en0"]["rx_errors"], 3)
        self.assertEqual(counters["en0"]["tx_errors"], 1)
        self.assertEqual(indexes["en0"], 12)
        self.assertEqual(counters["lo0"]["rx_packets"], 21254)

    def test_arp_pads_short_octets_and_flags_incomplete(self):
        entries = darwin.parse_arp(ARP)
        by_ip = {e["ip"]: e for e in entries}
        self.assertEqual(by_ip["192.168.1.1"]["mac"], "3c:22:fb:11:22:33")
        self.assertEqual(by_ip["192.168.1.77"]["mac"], "08:00:27:01:02:03")
        self.assertTrue(by_ip["192.168.1.90"]["incomplete"])
        self.assertEqual(by_ip["192.168.1.1"]["iface"], "en0")

    def test_dns_configuration(self):
        servers, search = darwin.parse_scutil_dns(SCUTIL_DNS)
        self.assertEqual(servers, ["192.168.1.1", "8.8.8.8"])
        self.assertEqual(search, ["lan"])


class TestWifiParsing(unittest.TestCase):
    def test_channel_specs(self):
        self.assertEqual(darwin.parse_channel_spec("5g36/80"), (36, "5", 80))
        self.assertEqual(darwin.parse_channel_spec("2g6/20"), (6, "2.4", 20))
        self.assertEqual(darwin.parse_channel_spec("6g37/160"), (37, "6", 160))
        self.assertEqual(darwin.parse_channel_spec("36 (5GHz, 80MHz)"), (36, "5", 80))
        self.assertEqual(darwin.parse_channel_spec("11 (2GHz, 20MHz)"), (11, "2.4", 20))
        self.assertEqual(darwin.parse_channel_spec("149"), (149, "5", None))
        self.assertEqual(darwin.parse_channel_spec(""), (None, "", None))

    def test_wdutil_link(self):
        link = darwin.parse_wdutil(WDUTIL)
        self.assertTrue(link["connected"])
        self.assertEqual(link["ssid"], "HomeNet")
        self.assertEqual(link["bssid"], "3c:22:fb:11:22:33")
        self.assertEqual(link["signal_dbm"], -47.0)
        self.assertEqual(link["noise_dbm"], -92.0)
        self.assertEqual(link["snr_db"], 45.0)
        self.assertEqual(link["channel"], 36)
        self.assertEqual(link["band"], "5")
        self.assertEqual(link["width_mhz"], 80)
        self.assertEqual(link["interface"], "en0")
        self.assertIn("1200", link["tx_bitrate"])
        self.assertFalse(link["redacted"])

    def test_wdutil_redaction_is_reported(self):
        link = darwin.parse_wdutil(WDUTIL_REDACTED)
        self.assertTrue(link["redacted"])
        self.assertEqual(link["ssid"], "")
        self.assertEqual(link["signal_dbm"], -61.0)
        self.assertEqual(link["channel"], 6)
        self.assertEqual(link["band"], "2.4")

    def test_system_profiler_scan(self):
        networks = darwin.parse_airport_json(AIRPORT_JSON)
        by_ssid = {n["ssid"]: n for n in networks}
        self.assertIn("HomeNet", by_ssid)
        self.assertIn("NeighborNet", by_ssid)
        self.assertEqual(by_ssid["NeighborNet"]["channel"], 6)
        self.assertEqual(by_ssid["NeighborNet"]["band"], "2.4")
        self.assertEqual(by_ssid["NeighborNet"]["signal_dbm"], -72.0)
        self.assertEqual(by_ssid["NeighborNet"]["security"], ["WPA2"])
        self.assertEqual(by_ssid["CoffeeShop"]["security"], ["open"])
        self.assertEqual(by_ssid["HomeNet"]["width_mhz"], 80)
        self.assertIn("ax", by_ssid["HomeNet"]["standards"])

    def test_system_profiler_current_network(self):
        link = darwin.parse_airport_current(AIRPORT_JSON)
        self.assertTrue(link["connected"])
        self.assertEqual(link["ssid"], "HomeNet")
        self.assertEqual(link["channel"], 36)
        self.assertEqual(link["signal_dbm"], -47.0)
        self.assertEqual(link["snr_db"], 45.0)
        self.assertEqual(link["interface"], "en0")

    def test_system_profiler_redaction_is_blanked_not_printed(self):
        payload = json.loads(AIRPORT_JSON)
        iface = payload["SPAirPortDataType"][0]["spairport_airport_interfaces"][0]
        iface["spairport_current_network_information"]["_name"] = "<redacted>"
        iface["spairport_airport_other_local_wireless_networks"][0]["_name"] = "<redacted>"
        text = json.dumps(payload)

        link = darwin.parse_airport_current(text)
        self.assertEqual(link["ssid"], "")
        self.assertTrue(link["redacted"])
        # The radio numbers alongside the blanked name are still real.
        self.assertEqual(link["signal_dbm"], -47.0)

        networks = darwin.parse_airport_json(text)
        blanked = [n for n in networks if n["redacted"]]
        self.assertTrue(blanked)
        self.assertTrue(all(n["ssid"] == "" for n in blanked))
        # Two neighbours both blanked must not collapse into one row.
        self.assertEqual(len(networks), len(darwin.parse_airport_json(AIRPORT_JSON)))

    def test_networksetup_ssid(self):
        self.assertEqual(
            darwin.parse_networksetup_ssid("Current Wi-Fi Network: HomeNet\n"),
            "HomeNet")
        self.assertEqual(
            darwin.parse_networksetup_ssid(
                "You are not associated with an AirPort network.\n"),
            "")
        self.assertEqual(
            darwin.parse_networksetup_ssid("Current Wi-Fi Network: <redacted>\n"), "")

    def test_scutil_airport_dictionary(self):
        text = """<dictionary> {
  BSSID : 3c:22:fb:11:22:33
  SSID : <data> 0x486f6d654e6574
  SSID_STR : HomeNet
  Power Status : 1
}
"""
        found = darwin.parse_scutil_airport(text)
        self.assertEqual(found["ssid"], "HomeNet")
        self.assertEqual(found["bssid"], "3c:22:fb:11:22:33")

    def test_scutil_data_blobs_are_decoded_not_echoed(self):
        # SystemConfiguration hands both fields back as CFData on some versions,
        # and printing scutil's rendering is how "0x0200..." reaches the screen.
        text = """<dictionary> {
  BSSID : <data> 0x3c22fb112233
  SSID : <data> 0x486f6d654e6574
}
"""
        found = darwin.parse_scutil_airport(text)
        self.assertEqual(found["bssid"], "3c:22:fb:11:22:33")
        self.assertEqual(found["ssid"], "HomeNet")

    def test_a_blob_that_is_not_an_address_is_dropped(self):
        found = darwin.parse_scutil_airport("  BSSID : <data> 0x0200000\n")
        self.assertEqual(found["bssid"], "")

    def test_normalise_mac_accepts_what_macos_actually_prints(self):
        for given, want in [
            ("3C:22:FB:11:22:33", "3c:22:fb:11:22:33"),
            ("3c-22-fb-11-22-33", "3c:22:fb:11:22:33"),
            ("3c22fb112233", "3c:22:fb:11:22:33"),
            ("<data> 0x3c22fb112233", "3c:22:fb:11:22:33"),
        ]:
            self.assertEqual(darwin.normalise_mac(given), want, given)
        for junk in ["", None, "0x0200000", "<data> 0x0200000", "not a mac",
                     "3c:22:fb:11:22", "3c:22:fb:11:22:33:44"]:
            self.assertEqual(darwin.normalise_mac(junk), "", repr(junk))

    def test_blanked_name_is_recovered_without_location_permission(self):
        link = {"interface": "en0", "ssid": "", "bssid": "", "redacted": True}
        calls = []

        def fake_run(argv, timeout=30, stdin=None):
            calls.append(argv[0])
            if argv[0] == "networksetup":
                return 0, "Current Wi-Fi Network: HomeNet\n", ""
            return 0, "<dictionary> {\n  BSSID : aa:bb:cc:dd:ee:ff\n}\n", ""

        saved = darwin.run_cmd
        darwin.run_cmd = fake_run
        try:
            out = darwin._unredact(dict(link))
        finally:
            darwin.run_cmd = saved
        self.assertEqual(out["ssid"], "HomeNet")
        self.assertEqual(out["bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertFalse(out["redacted"])
        self.assertEqual(calls, ["networksetup", "scutil"])

    def test_unrecoverable_name_stays_flagged(self):
        def fake_run(argv, timeout=30, stdin=None):
            return 1, "", "no"

        saved = darwin.run_cmd
        darwin.run_cmd = fake_run
        try:
            out = darwin._unredact({"interface": "en0", "ssid": "", "redacted": True})
        finally:
            darwin.run_cmd = saved
        self.assertTrue(out["redacted"])

    def test_name_sources_reports_every_door_it_tried(self):
        def fake_run(argv, timeout=30, stdin=None):
            if argv[0] == "networksetup":
                return 0, "Current Wi-Fi Network: HomeNet\n", ""
            if argv[0] == "scutil":
                return 0, "<dictionary> {\n  SSID_STR : HomeNet\n}\n", ""
            if argv[0] == "wdutil":
                return 0, WDUTIL_REDACTED, ""
            return 1, "", "not available"

        saved = darwin.run_cmd
        darwin.run_cmd = fake_run
        try:
            rows = darwin.name_sources("en0")
        finally:
            darwin.run_cmd = saved
        by_source = {source: (ssid, note) for source, ssid, note in rows}
        self.assertEqual(by_source["networksetup"][0], "HomeNet")
        self.assertEqual(by_source["scutil"][0], "HomeNet")
        # wdutil answered, but macOS had blanked what it said.
        self.assertEqual(by_source["wdutil"][0], "")
        self.assertIn("redacted", by_source["wdutil"][1])
        self.assertIn("system_profiler", by_source)

    def test_no_wifi_data_is_not_a_crash(self):
        self.assertEqual(darwin.parse_airport_json(json.dumps({"SPAirPortDataType": []})), [])
        self.assertFalse(darwin.parse_airport_current(json.dumps({}))["connected"])


if __name__ == "__main__":
    unittest.main()
