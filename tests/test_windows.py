"""Windows platform parsers, exercised against recorded command output."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nettool import windows

IPCONFIG = """
Windows IP Configuration

   Host Name . . . . . . . . . . . . : DESKTOP-N7K2Q1
   Primary Dns Suffix  . . . . . . . : corp.example.com
   Node Type . . . . . . . . . . . . : Hybrid

Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . : lan
   Description . . . . . . . . . . . : Intel(R) Wi-Fi 6 AX201 160MHz
   Physical Address. . . . . . . . . : 3C-22-FB-11-22-33
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : 2001:db8::1234(Preferred)
   IPv4 Address. . . . . . . . . . . : 192.168.1.42(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 192.168.1.1
                                       8.8.8.8

Ethernet adapter Ethernet:

   Media State . . . . . . . . . . . : Media disconnected
   Description . . . . . . . . . . . : Realtek PCIe GbE Family Controller
   Physical Address. . . . . . . . . : 00-1A-2B-3C-4D-5E
   DHCP Enabled. . . . . . . . . . . : Yes

Ethernet adapter vEthernet (WSL):

   Description . . . . . . . . . . . : Hyper-V Virtual Ethernet Adapter
   Physical Address. . . . . . . . . : 00-15-5D-AA-BB-CC
   IPv4 Address. . . . . . . . . . . : 172.20.16.1(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
"""

ROUTE_PRINT = """
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.42     35
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
      192.168.1.0    255.255.255.0         On-link      192.168.1.42    291
     192.168.1.42  255.255.255.255         On-link      192.168.1.42    291
===========================================================================
Persistent Routes:
  None
"""

ARP = """
Interface: 192.168.1.42 --- 0xd
  Internet Address      Physical Address      Type
  192.168.1.1           3c-37-86-11-22-33     dynamic
  192.168.1.55          aa-bb-cc-dd-ee-ff     dynamic
  224.0.0.22            01-00-5e-00-00-16     static

Interface: 172.20.16.1 --- 0x1a
  Internet Address      Physical Address      Type
  172.20.31.255         ff-ff-ff-ff-ff-ff     static
"""

WLAN_INTERFACES = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 8f2c1a44-1111-2222-3333-444455556666
    Physical address       : 3c:22:fb:11:22:33
    State                  : connected
    SSID                   : HomeNet
    BSSID                  : 3c:37:86:11:22:33
    Network type           : Infrastructure
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Connection mode        : Profile
    Band                   : 5 GHz
    Channel                : 48
    Receive rate (Mbps)    : 1200
    Transmit rate (Mbps)   : 1200
    Signal                 : 92%
    Profile                : HomeNet
"""

WLAN_NETWORKS = """
Interface name : Wi-Fi
There are 3 networks currently visible.

SSID 1 : HomeNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 3c:37:86:11:22:33
         Signal             : 92%
         Radio type         : 802.11ax
         Band               : 5 GHz
         Channel            : 48
    BSSID 2                 : 3c:37:86:11:22:34
         Signal             : 61%
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 6

SSID 2 : NeighborWifi
    Network type            : Infrastructure
    Authentication          : WPA3-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:00:11:22
         Signal             : 40%
         Radio type         : 802.11ac
         Band               : 5 GHz
         Channel            : 149

SSID 3 :
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : de:ad:be:ef:00:01
         Signal             : 24%
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 11
"""


class TestIpconfig(unittest.TestCase):
    def setUp(self):
        self.adapters = windows.parse_ipconfig(IPCONFIG)

    def test_adapters_are_keyed_by_connection_name(self):
        # The connection name is what netsh and route take as an argument; the
        # description is not addressable.
        self.assertEqual(sorted(self.adapters),
                         ["Ethernet", "Wi-Fi", "vEthernet (WSL)"])

    def test_addresses_and_mac(self):
        wifi = self.adapters["Wi-Fi"]
        self.assertEqual(wifi["mac"], "3c:22:fb:11:22:33")
        self.assertEqual(wifi["ipv4"], "192.168.1.42")
        self.assertEqual(wifi["netmask"], "255.255.255.0")
        self.assertEqual(wifi["prefixlen"], 24)
        self.assertEqual(wifi["gateway"], "192.168.1.1")
        self.assertEqual(wifi["ipv6"], ["2001:db8::1234"])
        self.assertTrue(wifi["dhcp"])
        self.assertTrue(wifi["wireless"])

    def test_continuation_lines_are_collected(self):
        # The second DNS server sits on its own line with no key at all.
        self.assertEqual(self.adapters["Wi-Fi"]["dns"], ["192.168.1.1", "8.8.8.8"])

    def test_media_disconnected_is_the_only_down_signal(self):
        # Windows prints the line only when down, and omits it otherwise.
        self.assertFalse(self.adapters["Ethernet"]["up"])
        self.assertEqual(self.adapters["Ethernet"]["operstate"], "down")
        self.assertTrue(self.adapters["Wi-Fi"]["up"])

    def test_a_bracketed_adapter_name_survives(self):
        self.assertEqual(self.adapters["vEthernet (WSL)"]["ipv4"], "172.20.16.1")

    def test_empty_input_is_not_a_crash(self):
        self.assertEqual(windows.parse_ipconfig(""), {})


class TestRoutes(unittest.TestCase):
    def test_default_route(self):
        routes = windows.parse_route_print(ROUTE_PRINT)
        default = [r for r in routes if r["destination"] == "default"]
        self.assertEqual(len(default), 1)
        self.assertEqual(default[0]["gateway"], "192.168.1.1")
        self.assertEqual(default[0]["metric"], 35)

    def test_on_link_means_no_gateway(self):
        routes = windows.parse_route_print(ROUTE_PRINT)
        local = [r for r in routes if r["destination"] == "192.168.1.0"][0]
        self.assertEqual(local["gateway"], "")
        self.assertEqual(local["prefixlen"], 24)

    def test_the_persistent_section_is_not_swallowed(self):
        self.assertEqual(len(windows.parse_route_print(ROUTE_PRINT)), 4)


class TestArp(unittest.TestCase):
    def test_entries_keep_the_interface_they_came_from(self):
        entries = windows.parse_arp(ARP)
        self.assertEqual(len(entries), 4)
        gateway = [e for e in entries if e["ip"] == "192.168.1.1"][0]
        self.assertEqual(gateway["mac"], "3c:37:86:11:22:33")
        self.assertEqual(gateway["iface"], "192.168.1.42")
        self.assertEqual(gateway["type"], "dynamic")
        self.assertEqual(entries[-1]["iface"], "172.20.16.1")


class TestWlan(unittest.TestCase):
    def test_current_association(self):
        link = windows.parse_wlan_interfaces(WLAN_INTERFACES)
        self.assertTrue(link["connected"])
        self.assertEqual(link["ssid"], "HomeNet")
        self.assertEqual(link["bssid"], "3c:37:86:11:22:33")
        self.assertEqual(link["channel"], 48)
        self.assertEqual(link["band"], "5")
        self.assertEqual(link["quality_pct"], 92)
        self.assertEqual(link["tx_bitrate"], "1200 Mbit/s")
        self.assertFalse(link["redacted"])

    def test_signal_percent_becomes_dbm(self):
        # Microsoft's documented mapping: 0% = -100 dBm, 100% = -50 dBm.
        self.assertEqual(windows._signal_to_dbm("100"), -50.0)
        self.assertEqual(windows._signal_to_dbm("0"), -100.0)
        self.assertEqual(windows._signal_to_dbm("92"), -54.0)
        self.assertIsNone(windows._signal_to_dbm("n/a"))

    def test_every_bss_is_its_own_row(self):
        networks = windows.parse_wlan_networks(WLAN_NETWORKS)
        self.assertEqual(len(networks), 4)
        home = [n for n in networks if n["ssid"] == "HomeNet"]
        self.assertEqual(len(home), 2)
        self.assertEqual({n["channel"] for n in home}, {6, 48})
        self.assertEqual({n["band"] for n in home}, {"2.4", "5"})

    def test_security_comes_from_the_ssid_block(self):
        networks = windows.parse_wlan_networks(WLAN_NETWORKS)
        neighbour = [n for n in networks if n["ssid"] == "NeighborWifi"][0]
        self.assertEqual(neighbour["security"], ["WPA3-Personal", "CCMP"])
        self.assertEqual(neighbour["standards"], ["ac"])

    def test_an_open_network_has_no_security_listed(self):
        networks = windows.parse_wlan_networks(WLAN_NETWORKS)
        hidden = [n for n in networks if n["bssid"] == "de:ad:be:ef:00:01"][0]
        self.assertEqual(hidden["security"], ["Open"])
        self.assertEqual(hidden["ssid"], "")

    def test_no_wlan_adapter_is_not_a_crash(self):
        self.assertFalse(windows.parse_wlan_interfaces("")["connected"])
        self.assertEqual(windows.parse_wlan_networks(""), [])


if __name__ == "__main__":
    unittest.main()


class TestNpcapDiscovery(unittest.TestCase):
    """The driver bridge, as far as it can be exercised off Windows."""

    def setUp(self):
        from nettool import npcap

        self.npcap = npcap

    def test_it_looks_where_npcap_actually_installs(self):
        paths = [p.lower() for p in self.npcap._candidates()]
        # Npcap puts wpcap.dll in System32\Npcap, beside its driver, so that it
        # can coexist with a legacy WinPcap in System32 itself.
        self.assertTrue(any(p.endswith("npcap\\wpcap.dll") for p in paths))
        self.assertTrue(any(p.endswith("system32\\wpcap.dll") for p in paths))

    def test_the_missing_driver_message_says_what_to_install(self):
        hint = self.npcap.INSTALL_HINT
        self.assertIn("npcap.com", hint)
        self.assertIn("WinPcap API-compatible", hint)
        # And that not having it is not the end of the tool.
        self.assertIn("ping", hint)

    @unittest.skipIf(sys.platform == "win32", "this is the non-Windows path")
    def test_it_fails_clearly_off_windows(self):
        from nettool.util import NetToolError

        with self.assertRaises(NetToolError):
            self.npcap.load()


class TestElevation(unittest.TestCase):
    def test_require_root_names_the_windows_fix(self):
        from nettool import util

        saved = util.IS_WINDOWS
        util.IS_WINDOWS = True
        try:
            with self.assertRaises(util.NetToolError) as caught:
                util.require_root("Packet capture")
        finally:
            util.IS_WINDOWS = saved
        message = str(caught.exception)
        self.assertIn("Administrator", message)
        self.assertIn("npcap.com", message)
        self.assertNotIn("sudo", message)
        self.assertNotIn("setcap", message)
