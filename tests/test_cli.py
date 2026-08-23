import io
import json
import os
import socket
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nettool import cli
from nettool import portscan
from nettool.cli import main
from nettool.pcap import PcapWriter
from nettool.util import NetToolError, parse_ports, parse_targets

sys.path.insert(0, os.path.dirname(__file__))
from test_lldp import build_cdp, build_lldp                      # noqa: E402
from test_pcap_decode import MAC_A, MAC_B, eth, ipv4, tcp, udp   # noqa: E402


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def sample_pcap():
    path = os.path.join(tempfile.mkdtemp(), "sample.pcap")
    with PcapWriter(path) as w:
        w.write(eth(MAC_B, MAC_A, 0x0800, ipv4("10.0.0.1", "10.0.0.2", 6, tcp(4444, 443))), 100.0)
        w.write(eth(MAC_A, MAC_B, 0x0800, ipv4("10.0.0.2", "10.0.0.1", 6, tcp(443, 4444, 0x12))), 100.1)
        w.write(eth(MAC_B, MAC_A, 0x0800, ipv4("10.0.0.1", "8.8.8.8", 17, udp(5000, 53))), 100.2)
        w.write(build_lldp(), 100.3)
        w.write(build_cdp(), 100.4)
    return path


class TestArgParsing(unittest.TestCase):
    def test_targets(self):
        self.assertEqual(parse_targets("10.0.0.1"), ["10.0.0.1"])
        self.assertEqual(len(parse_targets("10.0.0.0/29")), 6)
        self.assertEqual(parse_targets("10.0.0.5-7"),
                         ["10.0.0.5", "10.0.0.6", "10.0.0.7"])
        self.assertEqual(parse_targets("10.0.0.1,10.0.0.1"), ["10.0.0.1"])
        self.assertEqual(parse_targets("192.168.1.250-192.168.1.252"),
                         ["192.168.1.250", "192.168.1.251", "192.168.1.252"])

    def test_bad_target(self):
        with self.assertRaises(NetToolError):
            parse_targets("no-such-host.invalid")
        with self.assertRaises(NetToolError):
            parse_targets("10.0.0.9-10.0.0.1")

    def test_ports(self):
        self.assertEqual(parse_ports("80"), [80])
        self.assertEqual(parse_ports("80,443,80"), [80, 443])
        self.assertEqual(parse_ports("20-22"), [20, 21, 22])
        self.assertEqual(len(parse_ports("all")), 65535)
        self.assertGreater(len(parse_ports("top")), 50)
        with self.assertRaises(NetToolError):
            parse_ports("70000")


class TestCliCommands(unittest.TestCase):
    def test_version_and_help(self):
        with self.assertRaises(SystemExit):
            run_cli(["--version"])
        code, out, _ = run_cli([])
        self.assertEqual(code, 0)
        self.assertIn("nettool", out)

    def test_iface_json(self):
        code, out, _ = run_cli(["iface", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertIn("interfaces", payload)
        self.assertTrue(any(i["name"] == "lo" for i in payload["interfaces"])
                        or payload["interfaces"])

    def test_iface_text(self):
        code, out, _ = run_cli(["iface", "-a"])
        self.assertEqual(code, 0)
        self.assertIn("routing", out)
        self.assertIn("dns servers", out)

    def test_iface_unknown_interface(self):
        code, _out, err = run_cli(["iface", "definitely-not-real0"])
        self.assertEqual(code, 2)
        self.assertIn("no such interface", err)

    def test_pcap_summary(self):
        path = sample_pcap()
        code, out, _ = run_cli(["pcap", path])
        self.assertEqual(code, 0)
        self.assertIn("packets: 5", out)
        self.assertIn("top talkers", out)

    def test_pcap_filter_and_extract(self):
        path = sample_pcap()
        out_path = path.replace(".pcap", "-dns.pcap")
        code, out, _ = run_cli(["pcap", path, "-f", "udp and port 53", "-w", out_path])
        self.assertEqual(code, 0)
        self.assertIn("wrote 1 packets", out)
        code, out, _ = run_cli(["pcap", out_path, "--json"])
        self.assertEqual(json.loads(out)["packets"], 1)

    def test_pcap_missing_file(self):
        code, _out, err = run_cli(["pcap", "/nonexistent/file.pcap"])
        self.assertEqual(code, 2)
        self.assertIn("no such file", err)

    def test_pcap_bad_filter(self):
        code, _out, err = run_cli(["pcap", sample_pcap(), "-f", "gibberish"])
        self.assertEqual(code, 2)
        self.assertIn("unknown filter keyword", err)

    def test_lldp_from_pcap(self):
        code, out, _ = run_cli(["lldp", "--from-pcap", sample_pcap()])
        self.assertEqual(code, 0)
        self.assertIn("sw-idf3-01", out)
        self.assertIn("GigabitEthernet1/0/24", out)
        self.assertIn("sw-core-1.example.net", out)

    def test_lldp_from_pcap_json(self):
        code, out, _ = run_cli(["lldp", "--from-pcap", sample_pcap(), "--json"])
        payload = json.loads(out)
        self.assertEqual(len(payload["neighbors"]), 2)


class TestApLabel(unittest.TestCase):
    def test_names_the_access_point_with_its_vendor(self):
        self.assertEqual(
            cli._ap_label({"bssid": "3c:37:86:11:22:33", "bssid_vendor": "Ubiquiti Inc"}),
            "3c:37:86:11:22:33 (Ubiquiti Inc)")

    def test_unknown_vendor_leaves_the_mac_alone(self):
        self.assertEqual(cli._ap_label({"bssid": "aa:bb:cc:dd:ee:ff"}), "aa:bb:cc:dd:ee:ff")

    def test_blanked_bssid_says_who_blanked_it(self):
        self.assertEqual(cli._ap_label({"bssid": "", "redacted": True}), "(hidden by macOS)")
        self.assertEqual(cli._ap_label({"bssid": ""}), "")


class TestPortScanAgainstLocalListener(unittest.TestCase):
    def setUp(self):
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(8)
        self.port = self.server.getsockname()[1]

    def tearDown(self):
        self.server.close()

    def test_open_port_detected(self):
        state, _detail = portscan.scan_tcp_port("127.0.0.1", self.port, timeout=1.0)
        self.assertEqual(state, "open")

    def test_closed_port(self):
        self.server.close()
        state, _detail = portscan.scan_tcp_port("127.0.0.1", self.port, timeout=1.0)
        self.assertEqual(state, "closed")

    def test_scan_reports_only_open_by_default(self):
        results = portscan.scan(["127.0.0.1"], [self.port, 1], timeout=0.5, workers=4)
        self.assertEqual([r["port"] for r in results], [self.port])

    def test_scan_all_states(self):
        results = portscan.scan(["127.0.0.1"], [self.port, 1], timeout=0.5, workers=4,
                                open_only=False)
        self.assertEqual(len(results), 2)

    def test_tcp_ping(self):
        alive, port, rtt = portscan.tcp_ping("127.0.0.1", (self.port,), timeout=1.0)
        self.assertTrue(alive)
        self.assertEqual(port, self.port)
        self.assertIsNotNone(rtt)

    def test_cli_scan_json(self):
        code, out, _ = run_cli(["scan", "127.0.0.1", "-p", str(self.port), "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["results"][0]["state"], "open")

    def test_cli_scan_csv(self):
        code, out, _ = run_cli(["scan", "127.0.0.1", "-p", str(self.port), "--csv"])
        self.assertEqual(code, 0)
        self.assertIn("host,port,proto,state,service,detail", out)
        self.assertIn("127.0.0.1,%d,tcp,open" % self.port, out)


if __name__ == "__main__":
    unittest.main()
