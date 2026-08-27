import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nettool import decode
from nettool.pcap import PcapReader, PcapWriter
from nettool.pfilter import compile_filter
from nettool.util import NetToolError


def run_cli(argv):
    """(exit code, stdout, stderr) for a CLI invocation, without a subprocess."""
    import io
    from contextlib import redirect_stderr, redirect_stdout

    from nettool.cli import main

    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def eth(dst, src, etype, payload):
    return dst + src + struct.pack("!H", etype) + payload


def ipv4(src, dst, proto, payload, ttl=64, df=True):
    import socket
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234,
                      0x4000 if df else 0, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + payload


def tcp(sport, dport, flags=0x02, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, flags, 8192, 0, 0) + payload


def udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


MAC_A = bytes.fromhex("001122334455")
MAC_B = bytes.fromhex("66778899aabb")


class TestDecode(unittest.TestCase):
    def test_tcp_syn(self):
        frame = eth(MAC_B, MAC_A, 0x0800, ipv4("10.0.0.1", "10.0.0.2", 6, tcp(51000, 443)))
        pkt = decode.decode(frame)
        self.assertEqual(pkt["l3"], "IPv4")
        self.assertEqual(pkt["l4"], "TCP")
        self.assertEqual((pkt["src"], pkt["dst"]), ("10.0.0.1", "10.0.0.2"))
        self.assertEqual((pkt["sport"], pkt["dport"]), (51000, 443))
        self.assertIn("S", pkt["tcp_flags"])
        self.assertTrue(pkt["df"])

    def test_vlan_udp(self):
        inner = struct.pack("!H", 0x0800) + ipv4("192.168.1.5", "192.168.1.255", 17,
                                                 udp(68, 67, b"\x00" * 20))
        frame = MAC_B + MAC_A + struct.pack("!H", 0x8100) + struct.pack("!H", 0x001E) + inner
        pkt = decode.decode(frame)
        self.assertEqual(pkt["vlan"], 30)
        self.assertEqual(pkt["l4"], "UDP")
        self.assertIn("DHCP", pkt["info"])

    def test_arp(self):
        body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + MAC_A + bytes([10, 0, 0, 1]) \
            + b"\x00" * 6 + bytes([10, 0, 0, 9])
        pkt = decode.decode(eth(b"\xff" * 6, MAC_A, 0x0806, body))
        self.assertEqual(pkt["l3"], "ARP")
        self.assertEqual(pkt["info"], "who-has 10.0.0.9 tell 10.0.0.1")

    def test_icmp_frag_needed(self):
        icmp = struct.pack("!BBHHH", 3, 4, 0, 0, 1400)
        pkt = decode.decode(eth(MAC_B, MAC_A, 0x0800,
                                ipv4("10.0.0.254", "10.0.0.5", 1, icmp)))
        self.assertIn("frag-needed", pkt["info"])

    def test_runt_and_unknown(self):
        self.assertEqual(decode.decode(b"\x00" * 6)["proto"], "runt")
        pkt = decode.decode(eth(MAC_B, MAC_A, 0x88f7, b"\x00" * 20))
        self.assertEqual(pkt["l2"], "PTP")

    def test_llc_cdp(self):
        snap = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + b"\x02\xb4\x00\x00"
        frame = bytes.fromhex("01000ccccccc") + MAC_A + struct.pack("!H", len(snap)) + snap
        self.assertEqual(decode.decode(frame)["proto"], "CDP")


class TestFilter(unittest.TestCase):
    def setUp(self):
        self.syn = decode.decode(eth(MAC_B, MAC_A, 0x0800,
                                     ipv4("10.0.0.1", "10.0.0.2", 6, tcp(51000, 443))))
        self.dns = decode.decode(eth(MAC_B, MAC_A, 0x0800,
                                     ipv4("10.0.0.1", "8.8.8.8", 17, udp(40000, 53))))

    def check(self, expr, expected_syn, expected_dns):
        pred = compile_filter(expr)
        self.assertEqual(pred(self.syn), expected_syn, expr)
        self.assertEqual(pred(self.dns), expected_dns, expr)

    def test_expressions(self):
        self.check("tcp", True, False)
        self.check("udp", False, True)
        self.check("port 443", True, False)
        self.check("host 8.8.8.8", False, True)
        self.check("dst host 8.8.8.8", False, True)
        self.check("src host 8.8.8.8", False, False)
        self.check("net 10.0.0.0/24", True, True)
        self.check("dst net 10.0.0.0/24", True, False)
        self.check("tcp and port 443", True, False)
        self.check("tcp or dns", True, True)
        self.check("not tcp", False, True)
        self.check("(tcp and port 443) or (udp and port 53)", True, True)
        self.check("portrange 400-500", True, False)
        self.check("ether host 00:11:22:33:44:55", True, True)
        self.check("ether dst 00:11:22:33:44:55", False, False)
        self.check("tcp-syn", True, False)
        self.check("", True, True)
        self.check("8.8.8.8", False, True)

    def test_bad_filter(self):
        from nettool.util import NetToolError
        for expr in ["host", "wat", "port abc", "(tcp", "net 10.0.0.0/99"]:
            with self.assertRaises((NetToolError, ValueError), msg=expr):
                compile_filter(expr)


class TestPcapRoundTrip(unittest.TestCase):
    def test_write_read(self):
        frames = [
            eth(MAC_B, MAC_A, 0x0800, ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1234, 80))),
            eth(MAC_A, MAC_B, 0x0800, ipv4("10.0.0.2", "10.0.0.1", 6, tcp(80, 1234, 0x12))),
        ]
        path = os.path.join(tempfile.mkdtemp(), "t.pcap")
        with PcapWriter(path) as w:
            w.write(frames[0], 1700000000.123456)
            w.write(frames[1], 1700000000.999999)
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(4), bytes.fromhex("d4c3b2a1"))
        with PcapReader(path) as r:
            self.assertEqual(r.linktype, 1)
            got = list(r)
        self.assertEqual([g[1] for g in got], frames)
        self.assertAlmostEqual(got[0][0], 1700000000.123456, places=5)
        self.assertAlmostEqual(got[1][0], 1700000000.999999, places=5)

    def test_snaplen_truncation(self):
        path = os.path.join(tempfile.mkdtemp(), "s.pcap")
        frame = eth(MAC_B, MAC_A, 0x0800, ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2, payload=b"x" * 200)))
        with PcapWriter(path, snaplen=64) as w:
            w.write(frame, 1.0)
        with PcapReader(path) as r:
            ts, data, orig = list(r)[0]
        self.assertEqual(len(data), 64)
        self.assertEqual(orig, len(frame))



class TestBadCapturePaths(unittest.TestCase):
    """A path someone typed is not a bug, and must not arrive as a traceback."""

    def test_a_directory_says_so(self):
        with self.assertRaises(NetToolError) as caught:
            PcapReader("/")
        self.assertIn("directory", str(caught.exception))

    def test_a_missing_file_says_so(self):
        with self.assertRaises(NetToolError) as caught:
            PcapReader("/nonexistent/nowhere.pcap")
        self.assertIn("no such capture file", str(caught.exception))

    def test_a_file_that_is_not_a_capture_shows_what_it_found(self):
        path = os.path.join(tempfile.mkdtemp(), "notes.txt")
        with open(path, "wb") as fh:
            fh.write(b"this is not a pcap file at all, but it is long enough")
        with self.assertRaises(NetToolError) as caught:
            PcapReader(path)
        message = str(caught.exception)
        self.assertIn("not a classic pcap", message)
        self.assertIn("pcapng", message, "point at the likely cause")

    def test_an_empty_file_is_not_a_crash(self):
        path = os.path.join(tempfile.mkdtemp(), "empty.pcap")
        open(path, "wb").close()
        with self.assertRaises(NetToolError) as caught:
            PcapReader(path)
        self.assertIn("too short", str(caught.exception))

    def test_a_rejected_file_is_closed_again(self):
        # The constructor raises, so the caller never gets an object to close -
        # a run of bad paths would otherwise leak a descriptor each.
        import warnings

        path = os.path.join(tempfile.mkdtemp(), "notes.txt")
        with open(path, "wb") as fh:
            fh.write(b"not a pcap file, but long enough to reach the magic check")
        with warnings.catch_warnings():
            warnings.simplefilter("error", ResourceWarning)
            for _ in range(3):
                with self.assertRaises(NetToolError):
                    PcapReader(path)

    def test_the_cli_reports_it_without_a_traceback(self):
        code, out, err = run_cli(["analyze", "/"])
        self.assertEqual(code, 2)
        self.assertIn("error:", err)
        self.assertNotIn("Traceback", err)
        self.assertNotIn("Traceback", out)

if __name__ == "__main__":
    unittest.main()
