"""Raw link-layer abstraction: BPF record parsing and ioctl encoding.

The macOS back end cannot be exercised on Linux, but the two things most likely to be
wrong - the ioctl numbers and the batched read format - are pure arithmetic and pure
parsing, so both are pinned here against the values in <net/bpf.h>.
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nettool import link
from nettool.util import NetToolError


def bpf_record(payload, sec=100, usec=250000, hdrlen=18, caplen=None):
    caplen = len(payload) if caplen is None else caplen
    header = struct.pack("=iiIIH", sec, usec, caplen, len(payload), hdrlen)
    header += b"\x00" * (hdrlen - len(header))
    body = header + payload
    return body + b"\x00" * (-len(body) % link.BPF_ALIGNMENT)


class TestIoctlEncoding(unittest.TestCase):
    """Values taken from macOS <net/bpf.h>."""

    def unsigned(self, value):
        return value & 0xFFFFFFFF

    def test_known_constants(self):
        self.assertEqual(self.unsigned(link.BIOCGBLEN), 0x40044266)
        self.assertEqual(self.unsigned(link.BIOCSBLEN), 0xC0044266)
        self.assertEqual(self.unsigned(link.BIOCFLUSH), 0x20004268)
        self.assertEqual(self.unsigned(link.BIOCPROMISC), 0x20004269)
        self.assertEqual(self.unsigned(link.BIOCGDLT), 0x4004426A)
        self.assertEqual(self.unsigned(link.BIOCSETIF), 0x8020426C)
        self.assertEqual(self.unsigned(link.BIOCGSTATS), 0x4008426F)
        self.assertEqual(self.unsigned(link.BIOCIMMEDIATE), 0x80044270)
        self.assertEqual(self.unsigned(link.BIOCSHDRCMPLT), 0x80044275)
        self.assertEqual(self.unsigned(link.BIOCSSEESENT), 0x80044277)

    def test_write_ioctls_fit_in_a_c_int(self):
        # fcntl.ioctl rejects values above 0x7fffffff, so the encoder must fold them.
        for value in (link.BIOCSETIF, link.BIOCIMMEDIATE, link.BIOCSHDRCMPLT,
                      link.BIOCSSEESENT, link.BIOCSBLEN):
            self.assertLess(value, 0x80000000)
            self.assertGreaterEqual(value, -0x80000000)

    def test_alignment(self):
        self.assertEqual(link.bpf_align(18), 20)
        self.assertEqual(link.bpf_align(20), 20)
        self.assertEqual(link.bpf_align(1), 4)
        self.assertEqual(link.bpf_align(0), 0)


class TestBpfBufferParsing(unittest.TestCase):
    def test_single_packet(self):
        buffer = bpf_record(b"A" * 60, sec=1700000000, usec=500000)
        packets = link.parse_bpf_buffer(buffer)
        self.assertEqual(len(packets), 1)
        data, timestamp = packets[0]
        self.assertEqual(data, b"A" * 60)
        self.assertAlmostEqual(timestamp, 1700000000.5, places=5)

    def test_batched_packets_with_padding(self):
        # 61 bytes forces padding between records.
        buffer = bpf_record(b"A" * 61, sec=10) + bpf_record(b"B" * 74, sec=11) \
            + bpf_record(b"C" * 42, sec=12)
        packets = link.parse_bpf_buffer(buffer)
        self.assertEqual([len(data) for data, _ in packets], [61, 74, 42])
        self.assertEqual([int(ts) for _, ts in packets], [10, 11, 12])

    def test_snapped_packet_reports_capture_length(self):
        payload = b"D" * 100
        record = bpf_record(payload, caplen=40)
        packets = link.parse_bpf_buffer(record)
        self.assertEqual(len(packets[0][0]), 40)

    def test_truncated_trailing_record_is_ignored(self):
        buffer = bpf_record(b"A" * 60) + bpf_record(b"B" * 60)[:20]
        packets = link.parse_bpf_buffer(buffer)
        self.assertEqual(len(packets), 1)

    def test_garbage_does_not_raise(self):
        self.assertEqual(link.parse_bpf_buffer(b""), [])
        self.assertEqual(link.parse_bpf_buffer(b"\x00" * 10), [])
        self.assertEqual(link.parse_bpf_buffer(b"\xff" * 64), [])

    def test_larger_header_length_is_honoured(self):
        # Some kernels pad bpf_hdr out to 24 bytes; bh_hdrlen is the authority.
        buffer = bpf_record(b"E" * 50, hdrlen=24)
        packets = link.parse_bpf_buffer(buffer)
        self.assertEqual(packets[0][0], b"E" * 50)


class TestPlatformSelection(unittest.TestCase):
    def test_linux_uses_packet_sockets(self):
        if sys.platform.startswith("linux"):
            self.assertTrue(link.IS_LINUX)
            self.assertFalse(link.IS_DARWIN)

    def test_unsupported_platform_is_a_clear_error(self):
        original = (link.IS_LINUX, link.IS_DARWIN, sys.platform)
        link.IS_LINUX = False
        link.IS_DARWIN = False
        try:
            with self.assertRaises(NetToolError) as caught:
                link.open_link("eth0")
            self.assertIn("not implemented", str(caught.exception))
        finally:
            link.IS_LINUX, link.IS_DARWIN, _ = original


if __name__ == "__main__":
    unittest.main()
