"""Raw link-layer abstraction: BPF record parsing and ioctl encoding.

The macOS back end cannot be exercised on Linux, but the two things most likely to be
wrong - the ioctl numbers and the batched read format - are pure arithmetic and pure
parsing, so both are pinned here against the values in <net/bpf.h>.
"""

import errno
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


class FakeKernel(object):
    """A stand-in for macOS's BPF ioctls, with a cap on the buffer it will allocate."""

    def __init__(self, max_buffer=64 * 1024, attach_errno=errno.EINVAL,
                 interface="en0"):
        self.max_buffer = max_buffer
        self.attach_errno = attach_errno
        self.interface = interface
        self.buffer_len = 0
        self.attached = None
        self.calls = []

    def ioctl(self, fd, request, arg=0, mutate=False):
        self.calls.append(request)
        if request == link.BIOCSBLEN:
            # macOS records the request here and only discovers it cannot allocate
            # the memory when the interface is attached - which is why the retry
            # loop exists at all.
            self.buffer_len = struct.unpack("I", bytes(arg))[0]
            arg[:] = struct.pack("I", self.buffer_len)
            return 0
        if request == link.BIOCSETIF:
            name = arg[:16].split(b"\x00")[0].decode()
            if name != self.interface:
                raise OSError(errno.ENXIO, "Device not configured")
            if self.buffer_len > self.max_buffer:
                raise OSError(self.attach_errno, "Invalid argument")
            self.attached = name
            return 0
        if request == link.BIOCGBLEN:
            arg[:] = struct.pack("I", self.buffer_len)
            return 0
        return 0


class StrictKernel(FakeKernel):
    """A kernel that refuses BIOCSBLEN outright but still attaches."""

    def ioctl(self, fd, request, arg=0, mutate=False):
        if request == link.BIOCSBLEN:
            raise OSError(errno.EINVAL, "Invalid argument")
        if request == link.BIOCGBLEN:
            raise OSError(errno.EINVAL, "Invalid argument")
        return super(StrictKernel, self).ioctl(fd, request, arg, mutate)


class TestBpfAttach(unittest.TestCase):
    """The attach sequence is the part that actually failed on real hardware."""

    def test_shrinks_the_buffer_until_the_attach_succeeds(self):
        kernel = FakeKernel(max_buffer=64 * 1024)
        size = link.attach_bpf(3, "en0", buffer_size=1024 * 1024,
                               ioctl_fn=kernel.ioctl)
        self.assertEqual(kernel.attached, "en0")
        self.assertEqual(size, 64 * 1024)
        self.assertIn(link.BIOCSETIF, kernel.calls)
        # It must have tried more than once to get there.
        self.assertGreater(kernel.calls.count(link.BIOCSETIF), 1)

    def test_first_attempt_is_used_when_the_kernel_is_happy(self):
        kernel = FakeKernel(max_buffer=8 * 1024 * 1024)
        size = link.attach_bpf(3, "en0", buffer_size=512 * 1024,
                               ioctl_fn=kernel.ioctl)
        self.assertEqual(size, 512 * 1024)
        self.assertEqual(kernel.calls.count(link.BIOCSETIF), 1)

    def test_enobufs_is_retried_too(self):
        kernel = FakeKernel(max_buffer=32 * 1024, attach_errno=errno.ENOBUFS)
        size = link.attach_bpf(3, "en0", buffer_size=1024 * 1024,
                               ioctl_fn=kernel.ioctl)
        self.assertEqual(size, 32 * 1024)

    def test_attaches_even_when_the_buffer_cannot_be_set(self):
        kernel = StrictKernel(max_buffer=1024 * 1024)
        size = link.attach_bpf(3, "en0", buffer_size=256 * 1024,
                               ioctl_fn=kernel.ioctl)
        self.assertEqual(kernel.attached, "en0")
        self.assertEqual(size, 256 * 1024)

    def test_unknown_interface_says_so(self):
        kernel = FakeKernel(interface="en1")
        with self.assertRaises(NetToolError) as caught:
            link.attach_bpf(3, "en0", ioctl_fn=kernel.ioctl)
        self.assertIn("no such interface: en0", str(caught.exception))

    def test_other_errors_are_not_retried(self):
        kernel = FakeKernel(max_buffer=0, attach_errno=errno.EPERM)
        with self.assertRaises(NetToolError) as caught:
            link.attach_bpf(3, "en0", ioctl_fn=kernel.ioctl)
        message = str(caught.exception)
        self.assertIn("BIOCSETIF", message)
        self.assertEqual(kernel.calls.count(link.BIOCSETIF), 1)

    def test_exhausting_every_size_reports_the_range(self):
        kernel = FakeKernel(max_buffer=0)          # nothing is ever allocatable
        with self.assertRaises(NetToolError) as caught:
            link.attach_bpf(3, "en0", buffer_size=64 * 1024, ioctl_fn=kernel.ioctl)
        message = str(caught.exception)
        self.assertIn("65536", message)
        self.assertIn(str(link.BPF_MIN_BUFFER), message)


class TestSnaplenProgram(unittest.TestCase):
    def test_encodes_a_single_return_instruction(self):
        program, instructions = link.bpf_snaplen_program(96)
        length, _pointer = struct.unpack("@IP", program)
        self.assertEqual(length, 1)
        code, jt, jf, k = struct.unpack("=HBBI", instructions.raw[:8])
        self.assertEqual(code, 0x06)               # BPF_RET | BPF_K
        self.assertEqual((jt, jf), (0, 0))
        self.assertEqual(k, 96)

    def test_program_struct_is_the_size_the_ioctl_encodes(self):
        program, _instructions = link.bpf_snaplen_program(65535)
        self.assertEqual(len(program), 16)
        self.assertEqual(link.BIOCSETF & 0xFFFFFFFF, 0x80104267)


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
