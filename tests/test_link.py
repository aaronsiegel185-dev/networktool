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


class BlenHostileKernel(FakeKernel):
    """A kernel that refuses the attach whenever a buffer size was set first."""

    def __init__(self):
        super(BlenHostileKernel, self).__init__(max_buffer=1024 * 1024)
        self.blen_set = False

    def ioctl(self, fd, request, arg=0, mutate=False):
        if request == link.BIOCSBLEN:
            self.blen_set = True
            return super(BlenHostileKernel, self).ioctl(fd, request, arg, mutate)
        if request == link.BIOCSETIF:
            if self.blen_set:
                self.blen_set = False
                self.calls.append(request)
                raise OSError(errno.EINVAL, "Invalid argument")
            self.attached = "en0"
            self.calls.append(request)
            return 0
        return super(BlenHostileKernel, self).ioctl(fd, request, arg, mutate)


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
        self.assertIn("en0 cannot be captured on", str(caught.exception))

    def test_other_errors_are_not_retried(self):
        kernel = FakeKernel(max_buffer=0, attach_errno=errno.EPERM)
        with self.assertRaises(NetToolError) as caught:
            link.attach_bpf(3, "en0", ioctl_fn=kernel.ioctl)
        message = str(caught.exception)
        self.assertIn("BIOCSETIF", message)
        self.assertEqual(kernel.calls.count(link.BIOCSETIF), 1)

    def test_exhausting_every_size_reports_the_range(self):
        # ENOBUFS really is about memory, so the message names the sizes tried.
        kernel = FakeKernel(max_buffer=0, attach_errno=errno.ENOBUFS)
        with self.assertRaises(NetToolError) as caught:
            link.attach_bpf(3, "en0", buffer_size=64 * 1024, ioctl_fn=kernel.ioctl)
        message = str(caught.exception)
        self.assertIn("65536", message)
        self.assertIn(str(link.BPF_MIN_BUFFER), message)

    def test_einval_everywhere_is_reported_as_an_uncapturable_interface(self):
        # macOS returns EINVAL for an interface with no BPF device, which is what
        # libpcap treats as "no such device" - the buffer was never the problem.
        kernel = FakeKernel(max_buffer=0, attach_errno=errno.EINVAL)
        with self.assertRaises(NetToolError) as caught:
            link.attach_bpf(3, "en9", buffer_size=64 * 1024, ioctl_fn=kernel.ioctl)
        message = str(caught.exception)
        self.assertIn("en9 cannot be captured on", message)
        self.assertNotIn("Buffer sizes", message)

    def test_falls_back_to_attaching_without_setting_a_buffer(self):
        kernel = BlenHostileKernel()
        size = link.attach_bpf(3, "en0", buffer_size=512 * 1024, ioctl_fn=kernel.ioctl)
        self.assertEqual(kernel.attached, "en0")
        self.assertGreater(size, 0)


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


class TestCapturableInterfaces(unittest.TestCase):
    def test_lists_interfaces_that_actually_attach(self):
        from nettool.util import is_root

        usable = link.capturable_interfaces()
        self.assertIsInstance(usable, list)
        if is_root() and sys.platform.startswith("linux"):
            # Every up interface on Linux takes an AF_PACKET socket.
            self.assertIn("lo", usable)

    def test_unknown_names_are_skipped_not_fatal(self):
        self.assertEqual(link.capturable_interfaces(["definitely-not-real0"]), [])


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



class TestBpfExhaustion(unittest.TestCase):
    """What the message says when no capture device can be had."""

    def message(self, reasons):
        from nettool.link import BpfSocket

        return BpfSocket._exhausted_message(reasons)

    def test_all_busy_names_the_cause_and_the_command(self):
        # The old message reported only the last device's errno, which turned
        # "every capture device is taken" into a stray "Resource busy: bpf255".
        text = self.message({errno.EBUSY: 256})
        self.assertIn("256 busy", text)
        self.assertIn("lsof /dev/bpf", text)
        self.assertNotIn("bpf255", text)

    def test_absent_devices_are_a_different_story(self):
        text = self.message({errno.ENOENT: 256})
        self.assertIn("do not exist", text)
        self.assertNotIn("lsof", text)

    def test_other_refusals_are_named_not_swallowed(self):
        text = self.message({errno.EBUSY: 2, errno.EIO: 3})
        self.assertIn("EIO (3)", text)


class TestCapturableCache(unittest.TestCase):
    def test_the_probe_is_not_repeated_for_every_caller(self):
        # Probing means claiming a real BPF device per interface, and `serve`
        # asks on every handshake.
        from nettool import link

        link._capturable_cache.update({"at": 0.0, "names": None, "value": None})
        probed = []
        real = link._probe_capturable

        def counting(names=None):
            probed.append(names)
            return ["eth0"]

        link._probe_capturable = counting
        try:
            self.assertEqual(link.capturable_interfaces(), ["eth0"])
            self.assertEqual(link.capturable_interfaces(), ["eth0"])
            self.assertEqual(len(probed), 1)
            # A caller that needs the truth right now can still have it.
            link.capturable_interfaces(max_age=0)
            self.assertEqual(len(probed), 2)
        finally:
            link._probe_capturable = real
            link._capturable_cache.update({"at": 0.0, "names": None, "value": None})

if __name__ == "__main__":
    unittest.main()
