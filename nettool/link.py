"""Raw link-layer access, abstracted over Linux AF_PACKET and macOS BPF devices.

Both back ends present the same tiny interface::

    link = open_link("en0", promisc=True, snaplen=65535)
    for data, timestamp in link.read(timeout=0.5):
        ...
    link.write(frame)          # inject a frame (used by the ARP sweep)
    received, dropped = link.stats()
    link.close()

`read` returns a list because BPF hands back a batch of packets per syscall; the Linux
socket returns at most one. Callers just iterate.
"""

import errno
import os
import select
import socket
import struct
import sys
import time

from .util import NetToolError, require_root

IS_LINUX = sys.platform.startswith("linux")
IS_DARWIN = sys.platform == "darwin"

ETH_P_ALL = 0x0003
DLT_EN10MB = 1

# --- Linux ------------------------------------------------------------------

SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_STATISTICS = 6
SO_TIMESTAMPNS = 35
SCM_TIMESTAMPNS = 35

# --- macOS ------------------------------------------------------------------

IOC_VOID = 0x20000000
IOC_OUT = 0x40000000
IOC_IN = 0x80000000
IOC_INOUT = IOC_IN | IOC_OUT
BPF_ALIGNMENT = 4


def _ioc(direction, group, number, length):
    value = direction | ((length & 0x1FFF) << 16) | (ord(group) << 8) | number
    # fcntl.ioctl wants a C int: fold anything with the top bit set into a signed value.
    return value - 0x100000000 if value >= 0x80000000 else value


BIOCGBLEN = _ioc(IOC_OUT, "B", 102, 4)
BIOCSBLEN = _ioc(IOC_INOUT, "B", 102, 4)
BIOCFLUSH = _ioc(IOC_VOID, "B", 104, 0)
BIOCPROMISC = _ioc(IOC_VOID, "B", 105, 0)
BIOCGDLT = _ioc(IOC_OUT, "B", 106, 4)
BIOCSETIF = _ioc(IOC_IN, "B", 108, 32)          # struct ifreq
BIOCGSTATS = _ioc(IOC_OUT, "B", 111, 8)         # struct bpf_stat
BIOCIMMEDIATE = _ioc(IOC_IN, "B", 112, 4)
BIOCSHDRCMPLT = _ioc(IOC_IN, "B", 117, 4)
BIOCSSEESENT = _ioc(IOC_IN, "B", 119, 4)

# struct bpf_hdr { struct timeval32 bh_tstamp; u_int32 bh_caplen, bh_datalen;
#                  u_short bh_hdrlen; }
BPF_HDR = struct.Struct("=iiIIH")


def bpf_align(value):
    return (value + (BPF_ALIGNMENT - 1)) & ~(BPF_ALIGNMENT - 1)


def parse_bpf_buffer(buffer):
    """Split one BPF read() into [(data, timestamp), ...].

    Each record is a bpf_hdr followed by the captured bytes, and the next record starts
    at the next BPF_ALIGNMENT boundary after it.
    """
    packets = []
    offset = 0
    total = len(buffer)
    while offset + BPF_HDR.size <= total:
        sec, usec, caplen, datalen, hdrlen = BPF_HDR.unpack_from(buffer, offset)
        if hdrlen < BPF_HDR.size or caplen > datalen or hdrlen + caplen > total - offset:
            break
        start = offset + hdrlen
        packets.append((bytes(buffer[start:start + caplen]), sec + usec / 1_000_000.0))
        offset += bpf_align(hdrlen + caplen)
    return packets


class LinkSocket(object):
    """Common surface for the two back ends."""

    linktype = DLT_EN10MB

    def read(self, timeout=0.5):
        raise NotImplementedError

    def write(self, frame):
        raise NotImplementedError

    def stats(self):
        return None, None

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class PacketSocket(LinkSocket):
    """Linux AF_PACKET back end."""

    def __init__(self, ifname, promisc=True, snaplen=65535, buffer_size=4 * 1024 * 1024):
        self.ifname = ifname
        self.snaplen = snaplen
        self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        try:
            self._sock.bind((ifname, 0))
        except OSError as exc:
            self._sock.close()
            raise NetToolError("cannot open %s: %s" % (ifname, exc))
        for option, value in ((socket.SO_RCVBUF, buffer_size), (SO_TIMESTAMPNS, 1)):
            try:
                self._sock.setsockopt(socket.SOL_SOCKET, option, value)
            except OSError:
                pass
        if promisc:
            from . import iface as ifmod

            mreq = struct.pack("iHH8s", ifmod.ifindex(ifname), PACKET_MR_PROMISC, 0, b"")
            try:
                self._sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
            except OSError as exc:
                sys.stderr.write("warning: could not enable promiscuous mode: %s\n" % exc)
        self._sock.settimeout(0.5)

    def read(self, timeout=0.5):
        self._sock.settimeout(timeout)
        try:
            data, ancdata, _flags, _addr = self._sock.recvmsg(
                self.snaplen, socket.CMSG_SPACE(16))
        except socket.timeout:
            return []
        except (AttributeError, OSError) as exc:
            if isinstance(exc, OSError) and exc.errno not in (errno.EAGAIN, errno.EINTR):
                raise NetToolError("capture read failed: %s" % exc)
            return []
        timestamp = None
        for level, ctype, cdata in ancdata:
            if level == socket.SOL_SOCKET and ctype == SCM_TIMESTAMPNS and len(cdata) >= 16:
                sec, nsec = struct.unpack("qq", cdata[:16])
                timestamp = sec + nsec / 1e9
                break
        return [(data, timestamp if timestamp is not None else time.time())]

    def write(self, frame):
        return self._sock.send(frame)

    def stats(self):
        try:
            raw = self._sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
            return struct.unpack("II", raw)
        except OSError:
            return None, None

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass


class BpfSocket(LinkSocket):
    """macOS / BSD /dev/bpf back end."""

    def __init__(self, ifname, promisc=True, snaplen=65535, buffer_size=1024 * 1024):
        import fcntl

        self.ifname = ifname
        self.snaplen = snaplen
        self._fcntl = fcntl
        self._fd = self._open_device()
        try:
            # The buffer length must be set before the interface is attached.
            requested = max(4096, min(buffer_size, 8 * 1024 * 1024))
            size = bytearray(struct.pack("I", requested))
            fcntl.ioctl(self._fd, BIOCSBLEN, size, True)
            self.buffer_len = struct.unpack("I", bytes(size))[0]

            fcntl.ioctl(self._fd, BIOCSETIF, struct.pack("16s16x", ifname.encode()[:15]))
            fcntl.ioctl(self._fd, BIOCIMMEDIATE, struct.pack("I", 1))
            # We build complete Ethernet frames ourselves when injecting.
            fcntl.ioctl(self._fd, BIOCSHDRCMPLT, struct.pack("I", 1))
            try:
                fcntl.ioctl(self._fd, BIOCSSEESENT, struct.pack("I", 1))
            except OSError:
                pass
            if promisc:
                try:
                    fcntl.ioctl(self._fd, BIOCPROMISC)
                except OSError as exc:
                    sys.stderr.write("warning: could not enable promiscuous mode: %s\n" % exc)
            dlt = bytearray(4)
            try:
                fcntl.ioctl(self._fd, BIOCGDLT, dlt, True)
                self.linktype = struct.unpack("I", bytes(dlt))[0]
            except OSError:
                self.linktype = DLT_EN10MB
            try:
                fcntl.ioctl(self._fd, BIOCFLUSH)
            except OSError:
                pass
        except OSError as exc:
            os.close(self._fd)
            raise NetToolError("cannot capture on %s: %s" % (ifname, exc))

    def _open_device(self):
        last_error = None
        for index in range(0, 256):
            path = "/dev/bpf%d" % index
            try:
                return os.open(path, os.O_RDWR)
            except OSError as exc:
                last_error = exc
                if exc.errno in (errno.EBUSY, errno.ENOENT):
                    continue
                if exc.errno in (errno.EACCES, errno.EPERM):
                    raise NetToolError(
                        "no permission to open %s. Either run with sudo, or install the "
                        "BPF access helper (macos/install-bpf-access.sh) once so your "
                        "user can capture without sudo." % path)
                continue
        raise NetToolError("could not open any /dev/bpf device: %s" % last_error)

    def read(self, timeout=0.5):
        ready = select.select([self._fd], [], [], timeout)[0]
        if not ready:
            return []
        try:
            buffer = os.read(self._fd, self.buffer_len)
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EINTR):
                return []
            raise NetToolError("capture read failed: %s" % exc)
        return parse_bpf_buffer(buffer)

    def write(self, frame):
        return os.write(self._fd, frame)

    def stats(self):
        try:
            buffer = bytearray(8)
            self._fcntl.ioctl(self._fd, BIOCGSTATS, buffer, True)
            received, dropped = struct.unpack("II", bytes(buffer))
            return received, dropped
        except OSError:
            return None, None

    def close(self):
        try:
            os.close(self._fd)
        except OSError:
            pass


def open_link(ifname, promisc=True, snaplen=65535, buffer_size=None):
    """Open a raw link-layer handle on `ifname` for the current platform."""
    if not (IS_LINUX or IS_DARWIN or "bsd" in sys.platform):
        raise NetToolError("raw packet capture is not implemented on %s" % sys.platform)
    require_root("raw packet access")
    if IS_LINUX:
        return PacketSocket(ifname, promisc, snaplen, buffer_size or 4 * 1024 * 1024)
    return BpfSocket(ifname, promisc, snaplen, buffer_size or 1024 * 1024)
