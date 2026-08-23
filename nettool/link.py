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

from . import bpfprog
from .util import NetToolError, require_root

IS_LINUX = sys.platform.startswith("linux")
IS_DARWIN = sys.platform == "darwin"
IS_WINDOWS = sys.platform == "win32"

ETH_P_ALL = 0x0003
DLT_EN10MB = 1

# --- Linux ------------------------------------------------------------------

SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_STATISTICS = 6
PACKET_AUXDATA = 8
SO_TIMESTAMPNS = 35
SCM_TIMESTAMPNS = 35
SO_ATTACH_FILTER = 26
SO_DETACH_FILTER = 27

# struct tpacket_auxdata
TPACKET_AUXDATA = struct.Struct("=IIIHHHH")
TP_STATUS_VLAN_VALID = 1 << 4
TP_STATUS_VLAN_TPID_VALID = 1 << 6


def reinsert_vlan_tag(data, tci, tpid=0x8100):
    """Put a VLAN tag back into a frame the kernel stripped.

    Linux hands VLAN-tagged frames to AF_PACKET with the tag removed and the id
    delivered out of band, so a mirror capture would otherwise show no tags at all.
    This is what tcpdump does before writing the packet to a file.
    """
    if len(data) < 12:
        return data
    return data[:12] + struct.pack("!HH", tpid, tci & 0xFFFF) + data[12:]

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
BIOCSETF = _ioc(IOC_IN, "B", 103, 16)           # struct bpf_program
BIOCSBLEN = _ioc(IOC_INOUT, "B", 102, 4)
BIOCFLUSH = _ioc(IOC_VOID, "B", 104, 0)
BIOCPROMISC = _ioc(IOC_VOID, "B", 105, 0)
BIOCGDLT = _ioc(IOC_OUT, "B", 106, 4)
BIOCSETIF = _ioc(IOC_IN, "B", 108, 32)          # struct ifreq
BIOCGSTATS = _ioc(IOC_OUT, "B", 111, 8)         # struct bpf_stat
BIOCIMMEDIATE = _ioc(IOC_IN, "B", 112, 4)
BIOCSHDRCMPLT = _ioc(IOC_IN, "B", 117, 4)
BIOCSSEESENT = _ioc(IOC_IN, "B", 119, 4)
BIOCSDLT = _ioc(IOC_IN, "B", 120, 4)
BIOCGDLTLIST = _ioc(IOC_INOUT, "B", 121, 16)    # struct bpf_dltlist

DLT_IEEE802_11 = 105
DLT_IEEE802_11_RADIOTAP = 127

# struct bpf_hdr { struct timeval32 bh_tstamp; u_int32 bh_caplen, bh_datalen;
#                  u_short bh_hdrlen; }
BPF_HDR = struct.Struct("=iiIIH")

# macOS caps a BPF buffer at debug.bpf_maxbufsize (512 KiB by default) and refuses the
# interface attach when it cannot allocate what was asked for, so start there and shrink.
BPF_DEFAULT_BUFFER = 512 * 1024
BPF_MIN_BUFFER = 4096
# Errors that mean "that buffer was too big", as opposed to a real failure.
BPF_RETRY_ERRNOS = (errno.ENOBUFS, errno.EINVAL, errno.ENOMEM)


def attach_bpf(fd, ifname, buffer_size=BPF_DEFAULT_BUFFER, ioctl_fn=None):
    """Size the buffer and attach the descriptor to `ifname`.

    This follows libpcap's dance: BIOCSETIF fails when the kernel cannot allocate the
    requested buffer, and the only way to find a size it will accept is to halve and
    retry. Returns the buffer length the kernel actually gave us.
    """
    import fcntl

    ioctl_fn = ioctl_fn or fcntl.ioctl
    request = struct.pack("16s16x", ifname.encode()[:15])
    size = max(BPF_MIN_BUFFER, min(int(buffer_size), 8 * 1024 * 1024))
    requested = size
    attached = False
    last_error = None
    while size >= BPF_MIN_BUFFER:
        try:
            buffer = bytearray(struct.pack("I", size))
            ioctl_fn(fd, BIOCSBLEN, buffer, True)
        except OSError as exc:
            # Some kernels reject the size outright; the attach below may still work.
            last_error = exc
        try:
            ioctl_fn(fd, BIOCSETIF, request)
            attached = True
            break
        except OSError as exc:
            last_error = exc
            if exc.errno == errno.ENXIO:
                raise NetToolError(_no_such_device(ifname))
            if exc.errno not in BPF_RETRY_ERRNOS:
                raise NetToolError("cannot attach to %s (BIOCSETIF): %s" % (ifname, exc))
            size //= 2
    if not attached:
        # Last resort: let the kernel pick the buffer size itself. A descriptor that
        # refuses every size may still attach when BIOCSBLEN is never issued.
        try:
            ioctl_fn(fd, BIOCSETIF, request)
            attached = True
            size = 0
        except OSError as exc:
            last_error = exc
    if not attached:
        if getattr(last_error, "errno", None) in (errno.EINVAL, errno.ENXIO):
            # libpcap treats EINVAL from BIOCSETIF on macOS the same as ENXIO: the
            # kernel has no BPF-capable device by that name.
            raise NetToolError(_no_such_device(ifname, last_error))
        raise NetToolError(
            "cannot attach to %s: %s. Buffer sizes from %d down to %d bytes were all "
            "refused." % (ifname, last_error, requested, BPF_MIN_BUFFER))
    try:
        buffer = bytearray(4)
        ioctl_fn(fd, BIOCGBLEN, buffer, True)
        return struct.unpack("I", bytes(buffer))[0]
    except OSError:
        return size or BPF_DEFAULT_BUFFER


def _no_such_device(ifname, error=None):
    """The message for an interface BPF will not attach to, with the ones that work."""
    detail = " (%s)" % error if error else ""
    message = ["%s cannot be captured on%s." % (ifname, detail)]
    if IS_DARWIN:
        message.append(
            "macOS reports this for an interface that exists but has no BPF device - a "
            "utun/VPN interface, a bridge member, an adapter that is not attached, or "
            "simply the wrong name.")
    try:
        usable = capturable_interfaces()
    except Exception:                          # never let diagnosis hide the real error
        usable = []
    if usable:
        message.append("Interfaces that can be captured on: %s." % ", ".join(usable))
    else:
        message.append("Check the name with `nettool iface`.")
    return " ".join(message)


def capturable_interfaces(names=None):
    """Which interfaces a BPF descriptor will actually attach to.

    This is `tcpdump -D` in miniature: the only reliable way to know is to try, since
    plenty of interfaces show up in ifconfig but have no BPF device behind them.
    """
    if IS_WINDOWS:
        from . import npcap

        try:
            return [description or device for device, description in npcap.devices()]
        except NetToolError:
            return []
    if not IS_DARWIN and not IS_LINUX:
        return []
    from . import iface as ifmod

    if names is None:
        try:
            names = [info["name"] for info in ifmod.inventory()]
        except NetToolError:
            return []
    usable = []
    for name in names:
        try:
            link = open_link(name, promisc=False, snaplen=256, buffer_size=BPF_MIN_BUFFER)
        except (NetToolError, OSError):
            continue
        usable.append(name)
        link.close()
    return usable


def bpf_dlt_list(fd, ioctl_fn=None):
    """Every link type this BPF descriptor can be switched to.

    macOS advertises DLT_IEEE802_11_RADIOTAP on a Wi-Fi interface, and selecting it is
    what puts the radio into monitor mode.
    """
    import ctypes
    import fcntl

    ioctl_fn = ioctl_fn or fcntl.ioctl
    # First call with a null list to learn how many entries there are.
    request = bytearray(struct.pack("@IP", 0, 0))
    try:
        ioctl_fn(fd, BIOCGDLTLIST, request, True)
    except OSError:
        return []
    count = struct.unpack("@IP", bytes(request))[0]
    if not count or count > 256:
        return []
    buffer = ctypes.create_string_buffer(count * 4)
    request = bytearray(struct.pack("@IP", count, ctypes.addressof(buffer)))
    try:
        ioctl_fn(fd, BIOCGDLTLIST, request, True)
    except OSError:
        return []
    count = struct.unpack("@IP", bytes(request))[0]
    return list(struct.unpack("<%dI" % count, buffer.raw[:count * 4]))


def bpf_snaplen_program(snaplen):
    """A one-instruction BPF filter that accepts every packet, truncated to `snaplen`.

    BPF has no BIOCSSNAPLEN: the accept length is the filter's return value.
    """
    import ctypes

    # struct bpf_insn { u_short code; u_char jt, jf; bpf_u_int32 k; }
    # BPF_RET | BPF_K == 0x06, k = number of bytes to keep.
    instructions = ctypes.create_string_buffer(
        struct.pack("=HBBI", 0x06, 0, 0, max(1, int(snaplen))))
    # struct bpf_program { u_int bf_len; struct bpf_insn *bf_insns; }
    program = struct.pack("@IP", 1, ctypes.addressof(instructions))
    return program, instructions


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

    def set_filter(self, program):
        """Attach a kernel filter. Returns False when the platform cannot."""
        return False

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
            if exc.errno in (errno.ENODEV, errno.ENXIO):
                raise NetToolError(_no_such_device(ifname, exc))
            raise NetToolError("cannot open %s: %s" % (ifname, exc))
        for option, value in ((socket.SO_RCVBUF, buffer_size), (SO_TIMESTAMPNS, 1)):
            try:
                self._sock.setsockopt(socket.SOL_SOCKET, option, value)
            except OSError:
                pass
        # Ask for the VLAN id of frames whose tag the kernel has stripped.
        self._auxdata = False
        try:
            self._sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
            self._auxdata = True
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
        control_size = socket.CMSG_SPACE(16) + socket.CMSG_SPACE(TPACKET_AUXDATA.size)
        try:
            data, ancdata, _flags, _addr = self._sock.recvmsg(self.snaplen, control_size)
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
            elif level == SOL_PACKET and ctype == PACKET_AUXDATA \
                    and len(cdata) >= TPACKET_AUXDATA.size:
                status, _len, _snaplen, _mac, _net, tci, tpid = TPACKET_AUXDATA.unpack(
                    cdata[:TPACKET_AUXDATA.size])
                if status & TP_STATUS_VLAN_VALID:
                    if not status & TP_STATUS_VLAN_TPID_VALID or not tpid:
                        tpid = 0x8100
                    data = reinsert_vlan_tag(data, tci, tpid)
        return [(data, timestamp if timestamp is not None else time.time())]

    def write(self, frame):
        return self._sock.send(frame)

    def set_filter(self, program):
        """Attach a classic-BPF program so the kernel drops unwanted frames."""
        import ctypes

        if not program:
            try:
                self._sock.setsockopt(socket.SOL_SOCKET, SO_DETACH_FILTER,
                                      struct.pack("I", 0))
            except OSError:
                pass
            return False
        instructions = ctypes.create_string_buffer(bpfprog.to_bytes(program))
        fprog = struct.pack("@HP", len(program), ctypes.addressof(instructions))
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
        except OSError as exc:
            raise NetToolError("could not attach the capture filter: %s" % exc)
        return True

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

    def __init__(self, ifname, promisc=True, snaplen=65535, buffer_size=None,
                 monitor=False):
        import fcntl

        self.ifname = ifname
        self.snaplen = snaplen
        self.monitor = False
        self._fcntl = fcntl
        self._fd = self._open_device()
        step = "setup"
        try:
            self.buffer_len = attach_bpf(
                self._fd, ifname, buffer_size or BPF_DEFAULT_BUFFER)

            step = "BIOCIMMEDIATE"
            fcntl.ioctl(self._fd, BIOCIMMEDIATE, struct.pack("I", 1))
            # We build complete Ethernet frames ourselves when injecting.
            step = "BIOCSHDRCMPLT"
            fcntl.ioctl(self._fd, BIOCSHDRCMPLT, struct.pack("I", 1))
        except NetToolError:
            os.close(self._fd)
            raise
        except OSError as exc:
            os.close(self._fd)
            raise NetToolError("cannot capture on %s (%s): %s" % (ifname, step, exc))

        if monitor:
            self._enable_monitor()

        # Everything below is a refinement: warn, but keep the capture.
        try:
            fcntl.ioctl(self._fd, BIOCSSEESENT, struct.pack("I", 1))
        except OSError:
            pass
        if snaplen and snaplen < 262144:
            try:
                self.set_filter(bpfprog.snaplen_program(snaplen))
            except (NetToolError, OSError, ValueError):
                pass                      # capture full frames rather than none
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

    def _enable_monitor(self):
        """Switch the descriptor to radiotap, which puts the Wi-Fi radio in monitor mode.

        The association drops while this is active - that is the nature of monitor mode,
        not a bug. The link comes back when the capture ends.
        """
        available = bpf_dlt_list(self._fd)
        if DLT_IEEE802_11_RADIOTAP not in available:
            raise NetToolError(
                "%s cannot capture 802.11 frames (link types offered: %s). Monitor mode "
                "needs the Wi-Fi interface itself - check the name with `nettool iface`."
                % (self.ifname, ", ".join(str(d) for d in available) or "none"))
        try:
            self._fcntl.ioctl(self._fd, BIOCSDLT,
                              struct.pack("I", DLT_IEEE802_11_RADIOTAP))
        except OSError as exc:
            raise NetToolError(
                "could not put %s into monitor mode (BIOCSDLT): %s. Disconnecting from "
                "Wi-Fi first sometimes helps." % (self.ifname, exc))
        self.linktype = DLT_IEEE802_11_RADIOTAP
        self.monitor = True

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

    def set_filter(self, program):
        """Attach a classic-BPF program with BIOCSETF."""
        import ctypes

        instructions = ctypes.create_string_buffer(
            bpfprog.to_bytes(program or bpfprog.accept_all()))
        request = struct.pack("@IP", len(program or bpfprog.accept_all()),
                              ctypes.addressof(instructions))
        try:
            self._fcntl.ioctl(self._fd, BIOCSETF, request)
        except OSError as exc:
            raise NetToolError("could not attach the capture filter: %s" % exc)
        return True

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


def open_link(ifname, promisc=True, snaplen=65535, buffer_size=None, monitor=False):
    """Open a raw link-layer handle on `ifname` for the current platform.

    `monitor` requests 802.11 monitor mode, which is available on macOS by selecting the
    radiotap link type. On Linux, create a monitor interface first
    (`sudo iw dev wlan0 interface add mon0 type monitor && sudo ip link set mon0 up`)
    and capture on that.
    """
    if IS_WINDOWS:
        # Windows has no raw layer-2 socket; capture goes through the Npcap
        # driver, which presents the same read/filter/stats surface as the
        # sockets above so nothing further up has to know the difference.
        from . import npcap

        require_root("Packet capture")
        if monitor:
            raise NetToolError(
                "monitor mode on Windows needs an adapter and driver that support it; "
                "Npcap can enable it per-adapter through its own settings, but nettool "
                "cannot switch it on for you.")
        sock = npcap.NpcapSocket(ifname, promisc=promisc, snaplen=snaplen)
        return sock
    if not (IS_LINUX or IS_DARWIN or "bsd" in sys.platform):
        raise NetToolError("raw packet capture is not implemented on %s" % sys.platform)
    if IS_LINUX:
        # AF_PACKET is root-only, so say so before the socket call fails obscurely.
        require_root("Packet capture")
        if monitor:
            raise NetToolError(
                "Linux does not switch an interface into monitor mode from the capture "
                "socket. Create a monitor interface first:\n"
                "    sudo iw dev %s interface add mon0 type monitor\n"
                "    sudo ip link set mon0 up\n"
                "then capture on mon0." % ifname)
        return PacketSocket(ifname, promisc, snaplen, buffer_size or 4 * 1024 * 1024)
    # On macOS root is not required: opening /dev/bpf* succeeds for any user in the
    # access_bpf group (see macos/install-bpf-access.sh). Let the open attempt decide,
    # so people who installed the helper are not turned away here.
    return BpfSocket(ifname, promisc, snaplen, buffer_size or BPF_DEFAULT_BUFFER,
                     monitor=monitor)
