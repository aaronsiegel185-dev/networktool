"""Minimal classic-pcap reader/writer (libpcap 2.4 format, no dependencies).

Files written here open directly in Wireshark, tshark, tcpdump or any pcap tool.
"""

import struct

from .util import NetToolError

MAGIC_USEC = 0xA1B2C3D4
MAGIC_NSEC = 0xA1B23C4D

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_IEEE802_11 = 105
LINKTYPE_IEEE802_11_RADIOTAP = 127
LINKTYPE_LINUX_SLL = 113


class PcapWriter(object):
    """Write packets to a .pcap file.

    Usage:
        with PcapWriter("cap.pcap") as w:
            w.write(raw_bytes, timestamp)
    """

    def __init__(self, path, linktype=LINKTYPE_ETHERNET, snaplen=262144):
        self.path = path
        self.linktype = linktype
        self.snaplen = snaplen
        self.packets = 0
        self.bytes = 0
        self._fh = open(path, "wb")
        self._fh.write(struct.pack("<IHHiIII", MAGIC_USEC, 2, 4, 0, 0, snaplen, linktype))

    def write(self, data, timestamp, orig_len=None):
        if orig_len is None:
            orig_len = len(data)
        chunk = data[: self.snaplen]
        sec = int(timestamp)
        usec = int(round((timestamp - sec) * 1_000_000))
        if usec >= 1_000_000:  # rounding carry
            sec += 1
            usec -= 1_000_000
        self._fh.write(struct.pack("<IIII", sec, usec, len(chunk), orig_len))
        self._fh.write(chunk)
        self.packets += 1
        self.bytes += len(chunk)

    def flush(self):
        self._fh.flush()

    def close(self):
        if self._fh and not self._fh.closed:
            self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _read_pcap_header(handle, path):
    """The 24-byte file header, or a NetToolError saying why it is not one."""
    header = handle.read(24)
    if len(header) < 24:
        raise NetToolError("%s is too short to be a pcap file (%d bytes)"
                           % (path, len(header)))
    magic = struct.unpack("<I", header[:4])[0]
    if magic in (MAGIC_USEC, MAGIC_NSEC):
        return header, "<", magic
    swapped = struct.unpack(">I", header[:4])[0]
    if swapped in (MAGIC_USEC, MAGIC_NSEC):
        return header, ">", swapped
    raise NetToolError(
        "%s is not a classic pcap file - its first four bytes are %s. pcapng "
        "captures (what Wireshark writes by default) are not read here yet; save "
        "as \"Wireshark/tcpdump ... pcap\" instead."
        % (path, " ".join("%02x" % byte for byte in header[:4])))


def _open_capture(path):
    """Open a capture file, or explain what is wrong with the path.

    Every one of these arrives from something a person typed or picked, so none
    of them is a bug worth a traceback - and a traceback is what an unhandled
    OSError becomes by the time it reaches a GUI.
    """
    try:
        return open(path, "rb")
    except IsADirectoryError:
        raise NetToolError("%s is a directory, not a capture file." % path)
    except FileNotFoundError:
        raise NetToolError("no such capture file: %s" % path)
    except PermissionError:
        raise NetToolError("no permission to read %s." % path)
    except OSError as exc:
        raise NetToolError("cannot read %s: %s" % (path, exc.strerror or exc))


class PcapReader(object):
    """Iterate (timestamp, data, orig_len) tuples from a classic pcap file."""

    def __init__(self, path):
        self.path = path
        self._fh = _open_capture(path)
        # Anything that rejects the file from here on has to close it first: a
        # constructor that raises leaves no object for the caller to close, and
        # a run of bad paths would then leak a descriptor each.
        try:
            magic = self._read_header()
        except BaseException:
            self._fh.close()
            raise
        self.nano = magic == MAGIC_NSEC
        fields = struct.unpack(self.endian + "HHiIII", self._header[4:])
        self.version = (fields[0], fields[1])
        self.snaplen = fields[4]
        self.linktype = fields[5]

    def __iter__(self):
        divisor = 1_000_000_000.0 if self.nano else 1_000_000.0
        while True:
            hdr = self._fh.read(16)
            if len(hdr) < 16:
                return
            sec, frac, caplen, origlen = struct.unpack(self.endian + "IIII", hdr)
            data = self._fh.read(caplen)
            if len(data) < caplen:
                return
            yield sec + frac / divisor, data, origlen

    def close(self):
        self._fh.close()

    def _read_header(self):
        self._header, self.endian, magic = _read_pcap_header(self._fh, self.path)
        return magic

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
