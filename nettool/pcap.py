"""Minimal classic-pcap reader/writer (libpcap 2.4 format, no dependencies).

Files written here open directly in Wireshark, tshark, tcpdump or any pcap tool.
"""

import struct

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


class PcapReader(object):
    """Iterate (timestamp, data, orig_len) tuples from a classic pcap file."""

    def __init__(self, path):
        self.path = path
        self._fh = open(path, "rb")
        header = self._fh.read(24)
        if len(header) < 24:
            raise ValueError("%s is too short to be a pcap file" % path)
        magic = struct.unpack("<I", header[:4])[0]
        if magic in (MAGIC_USEC, MAGIC_NSEC):
            self.endian = "<"
        elif struct.unpack(">I", header[:4])[0] in (MAGIC_USEC, MAGIC_NSEC):
            self.endian = ">"
            magic = struct.unpack(">I", header[:4])[0]
        else:
            raise ValueError("%s is not a classic pcap file (bad magic)" % path)
        self.nano = magic == MAGIC_NSEC
        fields = struct.unpack(self.endian + "HHiIII", header[4:])
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

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
