"""Packet capture on Windows, through Npcap's wpcap.dll.

Windows has no AF_PACKET and no /dev/bpf: raw layer-2 capture goes through a
driver, and Npcap is the one everything else uses (Wireshark installs it). We
talk to its DLL with ctypes rather than binding a Python package, so nettool
still needs nothing from pip.

The DLL exposes exactly what the rest of nettool already expects - a handle you
read frames from, a BPF filter, and drop counters - so this presents the same
LinkSocket shape as the Linux and macOS backends and the capture code above it
does not change.
"""

import ctypes
import os
import sys

from .util import NetToolError

PCAP_ERRBUF_SIZE = 256

INSTALL_HINT = (
    "packet capture on Windows needs Npcap, which nettool does not bundle. "
    "Install it from https://npcap.com (tick \"WinPcap API-compatible mode\"), "
    "then run nettool as Administrator. Everything that does not capture - "
    "interfaces, routes, Wi-Fi, ping, traceroute, port scan - works without it."
)


class _timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _pkthdr(ctypes.Structure):
    _fields_ = [("ts", _timeval), ("caplen", ctypes.c_uint32), ("len", ctypes.c_uint32)]


class _bpf_program(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]


class _pcap_stat(ctypes.Structure):
    _fields_ = [("ps_recv", ctypes.c_uint), ("ps_drop", ctypes.c_uint),
                ("ps_ifdrop", ctypes.c_uint)]


class _pcap_if(ctypes.Structure):
    pass


_pcap_if._fields_ = [
    ("next", ctypes.POINTER(_pcap_if)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.c_void_p),
    ("flags", ctypes.c_uint),
]


def _candidates():
    """Where Npcap puts wpcap.dll, most specific first.

    Npcap installs into System32\\Npcap rather than System32 so it can sit
    alongside a legacy WinPcap; that directory is not on the default search
    path, so it has to be named.
    """
    root = os.environ.get("SystemRoot", r"C:\Windows").rstrip("\\/")
    # Joined with a literal backslash rather than os.path.join: these are Windows
    # paths whatever host is asking, which also makes them checkable in tests.
    return [
        root + r"\System32\Npcap\wpcap.dll",
        root + r"\SysWOW64\Npcap\wpcap.dll",
        root + r"\System32\wpcap.dll",
        "wpcap.dll",
    ]


_dll = None


def load(paths=None):
    """The wpcap handle, or a NetToolError naming what to install."""
    global _dll
    if _dll is not None:
        return _dll
    if sys.platform != "win32":
        raise NetToolError("Npcap is a Windows driver; this is %s" % sys.platform)
    errors = []
    for path in paths or _candidates():
        try:
            _dll = ctypes.CDLL(path)
            break
        except OSError as exc:
            errors.append("%s: %s" % (path, exc))
    if _dll is None:
        raise NetToolError(INSTALL_HINT)
    _declare(_dll)
    return _dll


def _declare(dll):
    """Prototypes, so ctypes does not truncate a pointer to an int."""
    dll.pcap_open_live.restype = ctypes.c_void_p
    dll.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, ctypes.c_char_p]
    dll.pcap_close.argtypes = [ctypes.c_void_p]
    dll.pcap_next_ex.restype = ctypes.c_int
    dll.pcap_next_ex.argtypes = [ctypes.c_void_p,
                                 ctypes.POINTER(ctypes.POINTER(_pkthdr)),
                                 ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
    dll.pcap_compile.restype = ctypes.c_int
    dll.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(_bpf_program),
                                 ctypes.c_char_p, ctypes.c_int, ctypes.c_uint]
    dll.pcap_setfilter.restype = ctypes.c_int
    dll.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(_bpf_program)]
    dll.pcap_freecode.argtypes = [ctypes.POINTER(_bpf_program)]
    dll.pcap_datalink.restype = ctypes.c_int
    dll.pcap_datalink.argtypes = [ctypes.c_void_p]
    dll.pcap_stats.restype = ctypes.c_int
    dll.pcap_stats.argtypes = [ctypes.c_void_p, ctypes.POINTER(_pcap_stat)]
    dll.pcap_geterr.restype = ctypes.c_char_p
    dll.pcap_geterr.argtypes = [ctypes.c_void_p]
    dll.pcap_findalldevs.restype = ctypes.c_int
    dll.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(_pcap_if)),
                                     ctypes.c_char_p]
    dll.pcap_freealldevs.argtypes = [ctypes.POINTER(_pcap_if)]
    dll.pcap_lib_version.restype = ctypes.c_char_p


def version():
    return load().pcap_lib_version().decode("utf-8", "replace")


def devices():
    """[(npcap name, description)] - the name is the \\Device\\NPF_{GUID} form."""
    dll = load()
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    head = ctypes.POINTER(_pcap_if)()
    if dll.pcap_findalldevs(ctypes.byref(head), errbuf) != 0:
        raise NetToolError("Npcap could not list interfaces: %s"
                           % errbuf.value.decode("utf-8", "replace"))
    found = []
    try:
        node = head
        while node:
            entry = node.contents
            found.append((
                entry.name.decode("utf-8", "replace") if entry.name else "",
                entry.description.decode("utf-8", "replace") if entry.description else "",
            ))
            node = entry.next
    finally:
        dll.pcap_freealldevs(head)
    return found


def resolve_device(name):
    """Map a Windows adapter name to the device string Npcap wants.

    Npcap identifies adapters as \\Device\\NPF_{GUID}, which nobody can be asked
    to type, so accept the friendly name and match it against the descriptions.
    """
    if name.startswith("\\Device\\"):
        return name
    wanted = name.strip().lower()
    listed = devices()
    for device, description in listed:
        if wanted and (wanted in description.lower() or wanted in device.lower()):
            return device
    raise NetToolError(
        "no Npcap device matches %r. Available: %s"
        % (name, ", ".join(description or device for device, description in listed)
           or "none"))


class NpcapSocket(object):
    """The LinkSocket shape, backed by Npcap."""

    def __init__(self, ifname, promisc=True, snaplen=65535, timeout_ms=100):
        self.ifname = ifname
        self.snaplen = snaplen
        self._dll = load()
        self._filter = None
        device = resolve_device(ifname)
        errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
        handle = self._dll.pcap_open_live(device.encode("utf-8"), snaplen,
                                          1 if promisc else 0, timeout_ms, errbuf)
        if not handle:
            message = errbuf.value.decode("utf-8", "replace")
            if "permission" in message.lower() or "access" in message.lower():
                message += " - run nettool as Administrator"
            raise NetToolError("cannot capture on %s: %s" % (ifname, message))
        self._handle = ctypes.c_void_p(handle)
        self.dlt = self._dll.pcap_datalink(self._handle)

    def set_filter(self, expression):
        """Compile and attach a BPF filter, so filtering happens in the driver."""
        program = _bpf_program()
        if self._dll.pcap_compile(self._handle, ctypes.byref(program),
                                  expression.encode("utf-8"), 1, 0xFFFFFFFF) != 0:
            raise NetToolError("bad capture filter %r: %s"
                               % (expression, self._error()))
        try:
            if self._dll.pcap_setfilter(self._handle, ctypes.byref(program)) != 0:
                raise NetToolError("could not attach filter: %s" % self._error())
        finally:
            self._dll.pcap_freecode(ctypes.byref(program))
        self._filter = expression

    def recv(self):
        """(bytes, seconds) for the next frame, or (None, None) on timeout."""
        header = ctypes.POINTER(_pkthdr)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        result = self._dll.pcap_next_ex(self._handle, ctypes.byref(header),
                                        ctypes.byref(data))
        if result == 0:
            return None, None          # read timeout, not an error
        if result < 0:
            raise NetToolError("capture failed: %s" % self._error())
        caplen = header.contents.caplen
        frame = bytes(bytearray(data[:caplen]))
        stamp = header.contents.ts.tv_sec + header.contents.ts.tv_usec / 1e6
        return frame, stamp

    def stats(self):
        counters = _pcap_stat()
        if self._dll.pcap_stats(self._handle, ctypes.byref(counters)) != 0:
            return {}
        return {"received": counters.ps_recv, "dropped": counters.ps_drop,
                "iface_dropped": counters.ps_ifdrop}

    def _error(self):
        raw = self._dll.pcap_geterr(self._handle)
        return raw.decode("utf-8", "replace") if raw else "unknown error"

    def close(self):
        if getattr(self, "_handle", None):
            self._dll.pcap_close(self._handle)
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
