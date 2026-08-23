"""Live packet capture with pcap export, and offline pcap inspection."""

import collections
import os
import signal
import sys
import time

from . import decode as dec
from . import dot11
from . import iface as ifmod
from .link import open_link

WIRELESS_LINKTYPES = (105, 127)
from .pcap import PcapReader, PcapWriter, LINKTYPE_ETHERNET
from .pfilter import compile_filter
from .util import NetToolError, human_bytes, human_secs, table


class Stats(object):
    def __init__(self):
        self.packets = 0
        self.bytes = 0
        self.protos = collections.Counter()
        self.talkers = collections.Counter()
        self.conversations = collections.Counter()
        self.ports = collections.Counter()
        self.macs = collections.Counter()
        self.vlans = collections.Counter()
        self.first_ts = None
        self.last_ts = None

    def add(self, pkt, ts):
        self.packets += 1
        self.bytes += pkt["len"]
        self.protos[pkt.get("proto") or pkt.get("l2") or "?"] += pkt["len"]
        if self.first_ts is None:
            self.first_ts = ts
        self.last_ts = ts
        src, dst = pkt.get("src"), pkt.get("dst")
        if src:
            self.talkers[src] += pkt["len"]
        if dst:
            self.talkers[dst] += pkt["len"]
        if src and dst:
            key = " <-> ".join(sorted([src, dst]))
            self.conversations[key] += pkt["len"]
        if pkt.get("eth_src"):
            self.macs[pkt["eth_src"]] += 1
        for p in (pkt.get("sport"), pkt.get("dport")):
            if p is not None and p < 1024 or (p is not None and p in (3389, 5900, 8080, 8443)):
                self.ports["%s/%s" % (p, (pkt.get("l4") or "").lower())] += 1
        if pkt.get("vlan") is not None:
            self.vlans[pkt["vlan"]] += 1

    def report(self, sink=None, top=10):
        sink = sink or sys.stdout
        duration = (self.last_ts - self.first_ts) if self.first_ts is not None else 0
        sink.write("\npackets: %d   bytes: %s   duration: %s" % (
            self.packets, human_bytes(self.bytes), human_secs(duration)))
        if duration > 0.5:
            sink.write("   avg: %.1f pkt/s, %s/s" % (
                self.packets / duration, human_bytes(self.bytes / duration)))
        sink.write("\n")
        if not self.packets:
            return
        sink.write("\nprotocol mix (by bytes)\n")
        table([[k, v, "%.1f%%" % (100.0 * v / max(1, self.bytes))]
               for k, v in self.protos.most_common(top)],
              ["proto", "bytes", "share"], sink)
        if self.talkers:
            sink.write("\ntop talkers\n")
            table([[k, human_bytes(v)] for k, v in self.talkers.most_common(top)],
                  ["address", "bytes"], sink)
        if self.conversations:
            sink.write("\ntop conversations\n")
            table([[k, human_bytes(v)] for k, v in self.conversations.most_common(top)],
                  ["pair", "bytes"], sink)
        if self.vlans:
            sink.write("\nVLANs seen\n")
            table([[k, v] for k, v in self.vlans.most_common(top)], ["vlan", "packets"], sink)


def live_capture(ifname=None, count=0, duration=0, snaplen=65535, outfile=None,
                 filter_expr=None, promisc=True, show=True, quiet=False, sink=None,
                 monitor=False):
    """Capture from an interface. Returns a Stats object.

    count/duration of 0 mean "until Ctrl-C". With `monitor`, the radio captures 802.11
    frames off the air instead of the machine's own Ethernet traffic, and the returned
    Stats carries a `survey` with the AP/client inventory.
    """
    sink = sink or sys.stdout
    ifname = ifname or ifmod.primary_interface()
    if not ifname:
        raise NetToolError("no capture interface found; pass -i <iface>")
    match = compile_filter(filter_expr)
    link = open_link(ifname, promisc=promisc, snaplen=snaplen, monitor=monitor)
    wireless = link.linktype in WIRELESS_LINKTYPES
    if wireless and filter_expr and not quiet:
        sink.write("note: the filter language describes IP traffic and does not apply to "
                   "802.11 frames; capturing everything.\n")
        match = compile_filter(None)
    writer = PcapWriter(outfile, link.linktype, snaplen) if outfile else None
    stats = Stats()
    stats.survey = dot11.Survey() if wireless else None
    stats.wireless = wireless
    stop = {"now": False}

    def _sigint(_sig, _frm):
        stop["now"] = True

    old_handler = signal.signal(signal.SIGINT, _sigint)
    started = time.time()
    seen = 0
    if not quiet:
        sink.write("capturing on %s (snaplen %d%s%s%s)%s\n" % (
            ifname, snaplen, ", promisc" if promisc else "",
            ", monitor/802.11" if wireless else "",
            ", filter: %s" % filter_expr if filter_expr and not wireless else "",
            " -> %s" % outfile if outfile else ""))
        if wireless:
            sink.write("the Wi-Fi association drops while monitor mode is active\n")
        sink.write("stop with Ctrl-C\n")
    try:
        while not stop["now"]:
            if duration and time.time() - started >= duration:
                break
            batch = link.read(timeout=0.5)
            if not batch:
                continue
            for data, ts in batch:
                seen += 1
                if wireless:
                    info = dot11.decode(data, link.linktype)
                    stats.survey.add(info, ts)
                    stats.packets += 1
                    stats.bytes += len(data)
                    if stats.first_ts is None:
                        stats.first_ts = ts
                    stats.last_ts = ts
                    if writer:
                        writer.write(data, ts)
                    if show and not quiet and info:
                        sink.write("%s %s\n" % (
                            time.strftime("%H:%M:%S", time.localtime(ts)),
                            dot11.summary(info)))
                        sink.flush()
                    if count and stats.packets >= count:
                        break
                    continue
                pkt = dec.decode(data)
                if not match(pkt):
                    continue
                stats.add(pkt, ts)
                if writer:
                    writer.write(data, ts)
                if show and not quiet:
                    sink.write("%s %s\n" % (time.strftime("%H:%M:%S", time.localtime(ts)),
                                            dec.summary(pkt)))
                    sink.flush()
                if count and stats.packets >= count:
                    break
            if count and stats.packets >= count:
                break
    finally:
        signal.signal(signal.SIGINT, old_handler)
        received, dropped = link.stats()
        link.close()
        if writer:
            writer.close()
        stats.kernel_seen = received
        stats.kernel_dropped = dropped
        stats.examined = seen
    if not quiet:
        if filter_expr:
            sink.write("\n%d frames examined, %d matched the filter\n" % (seen, stats.packets))
        if dropped:
            sink.write("warning: kernel dropped %d packets (buffer too small / host too "
                       "busy)\n" % dropped)
        if writer:
            sink.write("wrote %d packets (%s) to %s\n" % (
                writer.packets, human_bytes(writer.bytes), outfile))
    return stats


def read_wireless_pcap(path, show=False, limit=0, sink=None):
    """Decode a monitor-mode capture into a dot11.Survey."""
    sink = sink or sys.stdout
    survey = dot11.Survey()
    printed = 0
    with PcapReader(path) as reader:
        for ts, data, _orig in reader:
            info = dot11.decode(data, reader.linktype)
            survey.add(info, ts)
            if show and info and (not limit or printed < limit):
                printed += 1
                sink.write("%s %s\n" % (time.strftime("%H:%M:%S", time.localtime(ts)),
                                        dot11.summary(info)))
    return survey


def read_pcap(path, filter_expr=None, show=False, limit=0, outfile=None, sink=None):
    """Re-read a pcap: summarize, optionally filter into a new pcap.

    A wireless capture is returned as a dot11.Survey instead of packet counters.
    """
    sink = sink or sys.stdout
    if not os.path.exists(path):
        raise NetToolError("no such file: %s" % path)
    with PcapReader(path) as probe:
        linktype = probe.linktype
    if linktype in WIRELESS_LINKTYPES and not outfile:
        return read_wireless_pcap(path, show=show, limit=limit, sink=sink)
    match = compile_filter(filter_expr)
    stats = Stats()
    writer = None
    reader = PcapReader(path)
    try:
        if outfile:
            writer = PcapWriter(outfile, reader.linktype, reader.snaplen)
        for ts, data, orig_len in reader:
            if reader.linktype != LINKTYPE_ETHERNET:
                # Only Ethernet frames can be decoded here; still counted and copied.
                stats.packets += 1
                stats.bytes += orig_len
                if writer:
                    writer.write(data, ts, orig_len)
                continue
            pkt = dec.decode(data)
            if not match(pkt):
                continue
            stats.add(pkt, ts)
            if writer:
                writer.write(data, ts, orig_len)
            if show and (not limit or stats.packets <= limit):
                sink.write("%s %s\n" % (time.strftime("%H:%M:%S", time.localtime(ts)),
                                        dec.summary(pkt)))
    finally:
        reader.close()
        if writer:
            writer.close()
    stats.linktype = reader.linktype
    if writer:
        sink.write("wrote %d packets to %s\n" % (writer.packets, outfile))
    return stats
