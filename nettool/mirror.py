"""Capture from a switch port mirror (SPAN) and make sense of what arrives.

A mirror port hands you every frame on one or more VLANs, from devices that are not
yours, usually 802.1Q tagged. Three things matter and none of them are the same as an
ordinary capture:

* Filter in the kernel. A mirror of a busy VLAN will out-run a Python loop.
* Keep the VLAN tags. Linux strips them from capture sockets - `nettool.link` puts them
  back - and some switches strip them on the way out, which is worth warning about.
* Report per VLAN, because "all the traffic on a VLAN" is an inventory question: who is
  on it, who talks to whom, and what protocols are in play.
"""

import collections
import re

from .oui import lookup as oui_lookup

BROADCAST = "ff:ff:ff:ff:ff:ff"


class VlanStats(object):
    """Everything seen on one VLAN (`vlan` is None for untagged frames)."""

    def __init__(self, vlan):
        self.vlan = vlan
        self.packets = 0
        self.bytes = 0
        self.broadcast = 0
        self.multicast = 0
        self.macs = collections.Counter()
        self.hosts = {}                       # ip -> mac
        self.talkers = collections.Counter()
        self.conversations = collections.Counter()
        self.protocols = collections.Counter()
        self.ports = collections.Counter()
        self.dhcp_servers = set()
        self.routers = set()
        self.first_ts = None
        self.last_ts = None

    def add(self, pkt, timestamp):
        self.packets += 1
        self.bytes += pkt["len"]
        if self.first_ts is None:
            self.first_ts = timestamp
        self.last_ts = timestamp
        source_mac = pkt.get("eth_src") or ""
        dest_mac = pkt.get("eth_dst") or ""
        if source_mac:
            self.macs[source_mac] += 1
        if dest_mac == BROADCAST:
            self.broadcast += 1
        elif dest_mac and int(dest_mac[:2], 16) & 1:
            self.multicast += 1
        self.protocols[pkt.get("proto") or pkt.get("l2") or "?"] += pkt["len"]

        source, dest = pkt.get("src"), pkt.get("dst")
        if source:
            self.talkers[source] += pkt["len"]
            if source_mac:
                self.hosts.setdefault(source, source_mac)
        if dest:
            self.talkers[dest] += pkt["len"]
        if source and dest:
            self.conversations[" <-> ".join(sorted([source, dest]))] += pkt["len"]
        for port in (pkt.get("sport"), pkt.get("dport")):
            if port is not None and port < 1024:
                self.ports["%s/%s" % (port, (pkt.get("l4") or "").lower())] += 1
        # A DHCP offer comes from the server; ICMP redirects come from routers.
        if pkt.get("sport") == 67:
            if source:
                self.dhcp_servers.add(source)
        if pkt.get("icmp_type") == 5 and source:
            self.routers.add(source)
        if pkt.get("l3") == "ARP" and pkt.get("arp_op") == 2 and source:
            self.hosts.setdefault(source, pkt.get("arp_sha", ""))

    def duration(self):
        if self.first_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)

    def report(self, top=10):
        return {
            "vlan": self.vlan,
            "packets": self.packets,
            "bytes": self.bytes,
            "duration": round(self.duration(), 2),
            "broadcast": self.broadcast,
            "multicast": self.multicast,
            "unique_macs": len(self.macs),
            "unique_hosts": len(self.hosts),
            "hosts": [{"ip": ip, "mac": mac, "vendor": oui_lookup(mac)}
                      for ip, mac in sorted(self.hosts.items())],
            "top_talkers": dict(self.talkers.most_common(top)),
            "conversations": dict(self.conversations.most_common(top)),
            "protocols": dict(self.protocols.most_common(top)),
            "services": dict(self.ports.most_common(top)),
            "dhcp_servers": sorted(self.dhcp_servers),
            "routers": sorted(self.routers),
        }


class MirrorSurvey(object):
    """Per-VLAN inventory plus the checks that say whether the mirror is really working."""

    def __init__(self, local_macs=None):
        self.vlans = {}
        self.packets = 0
        self.bytes = 0
        self.tagged = 0
        self.untagged = 0
        self.qinq = 0
        self.local_macs = {m.lower() for m in (local_macs or []) if m}
        self.own_traffic = 0
        self.foreign_traffic = 0
        self.directions = collections.Counter()
        self.first_ts = None
        self.last_ts = None
        self.kernel_dropped = 0

    def add(self, pkt, timestamp):
        self.packets += 1
        self.bytes += pkt["len"]
        if self.first_ts is None:
            self.first_ts = timestamp
        self.last_ts = timestamp
        vlan = pkt.get("vlan")
        if vlan is None:
            self.untagged += 1
        else:
            self.tagged += 1
            if pkt.get("outer_vlan") is not None and pkt["outer_vlan"] != vlan:
                self.qinq += 1
        stats = self.vlans.get(vlan)
        if stats is None:
            stats = self.vlans[vlan] = VlanStats(vlan)
        stats.add(pkt, timestamp)

        source_mac = (pkt.get("eth_src") or "").lower()
        dest_mac = (pkt.get("eth_dst") or "").lower()
        if source_mac in self.local_macs or dest_mac in self.local_macs:
            self.own_traffic += 1
        elif source_mac:
            self.foreign_traffic += 1
        source, dest = pkt.get("src"), pkt.get("dst")
        if source and dest:
            self.directions[(source, dest)] += 1

    def duration(self):
        if self.first_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)

    def bidirectional_share(self):
        """Fraction of conversations seen in both directions.

        A mirror configured `rx` only shows one side, which makes TCP analysis useless
        and is one of the most common SPAN mistakes.
        """
        if not self.directions:
            return None
        pairs = set(self.directions)
        both = sum(1 for (a, b) in pairs if (b, a) in pairs)
        return round(both / float(len(pairs)), 2)

    def findings(self):
        out = []
        if not self.packets:
            out.append(("critical", "No frames captured at all. The mirror session may be "
                                    "down, or the cable is in the wrong port."))
            return out
        if self.foreign_traffic == 0:
            out.append(("critical", "Every frame involves this machine's own MAC - this is "
                                    "not a mirror port, or the session has no source."))
        elif self.own_traffic > self.foreign_traffic:
            out.append(("warn", "Most frames are this machine's own traffic (%d of %d). "
                                "Give the capture interface no IP address so it stays "
                                "quiet." % (self.own_traffic, self.packets)))
        else:
            out.append(("ok", "%d of %d frames are from other devices - the mirror is "
                              "delivering." % (self.foreign_traffic, self.packets)))
        if self.tagged == 0 and self.packets:
            out.append(("warn", "No 802.1Q tags on any frame. The mirror is stripping VLAN "
                                "tags, so traffic from different VLANs cannot be told "
                                "apart. On Cisco add `encapsulation dot1q` to the "
                                "destination, on Aruba use a tagged mirror port."))
        elif self.tagged:
            ids = sorted(v for v in self.vlans if v is not None)
            out.append(("info", "%d VLAN(s) seen: %s"
                        % (len(ids), ", ".join(str(v) for v in ids))))
        if self.qinq:
            out.append(("info", "%d double-tagged (QinQ) frames." % self.qinq))
        share = self.bidirectional_share()
        if share is not None and self.packets > 100:
            if share < 0.2:
                out.append(("warn", "Only %.0f%% of conversations appear in both "
                                    "directions - the mirror is probably configured for "
                                    "one direction (`rx` or `tx` only) instead of `both`."
                            % (share * 100)))
            elif share > 0.6:
                out.append(("ok", "Both directions of most conversations are present."))
        if self.kernel_dropped:
            out.append(("warn", "The kernel dropped %d frames - the mirror is faster than "
                                "this capture. Narrow it with --vlan, shrink --snaplen, or "
                                "write straight to disk with --write." % self.kernel_dropped))
        broadcast = sum(stats.broadcast for stats in self.vlans.values())
        if self.packets and broadcast / float(self.packets) > 0.3:
            out.append(("warn", "%.0f%% of frames are broadcast - a broadcast storm or a "
                                "very chatty VLAN." % (100.0 * broadcast / self.packets)))
        return out

    def report(self, top=10):
        return {
            "packets": self.packets,
            "bytes": self.bytes,
            "duration": round(self.duration(), 2),
            "tagged": self.tagged,
            "untagged": self.untagged,
            "qinq": self.qinq,
            "own_traffic": self.own_traffic,
            "foreign_traffic": self.foreign_traffic,
            "bidirectional_share": self.bidirectional_share(),
            "kernel_dropped": self.kernel_dropped,
            "vlans": [self.vlans[key].report(top)
                      for key in sorted(self.vlans, key=lambda v: (v is None, v))],
            "findings": self.findings(),
        }


# --- switch-side configuration ---------------------------------------------

VENDOR_PATTERNS = [
    ("cisco-nxos", re.compile(r"nx-?os|nexus", re.I)),
    ("cisco-ios", re.compile(r"cisco|catalyst|\bios\b", re.I)),
    ("aruba-cx", re.compile(r"aruba.*(cx|6[13]\d\d|8\d\d\d)|arubaos-cx", re.I)),
    ("aruba-procurve", re.compile(r"procurve|hp.*switch|hewlett", re.I)),
    ("juniper", re.compile(r"juniper|junos|\bex\d", re.I)),
    ("mikrotik", re.compile(r"mikrotik|routeros", re.I)),
    ("ubiquiti", re.compile(r"ubiquiti|unifi|edgeswitch", re.I)),
    ("extreme", re.compile(r"extreme|exos", re.I)),
]


def detect_vendor(neighbor):
    """Guess the switch platform from an LLDP/CDP neighbour record."""
    if not neighbor:
        return None
    haystack = " ".join(str(neighbor.get(field, "")) for field in
                        ("system_description", "platform", "system_name", "vendor",
                         "chassis_id"))
    for name, pattern in VENDOR_PATTERNS:
        if pattern.search(haystack):
            return name
    return None


def span_config(vendor, source_port=None, source_vlan=None, dest_port=None, session=1):
    """The commands to paste into the switch to mirror to the port we are plugged into.

    Nothing here is executed - it is printed for a human to review, because a bad SPAN
    configuration can take a switch port out of service.
    """
    source_port = source_port or "<source port>"
    dest_port = dest_port or "<the port this machine is plugged into>"
    vlan = source_vlan
    if vendor == "cisco-ios":
        lines = ["! Cisco IOS / IOS-XE", "configure terminal"]
        if vlan:
            lines.append("monitor session %d source vlan %s both" % (session, vlan))
        else:
            lines.append("monitor session %d source interface %s both" % (session, source_port))
        lines += [
            "monitor session %d destination interface %s encapsulation dot1q ingress"
            % (session, dest_port),
            "end",
            "! check it with: show monitor session %d" % session,
            "! remove it with: configure terminal ; no monitor session %d" % session,
        ]
        return "\n".join(lines)
    if vendor == "cisco-nxos":
        lines = ["! Cisco NX-OS", "configure terminal",
                 "monitor session %d" % session]
        lines.append("  source vlan %s both" % vlan if vlan
                     else "  source interface %s both" % source_port)
        lines += ["  destination interface %s" % dest_port, "  no shut", "end",
                  "! the destination port must first be: switchport monitor"]
        return "\n".join(lines)
    if vendor == "aruba-cx":
        lines = ["# ArubaOS-CX", "configure terminal", "mirror session %d" % session]
        lines.append("    source vlan %s both" % vlan if vlan
                     else "    source interface %s both" % source_port)
        lines += ["    destination interface %s" % dest_port, "    enable", "exit",
                  "# check it with: show mirror %d" % session]
        return "\n".join(lines)
    if vendor == "aruba-procurve":
        lines = ["# ProCurve / ArubaOS-Switch", "configure",
                 "mirror %d port %s" % (session, dest_port)]
        lines.append("vlan %s monitor all both mirror %d" % (vlan, session) if vlan
                     else "interface %s monitor all both mirror %d" % (source_port, session))
        lines.append("# check it with: show monitor")
        return "\n".join(lines)
    if vendor == "juniper":
        lines = ["# Junos", "configure",
                 "set forwarding-options analyzer span output interface %s" % dest_port]
        if vlan:
            lines.append("set forwarding-options analyzer span input ingress vlan %s" % vlan)
            lines.append("set forwarding-options analyzer span input egress vlan %s" % vlan)
        else:
            lines.append("set forwarding-options analyzer span input ingress interface %s"
                         % source_port)
            lines.append("set forwarding-options analyzer span input egress interface %s"
                         % source_port)
        lines.append("commit")
        return "\n".join(lines)
    if vendor == "mikrotik":
        return "\n".join([
            "# RouterOS (switch chip mirroring)",
            "/interface ethernet switch set 0 mirror-source=%s mirror-target=%s"
            % (source_port, dest_port),
            "# RouterOS mirrors a port, not a VLAN; mirror the VLAN's uplink instead.",
        ])
    if vendor == "ubiquiti":
        return "\n".join([
            "# UniFi switches configure mirroring in the controller UI:",
            "#   Devices -> <switch> -> Ports -> %s -> Port Profile -> Mirror" % dest_port,
            "#   set the mirror source to %s" % (("VLAN %s" % vlan) if vlan else source_port),
            "# EdgeSwitch CLI: configure ; monitor session 1 source interface %s ; "
            "monitor session 1 destination interface %s" % (source_port, dest_port),
        ])
    if vendor == "extreme":
        lines = ["# Extreme EXOS", "configure mirror %d add ports %s"
                 % (session, source_port)]
        if vlan:
            lines = ["# Extreme EXOS", "configure mirror %d add vlan %s" % (session, vlan)]
        lines += ["configure mirror %d to port %s" % (session, dest_port),
                  "enable mirror %d" % session]
        return "\n".join(lines)
    return "\n".join([
        "# Switch platform not recognised. The mirror needs, in your switch's words:",
        "#   source:      %s" % (("VLAN %s, both directions" % vlan) if vlan
                                 else "%s, both directions" % source_port),
        "#   destination: %s" % dest_port,
        "#   keep the 802.1Q tags on the destination port if the switch offers the option",
    ])


def plan(neighbor, source_vlan=None, source_port=None, vendor=None, session=1):
    """Build a mirror plan from what LLDP/CDP told us about the switch we are on."""
    neighbor = neighbor or {}
    vendor = vendor or detect_vendor(neighbor) or "unknown"
    dest_port = neighbor.get("port_id") or None
    return {
        "vendor": vendor,
        "switch": neighbor.get("system_name") or neighbor.get("chassis_id") or "",
        "management_ip": (neighbor.get("mgmt_addrs") or [{}])[0].get("address", ""),
        "destination_port": dest_port or "",
        "source_vlan": source_vlan,
        "source_port": source_port,
        "native_vlan": neighbor.get("port_vlan_id"),
        "config": span_config(vendor, source_port=source_port, source_vlan=source_vlan,
                              dest_port=dest_port, session=session),
    }


# --- capture ----------------------------------------------------------------


def _writer_path(base, suffix):
    if "." in base.rsplit("/", 1)[-1]:
        stem, extension = base.rsplit(".", 1)
        return "%s-%s.%s" % (stem, suffix, extension)
    return "%s-%s.pcap" % (base, suffix)


class _Writers(object):
    """One pcap writer, or one per VLAN when splitting, with optional rotation."""

    def __init__(self, outfile, snaplen, split=False, rotate_bytes=0, linktype=1):
        self.outfile = outfile
        self.snaplen = snaplen
        self.split = split
        self.rotate_bytes = rotate_bytes
        self.linktype = linktype
        self.writers = {}
        self.sequence = {}
        self.files = []

    def _open(self, key):
        from .pcap import PcapWriter

        if self.split:
            label = "untagged" if key is None else "vlan%d" % key
            path = _writer_path(self.outfile, label)
        else:
            path = self.outfile
        index = self.sequence.get(key, 0)
        if index:
            path = _writer_path(path, "%03d" % index)
        writer = PcapWriter(path, self.linktype, self.snaplen)
        self.writers[key] = writer
        if path not in self.files:
            self.files.append(path)
        return writer

    def write(self, vlan, data, timestamp):
        if not self.outfile:
            return
        key = vlan if self.split else "all"
        writer = self.writers.get(key)
        if writer is None:
            writer = self._open(key)
        if self.rotate_bytes and writer.bytes >= self.rotate_bytes:
            writer.close()
            self.sequence[key] = self.sequence.get(key, 0) + 1
            writer = self._open(key)
        writer.write(data, timestamp)

    def close(self):
        for writer in self.writers.values():
            writer.close()

    def summary(self):
        return [{"file": writer.path, "packets": writer.packets, "bytes": writer.bytes}
                for writer in self.writers.values()]


def capture(ifname=None, vlans=None, duration=0, count=0, snaplen=65535, outfile=None,
            split=False, include_untagged=False, rotate_mb=0, show=False, quiet=False,
            sink=None, on_packet=None):
    """Capture from a mirror port. Returns a MirrorSurvey.

    `vlans` installs a kernel filter so the machine only ever sees those VLANs, which is
    what keeps up with a busy mirror.
    """
    import signal
    import sys
    import time

    from . import bpfprog
    from . import decode as dec
    from . import iface as ifmod
    from .link import open_link
    from .util import NetToolError

    sink = sink or sys.stdout
    ifname = ifname or ifmod.primary_interface()
    if not ifname:
        raise NetToolError("no capture interface found; pass -i <iface>")

    local_macs = []
    try:
        local_macs = [info["mac"] for info in ifmod.inventory() if info.get("mac")]
    except NetToolError:
        pass

    link = open_link(ifname, promisc=True, snaplen=snaplen)
    filtered = False
    if vlans:
        filtered = link.set_filter(
            bpfprog.vlan_program(vlans, snaplen=snaplen or bpfprog.ACCEPT_ALL,
                                 include_untagged=include_untagged))
    survey = MirrorSurvey(local_macs=local_macs)
    writers = _Writers(outfile, snaplen, split=split,
                       rotate_bytes=int(rotate_mb * 1024 * 1024),
                       linktype=getattr(link, "linktype", 1))

    if not quiet:
        sink.write("mirror capture on %s (snaplen %d%s)%s\n" % (
            ifname, snaplen,
            ", VLAN %s in the kernel" % ",".join(str(v) for v in vlans) if filtered else
            (", VLAN filter in userspace" if vlans else ""),
            " -> %s" % outfile if outfile else ""))
        sink.write("stop with Ctrl-C\n")

    stop = {"now": False}

    def _sigint(_sig, _frame):
        stop["now"] = True

    previous = signal.signal(signal.SIGINT, _sigint)
    started = time.time()
    wanted = {int(v) for v in vlans} if vlans else None
    try:
        while not stop["now"]:
            if duration and time.time() - started >= duration:
                break
            for data, timestamp in link.read(timeout=0.5):
                pkt = dec.decode(data)
                if wanted is not None and not filtered:
                    # No kernel filter available: fall back to dropping here.
                    if pkt.get("vlan") not in wanted and not (
                            include_untagged and pkt.get("vlan") is None):
                        continue
                survey.add(pkt, timestamp)
                writers.write(pkt.get("vlan"), data, timestamp)
                if on_packet:
                    on_packet(pkt, timestamp)
                if show and not quiet:
                    sink.write("%s %s\n" % (
                        time.strftime("%H:%M:%S", time.localtime(timestamp)),
                        dec.summary(pkt)))
                    sink.flush()
                if count and survey.packets >= count:
                    stop["now"] = True
                    break
    finally:
        signal.signal(signal.SIGINT, previous)
        _received, dropped = link.stats()
        link.close()
        writers.close()
        survey.kernel_dropped = dropped or 0
        survey.files = writers.summary()
        survey.interface = ifname
        survey.kernel_filtered = filtered
    return survey


def survey_pcap(path, vlans=None):
    """Build the same per-VLAN inventory from a capture file."""
    from . import decode as dec
    from .pcap import PcapReader

    wanted = {int(v) for v in vlans} if vlans else None
    survey = MirrorSurvey()
    with PcapReader(path) as reader:
        for timestamp, data, _orig in reader:
            pkt = dec.decode(data)
            if wanted is not None and pkt.get("vlan") not in wanted:
                continue
            survey.add(pkt, timestamp)
    return survey
