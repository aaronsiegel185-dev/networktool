"""nettool command line interface."""

import argparse
import csv
import json
import sys
import time

from . import __version__
from . import analyze as analyzemod
from . import capture as capmod
from . import diag as diagmod
from . import dot11
from . import discover as discmod
from . import iface as ifmod
from . import lldp as lldpmod
from . import mirror as mirrormod
from . import ping as pingmod
from . import portscan
from . import wifi as wifimod
from .util import (NetToolError, human_bytes, is_root, parse_ports, parse_targets,
                   section, table)

SEV_MARK = {"ok": "[ ok ]", "info": "[info]", "warn": "[WARN]", "critical": "[FAIL]"}


def _emit_json(payload):
    json.dump(payload, sys.stdout, indent=2, default=str, sort_keys=False)
    sys.stdout.write("\n")


# --- iface -----------------------------------------------------------------

def cmd_iface(args):
    if args.capturable:
        from .link import capturable_interfaces

        usable = capturable_interfaces()
        if args.json:
            _emit_json({"capturable": usable})
            return 0
        section("interfaces a capture can attach to")
        if usable:
            table([[name] for name in usable], ["interface"])
        else:
            sys.stdout.write("none - raw packet access needs root or BPF group "
                             "membership\n")
        return 0
    interfaces = ifmod.inventory()
    if args.name:
        interfaces = [i for i in interfaces if i["name"] == args.name]
        if not interfaces:
            raise NetToolError("no such interface: %s" % args.name)
    if not args.all:
        interfaces = [i for i in interfaces if i["up"]]
    gateway, gw_dev = ifmod.default_gateway()
    servers, search = ifmod.dns_servers()
    if args.json:
        _emit_json({"interfaces": interfaces, "routes": ifmod.routes(),
                    "default_gateway": gateway, "gateway_interface": gw_dev,
                    "dns_servers": servers, "dns_search": search,
                    "arp": ifmod.arp_table()})
        return 0
    rows = []
    for i in interfaces:
        addr = "%s/%d" % (i["ipv4"], i["prefixlen"]) if i["ipv4"] else "-"
        speed = "%s Mb/s" % i["speed_mbps"] if i["speed_mbps"] and i["speed_mbps"] > 0 else "-"
        kind = "wifi" if i["wireless"] else ("loopback" if i["loopback"] else "wired")
        rows.append([i["name"], kind, "up" if i["up"] else "down", i["operstate"],
                     addr, i["mac"], i["mtu"], speed, i["duplex"] or "-",
                     human_bytes(i["counters"]["rx_bytes"]),
                     human_bytes(i["counters"]["tx_bytes"]),
                     i["counters"]["rx_errors"] + i["counters"]["tx_errors"]])
    table(rows, ["iface", "type", "admin", "oper", "ipv4", "mac", "mtu", "speed",
                 "duplex", "rx", "tx", "errs"])
    if args.verbose:
        for i in interfaces:
            if i["ipv6"]:
                sys.stdout.write("%s IPv6: %s\n" % (i["name"], ", ".join(i["ipv6"])))
    section("routing")
    table([[r["iface"], "%s/%d" % (r["dest"], r["prefixlen"]), r["gateway"], r["metric"]]
           for r in ifmod.routes()], ["iface", "destination", "gateway", "metric"])
    sys.stdout.write("\ndefault gateway: %s%s\n" % (gateway or "(none)",
                                                    " via %s" % gw_dev if gw_dev else ""))
    sys.stdout.write("dns servers:     %s\n" % (", ".join(servers) or "(none)"))
    if search:
        sys.stdout.write("dns search:      %s\n" % " ".join(search))
    if args.verbose:
        section("arp cache")
        table([[e["ip"], e["mac"], e["iface"], "incomplete" if e["incomplete"] else ""]
               for e in ifmod.arp_table()], ["ip", "mac", "iface", "state"])
    return 0


# --- discover --------------------------------------------------------------

def cmd_discover(args):
    printed = set()

    def on_host(host):
        if args.json or host["ip"] in printed:
            return
        printed.add(host["ip"])
        sys.stdout.write("  found %-15s %s\n" % (host["ip"], host.get("mac", "")))
        sys.stdout.flush()

    if not args.json:
        sys.stdout.write("discovering hosts...\n")
    hosts, method = discmod.discover(args.interface, args.cidr, args.method,
                                     timeout=args.timeout, resolve=not args.no_resolve,
                                     on_host=on_host if args.progress else None)
    duplicates = discmod.find_duplicate_ips(hosts)
    if args.json:
        _emit_json({"method": method, "hosts": hosts, "duplicate_ips": duplicates})
        return 0
    section("hosts on the LAN (%d found via %s)" % (len(hosts), method))
    table([[h["ip"], h.get("mac", ""), h.get("vendor", ""), h.get("name", ""),
            h.get("method", ""),
            "%.1f ms" % h["rtt_ms"] if h.get("rtt_ms") else ""]
           for h in hosts],
          ["ip", "mac", "vendor", "hostname", "via", "rtt"])
    if duplicates:
        section("duplicate IP addresses (two devices claiming one address)")
        for ip, macs in duplicates.items():
            sys.stdout.write("  %s claimed by %s\n" % (ip, ", ".join(macs)))
    if not is_root() and method != "arp":
        sys.stdout.write("\nnote: run with sudo for an ARP sweep - it finds hosts that "
                         "ignore ping and firewall every port.\n")
    return 0


# --- scan ------------------------------------------------------------------

def cmd_scan(args):
    hosts = parse_targets(args.target)
    ports = parse_ports(args.ports)
    proto = "udp" if args.udp else "tcp"
    if not args.json:
        sys.stdout.write("scanning %d host(s) x %d %s port(s)...\n"
                         % (len(hosts), len(ports), proto))

    def progress(done, total):
        if not args.json and args.progress:
            pct = 100.0 * done / total
            sys.stderr.write("\r  %d/%d (%.0f%%)" % (done, total, pct))
            sys.stderr.flush()
            if done == total:
                sys.stderr.write("\n")

    started = time.time()
    results = portscan.scan(hosts, ports, proto=proto, timeout=args.timeout,
                            workers=args.workers, banner=args.banner,
                            open_only=not args.all_states, progress=progress)
    elapsed = time.time() - started
    if args.json:
        _emit_json({"target": args.target, "proto": proto, "hosts": len(hosts),
                    "ports": len(ports), "seconds": round(elapsed, 2), "results": results})
        return 0
    if args.csv:
        writer = csv.DictWriter(sys.stdout,
                                fieldnames=["host", "port", "proto", "state", "service",
                                            "detail"])
        writer.writeheader()
        writer.writerows(results)
        return 0
    by_host = portscan.summarize(results)
    for host in sorted(by_host, key=lambda h: tuple(int(p) for p in h.split(".")
                                                    if p.isdigit()) or (0,)):
        section("%s" % host)
        table([[r["port"], r["proto"], r["state"], r["service"], r["detail"]]
               for r in by_host[host]], ["port", "proto", "state", "service", "detail"])
    open_count = sum(1 for r in results if r["state"].startswith("open"))
    sys.stdout.write("\n%d open port(s) across %d host(s) in %.1fs\n"
                     % (open_count, len(by_host), elapsed))
    if not by_host:
        sys.stdout.write("no open ports found (closed and filtered ports are hidden; "
                         "use --all-states to see them)\n")
    return 0


# --- lldp ------------------------------------------------------------------

def cmd_lldp(args):
    if args.from_pcap:
        neighbors = lldpmod.from_pcap(args.from_pcap)
    else:
        def on_neighbor(n):
            if not args.json:
                sys.stdout.write("\n" + lldpmod.describe(n) + "\n")
                sys.stdout.flush()
        if not args.json:
            sys.stdout.write("listening for LLDP/CDP on %s for up to %ds "
                             "(switches announce every 30-60s)...\n"
                             % (args.interface or ifmod.primary_interface(), args.timeout))
        neighbors = lldpmod.listen(args.interface, timeout=args.timeout,
                                   stop_after=0 if args.wait_all else 1,
                                   save_pcap=args.pcap, on_neighbor=on_neighbor)
    if args.json:
        _emit_json({"neighbors": neighbors})
        return 0
    if not neighbors:
        sys.stdout.write("\nNo LLDP or CDP frames seen.\n"
                         "  - the switch port may have LLDP/CDP disabled\n"
                         "  - you may be behind an unmanaged switch or a hypervisor bridge\n"
                         "  - try a longer window: nettool lldp -t 120\n")
        return 1
    if args.from_pcap:
        for n in neighbors:
            sys.stdout.write("\n" + lldpmod.describe(n) + "\n")
    section("summary")
    table([[n.get("protocol"), n.get("system_name") or n.get("chassis_id"),
            n.get("port_id"), n.get("port_vlan_id", ""), n.get("mgmt_addrs") and
            n["mgmt_addrs"][0]["address"] or ""] for n in neighbors],
          ["proto", "neighbour", "port", "vlan", "mgmt ip"])
    if args.pcap:
        sys.stdout.write("\nframes saved to %s\n" % args.pcap)
    return 0


# --- capture ---------------------------------------------------------------

def cmd_capture(args):
    stats = capmod.live_capture(
        ifname=args.interface, count=args.count, duration=args.duration,
        snaplen=args.snaplen, outfile=args.write, filter_expr=args.filter,
        promisc=not args.no_promisc, show=not args.quiet and not args.write_only,
        quiet=args.json, monitor=args.monitor)
    if getattr(stats, "wireless", False):
        report = stats.survey.report()
        report["file"] = args.write
        if args.json:
            _emit_json(report)
            return 0
        render_wireless(report)
        return 0
    if args.json:
        _emit_json({
            "packets": stats.packets, "bytes": stats.bytes,
            "kernel_dropped": getattr(stats, "kernel_dropped", None),
            "protocols": dict(stats.protos), "top_talkers": dict(stats.talkers.most_common(20)),
            "conversations": dict(stats.conversations.most_common(20)),
            "vlans": dict(stats.vlans), "file": args.write,
        })
        return 0
    stats.report()
    return 0


def cmd_pcap(args):
    stats = capmod.read_pcap(args.file, filter_expr=args.filter, show=args.print_packets,
                             limit=args.limit, outfile=args.write)
    if isinstance(stats, dot11.Survey):
        report = stats.report()
        report["file"] = args.file
        if args.json:
            _emit_json(report)
            return 0
        render_wireless(report)
        return 0
    if args.json:
        _emit_json({"file": args.file, "packets": stats.packets, "bytes": stats.bytes,
                    "protocols": dict(stats.protos),
                    "top_talkers": dict(stats.talkers.most_common(20)),
                    "conversations": dict(stats.conversations.most_common(20))})
        return 0
    stats.report()
    return 0


def render_wireless(report, sink=None):
    """Render a monitor-mode capture: who is on the air, and what is going wrong."""
    sink = sink or sys.stdout
    section("wireless capture summary")
    table([["frames", report["frames"]],
           ["duration", widgets_secs(report["duration"])],
           ["retransmissions", "%.1f%%" % report["retry_pct"]],
           ["failed checksums", report["bad_fcs"]],
           ["access points", len(report["access_points"])],
           ["clients", len(report["clients"])]],
          ["field", "value"], sink)

    if report["access_points"]:
        section("access points")
        table([[ap["ssid"] or "(hidden)", ap["bssid"], ap.get("band", ""), ap.get("channel", ""),
                "" if ap["signal_dbm"] is None else "%.0f" % ap["signal_dbm"],
                ap["beacons"],
                "" if ap.get("utilization_pct") is None else "%.0f%%" % ap["utilization_pct"],
                "" if ap.get("stations") is None else ap["stations"],
                ",".join(ap.get("standards") or []),
                ",".join(ap.get("security") or []),
                ap.get("vendor", "")]
               for ap in report["access_points"]],
              ["ssid", "bssid", "band", "ch", "dBm", "beacons", "util", "sta", "std",
               "security", "vendor"], sink)

    if report["clients"]:
        section("clients")
        table([[client["mac"], client.get("vendor", ""), client["frames"],
                "%.0f%%" % client["retry_pct"],
                "" if client["signal_dbm"] is None else "%.0f" % client["signal_dbm"],
                ", ".join(client["bssids"][:2]),
                ", ".join(client["probes"][:3])]
               for client in report["clients"][:25]],
              ["mac", "vendor", "frames", "retry", "dBm", "bssid", "probing for"], sink)

    if report["channels"]:
        section("channels")
        table([[channel, data["frames"], data["bssids"]]
               for channel, data in sorted(report["channels"].items())],
              ["ch", "frames", "bssids"], sink)

    if report["deauths"]:
        section("deauthentication / disassociation")
        table([[entry["subtype"], entry["src"], entry["dst"], entry["reason"], entry["count"]]
               for entry in report["deauths"]],
              ["frame", "from", "to", "reason", "count"], sink)

    if report["frame_types"]:
        section("frame mix")
        table([[name, count] for name, count in list(report["frame_types"].items())[:12]],
              ["frame", "count"], sink)

    section("findings")
    for level, message in report["findings"]:
        sink.write("  %s %s\n" % (SEV_MARK.get(level, "[    ]"), message))


def widgets_secs(seconds):
    if seconds < 60:
        return "%.1f s" % seconds
    return "%dm %02ds" % (int(seconds) // 60, int(seconds) % 60)


# --- analyze ---------------------------------------------------------------

CONVERSATION_KINDS = ["tcp", "udp", "ip", "ipv6", "ethernet"]


def _sparkline(values):
    """A one-line throughput graph, so the shape of the traffic is visible in a terminal."""
    if not values:
        return ""
    blocks = " .:-=+*#%@"
    peak = max(values) or 1
    return "".join(blocks[min(len(blocks) - 1, int(value * (len(blocks) - 1) / peak))]
                   for value in values)


def render_analysis(report, top=20, kinds=None, sink=None):
    sink = sink or sys.stdout
    section("capture")
    table([["packets", report["packets"]],
           ["bytes", human_bytes(report["bytes"])],
           ["duration", widgets_secs(report["duration"])],
           ["average rate", "%s/s" % human_bytes(
               report["bytes"] / report["duration"]) if report["duration"] else "-"]],
          ["field", "value"], sink)

    section("protocol hierarchy")
    table([[entry["layers"], entry["packets"], "%.1f%%" % entry["packets_pct"],
            human_bytes(entry["bytes"]), "%.1f%%" % entry["bytes_pct"]]
           for entry in report["hierarchy"][:15]],
          ["layers", "packets", "of packets", "bytes", "of bytes"], sink)

    for kind in (kinds or ["tcp", "udp", "ip"]):
        conversations = report["conversations"].get(kind) or []
        if not conversations:
            continue
        section("%s conversations" % kind.upper())
        table([[conversation["a"], conversation["b"],
                conversation["packets_ab"], human_bytes(conversation["bytes_ab"]),
                conversation["packets_ba"], human_bytes(conversation["bytes_ba"]),
                human_bytes(conversation["bytes"]),
                "%.2fs" % conversation["duration"],
                "%.0f" % conversation["bps_ab"], "%.0f" % conversation["bps_ba"]]
               for conversation in conversations[:top]],
              ["address A", "address B", "A->B", "bytes A->B", "B->A", "bytes B->A",
               "total", "duration", "bps A->B", "bps B->A"], sink)

    section("endpoints")
    table([[endpoint["address"], endpoint["packets"], human_bytes(endpoint["bytes"]),
            endpoint["packets_tx"], human_bytes(endpoint["bytes_tx"]),
            endpoint["packets_rx"], human_bytes(endpoint["bytes_rx"]),
            endpoint["peers"],
            ",".join(str(port) for port in endpoint["top_ports"])]
           for endpoint in report["endpoints"][:top]],
          ["address", "packets", "bytes", "tx", "bytes tx", "rx", "bytes rx", "peers",
           "ports"], sink)

    tcp = report["tcp"]
    if tcp["segments"]:
        section("tcp health")
        table([["segments / flows", "%d / %d" % (tcp["segments"], tcp["flows"])],
               ["completed handshakes", "%d of %d SYNs"
                % (tcp["completed_handshakes"], tcp["syns"])],
               ["handshake time", "avg %s ms, max %s ms"
                % (tcp["handshake_ms_avg"], tcp["handshake_ms_max"])],
               ["retransmissions", "%d (%.2f%%)"
                % (tcp["retransmissions"], tcp["retransmission_pct"])],
               ["out of order", tcp["out_of_order"]],
               ["duplicate acks", tcp["duplicate_acks"]],
               ["zero window", tcp["zero_window"]],
               ["resets", tcp["resets"]]],
              ["field", "value"], sink)

    dns = report["dns"]
    if dns["queries"]:
        section("dns")
        table([["queries", dns["queries"]],
               ["answered / unanswered", "%d / %d" % (dns["answered"], dns["unanswered"])],
               ["response time", "avg %s ms, max %s ms"
                % (dns["latency_ms_avg"], dns["latency_ms_max"])],
               ["slowest", ", ".join("%s (%.0f ms)" % (entry["name"], entry["ms"])
                                     for entry in dns["slowest"][:3])],
               ["failures", ", ".join(dns["failures"]) or "none"]],
              ["field", "value"], sink)

    if report["vlans"]:
        section("vlans")
        table([[vlan, count] for vlan, count in report["vlans"].items()],
              ["vlan", "packets"], sink)

    throughput = report["throughput"]
    if len(throughput) > 2:
        section("throughput over time")
        rates = [entry["bps"] for entry in throughput]
        sink.write("  %s\n" % _sparkline(rates))
        end_label = "%.0fs" % throughput[-1]["t"]
        padding = max(1, len(rates) - 2 - len(end_label))
        sink.write("  0s%s%s   peak %s/s\n" % (" " * padding, end_label,
                                               human_bytes(max(rates) / 8)))

    section("findings")
    for level, message in report["findings"]:
        sink.write("  %s %s\n" % (SEV_MARK.get(level, "[    ]"), message))


def cmd_analyze(args):
    if args.follow is not None:
        conversation, chunks = analyzemod.follow_stream(
            args.file, index=args.follow, kind=args.stream_kind)
        if args.json:
            _emit_json({
                "conversation": conversation,
                "bytes": sum(len(payload) for _direction, payload in chunks),
                "stream": analyzemod.format_stream(chunks, as_hex=args.hex),
            })
            return 0
        section("stream %d: %s <-> %s" % (args.follow, conversation["a"], conversation["b"]))
        sys.stdout.write("-> is %s, <- is %s\n\n" % (conversation["a"], conversation["b"]))
        sys.stdout.write(analyzemod.format_stream(chunks, as_hex=args.hex) + "\n")
        return 0

    analysis = analyzemod.analyze_pcap(args.file, filter_expr=args.filter,
                                       bucket_seconds=args.bucket)
    report = analysis.report(top=args.top)
    if args.json:
        _emit_json(report)
        return 0
    kinds = [args.conversations] if args.conversations else None
    render_analysis(report, top=args.top, kinds=kinds)
    return 0


# --- mirror ----------------------------------------------------------------

def render_mirror(report, verbose=False, sink=None):
    """Render a mirror capture: what is on each VLAN, and whether the mirror is sane."""
    sink = sink or sys.stdout
    section("mirror capture")
    table([["frames", report["packets"]],
           ["bytes", human_bytes(report["bytes"])],
           ["duration", widgets_secs(report["duration"])],
           ["tagged / untagged", "%d / %d" % (report["tagged"], report["untagged"])],
           ["double-tagged (QinQ)", report["qinq"]],
           ["from other devices", report["foreign_traffic"]],
           ["this machine's own", report["own_traffic"]],
           ["both directions seen",
            "-" if report["bidirectional_share"] is None
            else "%.0f%% of conversations" % (report["bidirectional_share"] * 100)],
           ["dropped by kernel", report["kernel_dropped"]]],
          ["field", "value"], sink)

    if report["vlans"]:
        section("VLANs")
        rows = []
        for vlan in report["vlans"]:
            protocols = ", ".join(list(vlan["protocols"])[:3])
            talker = next(iter(vlan["top_talkers"]), "")
            rows.append([
                "untagged" if vlan["vlan"] is None else vlan["vlan"],
                vlan["packets"], human_bytes(vlan["bytes"]),
                vlan["unique_hosts"], vlan["unique_macs"],
                "%.0f%%" % (100.0 * vlan["broadcast"] / vlan["packets"])
                if vlan["packets"] else "0%",
                protocols, talker,
                ", ".join(vlan["dhcp_servers"][:2]),
            ])
        table(rows, ["vlan", "frames", "bytes", "hosts", "macs", "bcast", "protocols",
                     "top talker", "dhcp"], sink)

    if verbose:
        for vlan in report["vlans"]:
            label = "untagged" if vlan["vlan"] is None else "VLAN %d" % vlan["vlan"]
            section("%s - hosts" % label)
            table([[host["ip"], host["mac"], host["vendor"]] for host in vlan["hosts"][:50]],
                  ["ip", "mac", "vendor"], sink)
            if vlan["conversations"]:
                section("%s - conversations" % label)
                table([[pair, human_bytes(count)]
                       for pair, count in list(vlan["conversations"].items())[:10]],
                      ["pair", "bytes"], sink)

    if report.get("files"):
        section("files written")
        table([[entry["file"], entry["packets"], human_bytes(entry["bytes"])]
               for entry in report["files"]], ["file", "packets", "bytes"], sink)

    section("findings")
    for level, message in report["findings"]:
        sink.write("  %s %s\n" % (SEV_MARK.get(level, "[    ]"), message))


def render_plan(plan, sink=None):
    sink = sink or sys.stdout
    section("mirror plan")
    rows = [["switch", plan["switch"] or "(unknown - no LLDP/CDP neighbour)"],
            ["platform", plan["vendor"]],
            ["management ip", plan["management_ip"] or "-"],
            ["mirror destination", plan["destination_port"] or "(this machine's port)"],
            ["native vlan", plan["native_vlan"] if plan["native_vlan"] else "-"]]
    if plan["source_vlan"]:
        rows.append(["mirror source", "VLAN %s" % plan["source_vlan"]])
    elif plan["source_port"]:
        rows.append(["mirror source", plan["source_port"]])
    table(rows, ["field", "value"], sink)
    section("switch configuration")
    sink.write(plan["config"] + "\n")
    sink.write("\nReview this before pasting it: a mirror destination port stops "
               "forwarding normal traffic.\n")


def cmd_mirror(args):
    if args.split and not args.write:
        raise NetToolError("--split needs --write to name the per-VLAN files")
    if args.rotate and not args.write:
        raise NetToolError("--rotate needs --write to name the files")
    vlans = []
    if args.vlan:
        for chunk in args.vlan:
            for part in str(chunk).split(","):
                part = part.strip()
                if part:
                    vlans.append(int(part))

    if args.plan:
        neighbor = {}
        if not args.no_listen:
            if not args.json:
                sys.stdout.write("listening for LLDP/CDP to identify the switch "
                                 "(up to %ds)...\n" % args.wait)
            neighbors = lldpmod.listen(args.interface, timeout=args.wait, stop_after=1)
            if neighbors:
                neighbor = neighbors[0]
            elif not args.json:
                sys.stdout.write("no neighbour seen; falling back to a generic plan\n")
        plan = mirrormod.plan(neighbor, source_vlan=vlans[0] if vlans else None,
                              source_port=args.source_port, vendor=args.vendor,
                              session=args.session)
        if args.json:
            _emit_json(plan)
        else:
            render_plan(plan)
        return 0

    if args.from_pcap:
        survey = mirrormod.survey_pcap(args.from_pcap, vlans=vlans or None)
        report = survey.report()
        report["files"] = []
    else:
        duration = args.duration
        if args.check and not duration:
            duration = 10
        survey = mirrormod.capture(
            ifname=args.interface, vlans=vlans or None, duration=duration,
            count=args.count, snaplen=args.snaplen, outfile=args.write,
            split=args.split, include_untagged=args.untagged, rotate_mb=args.rotate,
            show=args.print_packets, quiet=args.json)
        report = survey.report()
        report["files"] = getattr(survey, "files", [])
        report["interface"] = getattr(survey, "interface", "")
        report["kernel_filtered"] = getattr(survey, "kernel_filtered", False)

    if args.json:
        _emit_json(report)
    else:
        render_mirror(report, verbose=args.verbose)
    worst = max((level for level, _ in report["findings"]),
                key=lambda level: {"ok": 0, "info": 1, "warn": 2, "critical": 3}.get(level, 0),
                default="ok")
    return 1 if worst == "critical" else 0


# --- wifi ------------------------------------------------------------------

def _ssid_label(net):
    """A network's name, or why we do not have one."""
    if net.get("ssid"):
        return net["ssid"]
    return "(hidden by macOS)" if net.get("redacted") else "(hidden)"


def _hidden_names_note(networks, current=None):
    """Explain blanked names once, if anything in this result was blanked."""
    if not (current or {}).get("redacted") and not any(n.get("redacted") for n in networks):
        return
    sys.stdout.write("\nnote: %s\n" % wifimod.HIDDEN_NAMES_HINT)


def _wifi_scan_rows(networks, sort_by):
    if sort_by == "signal":
        networks = sorted(networks, key=lambda n: n["signal_dbm"] or -999, reverse=True)
    elif sort_by == "channel":
        networks = sorted(networks, key=lambda n: (n.get("band") or "", n.get("channel") or 0))
    else:
        networks = sorted(networks, key=lambda n: (n.get("ssid") or "").lower())
    rows = []
    for n in networks:
        rows.append([
            _ssid_label(n), n.get("bssid", ""), n.get("band", ""),
            n.get("channel", ""), "%.0f" % n["signal_dbm"] if n.get("signal_dbm") is not None else "",
            n.get("quality_pct", ""), n.get("rating", ""),
            "%d" % n["width_mhz"] if n.get("width_mhz") else "",
            "" if n.get("utilization_pct") is None else "%.0f%%" % n["utilization_pct"],
            "" if n.get("stations") is None else n["stations"],
            ",".join(n.get("standards") or []), ",".join(n.get("security") or []),
        ])
    return rows


def cmd_wifi_scan(args):
    networks, source = wifimod.scan(args.interface, use_cache=args.cached)
    if args.json:
        _emit_json({"source": source, "networks": networks})
        return 0
    section("nearby networks (%d BSS via %s)" % (len(networks), source))
    table(_wifi_scan_rows(networks, args.sort),
          ["ssid", "bssid", "band", "ch", "dBm", "qual%", "rating", "width",
           "util", "sta", "std", "security"])
    _hidden_names_note(networks)
    return 0


def cmd_wifi_link(args):
    state = wifimod.link(args.interface)
    if args.json:
        _emit_json(state)
        return 0
    if not state.get("connected") and state.get("signal_dbm") is None:
        sys.stdout.write("%s is not associated with any network.\n" % state["interface"])
        return 1
    section("association on %s" % state["interface"])
    rows = [
        ["ssid", _ssid_label(state)],
        ["bssid", state.get("bssid", "") or ("(hidden by macOS)"
                                             if state.get("redacted") else "")],
        ["band / channel", "%s GHz / %s" % (state.get("band", "?"), state.get("channel", "?"))],
        ["frequency", "%s MHz" % state.get("freq", "?")],
        ["signal", "%s dBm (%s, %s%%)" % (state.get("signal_dbm"), state.get("rating"),
                                          state.get("quality_pct"))],
        ["noise", "%s dBm" % state.get("noise_dbm", "?")],
        ["snr", "%s dB" % state.get("snr_db", "?")],
        ["tx bitrate", state.get("tx_bitrate", "")],
        ["rx bitrate", state.get("rx_bitrate", "")],
    ]
    station = state.get("station") or {}
    if station:
        rows += [
            ["tx retries", "%s (%s%%)" % (station.get("tx_retries", "?"),
                                          station.get("retry_pct", "?"))],
            ["tx failed", "%s (%s%%)" % (station.get("tx_failed", "?"),
                                         station.get("fail_pct", "?"))],
            ["connected for", "%ss" % station.get("connected_time", "?")],
        ]
    proc = state.get("proc") or {}
    if proc:
        rows += [["missed beacons", proc.get("missed_beacons")],
                 ["rx crypt errors", proc.get("rx_invalid_crypt")]]
    table(rows, ["field", "value"])
    _hidden_names_note([], state)
    return 0


def cmd_wifi_permission(args):
    """Show, and optionally ask for, the macOS grant that unhides network names."""
    if sys.platform != "darwin":
        raise NetToolError("Location Services is a macOS concept; nothing to grant here")
    from . import maclocation

    try:
        enabled = maclocation.services_enabled()
        if args.request:
            code, name = maclocation.request(timeout=args.timeout)
        else:
            code, name = maclocation.status()
    except maclocation.LocationError as exc:
        raise NetToolError(str(exc))

    granted = code in maclocation.GRANTED
    if args.json:
        _emit_json({"services_enabled": enabled, "status": code, "status_name": name,
                    "granted": granted})
        return 0

    section("location services")
    table([["system-wide", "on" if enabled else "off"],
           ["this app", name],
           ["network names", "visible" if granted else "hidden"]],
          ["field", "value"])
    if granted:
        sys.stdout.write("\nNetwork names are visible to whatever launched nettool.\n")
        return 0
    if not enabled:
        sys.stdout.write("\nLocation Services is off system-wide. Turn it on in System "
                         "Settings > Privacy & Security > Location Services first.\n")
        return 1
    if code == 0 and not args.request:
        sys.stdout.write("\nmacOS has never asked. Run `wifi permission --request` to "
                         "make it ask - the prompt is attributed to whatever launched "
                         "nettool (your terminal, or nettool.app).\n")
        return 1
    if code == 2:
        sys.stdout.write("\nPermission was refused earlier, so macOS will not ask again. "
                         "Turn it back on in System Settings > Privacy & Security > "
                         "Location Services.\n")
        return 1
    sys.stdout.write("\n%s\n" % wifimod.HIDDEN_NAMES_HINT)
    return 1


def cmd_wifi_survey(args):
    surveys = wifimod.survey_dump(args.interface)
    if args.json:
        _emit_json({"survey": surveys})
        return 0
    section("channel airtime survey")
    rows = []
    for s in sorted(surveys, key=lambda x: x.get("freq") or 0):
        if "active_time" not in s:
            continue
        rows.append([s.get("channel", "?"), s.get("freq", "?"), s.get("band", ""),
                     "yes" if s.get("in_use") else "",
                     s.get("noise_dbm", ""),
                     "%.0f%%" % s.get("busy_pct", 0),
                     "%.0f%%" % s.get("rx_pct", 0), "%.0f%%" % s.get("tx_pct", 0),
                     "%.0f%%" % s.get("interference_pct", 0)])
    table(rows, ["ch", "freq", "band", "in use", "noise", "busy", "our rx", "our tx",
                 "other"])
    sys.stdout.write("\n'other' is airtime the radio saw as busy but could not attribute "
                     "to our own traffic:\nnon-Wi-Fi interference (microwaves, cameras, "
                     "cordless phones) or distant co-channel APs.\n")
    return 0


def cmd_wifi_monitor(args):
    if not args.json:
        sys.stdout.write("sampling %s every %.1fs for %ds...\n"
                         % (args.interface or "wifi", args.interval, args.duration))

    def on_sample(s):
        if args.json:
            return
        sys.stdout.write("  %s  %s dBm  ch %s  %s\n" % (
            time.strftime("%H:%M:%S"), s.get("signal_dbm"), s.get("channel"),
            s.get("tx_bitrate", "")))
        sys.stdout.flush()

    result = wifimod.monitor(args.interface, duration=args.duration,
                             interval=args.interval, on_sample=on_sample)
    if args.json:
        _emit_json(result)
        return 0
    section("link stability over %ds" % args.duration)
    table([["samples", result["count"]],
           ["signal avg", "%s dBm (%s)" % (result.get("signal_avg"), result.get("rating"))],
           ["signal min/max", "%s / %s dBm" % (result.get("signal_min"),
                                               result.get("signal_max"))],
           ["swing", "%s dB" % result.get("signal_swing")],
           ["std deviation", result.get("stdev")],
           ["roamed to another AP", "yes" if result.get("roamed") else "no"],
           ["bssids seen", ", ".join(result.get("bssids") or [])],
           ["missed beacons", result.get("missed_beacons_delta")]],
          ["field", "value"])
    swing = result.get("signal_swing") or 0
    if swing > 15:
        sys.stdout.write("\nsignal swings by %.0f dB - multipath, movement or a "
                         "duty-cycled interferer.\n" % swing)
    return 0


def cmd_wifi_analyze(args):
    networks, source = wifimod.scan(args.interface, use_cache=args.cached)
    current = wifimod.link(args.interface)
    try:
        survey = wifimod.survey_dump(args.interface)
    except NetToolError:
        survey = []
    report = wifimod.analyze(networks, current, survey)
    if args.json:
        _emit_json({"source": source, "report": report, "networks": networks,
                    "current": current, "survey": survey})
        return 0
    section("radio environment (%d BSS via %s)" % (len(networks), source))
    for band in sorted(report["bands"]):
        band_report = report["bands"][band]
        sys.stdout.write("\n%s GHz - %d BSS\n" % (band, band_report["bss_count"]))
        rows = []
        for ch in sorted(band_report["channels"]):
            info = band_report["channels"][ch]
            rows.append([ch, info["bss"], info["overlapping"],
                         info["strongest_dbm"], info["strongest_ssid"],
                         "" if info["utilization_pct"] is None
                         else "%.0f%%" % info["utilization_pct"],
                         band_report["congestion_score"].get(ch, "")])
        table(rows, ["ch", "bss", "overlapping", "strongest", "ssid", "util", "load score"])
        if band_report.get("best_channel"):
            sys.stdout.write("  suggested channel: %d (load score %.2f)%s\n"
                             % (band_report["best_channel"], band_report["best_score"],
                                "" if band != "2.4" else " - only 1/6/11 avoid overlap"))
    if current.get("connected"):
        section("your link")
        sys.stdout.write("  %s on ch %s, %s dBm (%s)%s\n" % (
            _ssid_label(current), current.get("channel"), current.get("signal_dbm"),
            current.get("rating"),
            ", SNR %s dB" % current["snr_db"] if current.get("snr_db") else ""))
    section("findings")
    for level, message in report["findings"]:
        sys.stdout.write("  %s %s\n" % (SEV_MARK.get(level, "[    ]"), message))
    return 0


# --- ping / trace / mtu ----------------------------------------------------

def cmd_ping(args):
    stats = pingmod.ping(args.host, count=args.count, interval=args.interval,
                         timeout=args.timeout, size=args.size,
                         quiet=args.json, sink=sys.stdout)
    if args.json:
        _emit_json({k: v for k, v in stats.items() if k != "rtts"})
        return 0
    sys.stdout.write("\n--- %s (%s) ---\n" % (stats["host"], stats["address"]))
    sys.stdout.write("%d sent, %d received, %.0f%% loss\n"
                     % (stats["sent"], stats["received"], stats["loss_pct"]))
    if stats["received"]:
        sys.stdout.write("rtt min/avg/max = %.2f/%.2f/%.2f ms, jitter %.2f ms\n"
                         % (stats["rtt_min"], stats["rtt_avg"], stats["rtt_max"],
                            stats["jitter"] or 0.0))
    for err in stats["errors"]:
        sys.stdout.write("error: %s\n" % err)
    return 0 if stats["received"] else 1


def cmd_trace(args):
    hops = pingmod.traceroute(args.host, max_hops=args.max_hops, probes=args.probes,
                              timeout=args.timeout, resolve=not args.no_resolve,
                              sink=None if args.json else sys.stdout)
    if args.json:
        _emit_json({"host": args.host, "hops": hops})
    return 0


def cmd_mtu(args):
    result = pingmod.path_mtu(args.host, low=args.low, high=args.high)
    if args.json:
        _emit_json(result)
        return 0
    if result["mtu"] is None:
        sys.stdout.write("path MTU to %s: unknown - %s\n" % (args.host, result["note"]))
        return 1
    sys.stdout.write("path MTU to %s (%s): %d bytes\n"
                     % (args.host, result["address"], result["mtu"]))
    if result["mtu"] < 1500:
        sys.stdout.write("that is below the 1500-byte Ethernet default: a tunnel, VPN or "
                         "PPPoE link is in the path.\n")
    return 0


# --- diag ------------------------------------------------------------------

def cmd_diag(args):
    report = diagmod.run(args.interface, skip=set(args.skip or ()))
    if args.json:
        _emit_json({"verdict": report.verdict(), "worst": report.worst(),
                    "checks": report.checks, "data": report.data})
        return 0 if report.worst() != "critical" else 1
    section("network health check")
    for check in report.checks:
        sys.stdout.write("  %s %-9s %s\n" % (SEV_MARK.get(check["severity"], "[    ]"),
                                             check["check"], check["message"]))
    sys.stdout.write("\n%s\n" % report.verdict())
    if not is_root():
        sys.stdout.write("(running unprivileged - re-run with sudo for ARP, MTU and "
                         "capture checks)\n")
    return 0 if report.worst() != "critical" else 1


# --- parser ----------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="nettool",
        description="Field network diagnostics: LAN discovery, port scanning, LLDP/CDP "
                    "neighbours, packet capture export and Wi-Fi interference analysis.",
        epilog="Most commands accept --json for scripting. Raw-socket features "
               "(capture, lldp, arp sweep, ping, mtu) need root or CAP_NET_RAW.")
    parser.add_argument("--version", action="version", version="nettool %s" % __version__)
    sub = parser.add_subparsers(dest="command")

    def add_json(p):
        p.add_argument("--json", action="store_true", help="emit machine-readable JSON")
        return p

    p = add_json(sub.add_parser("iface", help="list interfaces, addresses, routes, DNS"))
    p.add_argument("name", nargs="?", help="only this interface")
    p.add_argument("-a", "--all", action="store_true", help="include down interfaces")
    p.add_argument("-v", "--verbose", action="store_true", help="also show IPv6 and ARP")
    p.add_argument("--capturable", action="store_true",
                   help="list only the interfaces a capture can actually attach to "
                        "(needs root or BPF access)")
    p.set_defaults(func=cmd_iface)

    p = add_json(sub.add_parser("discover", help="find live hosts on the LAN"))
    p.add_argument("-i", "--interface")
    p.add_argument("-c", "--cidr", help="subnet to sweep (default: this interface's)")
    p.add_argument("-m", "--method", choices=["auto", "arp", "icmp", "tcp"], default="auto")
    p.add_argument("-t", "--timeout", type=float, default=3.0,
                   help="seconds to wait for ARP replies (default 3)")
    p.add_argument("--no-resolve", action="store_true", help="skip reverse DNS")
    p.add_argument("--no-progress", dest="progress", action="store_false", default=True)
    p.set_defaults(func=cmd_discover)

    p = add_json(sub.add_parser("scan", help="TCP/UDP port scan"))
    p.add_argument("target", help="IP, hostname, CIDR (10.0.0.0/24) or range (10.0.0.1-50)")
    p.add_argument("-p", "--ports", default="top",
                   help="ports: 'top' (default), 'all', '22,80,443' or '1-1024'")
    p.add_argument("-u", "--udp", action="store_true", help="UDP probe scan instead of TCP")
    p.add_argument("-t", "--timeout", type=float, default=1.0)
    p.add_argument("-w", "--workers", type=int, default=256, help="parallel probes")
    p.add_argument("-b", "--banner", action="store_true",
                   help="grab service banners / TLS versions from open ports")
    p.add_argument("--all-states", action="store_true",
                   help="also report closed and filtered ports")
    p.add_argument("--csv", action="store_true", help="CSV output")
    p.add_argument("--no-progress", dest="progress", action="store_false", default=True)
    p.set_defaults(func=cmd_scan)

    p = add_json(sub.add_parser("lldp", help="LLDP/CDP neighbours: which switch port am I on?"))
    p.add_argument("-i", "--interface")
    p.add_argument("-t", "--timeout", type=int, default=65,
                   help="listen window in seconds (default 65; LLDP repeats every 30)")
    p.add_argument("--wait-all", action="store_true",
                   help="keep listening for the whole window instead of stopping at the "
                        "first neighbour")
    p.add_argument("--pcap", metavar="FILE", help="also save the frames to a pcap file")
    p.add_argument("--from-pcap", metavar="FILE", help="parse neighbours out of a capture")
    p.set_defaults(func=cmd_lldp)

    p = add_json(sub.add_parser("capture", help="capture packets and export a pcap file"))
    p.add_argument("-i", "--interface")
    p.add_argument("-w", "--write", metavar="FILE", help="write packets to FILE (pcap)")
    p.add_argument("-c", "--count", type=int, default=0, help="stop after N packets")
    p.add_argument("-d", "--duration", type=float, default=0, help="stop after N seconds")
    p.add_argument("-s", "--snaplen", type=int, default=65535,
                   help="bytes captured per packet (use 96 for headers only)")
    p.add_argument("-f", "--filter", help="filter, e.g. 'tcp and port 443', 'host 10.0.0.5'")
    p.add_argument("-q", "--quiet", action="store_true", help="do not print each packet")
    p.add_argument("--write-only", action="store_true",
                   help="write to file without printing packets")
    p.add_argument("--no-promisc", action="store_true",
                   help="do not put the interface in promiscuous mode")
    p.add_argument("-M", "--monitor", action="store_true",
                   help="capture 802.11 frames off the air (macOS: switches the Wi-Fi "
                        "radio to monitor mode and drops the association)")
    p.set_defaults(func=cmd_capture)

    p = add_json(sub.add_parser(
        "analyze", help="Wireshark-style analysis of a capture: conversations, endpoints, "
                        "protocol hierarchy, TCP health, DNS timing"))
    p.add_argument("file")
    p.add_argument("-f", "--filter", help="only analyse packets matching this filter")
    p.add_argument("-n", "--top", type=int, default=20, help="rows per table (default 20)")
    p.add_argument("-c", "--conversations", choices=CONVERSATION_KINDS,
                   help="show only this conversation table")
    p.add_argument("--bucket", type=float, default=1.0,
                   help="seconds per throughput bucket (default 1)")
    p.add_argument("--follow", type=int, metavar="N",
                   help="reassemble conversation N (0 is the busiest) and print its payload")
    p.add_argument("--stream-kind", choices=["tcp", "udp"], default="tcp",
                   help="which conversation table --follow indexes into")
    p.add_argument("--hex", action="store_true", help="hex dump the followed stream")
    p.set_defaults(func=cmd_analyze)

    p = add_json(sub.add_parser(
        "mirror", help="capture from a switch port mirror (SPAN) and report per VLAN"))
    p.add_argument("-i", "--interface", help="the interface plugged into the mirror port")
    p.add_argument("--vlan", action="append",
                   help="only this VLAN (repeatable, or 10,20,30) - filtered in the kernel")
    p.add_argument("--untagged", action="store_true",
                   help="also keep untagged frames when --vlan is used")
    p.add_argument("-d", "--duration", type=float, default=0, help="stop after N seconds")
    p.add_argument("-c", "--count", type=int, default=0, help="stop after N frames")
    p.add_argument("-s", "--snaplen", type=int, default=65535)
    p.add_argument("-w", "--write", metavar="FILE", help="write the frames to a pcap")
    p.add_argument("--split", action="store_true",
                   help="write one pcap per VLAN instead of a single file, named after "
                        "--write (span.pcap -> span-vlan30.pcap, span-vlan40.pcap, ...)")
    p.add_argument("--rotate", type=float, default=0, metavar="MB",
                   help="start a new file every MB megabytes")
    p.add_argument("-P", "--print", dest="print_packets", action="store_true",
                   help="print a line per frame")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="list the hosts and conversations on each VLAN")
    p.add_argument("--check", action="store_true",
                   help="short capture that only answers \"is this mirror working?\"")
    p.add_argument("--from-pcap", metavar="FILE",
                   help="analyse a mirror capture that was taken earlier")
    p.add_argument("--plan", action="store_true",
                   help="print the switch commands that set up the mirror")
    p.add_argument("--vendor", help="switch platform for --plan (cisco-ios, cisco-nxos, "
                                    "aruba-cx, aruba-procurve, juniper, mikrotik, "
                                    "ubiquiti, extreme)")
    p.add_argument("--source-port", help="the switch port to mirror, for --plan")
    p.add_argument("--session", type=int, default=1, help="mirror session number for --plan")
    p.add_argument("--wait", type=int, default=65,
                   help="how long --plan listens for LLDP/CDP")
    p.add_argument("--no-listen", action="store_true",
                   help="skip the LLDP listen in --plan")
    p.set_defaults(func=cmd_mirror)

    p = add_json(sub.add_parser("pcap", help="inspect, filter or split an existing pcap"))
    p.add_argument("file")
    p.add_argument("-f", "--filter", help="only count/keep packets matching this filter")
    p.add_argument("-w", "--write", metavar="FILE", help="write matching packets to FILE")
    p.add_argument("-P", "--print", dest="print_packets", action="store_true",
                   help="print a line per packet")
    p.add_argument("-n", "--limit", type=int, default=0, help="max lines to print")
    p.set_defaults(func=cmd_pcap)

    wifi_parser = sub.add_parser("wifi", help="wireless scanning and interference analysis")
    wifi_sub = wifi_parser.add_subparsers(dest="wifi_command")

    q = add_json(wifi_sub.add_parser("scan", help="list nearby networks"))
    q.add_argument("-i", "--interface")
    q.add_argument("--cached", action="store_true",
                   help="use the last scan results instead of triggering a new scan")
    q.add_argument("--sort", choices=["signal", "channel", "ssid"], default="signal")
    q.set_defaults(func=cmd_wifi_scan)

    q = add_json(wifi_sub.add_parser("link", help="current association quality"))
    q.add_argument("-i", "--interface")
    q.set_defaults(func=cmd_wifi_link)

    q = add_json(wifi_sub.add_parser("survey", help="per-channel airtime / noise survey"))
    q.add_argument("-i", "--interface")
    q.set_defaults(func=cmd_wifi_survey)

    q = add_json(wifi_sub.add_parser("monitor", help="watch signal quality over time"))
    q.add_argument("-i", "--interface")
    q.add_argument("-d", "--duration", type=int, default=30)
    q.add_argument("-n", "--interval", type=float, default=1.0)
    q.set_defaults(func=cmd_wifi_monitor)

    q = add_json(wifi_sub.add_parser("analyze",
                                     help="diagnose signal, congestion and interference"))
    q.add_argument("-i", "--interface")
    q.add_argument("--cached", action="store_true")
    q.set_defaults(func=cmd_wifi_analyze)

    q = add_json(wifi_sub.add_parser(
        "permission",
        help="macOS: show or request the Location Services grant that reveals "
             "network names"))
    q.add_argument("--request", action="store_true",
                   help="ask macOS for the permission (shows the system prompt)")
    q.add_argument("-t", "--timeout", type=float, default=15.0,
                   help="seconds to wait for an answer to the prompt")
    q.set_defaults(func=cmd_wifi_permission)
    wifi_parser.set_defaults(func=lambda a: (wifi_parser.print_help(), 0)[1],
                             wifi_command=None)

    p = add_json(sub.add_parser("ping", help="ICMP echo with loss and jitter stats"))
    p.add_argument("host")
    p.add_argument("-c", "--count", type=int, default=5)
    p.add_argument("-n", "--interval", dest="interval", type=float, default=0.5)
    p.add_argument("-t", "--timeout", type=float, default=1.0)
    p.add_argument("-s", "--size", type=int, default=32, help="payload bytes")
    p.set_defaults(func=cmd_ping)

    p = add_json(sub.add_parser("trace", help="ICMP traceroute"))
    p.add_argument("host")
    p.add_argument("-m", "--max-hops", type=int, default=30)
    p.add_argument("-q", "--probes", type=int, default=3)
    p.add_argument("-t", "--timeout", type=float, default=1.5)
    p.add_argument("--no-resolve", action="store_true")
    p.set_defaults(func=cmd_trace)

    p = add_json(sub.add_parser("mtu", help="discover the path MTU to a host"))
    p.add_argument("host")
    p.add_argument("--low", type=int, default=576)
    p.add_argument("--high", type=int, default=9000)
    p.set_defaults(func=cmd_mtu)

    p = add_json(sub.add_parser("diag", help="run the full health check"))
    p.add_argument("-i", "--interface")
    p.add_argument("--skip", action="append",
                   choices=["address", "gateway", "dns", "internet", "wifi", "mtu"],
                   help="skip a check (repeatable)")
    p.set_defaults(func=cmd_diag)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(args) or 0
    except NetToolError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
