#!/usr/bin/env python3
"""A stand-in for the nettool CLI that replays recorded JSON fixtures.

The GUI shells out to nettool, so pointing it at this script exercises every view with
realistic data on machines that have no Wi-Fi radio, no switch and no root:

    nettool-gui --nettool "python3 gui/fixtures/fake_nettool.py"

The fixtures in this directory were produced by the real tool.
"""

import json
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def emit(name):
    with open(os.path.join(HERE, name)) as fh:
        sys.stdout.write(fh.read())
    return 0


def main(argv):
    if not argv or argv[0] == "--version":
        print("nettool 0.1.0 (fixture replay)")
        return 0
    command = argv[0]
    rest = argv[1:]
    json_mode = "--json" in rest

    if command == "iface":
        return emit("iface.json")
    if command == "diag":
        return emit("diag.json")
    if command == "discover":
        return emit("discover.json")
    if command == "scan":
        return emit("scan.json")
    if command == "lldp":
        return emit("lldp.json")
    if command == "pcap":
        return emit("pcap.json")
    if command == "mirror":
        if "--plan" in rest:
            return emit("mirror_plan.json")
        return emit("mirror.json")
    if command == "ping":
        return emit("ping.json")
    if command == "capture":
        if json_mode:
            return emit("capture.json")
        return fake_capture(rest)
    if command == "wifi":
        sub = rest[0] if rest else "scan"
        if sub == "link":
            return wifi_link()
        return emit({"scan": "wifi_scan.json", "survey": "wifi_survey.json",
                     "analyze": "wifi_analyze.json"}.get(sub, "wifi_scan.json"))
    sys.stderr.write("error: fixture replay does not implement %r\n" % command)
    return 2


def wifi_link():
    """Jitter the signal a little so the live monitor chart has something to draw."""
    with open(os.path.join(HERE, "wifi_link.json")) as fh:
        link = json.load(fh)
    base = link.get("signal_dbm") or -55
    link["signal_dbm"] = round(base + random.uniform(-6, 4), 1)
    if link.get("noise_dbm"):
        link["snr_db"] = round(link["signal_dbm"] - link["noise_dbm"], 1)
    json.dump(link, sys.stdout)
    return 0


def fake_capture(argv):
    duration = 6.0
    for index, arg in enumerate(argv):
        if arg == "-d" and index + 1 < len(argv):
            duration = float(argv[index + 1])
    hosts = ["192.168.1.42", "192.168.1.1", "192.168.1.77", "1.1.1.1", "34.107.221.82"]
    print("capturing on eth0 (snaplen 65535, promisc)")
    print("stop with Ctrl-C")
    sys.stdout.flush()
    end = time.time() + min(duration, 600)
    count = 0
    while time.time() < end:
        src, dst = random.sample(hosts, 2)
        kind = random.choice(["tcp", "tcp", "udp", "arp"])
        stamp = time.strftime("%H:%M:%S")
        if kind == "tcp":
            print("%s IPv4 %s:%d > %s:%d [%s] seq=%d win=%d len=%d"
                  % (stamp, src, random.randint(32768, 60999), dst,
                     random.choice([443, 80, 22, 445]),
                     random.choice(["S", "A", "PA", "FA"]),
                     random.getrandbits(30), random.randint(64, 65535),
                     random.choice([0, 0, 517, 1400])))
        elif kind == "udp":
            print("%s IPv4 %s:%d > %s:53 UDP len=%d (DNS)"
                  % (stamp, src, random.randint(32768, 60999), dst, random.randint(30, 120)))
        else:
            print("%s ARP who-has %s tell %s" % (stamp, dst, src))
        count += 1
        sys.stdout.flush()
        time.sleep(0.08)
    print("\npackets: %d   bytes: %s   duration: %.0fs" % (count, count * 340, duration))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
