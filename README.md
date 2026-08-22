# nettool

A single-file-install, dependency-free network diagnostics CLI for Linux. It answers the
questions you actually have when a network is misbehaving:

* **What is on this LAN?** ARP/ICMP/TCP host discovery with MAC vendor lookup.
* **What is this host running?** Threaded TCP connect scan and UDP probe scan with banner grabbing.
* **Which switch port am I plugged into, and what VLAN is it?** LLDP and CDP neighbour decoding
  (system name, port, native VLAN, PoE budget, management IP, MTU, duplex).
* **What is actually on the wire?** Live packet capture exported as standard `.pcap`
  for Wireshark, with a tcpdump-style filter language.
* **Why is Wi-Fi bad here?** Signal, SNR, retry rates, per-channel airtime survey,
  co-channel and overlapping-channel analysis, and a recommended channel.
* **Is it me or the network?** A single `diag` command that checks link, addressing,
  gateway, DNS, internet reachability, path MTU and Wi-Fi in one pass.

Everything is Python 3.8+ standard library. No pip dependencies, no libpcap, no scapy.

## Install

```bash
git clone <this repo> && cd network-tool
python3 -m nettool --help          # run straight from the checkout

pip install .                      # or install the `nettool` command
```

### Permissions

Raw sockets need privileges. Either run under `sudo`, or grant the capabilities once:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which python3)")"
```

| Feature | Needs root / CAP_NET_RAW |
|---|---|
| `iface`, `scan`, `pcap` | no |
| `discover` (ARP sweep) | yes — falls back to TCP sweep without it |
| `lldp`, `capture` | yes |
| `ping`, `trace`, `mtu` | usually — works unprivileged if `net.ipv4.ping_group_range` allows it |
| `wifi scan/survey` | needs the `iw` tool; scanning normally requires root |

## Commands

### Inventory

```bash
nettool iface                 # interfaces, IPs, routes, DNS, error counters
nettool iface -v              # plus IPv6 and the ARP cache
nettool iface --json
```

### Health check

```bash
nettool diag                  # link, address, gateway, DNS, internet, MTU, Wi-Fi
nettool diag --skip internet --skip mtu
nettool diag --json           # exit code 1 when a check is critical
```

```
== network health check ==
  [ ok ] link      eth0 is up (1000 Mb/s full, MTU 1500).
  [ ok ] address   192.168.1.42/24 on eth0.
  [WARN] gateway   Gateway 192.168.1.1: 4.1 ms avg, 12% loss - any loss to the gateway
                   is a local problem (cable, Wi-Fi, switch port).
  [ ok ] dns       DNS resolves (example.com -> 93.184.215.14 in 21 ms).
  [ ok ] internet  Internet reachable (1.1.1.1:443 in 12 ms).
```

### Host discovery

```bash
sudo nettool discover                     # ARP sweep of this interface's subnet
sudo nettool discover -c 10.10.0.0/24     # a specific subnet
nettool discover -m tcp                   # no privileges needed
nettool discover --json
```

ARP discovery finds hosts that drop pings and firewall every port, and flags
**duplicate IP addresses** — one of the nastier intermittent LAN faults.

### Port scanning

```bash
nettool scan 192.168.1.10                       # top ~100 ports
nettool scan 192.168.1.10 -p 1-1024 -b          # range, with banner/TLS grabbing
nettool scan 192.168.1.0/24 -p 22,443 -w 512    # whole subnet, 512 workers
nettool scan 10.0.0.5 -p 53,123,161 --udp       # UDP with real protocol probes
nettool scan 10.0.0.5 --csv > ports.csv
```

TCP states are `open` / `closed` / `filtered` (timeout — usually a firewall).
UDP is unacknowledged, so a silent port is honestly reported as `open|filtered`.

### LLDP / CDP neighbours

```bash
sudo nettool lldp                          # listen up to 65s, print the first neighbour
sudo nettool lldp -t 120 --wait-all        # collect everything in a 2 minute window
sudo nettool lldp --pcap neighbours.pcap   # keep the raw frames
nettool lldp --from-pcap neighbours.pcap   # decode neighbours out of any capture
```

```
sw-idf3-01  (LLDP from aa:bb:cc:dd:ee:ff, Cisco)
  chassis:           aa:bb:cc:dd:ee:ff (mac)
  port:              GigabitEthernet1/0/24 (interface-name)
  port desc:         uplink to lab bench
  native VLAN:       30
  VLANs:             30(LABS)
  MED policy:        voice vlan 176 prio 2 dscp 46
  mgmt address:      10.20.0.5
  MAU/link:          1000BASE-T full
  max frame:         9216
  PoE:               PSE class 4, allocated 15.4 W
```

Decoded LLDP TLVs include chassis/port IDs, capabilities, management addresses,
802.1 VLAN, 802.3 MAC/PHY, PoE (LLDP-MED and 802.3), link aggregation and max frame size.
CDP adds platform, software version, VTP domain, native and voice VLAN, duplex and power draw.

### Packet capture and pcap export

```bash
sudo nettool capture -i eth0 -d 30 -w lan.pcap             # 30 seconds to a pcap
sudo nettool capture -f "host 10.0.0.5 and tcp" -c 200 -w host.pcap
sudo nettool capture -f "dhcp or dns" -s 128               # headers only, live view
sudo nettool capture -d 60 -w big.pcap --write-only        # quiet, file only

nettool pcap lan.pcap                                      # summarize an existing capture
nettool pcap lan.pcap -f "port 443" -w tls.pcap            # split out a subset
nettool pcap lan.pcap -P -n 50                             # print the first 50 packets
```

The files are classic libpcap format — open them in Wireshark, `tshark`, or anything else.
Captures report protocol mix, top talkers, top conversations, VLANs seen, and kernel drops.

**Filter syntax** (userspace, tcpdump-flavoured):

```
host 10.0.0.5      src host 10.0.0.5     dst net 192.168.1.0/24
port 443           src port 22           portrange 8000-8100
tcp udp icmp icmp6 arp ip ip6 lldp cdp stp eapol dhcp dns mdns ssdp ntp
vlan               vlan 30               ether host aa:bb:cc:dd:ee:ff
tcp-syn tcp-rst    broadcast             multicast
and / or / not / ( ) / && / || / !
```

### Wi-Fi

```bash
sudo nettool wifi scan                 # nearby BSSes: signal, channel, width, load, security
nettool wifi link                      # your association: RSSI, SNR, bitrate, retries
sudo nettool wifi survey               # per-channel airtime: busy vs. our traffic vs. noise
nettool wifi monitor -d 60             # signal stability over a minute (roaming, fading)
sudo nettool wifi analyze              # the full interference verdict + channel recommendation
```

```
== radio environment (23 BSS via iw) ==

2.4 GHz - 14 BSS
ch  bss  overlapping  strongest  ssid          util  load score
1   5    4            -58.0      NeighborNet   31%   6.21
6   6    5            -47.0      HomeNet       50%   7.80
11  3    2            -71.0      Guest         --    2.15
  suggested channel: 11 (load score 2.15) - only 1/6/11 avoid overlap

== findings ==
  [WARN] TX retry rate 25.0% - a hallmark of interference or a weak link.
  [FAIL] Channel 6 airtime 75% busy (10% our RX, 5% our TX, 60% other/interference).
  [WARN] 60% of airtime is busy with traffic we cannot decode - non-Wi-Fi interference
         or distant co-channel APs.
  [info] Channel 11 looks clearer than your current channel 6 (load 2.15 vs 7.80).
```

How the analysis works:

* **Signal rating** — ≥ -50 excellent, ≥ -60 good, ≥ -67 the floor for voice/video,
  ≥ -72 marginal, below -80 unusable.
* **SNR** — signal minus the measured noise floor; under 15 dB means retries and low rates.
* **Overlap** — 2.4 GHz channels sit 5 MHz apart but are 20 MHz wide, so anything within
  4 channels partially overlaps, which is worse than sharing a channel outright. Only
  1 / 6 / 11 are recommended.
* **Load score** — every neighbouring BSS is weighted by how much it overlaps your channel,
  how strong it is, and its advertised channel utilisation (802.11 BSS Load).
* **Airtime survey** — the honest measure. Busy time that is neither our transmit nor
  decodable receive is non-Wi-Fi interference (microwaves, cameras, cordless phones,
  video senders) or distant co-channel APs.
* **Retries / failures / missed beacons** — read from `iw station dump` and
  `/proc/net/wireless`; high retries with a strong signal means interference, not distance.

5 GHz recommendations prefer non-DFS channels, since DFS channels can vanish mid-session
when a radar event is detected.

### Reachability

```bash
nettool ping 1.1.1.1 -c 10        # loss, min/avg/max, jitter
nettool trace example.com
nettool mtu 1.1.1.1              # binary-searched path MTU with DF set
```

## Troubleshooting playbooks

**"The port doesn't work"** — `sudo nettool lldp` tells you the switch, the port name and the
VLAN. If nothing appears, you are behind an unmanaged switch or LLDP is off on that port.

**"It's slow"** — `nettool diag` first. Loss or jitter to the gateway is a local problem
(cable, duplex, Wi-Fi); clean local numbers with bad upstream numbers point past your demarc.
`nettool iface` shows negotiated speed, duplex and error counters.

**"Some sites hang"** — classic MTU black hole. `nettool mtu <host>`; if the path MTU is
below the interface MTU, something is tunnelling (VPN, PPPoE) and dropping big DF packets.

**"Wi-Fi keeps dropping"** — `nettool wifi monitor -d 120` while walking the area. A large
swing with a stable BSSID is multipath or an interferer; a changing BSSID is roaming.
Then `sudo nettool wifi analyze` for the channel picture.

**"Two devices keep losing connectivity"** — `sudo nettool discover` reports duplicate IPs.

**"I need evidence for someone else"** — `sudo nettool capture -d 60 -w evidence.pcap -f "host X"`
and hand over the pcap.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The suite covers the packet decoder, pcap reader/writer round-trips, the filter language,
LLDP/CDP TLV parsing (including PoE, VLAN, MED policies), `iw` scan/link/station/survey
parsing, the Wi-Fi interference analysis, target/port expansion and the CLI commands.

## Scope and limitations

* Linux only. Capture, ARP sweep and LLDP use `AF_PACKET`; interface data comes from
  `/sys/class/net`, `/proc/net/*` and ioctls.
* Wi-Fi scanning shells out to `iw` (preferred), `nmcli` or `iwlist`. Without one of those
  installed, only `/proc/net/wireless` data is available.
* Capture filtering happens in userspace after decoding rather than as kernel BPF, so a
  very high packet rate can drop frames — the kernel drop count is reported at the end.
* Scanning and capturing networks you do not own or administer may be illegal. Use this
  on networks you are responsible for.
