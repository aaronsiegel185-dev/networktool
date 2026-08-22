"""nettool - field network diagnostics.

Modules:
    iface     interfaces, addresses, routes, ARP, DNS
    discover  LAN host discovery (ARP / ICMP / TCP sweeps)
    portscan  TCP connect and UDP probe scanning
    lldp      LLDP and CDP neighbour discovery
    capture   live packet capture with pcap export
    pcap      classic pcap reader/writer
    pfilter   tcpdump-flavoured filter language
    wifi      wireless scan, link quality, channel and interference analysis
    ping      ICMP echo, traceroute, path MTU
    diag      combined health check
"""

__version__ = "0.1.0"
