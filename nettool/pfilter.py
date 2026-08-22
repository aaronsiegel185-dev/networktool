"""A small tcpdump-flavoured filter language, evaluated in userspace on decoded packets.

This is deliberately not BPF: it runs after the packet is decoded, so it costs CPU
rather than kernel cycles, but it needs no libpcap and works identically on every
capture source (live socket or a pcap file being re-read).

Supported::

    host 10.0.0.5            src host 10.0.0.5      dst host fe80::1
    net 10.0.0.0/24          src net 192.168.1.0/24
    port 443                 src port 22            portrange 8000-8100
    tcp udp icmp icmp6 arp ip ip6 lldp cdp stp dhcp dns mdns ssdp vlan
    vlan 30                  ether host aa:bb:cc:dd:ee:ff      ether src <mac>   ether dst <mac>
    tcp-syn                  broadcast              multicast
    combined with: and / or / not / && / || / ! / parentheses
"""

import ipaddress
import re

from .util import NetToolError

_TOKEN = re.compile(r"\s*(\(|\)|&&|\|\||!|[^\s()]+)")

_L2_KEYWORDS = {
    "arp": lambda p: p.get("l3") == "ARP",
    "ip": lambda p: p.get("l3") == "IPv4",
    "ipv4": lambda p: p.get("l3") == "IPv4",
    "ip6": lambda p: p.get("l3") == "IPv6",
    "ipv6": lambda p: p.get("l3") == "IPv6",
    "tcp": lambda p: p.get("l4") == "TCP",
    "udp": lambda p: p.get("l4") == "UDP",
    "icmp": lambda p: p.get("l4") == "ICMP",
    "icmp6": lambda p: p.get("proto") == "ICMPv6",
    "lldp": lambda p: p.get("ethertype") == 0x88CC,
    "cdp": lambda p: p.get("proto") == "CDP",
    "stp": lambda p: p.get("proto") == "STP",
    "eapol": lambda p: p.get("ethertype") == 0x888E,
    "vlan": lambda p: p.get("vlan") is not None,
    "dhcp": lambda p: p.get("l4") == "UDP" and (
        p.get("sport") in (67, 68) or p.get("dport") in (67, 68)),
    "dns": lambda p: p.get("l4") == "UDP" and (
        p.get("sport") == 53 or p.get("dport") == 53),
    "mdns": lambda p: p.get("sport") == 5353 or p.get("dport") == 5353,
    "ssdp": lambda p: p.get("sport") == 1900 or p.get("dport") == 1900,
    "ntp": lambda p: p.get("sport") == 123 or p.get("dport") == 123,
    "tcp-syn": lambda p: p.get("l4") == "TCP" and "S" in (p.get("tcp_flags") or ""),
    "tcp-rst": lambda p: p.get("l4") == "TCP" and "R" in (p.get("tcp_flags") or ""),
    "broadcast": lambda p: p.get("eth_dst") == "ff:ff:ff:ff:ff:ff",
    "multicast": lambda p: bool(p.get("eth_dst")) and int(p["eth_dst"][:2], 16) & 1 == 1,
}


def _tokenize(text):
    tokens = []
    pos = 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            break
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


class _Parser(object):
    def __init__(self, tokens):
        self.tokens = tokens
        self.i = 0

    def peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def next(self):
        tok = self.peek()
        if tok is None:
            raise NetToolError("filter ended unexpectedly")
        self.i += 1
        return tok

    def accept(self, *words):
        tok = self.peek()
        if tok is not None and tok.lower() in words:
            self.i += 1
            return tok.lower()
        return None

    def parse(self):
        pred = self.parse_or()
        if self.peek() is not None:
            raise NetToolError("unexpected token in filter: %r" % self.peek())
        return pred

    def parse_or(self):
        left = self.parse_and()
        while self.accept("or", "||"):
            right = self.parse_and()
            left = (lambda a, b: lambda p: a(p) or b(p))(left, right)
        return left

    def parse_and(self):
        left = self.parse_not()
        while True:
            if self.accept("and", "&&"):
                right = self.parse_not()
                left = (lambda a, b: lambda p: a(p) and b(p))(left, right)
            else:
                return left

    def parse_not(self):
        if self.accept("not", "!"):
            inner = self.parse_not()
            return lambda p: not inner(p)
        return self.parse_atom()

    def parse_atom(self):
        tok = self.next()
        low = tok.lower()
        if low == "(":
            inner = self.parse_or()
            if self.accept(")") is None:
                raise NetToolError("unbalanced parenthesis in filter")
            return inner
        direction = None
        if low in ("src", "dst"):
            direction = low
            nxt = self.peek()
            if nxt is None:
                raise NetToolError("'%s' must be followed by host/net/port" % low)
            low = self.next().lower()
        if low == "host":
            return self._host(self.next(), direction)
        if low == "net":
            return self._net(self.next(), direction)
        if low == "port":
            return self._port(self.next(), direction)
        if low == "portrange":
            return self._portrange(self.next(), direction)
        if low == "ether":
            what = self.next().lower()
            if what in ("src", "dst"):
                direction = what
                what = self.next().lower()
            if what == "host":
                what = self.next()
            return self._ether(what, direction)
        if low == "vlan":
            nxt = self.peek()
            if nxt is not None and nxt.isdigit():
                vid = int(self.next())
                return lambda p: p.get("vlan") == vid
            return _L2_KEYWORDS["vlan"]
        if low in _L2_KEYWORDS:
            if direction:
                raise NetToolError("'%s' cannot take a direction" % low)
            return _L2_KEYWORDS[low]
        if low.isdigit():
            return self._port(low, direction)
        # bare address / CIDR
        if "/" in low:
            return self._net(tok, direction)
        try:
            ipaddress.ip_address(tok)
        except ValueError:
            raise NetToolError("unknown filter keyword: %r" % tok)
        return self._host(tok, direction)

    @staticmethod
    def _host(value, direction):
        try:
            addr = str(ipaddress.ip_address(value))
        except ValueError:
            raise NetToolError("bad address in filter: %r" % value)
        if direction == "src":
            return lambda p: p.get("src") == addr
        if direction == "dst":
            return lambda p: p.get("dst") == addr
        return lambda p: addr in (p.get("src"), p.get("dst"))

    @staticmethod
    def _net(value, direction):
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise NetToolError("bad network in filter: %r" % value)

        def inside(addr):
            if not addr:
                return False
            try:
                return ipaddress.ip_address(addr) in net
            except ValueError:
                return False

        if direction == "src":
            return lambda p: inside(p.get("src"))
        if direction == "dst":
            return lambda p: inside(p.get("dst"))
        return lambda p: inside(p.get("src")) or inside(p.get("dst"))

    @staticmethod
    def _port(value, direction):
        try:
            port = int(value)
        except ValueError:
            raise NetToolError("bad port in filter: %r" % value)
        if direction == "src":
            return lambda p: p.get("sport") == port
        if direction == "dst":
            return lambda p: p.get("dport") == port
        return lambda p: port in (p.get("sport"), p.get("dport"))

    @staticmethod
    def _portrange(value, direction):
        m = re.match(r"^(\d+)-(\d+)$", value)
        if not m:
            raise NetToolError("bad portrange in filter: %r" % value)
        lo, hi = int(m.group(1)), int(m.group(2))

        def hit(port):
            return port is not None and lo <= port <= hi

        if direction == "src":
            return lambda p: hit(p.get("sport"))
        if direction == "dst":
            return lambda p: hit(p.get("dport"))
        return lambda p: hit(p.get("sport")) or hit(p.get("dport"))

    @staticmethod
    def _ether(value, direction):
        mac = value.lower().replace("-", ":")
        if not re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac):
            raise NetToolError("bad MAC in filter: %r" % value)
        if direction == "src":
            return lambda p: p.get("eth_src") == mac
        if direction == "dst":
            return lambda p: p.get("eth_dst") == mac
        return lambda p: mac in (p.get("eth_src"), p.get("eth_dst"))


def compile_filter(expr):
    """Return predicate(decoded_packet) -> bool. None/empty expression matches all."""
    if not expr or not expr.strip():
        return lambda p: True
    tokens = _tokenize(expr)
    if not tokens:
        return lambda p: True
    return _Parser(tokens).parse()
