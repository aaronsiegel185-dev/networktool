"""Keeping the data on this machine, by enforcement rather than by promise.

The whole point of running the model locally is that tickets, screenshots and
system details never reach anyone else. That is easy to claim and easy to break
by accident - a library that phones home for telemetry, a model endpoint
misconfigured to a hosted URL, a copy-pasted base URL with a public hostname.

So this does three things, in increasing order of how much they are worth:

1. `is_local_endpoint` refuses a model server that is not on this machine or,
   if explicitly allowed, on the local network.
2. `describe_egress` says in plain words where data would go, so `doctor` can
   show it before anything is sent.
3. `no_egress` is a context manager that intercepts outbound socket connections
   and raises on any destination outside the allowed set. That one is the
   difference between a policy and a guarantee - it holds even for code that
   never heard of this module.
"""

import ipaddress
import socket
from urllib.parse import urlparse


class EgressBlocked(Exception):
    """An outbound connection was attempted to somewhere it must not go."""


# Addresses that cannot leave the machine.
LOOPBACK = ("127.0.0.1", "::1", "localhost")


def resolve_host(host):
    """Every address a hostname resolves to, as ipaddress objects.

    All of them, not just the first: a name that resolves to both a loopback
    and a public address must not pass because the loopback happened to come
    back first.
    """
    try:
        candidate = ipaddress.ip_address(host)
        return [candidate]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    found = []
    for info in infos:
        address = info[4][0]
        try:
            parsed = ipaddress.ip_address(address.split("%")[0])
        except ValueError:
            continue
        if parsed not in found:
            found.append(parsed)
    return found


def classify(host):
    """'loopback', 'private', 'public' or 'unresolved' for a hostname."""
    addresses = resolve_host(host)
    if not addresses:
        return "unresolved"
    # The weakest answer wins: anything public makes the whole name public.
    if any(not (a.is_loopback or a.is_private or a.is_link_local) for a in addresses):
        return "public"
    if any(a.is_private or a.is_link_local for a in addresses):
        return "private" if not all(a.is_loopback for a in addresses) else "loopback"
    return "loopback"


def is_local_endpoint(url, allow_lan=False):
    """(ok, reason) for a model server URL."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "%s is not an http(s) URL" % url
    host = parsed.hostname
    if not host:
        return False, "%s has no host" % url
    kind = classify(host)
    if kind == "loopback":
        return True, "%s is this machine" % host
    if kind == "private":
        if allow_lan:
            return True, "%s is on your local network" % host
        return False, ("%s is on your local network, not this machine. Pass "
                       "--allow-lan if you meant to use a model server on another "
                       "box you control." % host)
    if kind == "unresolved":
        return False, "%s does not resolve, so where it points cannot be checked" % host
    return False, ("%s is a public address. A model server out on the internet "
                   "would mean sending your tickets and screenshots to it, which "
                   "is the one thing this is built not to do." % host)


def describe_egress(url, allow_lan=False):
    """What `doctor` prints: where data goes, in words."""
    ok, reason = is_local_endpoint(url, allow_lan=allow_lan)
    addresses = resolve_host(urlparse(url).hostname or "")
    return {
        "endpoint": url,
        "host": urlparse(url).hostname,
        "resolves_to": [str(a) for a in addresses],
        "classification": classify(urlparse(url).hostname or ""),
        "allowed": ok,
        "reason": reason,
        "leaves_machine": bool(ok and classify(urlparse(url).hostname or "") != "loopback"),
    }


class _GuardedSocket(socket.socket):
    """A socket that will not connect anywhere it has not been told it may."""

    _allowed = ()

    def connect(self, address):
        self._check(address)
        return super().connect(address)

    def connect_ex(self, address):
        self._check(address)
        return super().connect_ex(address)

    @classmethod
    def _check(cls, address):
        if not isinstance(address, tuple) or not address:
            return                                  # AF_UNIX and friends stay local
        host = str(address[0])
        try:
            parsed = ipaddress.ip_address(host.split("%")[0])
        except ValueError:
            parsed = None
        if parsed is not None and parsed.is_loopback:
            return
        for allowed in cls._allowed:
            if host == allowed:
                return
            if parsed is not None and str(parsed) == allowed:
                return
        raise EgressBlocked(
            "blocked a connection to %s. Assist runs entirely on this machine, so "
            "the only destinations it may reach are this computer and the model "
            "server you configured." % host)


class no_egress(object):
    """Refuse outbound connections to anywhere but the allowed destinations.

    Used around the whole of an assist run. It is deliberately blunt - it
    replaces the socket class for the duration - because the point is to catch
    the connection nobody knew was there, not the ones already audited.
    """

    def __init__(self, allow=()):
        resolved = []
        for host in allow:
            resolved.append(host)
            for address in resolve_host(host):
                resolved.append(str(address))
        self.allow = tuple(dict.fromkeys(resolved))
        self._saved = None

    def __enter__(self):
        self._saved = socket.socket
        guard = type("GuardedSocket", (_GuardedSocket,), {"_allowed": self.allow})
        socket.socket = guard
        return self

    def __exit__(self, *exc):
        if self._saved is not None:
            socket.socket = self._saved
        return False
