"""What the machine can say about itself, gathered locally.

This is where the two halves of Toolbox meet. A ticket that says "the wifi keeps
dropping" is worth very little on its own; the same ticket alongside the signal
strength, the interference breakdown, the retry rate and the route table is
most of a diagnosis. Network Tool already measures all of that, so Assist asks
it rather than asking the user.

Everything here runs on this machine and stays on it. Nothing is uploaded; the
facts are gathered so the *local* model can read them.
"""

import os
import platform
import socket

# Each probe is (name, what it answers, the callable). They are run
# independently so one failure - no wireless card, no permission - costs only
# its own section rather than the whole context.
def _interfaces():
    from nettool import iface as ifmod

    return {"interfaces": ifmod.inventory(include_down=False),
            "routes": ifmod.routes()}


def _dns():
    from nettool import iface as ifmod

    servers, search = ifmod.dns_servers()
    return {"servers": servers, "search": search}


def _wifi():
    from nettool import wifi as wifimod

    link = wifimod.link()
    if not link.get("connected"):
        return {"connected": False}
    try:
        networks, _source = wifimod.scan(use_cache=True)
    except Exception:
        networks = []
    report = {"link": link}
    if networks:
        try:
            survey = wifimod.survey_dump()
        except Exception:
            survey = []
        analysis = wifimod.analyze(networks, link, survey)
        # The interference breakdown is the single most useful thing here, and
        # the full scan list is mostly noise to a model, so keep the summary.
        report["interference"] = analysis.get("interference")
        report["findings"] = analysis.get("findings", [])
    return report


def _health():
    from nettool import diag as diagmod

    report = diagmod.run()
    return {"verdict": report.data.get("verdict", ""),
            "worst": report.data.get("worst_severity", "ok"),
            "checks": report.checks}


PROBES = (
    ("system", "what this computer is", lambda: {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "hostname": socket.gethostname(),
        "user": os.environ.get("USER") or os.environ.get("USERNAME") or "",
    }),
    ("network", "interfaces and routes", _interfaces),
    ("dns", "resolvers", _dns),
    ("wifi", "the radio, if there is one", _wifi),
    ("health", "the standard health check", _health),
)


def gather(include=None, on_progress=None):
    """Run the probes and return what they found, plus what failed and why.

    Failures are kept rather than dropped: "no wireless interface" is itself a
    fact worth a model seeing when the ticket is about wifi.
    """
    wanted = set(include) if include else {name for name, _, _ in PROBES}
    context = {}
    problems = {}
    for name, description, probe in PROBES:
        if name not in wanted:
            continue
        if on_progress:
            on_progress(name, description)
        try:
            context[name] = probe()
        except Exception as exc:
            problems[name] = "%s: %s" % (type(exc).__name__, exc)
    if problems:
        context["unavailable"] = problems
    return context


def summarise(context, limit=4000):
    """Context as compact text for a prompt.

    JSON straight from the probes is mostly punctuation and repeated keys, and
    a local model's context window is a scarcer resource than a hosted one's -
    so this writes the same facts as lines a person could read.
    """
    lines = []

    system = context.get("system") or {}
    if system:
        lines.append("Machine: %s, %s, host %s, user %s"
                     % (system.get("platform", "?"), system.get("machine", "?"),
                        system.get("hostname", "?"), system.get("user", "?")))

    for entry in (context.get("network") or {}).get("interfaces", []):
        lines.append("Interface %s: %s, ipv4 %s, mtu %s%s"
                     % (entry.get("name"), "up" if entry.get("up") else "down",
                        entry.get("ipv4") or "none", entry.get("mtu"),
                        ", wireless" if entry.get("wireless") else ""))
    for route in (context.get("network") or {}).get("routes", [])[:6]:
        destination = route.get("dest") or route.get("destination") or "?"
        if destination in ("0.0.0.0", "default") and not route.get("prefixlen"):
            destination = "default"
        lines.append("Route %s via %s on %s"
                     % (destination, route.get("gateway") or "on-link",
                        route.get("iface")))

    dns = context.get("dns") or {}
    if dns.get("servers"):
        lines.append("DNS servers: %s" % ", ".join(dns["servers"]))

    wifi = context.get("wifi") or {}
    link = wifi.get("link") or {}
    if link.get("connected"):
        lines.append("Wi-Fi: %s on channel %s (%s GHz), %s dBm (%s), SNR %s dB, via %s"
                     % (link.get("ssid") or "(hidden)", link.get("channel"),
                        link.get("band"), link.get("signal_dbm"), link.get("rating"),
                        link.get("snr_db"), link.get("bssid") or "unknown AP"))
        station = link.get("station") or {}
        if station.get("retry_pct") is not None:
            lines.append("Wi-Fi TX retries: %.1f%%, failures %.1f%%"
                         % (station.get("retry_pct", 0), station.get("fail_pct", 0)))
    elif "wifi" in context:
        lines.append("Wi-Fi: not associated")

    interference = wifi.get("interference")
    if interference:
        lines.append("Interference on channel %s: %.0f%% (%s, %s)"
                     % (interference.get("channel"), interference.get("headline_pct", 0),
                        interference.get("rating"), interference.get("source")))
        for source in (interference.get("sources") or [])[:5]:
            lines.append("  %s on ch %s, %s dBm, %.0f%% overlap, %.0f%% of the interference"
                         % (source.get("ssid") or "(hidden)", source.get("channel"),
                            source.get("signal_dbm"), source.get("overlap_pct", 0),
                            source.get("share_pct", 0)))

    health = context.get("health") or {}
    if health.get("verdict"):
        lines.append("Health check: %s" % health["verdict"])
    for check in health.get("checks", []):
        # The clean ones are noise; what the model needs is what is wrong.
        if check.get("severity") in ("warn", "critical"):
            lines.append("  %s %s: %s" % (check["severity"], check["check"],
                                          check["message"]))

    for name, problem in (context.get("unavailable") or {}).items():
        lines.append("Could not gather %s - %s" % (name, problem))

    text = "\n".join(lines)
    if len(text) > limit:
        text = text[:limit] + "\n... (truncated)"
    return text
