"""Wi-Fi diagnostics: scan, association quality, channel utilisation and interference.

Radio state is read from the kernel (/proc/net/wireless, /sys) and from `iw`, with
`nmcli` and `iwlist` as fallbacks, so this works on anything from a laptop to a
stripped-down field box.
"""

import re
import sys
import time

from . import iface as ifmod
from . import oui
from .util import NetToolError, have_cmd, run_cmd

IS_DARWIN = sys.platform == "darwin"
IS_WINDOWS = sys.platform == "win32"

# macOS hands "<redacted>" to a process that has not been granted Location
# Services, so a blank name here is a permission story, not a hidden SSID.
HIDDEN_NAMES_HINT = (
    "macOS hides Wi-Fi names from processes without Location Services. Your own "
    "network's name is read back from the interface configuration, but "
    "neighbouring names stay blank until you grant it: System Settings > Privacy "
    "& Security > Location Services > turn on the app running nettool (Terminal, "
    "or nettool). Signal, channel and noise figures are unaffected either way."
)

# --- channel / frequency maths ---------------------------------------------

DFS_CHANNELS = set(range(52, 145))          # 5 GHz channels requiring radar detection
NON_DFS_5GHZ = [36, 40, 44, 48, 149, 153, 157, 161, 165]
CLEAN_24GHZ = [1, 6, 11]


def freq_to_channel(freq_mhz):
    f = int(freq_mhz)
    if f == 2484:
        return 14
    if 2412 <= f <= 2472:
        return (f - 2407) // 5
    if 5160 <= f <= 5885:
        return (f - 5000) // 5
    if f == 5935:
        return 2
    if 5955 <= f <= 7115:
        return (f - 5950) // 5
    if 56160 <= f <= 70200:
        return (f - 56160) // 2160 + 1
    return 0


def channel_to_freq(channel, band="2.4"):
    if band == "2.4":
        return 2484 if channel == 14 else 2407 + channel * 5
    if band == "5":
        return 5000 + channel * 5
    if band == "6":
        return 5950 + channel * 5
    return 0


def band_of(freq_mhz):
    f = int(freq_mhz)
    if 2400 <= f <= 2500:
        return "2.4"
    if 5150 <= f <= 5900:
        return "5"
    if 5925 <= f <= 7125:
        return "6"
    if f >= 56000:
        return "60"
    return "?"


def signal_rating(dbm):
    """Plain-language verdict for an RSSI value."""
    if dbm is None:
        return "unknown"
    if dbm >= -50:
        return "excellent"
    if dbm >= -60:
        return "good"
    if dbm >= -67:
        return "ok (min for voice/video)"
    if dbm >= -72:
        return "marginal"
    if dbm >= -80:
        return "poor"
    return "unusable"


def quality_percent(dbm):
    """Rough RSSI -> 0-100 mapping (-90 dBm = 0%, -30 dBm = 100%)."""
    if dbm is None:
        return None
    return max(0, min(100, int(round((dbm + 90) * 100 / 60.0))))


def overlap_factor(ch_a, ch_b, band):
    """1.0 = same channel, 0.0 = no overlap. 2.4 GHz channels are 5 MHz apart but
    20 MHz wide, so anything within 4 channels bleeds into you."""
    if band == "2.4":
        delta = abs(ch_a - ch_b)
        if delta == 0:
            return 1.0
        if delta >= 5:
            return 0.0
        return (5.0 - delta) / 5.0
    return 1.0 if ch_a == ch_b else 0.0


def signal_weight(dbm):
    """How much a neighbour's transmissions actually matter to you."""
    if dbm is None:
        return 0.4
    return max(0.0, min(1.0, (dbm + 95) / 45.0))


# --- wireless interfaces ---------------------------------------------------


def wireless_interfaces():
    if IS_WINDOWS:
        from . import windows

        return windows.wireless_interfaces()
    if IS_DARWIN:
        from . import darwin

        return darwin.wireless_interfaces()
    return [n for n in ifmod.list_names() if ifmod.is_wireless(n)]


def _rate_networks(networks):
    """Fill in the derived rating fields the views expect."""
    for net in networks:
        net.setdefault("freq", None)
        if net.get("freq") is None and net.get("channel") and net.get("band"):
            net["freq"] = channel_to_freq(net["channel"], net["band"]) or None
        net["quality_pct"] = quality_percent(net.get("signal_dbm"))
        net["rating"] = signal_rating(net.get("signal_dbm"))
        net.setdefault("security", [])
        net.setdefault("standards", [])
        net.setdefault("width_mhz", 20)
        net.setdefault("utilization_pct", None)
        net.setdefault("stations", None)
    return networks


def pick_interface(preferred=None):
    if preferred:
        if not ifmod.is_wireless(preferred):
            raise NetToolError("%s is not a wireless interface" % preferred)
        return preferred
    found = wireless_interfaces()
    if not found:
        raise NetToolError("no wireless interface found on this machine")
    for name in found:
        if ifmod.describe(name)["up"]:
            return name
    return found[0]


def proc_wireless():
    """Parse /proc/net/wireless -> {iface: {link, signal_dbm, noise_dbm, retries, ...}}."""
    out = {}
    try:
        with open("/proc/net/wireless") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return out
    for line in lines[2:]:
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        f = rest.split()
        if len(f) < 10:
            continue
        def num(value):
            try:
                return float(value.rstrip("."))
            except ValueError:
                return None
        out[name.strip()] = {
            "status": f[0],
            "link_quality": num(f[1]),
            "signal_dbm": num(f[2]),
            "noise_dbm": num(f[3]),
            "rx_invalid_nwid": int(float(f[4])),
            "rx_invalid_crypt": int(float(f[5])),
            "rx_invalid_frag": int(float(f[6])),
            "tx_retries": int(float(f[7])),
            "invalid_misc": int(float(f[8])),
            "missed_beacons": int(float(f[9])),
        }
    return out


# --- `iw` parsing ----------------------------------------------------------


def _iw(args, timeout=25):
    rc, out, err = run_cmd(["iw"] + args, timeout=timeout)
    if rc == -1:
        raise NetToolError("the `iw` tool is not installed (package: iw / wireless-tools)")
    if rc != 0:
        raise NetToolError("iw %s failed: %s" % (" ".join(args), (err or out).strip()))
    return out


def parse_iw_scan(text):
    """Parse `iw dev X scan` output into a list of BSS dicts."""
    networks = []
    current = None
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"^BSS ([0-9a-fA-F:]{17})", line)
        if m:
            current = {"bssid": m.group(1).lower(), "ssid": "", "signal_dbm": None,
                       "freq": None, "channel": None, "band": "", "security": [],
                       "width_mhz": 20, "stations": None, "utilization_pct": None,
                       "associated": "associated" in line, "capabilities": "",
                       "beacon_interval": None, "last_seen_ms": None, "country": "",
                       "standards": []}
            networks.append(current)
            section = None
            continue
        if current is None:
            continue
        if line.startswith("SSID:"):
            current["ssid"] = line[5:].strip()
        elif line.startswith("freq:"):
            freq = re.sub(r"[^0-9.]", "", line.split(":", 1)[1])
            if freq:
                current["freq"] = int(float(freq))
                current["channel"] = freq_to_channel(current["freq"])
                current["band"] = band_of(current["freq"])
        elif line.startswith("signal:"):
            m = re.search(r"(-?\d+(?:\.\d+)?)\s*dBm", line)
            if m:
                current["signal_dbm"] = float(m.group(1))
        elif line.startswith("last seen:"):
            m = re.search(r"(\d+)\s*ms", line)
            if m:
                current["last_seen_ms"] = int(m.group(1))
        elif line.startswith("beacon interval:"):
            m = re.search(r"(\d+)", line)
            if m:
                current["beacon_interval"] = int(m.group(1))
        elif line.startswith("capability:"):
            current["capabilities"] = line.split(":", 1)[1].strip()
        elif line.startswith("Country:"):
            current["country"] = line.split(":", 1)[1].split()[0].strip()
        elif line.startswith("DS Parameter set: channel"):
            current["channel"] = int(re.search(r"channel\s+(\d+)", line).group(1))
        elif line.startswith("RSN:"):
            section = "rsn"
            current["security"].append("WPA2/WPA3")
        elif line.startswith("WPA:"):
            section = "wpa"
            if "WPA" not in current["security"]:
                current["security"].append("WPA")
        elif line.startswith("BSS Load:"):
            section = "bssload"
        elif line.startswith("HT operation:"):
            section = "ht"
            current["standards"].append("n")
        elif line.startswith("VHT operation:"):
            section = "vht"
            current["standards"].append("ac")
        elif line.startswith("HE ") or line.startswith("HE capabilities"):
            if "ax" not in current["standards"]:
                current["standards"].append("ax")
        elif line.startswith("EHT "):
            if "be" not in current["standards"]:
                current["standards"].append("be")
        elif section == "bssload" and "station count" in line:
            m = re.search(r"(\d+)", line)
            if m:
                current["stations"] = int(m.group(1))
        elif section == "bssload" and "channel utilisation" in line.lower():
            m = re.search(r"(\d+)\s*/\s*(\d+)", line)
            if m:
                current["utilization_pct"] = round(
                    100.0 * int(m.group(1)) / max(1, int(m.group(2))), 1)
        elif section == "ht" and "secondary channel offset" in line:
            if "above" in line or "below" in line:
                current["width_mhz"] = max(current["width_mhz"], 40)
        elif section == "vht" and "channel width" in line:
            if "80+80" in line or "160 MHz" in line:
                current["width_mhz"] = 160
            elif "80 MHz" in line:
                current["width_mhz"] = max(current["width_mhz"], 80)
            elif "40 MHz" in line:
                current["width_mhz"] = max(current["width_mhz"], 40)
        elif section in ("rsn", "wpa") and "Authentication suites:" in line:
            suites = line.split(":", 1)[1].strip()
            if "SAE" in suites and "WPA3" not in current["security"]:
                current["security"].append("WPA3-SAE")
            if "802.1X" in suites or "IEEE 802.1X" in suites:
                current["security"].append("802.1X/Enterprise")
    for net in networks:
        if not net["security"]:
            net["security"] = ["open"] if "Privacy" not in net["capabilities"] else ["WEP"]
        net["quality_pct"] = quality_percent(net["signal_dbm"])
        net["rating"] = signal_rating(net["signal_dbm"])
    return networks


def parse_iw_link(text):
    """Parse `iw dev X link` output."""
    if "Not connected" in text:
        return {"connected": False}
    info = {"connected": True, "ssid": "", "bssid": "", "freq": None, "signal_dbm": None,
            "tx_bitrate": "", "rx_bitrate": "", "channel": None, "band": ""}
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"Connected to ([0-9a-fA-F:]{17})", line)
        if m:
            info["bssid"] = m.group(1).lower()
        elif line.startswith("SSID:"):
            info["ssid"] = line[5:].strip()
        elif line.startswith("freq:"):
            freq = re.sub(r"[^0-9.]", "", line.split(":", 1)[1])
            if freq:
                info["freq"] = int(float(freq))
                info["channel"] = freq_to_channel(info["freq"])
                info["band"] = band_of(info["freq"])
        elif line.startswith("signal:"):
            m = re.search(r"(-?\d+)", line)
            if m:
                info["signal_dbm"] = float(m.group(1))
        elif line.startswith("tx bitrate:"):
            info["tx_bitrate"] = line.split(":", 1)[1].strip()
        elif line.startswith("rx bitrate:"):
            info["rx_bitrate"] = line.split(":", 1)[1].strip()
    info["rating"] = signal_rating(info["signal_dbm"])
    info["quality_pct"] = quality_percent(info["signal_dbm"])
    return info


def parse_iw_station(text):
    """Parse `iw dev X station dump` - retries and failures expose interference."""
    stations = []
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"Station ([0-9a-fA-F:]{17})", line)
        if m:
            current = {"mac": m.group(1).lower()}
            stations.append(current)
            continue
        if current is None or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower().replace(" ", "_")
        value = value.strip()
        if key in ("signal", "signal_avg"):
            m = re.search(r"(-?\d+)", value)
            if m:
                current[key + "_dbm"] = int(m.group(1))
        elif key in ("tx_retries", "tx_failed", "tx_packets", "rx_packets", "tx_bytes",
                     "rx_bytes", "beacon_loss", "expected_throughput", "connected_time",
                     "inactive_time", "rx_drop_misc"):
            m = re.search(r"(\d+)", value)
            if m:
                current[key] = int(m.group(1))
        elif key in ("tx_bitrate", "rx_bitrate"):
            current[key] = value
    for st in stations:
        sent = st.get("tx_packets", 0)
        if sent:
            st["retry_pct"] = round(100.0 * st.get("tx_retries", 0) / sent, 1)
            st["fail_pct"] = round(100.0 * st.get("tx_failed", 0) / sent, 1)
    return stations


def parse_iw_survey(text):
    """Parse `iw dev X survey dump` - the honest measure of how busy a channel is,
    including interference from non-Wi-Fi sources."""
    surveys = []
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("Survey data from"):
            current = {"iface": line.rsplit(None, 1)[-1], "in_use": False}
            surveys.append(current)
            continue
        if current is None or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "frequency":
            m = re.search(r"(\d+)", value)
            if m:
                current["freq"] = int(m.group(1))
                current["channel"] = freq_to_channel(current["freq"])
                current["band"] = band_of(current["freq"])
            current["in_use"] = "in use" in value
        elif key == "noise":
            m = re.search(r"(-?\d+)", value)
            if m:
                current["noise_dbm"] = int(m.group(1))
        elif key.startswith("channel "):
            m = re.search(r"(\d+)", value)
            if m:
                current[key.replace("channel ", "").replace(" ", "_")] = int(m.group(1))
    for s in surveys:
        active = s.get("active_time", 0)
        if active:
            s["busy_pct"] = round(100.0 * s.get("busy_time", 0) / active, 1)
            s["tx_pct"] = round(100.0 * s.get("transmit_time", 0) / active, 1)
            s["rx_pct"] = round(100.0 * s.get("receive_time", 0) / active, 1)
            # Airtime that is busy but neither our TX nor decodable RX is the
            # signature of interference / distant co-channel traffic.
            s["interference_pct"] = round(
                max(0.0, s["busy_pct"] - s["tx_pct"] - s["rx_pct"]), 1)
    return surveys


# --- fallbacks -------------------------------------------------------------


def parse_nmcli_scan(text):
    nets = []
    for line in text.splitlines():
        if not line.strip():
            continue
        # nmcli -t escapes field-internal colons (MAC addresses) with a backslash.
        parts = re.split(r"(?<!\\):", line)
        if len(parts) < 6:
            continue
        ssid, bssid, chan, freq, signal = parts[0], parts[1], parts[2], parts[3], parts[4]
        security = ":".join(parts[5:])
        bssid = bssid.replace("\\:", ":").lower()
        try:
            freq_i = int(re.sub(r"[^0-9]", "", freq) or 0)
        except ValueError:
            freq_i = 0
        try:
            pct = int(signal)
        except ValueError:
            pct = None
        nets.append({
            "bssid": bssid, "ssid": ssid, "freq": freq_i or None,
            "channel": int(chan) if chan.isdigit() else freq_to_channel(freq_i),
            "band": band_of(freq_i) if freq_i else "",
            # nmcli reports a 0-100 quality; convert back to an approximate dBm.
            "signal_dbm": (pct * 60 / 100.0 - 90) if pct is not None else None,
            "quality_pct": pct, "security": [s for s in security.split() if s] or ["open"],
            "width_mhz": 20, "stations": None, "utilization_pct": None,
            "standards": [], "approx": True,
        })
    for net in nets:
        net["rating"] = signal_rating(net["signal_dbm"])
    return nets


def scan(ifname=None, use_cache=False, passive_ok=True):
    """Scan for nearby BSSes. Returns (networks, source)."""
    if IS_DARWIN:
        from . import darwin

        networks, source = darwin.wifi_scan()
        return _rate_networks(networks), source
    if IS_WINDOWS:
        from . import windows

        networks, source = windows.wifi_scan(refresh=not use_cache)
        return _rate_networks(networks), source
    ifname = pick_interface(ifname)
    if have_cmd("iw"):
        args = ["dev", ifname, "scan"]
        if use_cache:
            args.append("dump")
        try:
            return parse_iw_scan(_iw(args, timeout=40)), "iw"
        except NetToolError as exc:
            if not use_cache and have_cmd("iw"):
                try:
                    return parse_iw_scan(_iw(["dev", ifname, "scan", "dump"])), "iw (cached)"
                except NetToolError:
                    pass
            if not have_cmd("nmcli"):
                raise exc
    if have_cmd("nmcli"):
        rc, out, err = run_cmd(
            ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY", "dev", "wifi",
             "list", "--rescan", "yes"], timeout=40)
        if rc == 0:
            return parse_nmcli_scan(out), "nmcli"
    if have_cmd("iwlist"):
        rc, out, _err = run_cmd(["iwlist", ifname, "scan"], timeout=40)
        if rc == 0:
            return parse_iwlist_scan(out), "iwlist"
    raise NetToolError("no usable scan tool found; install `iw` (preferred) or NetworkManager")


def parse_iwlist_scan(text):
    nets = []
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"Cell \d+ - Address: ([0-9A-Fa-f:]{17})", line)
        if m:
            current = {"bssid": m.group(1).lower(), "ssid": "", "signal_dbm": None,
                       "freq": None, "channel": None, "band": "", "security": [],
                       "width_mhz": 20, "stations": None, "utilization_pct": None,
                       "standards": []}
            nets.append(current)
            continue
        if current is None:
            continue
        if line.startswith("ESSID:"):
            current["ssid"] = line.split(":", 1)[1].strip().strip('"')
        elif "Frequency:" in line:
            m = re.search(r"Frequency:([\d.]+) GHz", line)
            if m:
                current["freq"] = int(float(m.group(1)) * 1000)
                current["band"] = band_of(current["freq"])
            m = re.search(r"Channel (\d+)", line)
            if m:
                current["channel"] = int(m.group(1))
            elif current["freq"]:
                current["channel"] = freq_to_channel(current["freq"])
        elif "Signal level=" in line:
            m = re.search(r"Signal level=(-?\d+)", line)
            if m:
                current["signal_dbm"] = float(m.group(1))
        elif "Encryption key:" in line:
            if "off" in line:
                current["security"] = ["open"]
        elif "IE: IEEE 802.11i/WPA2" in line:
            current["security"].append("WPA2")
        elif "IE: WPA Version 1" in line:
            current["security"].append("WPA")
    for net in nets:
        net["quality_pct"] = quality_percent(net["signal_dbm"])
        net["rating"] = signal_rating(net["signal_dbm"])
        if not net["security"]:
            net["security"] = ["unknown"]
    return nets


def _name_the_ap(state):
    """Label the BSSID with whoever made the radio.

    A bare MAC does not tell you which box you are on; the OUI does, and on a
    site with mixed hardware that is usually the question being asked.
    """
    bssid = state.get("bssid") or ""
    if IS_DARWIN:
        from . import darwin

        # Never let a CFData rendering reach a vendor lookup: oui.lookup strips
        # the punctuation and would happily name a vendor for "0x020000...".
        bssid = darwin.usable_bssid(bssid)
        state["bssid"] = bssid
    state["bssid_vendor"] = oui.lookup(bssid) if bssid else ""
    return state


def link(ifname=None):
    """Current association state.

    Linux merges `iw link`, `iw station dump` and /proc/net/wireless; macOS uses
    `wdutil info` when it can (root) and system_profiler otherwise.
    """
    if IS_WINDOWS:
        from . import windows

        state = windows.wifi_link(ifname)
        state["rating"] = signal_rating(state.get("signal_dbm"))
        if state.get("channel") and state.get("band"):
            state["freq"] = channel_to_freq(state["channel"], state["band"]) or None
        return _name_the_ap(state)
    if IS_DARWIN:
        from . import darwin

        state = darwin.wifi_link()
        state.setdefault("interface", "")
        if not state.get("interface"):
            radios = darwin.wireless_interfaces()
            state["interface"] = ifname or (radios[0] if radios else "")
        signal = state.get("signal_dbm")
        state["rating"] = signal_rating(signal)
        state["quality_pct"] = quality_percent(signal)
        if state.get("freq") is None and state.get("channel") and state.get("band"):
            state["freq"] = channel_to_freq(state["channel"], state["band"]) or None
        return _name_the_ap(state)
    ifname = pick_interface(ifname)
    info = {"interface": ifname, "connected": False}
    if have_cmd("iw"):
        try:
            info.update(parse_iw_link(_iw(["dev", ifname, "link"])))
        except NetToolError:
            pass
        try:
            stations = parse_iw_station(_iw(["dev", ifname, "station", "dump"]))
            if stations:
                info["station"] = stations[0]
                info["stations"] = stations
        except NetToolError:
            pass
    proc = proc_wireless().get(ifname)
    if proc:
        info["proc"] = proc
        if info.get("signal_dbm") is None and proc.get("signal_dbm") is not None:
            info["signal_dbm"] = proc["signal_dbm"]
            info["rating"] = signal_rating(info["signal_dbm"])
            info["quality_pct"] = quality_percent(info["signal_dbm"])
        if proc.get("noise_dbm") is not None and info.get("signal_dbm") is not None:
            if proc["noise_dbm"] < 0:
                info["noise_dbm"] = proc["noise_dbm"]
                info["snr_db"] = round(info["signal_dbm"] - proc["noise_dbm"], 1)
    if info.get("snr_db") is None and info.get("signal_dbm") is not None:
        survey = None
        try:
            survey = [s for s in survey_dump(ifname) if s.get("in_use")]
        except NetToolError:
            survey = None
        if survey and survey[0].get("noise_dbm") is not None:
            info["noise_dbm"] = survey[0]["noise_dbm"]
            info["snr_db"] = round(info["signal_dbm"] - survey[0]["noise_dbm"], 1)
    return _name_the_ap(info)


def survey_dump(ifname=None):
    if IS_WINDOWS:
        raise NetToolError(
            "Windows exposes no per-channel airtime survey (netsh reports signal "
            "and channel, not busy time), so busy/interference percentages are "
            "unavailable here. Signal, SNR, channel load and the channel "
            "recommendation still work.")
    if IS_DARWIN:
        raise NetToolError(
            "macOS exposes no per-channel airtime survey (there is no `iw survey` "
            "equivalent), so busy/interference percentages are unavailable here. "
            "Signal, SNR, channel load and the channel recommendation still work.")
    ifname = pick_interface(ifname)
    if not have_cmd("iw"):
        raise NetToolError("`iw` is required for a channel survey")
    return parse_iw_survey(_iw(["dev", ifname, "survey", "dump"]))


def monitor(ifname=None, duration=30, interval=1.0, on_sample=None):
    """Sample link quality over time: exposes fading, roaming and bursty interference."""
    ifname = pick_interface(ifname)
    samples = []
    end = time.time() + duration
    while time.time() < end:
        state = link(ifname)
        sample = {
            "t": time.time(),
            "signal_dbm": state.get("signal_dbm"),
            "bssid": state.get("bssid", ""),
            "channel": state.get("channel"),
            "tx_bitrate": state.get("tx_bitrate", ""),
            "retry_pct": (state.get("station") or {}).get("retry_pct"),
            "missed_beacons": (state.get("proc") or {}).get("missed_beacons"),
        }
        samples.append(sample)
        if on_sample:
            on_sample(sample)
        time.sleep(max(0.1, interval))
    return summarize_monitor(samples)


def summarize_monitor(samples):
    signals = [s["signal_dbm"] for s in samples if s.get("signal_dbm") is not None]
    result = {"samples": samples, "count": len(samples)}
    if signals:
        avg = sum(signals) / len(signals)
        result.update({
            "signal_min": min(signals), "signal_max": max(signals),
            "signal_avg": round(avg, 1),
            "signal_swing": round(max(signals) - min(signals), 1),
            "stdev": round((sum((s - avg) ** 2 for s in signals) / len(signals)) ** 0.5, 2),
            "rating": signal_rating(avg),
        })
    bssids = [s["bssid"] for s in samples if s.get("bssid")]
    result["roamed"] = len(set(bssids)) > 1
    result["bssids"] = sorted(set(bssids))
    beacons = [s["missed_beacons"] for s in samples if s.get("missed_beacons") is not None]
    if len(beacons) > 1:
        result["missed_beacons_delta"] = beacons[-1] - beacons[0]
    return result


# --- interference analysis -------------------------------------------------


def analyze(networks, current=None, survey=None):
    """Turn a scan into an interference verdict and a channel recommendation."""
    by_band = {}
    for net in networks:
        if not net.get("channel"):
            continue
        by_band.setdefault(net.get("band") or band_of(net.get("freq") or 0), []).append(net)

    report = {"total_bss": len(networks), "bands": {}, "current": current or {},
              "findings": [], "recommendations": {}, "redacted": False}

    for band, nets in sorted(by_band.items()):
        channels = {}
        for net in nets:
            channels.setdefault(net["channel"], []).append(net)
        band_report = {
            "bss_count": len(nets),
            "channels": {},
            "congestion_score": {},
        }
        candidates = sorted(channels)
        if band == "2.4":
            candidates = sorted(set(candidates) | set(CLEAN_24GHZ))
        for cand in candidates:
            score = 0.0
            cochannel = 0
            adjacent = 0
            for net in nets:
                factor = overlap_factor(cand, net["channel"], band)
                if factor <= 0:
                    continue
                if net["channel"] == cand:
                    cochannel += 1
                else:
                    adjacent += 1
                weight = factor * signal_weight(net["signal_dbm"])
                if net.get("utilization_pct") is not None:
                    weight *= 1.0 + net["utilization_pct"] / 100.0
                score += weight
            band_report["congestion_score"][cand] = round(score, 2)
            if cand in channels:
                strongest = max(channels[cand],
                                key=lambda n: n["signal_dbm"] if n["signal_dbm"] is not None else -999)
                band_report["channels"][cand] = {
                    "bss": len(channels[cand]),
                    "cochannel": cochannel,
                    "overlapping": adjacent,
                    "strongest_dbm": strongest["signal_dbm"],
                    "strongest_ssid": strongest["ssid"] or (
                        "(hidden by macOS)" if strongest.get("redacted") else "(hidden)"),
                    "utilization_pct": max(
                        [n["utilization_pct"] for n in channels[cand]
                         if n.get("utilization_pct") is not None] or [None]),
                }
        pool = candidates
        if band == "2.4":
            pool = CLEAN_24GHZ
        elif band == "5":
            non_dfs = [c for c in candidates if c not in DFS_CHANNELS]
            pool = non_dfs or candidates
        if pool:
            best = min(pool, key=lambda c: band_report["congestion_score"].get(c, 0.0))
            band_report["best_channel"] = best
            band_report["best_score"] = band_report["congestion_score"].get(best, 0.0)
            report["recommendations"][band] = {
                "channel": best,
                "score": band_report["best_score"],
                "note": "lowest weighted co/adjacent-channel load%s" % (
                    "; 1/6/11 only (2.4 GHz channels overlap)" if band == "2.4" else
                    "; non-DFS preferred" if band == "5" else ""),
            }
        report["bands"][band] = band_report

    _add_findings(report, networks, current, survey)
    return report


def _add_findings(report, networks, current, survey):
    findings = report["findings"]
    cur = current or {}
    report["redacted"] = bool(cur.get("redacted")
                              or any(n.get("redacted") for n in networks))
    if report["redacted"]:
        findings.append(("info", HIDDEN_NAMES_HINT))
    sig = cur.get("signal_dbm")
    if sig is not None:
        if sig < -75:
            findings.append(("critical", "Signal %.0f dBm (%s): too weak for reliable "
                                         "traffic - move closer or add an AP."
                             % (sig, signal_rating(sig))))
        elif sig < -67:
            findings.append(("warn", "Signal %.0f dBm (%s): below the -67 dBm floor for "
                                     "voice/video." % (sig, signal_rating(sig))))
    snr = cur.get("snr_db")
    if snr is not None:
        if snr < 15:
            findings.append(("critical", "SNR %.0f dB: noise floor is close to the signal; "
                                         "expect retries and low rates." % snr))
        elif snr < 25:
            findings.append(("warn", "SNR %.0f dB: workable but not comfortable "
                                     "(25 dB+ is the target)." % snr))
    station = cur.get("station") or {}
    if station.get("retry_pct") is not None and station["retry_pct"] > 15:
        findings.append(("warn", "TX retry rate %.1f%% - a hallmark of interference or a "
                                 "weak link." % station["retry_pct"]))
    if station.get("fail_pct") is not None and station["fail_pct"] > 2:
        findings.append(("warn", "TX failure rate %.1f%% - frames are being dropped after "
                                 "retries." % station["fail_pct"]))
    proc = cur.get("proc") or {}
    if proc.get("missed_beacons"):
        findings.append(("info", "%d missed beacons counted since association."
                         % proc["missed_beacons"]))

    for entry in survey or []:
        if not entry.get("in_use"):
            continue
        if entry.get("busy_pct") is not None:
            level = "critical" if entry["busy_pct"] > 70 else (
                "warn" if entry["busy_pct"] > 40 else "info")
            findings.append((level, "Channel %s airtime %.0f%% busy (%.0f%% our RX, "
                                    "%.0f%% our TX, %.0f%% other/interference)."
                             % (entry.get("channel", "?"), entry["busy_pct"],
                                entry.get("rx_pct", 0), entry.get("tx_pct", 0),
                                entry.get("interference_pct", 0))))
            if entry.get("interference_pct", 0) > 20:
                findings.append(("warn", "%.0f%% of airtime is busy with traffic we cannot "
                                         "decode - non-Wi-Fi interference or distant "
                                         "co-channel APs." % entry["interference_pct"]))

    cur_channel = cur.get("channel")
    cur_band = cur.get("band") or (band_of(cur["freq"]) if cur.get("freq") else None)
    if cur_channel and cur_band and cur_band in report["bands"]:
        band_report = report["bands"][cur_band]
        info = band_report["channels"].get(cur_channel)
        if info:
            if info["cochannel"] > 3:
                findings.append(("warn", "%d other BSSes share channel %d - they take turns "
                                         "with you for airtime." % (info["cochannel"] - 1,
                                                                    cur_channel)))
            if cur_band == "2.4" and info["overlapping"] > 0:
                findings.append(("warn", "%d BSSes overlap channel %d without sharing it - "
                                         "partial overlap is worse than co-channel."
                                 % (info["overlapping"], cur_channel)))
        best = band_report.get("best_channel")
        if best and best != cur_channel:
            score_now = band_report["congestion_score"].get(cur_channel, 0.0)
            score_best = band_report.get("best_score", 0.0)
            if score_now - score_best > 1.0:
                findings.append(("info", "Channel %d looks clearer than your current "
                                         "channel %d (load %.1f vs %.1f)."
                                 % (best, cur_channel, score_best, score_now)))
    if cur_band == "2.4" and any(b == "5" for b in report["bands"]):
        findings.append(("info", "You are on 2.4 GHz; 5 GHz was seen nearby and is usually "
                                 "the better band indoors."))
    hidden = sum(1 for n in networks if not n.get("ssid"))
    if hidden:
        findings.append(("info", "%d hidden SSID(s) in range." % hidden))
    if not findings:
        findings.append(("ok", "No obvious radio problems in this snapshot."))
