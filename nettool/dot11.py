"""802.11 (Wi-Fi) frame decoding: radiotap headers, management/control/data frames,
and the information elements that matter for diagnosing a wireless network.

This is what makes a monitor-mode capture readable: which APs are beaconing, at what
signal, on what channel, how loaded they say they are, who is being deauthenticated and
why, and how much of the air is retries.
"""

import struct

from .oui import lookup as oui_lookup

# --- radiotap ---------------------------------------------------------------

# (index, name, struct format, alignment) in presence-bit order.
RADIOTAP_FIELDS = [
    (0, "tsft", "<Q", 8),
    (1, "flags", "<B", 1),
    (2, "rate", "<B", 1),
    (3, "channel", "<HH", 2),
    (4, "fhss", "<BB", 1),
    (5, "signal_dbm", "<b", 1),
    (6, "noise_dbm", "<b", 1),
    (7, "lock_quality", "<H", 2),
    (8, "tx_attenuation", "<H", 2),
    (9, "db_tx_attenuation", "<H", 2),
    (10, "tx_power_dbm", "<b", 1),
    (11, "antenna", "<B", 1),
    (12, "db_signal", "<B", 1),
    (13, "db_noise", "<B", 1),
    (14, "rx_flags", "<H", 2),
    (15, "tx_flags", "<H", 2),
    (16, "rts_retries", "<B", 1),
    (17, "data_retries", "<B", 1),
    (18, "xchannel", "<IHBB", 4),
    (19, "mcs", "<BBB", 1),
    (20, "ampdu", "<IHBB", 4),
    (21, "vht", "<HBB4sBBH", 2),
    (22, "timestamp", "<QHBB", 8),
]
RADIOTAP_BY_BIT = {index: entry for entry in RADIOTAP_FIELDS for index in (entry[0],)}

RADIOTAP_FLAG_FCS = 0x10
RADIOTAP_FLAG_BADFCS = 0x40
CHANNEL_FLAG_2GHZ = 0x0080
CHANNEL_FLAG_5GHZ = 0x0100


def _align(offset, alignment):
    remainder = offset % alignment
    return offset + (alignment - remainder) if remainder else offset


def parse_radiotap(data):
    """Decode a radiotap header. Returns (fields, payload_offset).

    Unknown or vendor fields end field parsing but never break the offset: `it_len`
    always tells us where the 802.11 frame starts.
    """
    if len(data) < 8:
        return {}, 0
    version, _pad, length, present = struct.unpack_from("<BBHI", data, 0)
    if version != 0 or length < 8 or length > len(data):
        return {}, 0
    fields = {"radiotap_len": length}
    presence = [present]
    offset = 8
    while present & 0x80000000 and offset + 4 <= length:
        present = struct.unpack_from("<I", data, offset)[0]
        presence.append(present)
        offset += 4
    # Only the first presence word maps to the standard fields we care about.
    bitmap = presence[0]
    for bit, name, fmt, alignment in RADIOTAP_FIELDS:
        if not bitmap & (1 << bit):
            continue
        size = struct.calcsize(fmt)
        offset = _align(offset, alignment)
        if offset + size > length:
            break
        values = struct.unpack_from(fmt, data, offset)
        offset += size
        if name == "channel":
            freq, flags = values
            fields["freq"] = freq
            fields["channel"] = freq_to_channel(freq)
            fields["band"] = "2.4" if flags & CHANNEL_FLAG_2GHZ else (
                "5" if flags & CHANNEL_FLAG_5GHZ else band_of(freq))
        elif name == "rate":
            fields["rate_mbps"] = values[0] / 2.0
        elif name == "flags":
            fields["flags"] = values[0]
            fields["has_fcs"] = bool(values[0] & RADIOTAP_FLAG_FCS)
            fields["bad_fcs"] = bool(values[0] & RADIOTAP_FLAG_BADFCS)
        elif name == "mcs":
            known, mcs_flags, index = values
            fields["mcs_index"] = index
            if known & 0x01:
                fields["bandwidth_mhz"] = {0: 20, 1: 40, 2: 20, 3: 20}.get(mcs_flags & 0x03, 20)
            fields["short_gi"] = bool(mcs_flags & 0x04)
        elif len(values) == 1:
            fields[name] = values[0]
        else:
            fields[name] = values
    return fields, length


def freq_to_channel(freq):
    freq = int(freq)
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if 5160 <= freq <= 5885:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return 0


def band_of(freq):
    freq = int(freq)
    if 2400 <= freq <= 2500:
        return "2.4"
    if 5150 <= freq <= 5900:
        return "5"
    if 5925 <= freq <= 7125:
        return "6"
    return "?"


# --- 802.11 frames ----------------------------------------------------------

TYPE_MANAGEMENT = 0
TYPE_CONTROL = 1
TYPE_DATA = 2

MANAGEMENT_SUBTYPES = {
    0: "assoc-request", 1: "assoc-response", 2: "reassoc-request", 3: "reassoc-response",
    4: "probe-request", 5: "probe-response", 6: "timing-advert", 8: "beacon", 9: "atim",
    10: "disassociation", 11: "authentication", 12: "deauthentication", 13: "action",
    14: "action-no-ack",
}
CONTROL_SUBTYPES = {
    4: "beamforming-report", 5: "vht-ndp-announce", 7: "control-wrapper",
    8: "block-ack-request", 9: "block-ack", 10: "ps-poll", 11: "rts", 12: "cts",
    13: "ack", 14: "cf-end", 15: "cf-end-ack",
}
DATA_SUBTYPES = {
    0: "data", 1: "data-cf-ack", 2: "data-cf-poll", 4: "null", 8: "qos-data",
    9: "qos-data-cf-ack", 12: "qos-null",
}

# The reason a client was thrown off, which is often the whole answer.
REASON_CODES = {
    1: "unspecified", 2: "previous authentication no longer valid",
    3: "station left (deauthenticated)", 4: "inactivity timeout",
    5: "AP out of resources", 6: "class 2 frame from non-authenticated station",
    7: "class 3 frame from non-associated station", 8: "station left (disassociated)",
    9: "not authenticated", 13: "invalid information element",
    14: "MIC failure", 15: "4-way handshake timeout",
    16: "group key handshake timeout", 17: "handshake element mismatch",
    18: "invalid group cipher", 19: "invalid pairwise cipher", 20: "invalid AKMP",
    23: "802.1X authentication failed", 24: "cipher suite rejected",
    34: "poor channel conditions (disassociated)",
}
STATUS_CODES = {0: "success", 1: "unspecified failure", 12: "association denied - no more room",
                17: "association denied - too many stations", 18: "unsupported rates",
                40: "invalid information element", 43: "invalid pairwise cipher"}


def _mac(raw):
    return ":".join("%02x" % b for b in bytearray(raw))


def parse_dot11(frame):
    """Decode an 802.11 frame (no radiotap). Returns a dict; never raises."""
    if len(frame) < 10:
        return {"type": "runt", "subtype": "", "length": len(frame)}
    fc, duration = struct.unpack_from("<HH", frame, 0)
    version = fc & 0x0003
    ftype = (fc >> 2) & 0x0003
    subtype = (fc >> 4) & 0x000F
    flags = (fc >> 8) & 0x00FF
    info = {
        "version": version,
        "type_id": ftype,
        "subtype_id": subtype,
        "duration": duration,
        "to_ds": bool(flags & 0x01),
        "from_ds": bool(flags & 0x02),
        "more_fragments": bool(flags & 0x04),
        "retry": bool(flags & 0x08),
        "power_management": bool(flags & 0x10),
        "more_data": bool(flags & 0x20),
        "protected": bool(flags & 0x40),
        "length": len(frame),
    }
    if ftype == TYPE_MANAGEMENT:
        info["type"] = "management"
        info["subtype"] = MANAGEMENT_SUBTYPES.get(subtype, "subtype-%d" % subtype)
    elif ftype == TYPE_CONTROL:
        info["type"] = "control"
        info["subtype"] = CONTROL_SUBTYPES.get(subtype, "subtype-%d" % subtype)
    elif ftype == TYPE_DATA:
        info["type"] = "data"
        info["subtype"] = DATA_SUBTYPES.get(subtype, "subtype-%d" % subtype)
    else:
        info["type"] = "extension"
        info["subtype"] = "subtype-%d" % subtype

    # Control frames carry fewer addresses than everything else.
    if ftype == TYPE_CONTROL:
        if len(frame) >= 10:
            info["addr1"] = _mac(frame[4:10])
            info["dst"] = info["addr1"]
        if subtype in (8, 9, 10, 11, 14, 15) and len(frame) >= 16:
            info["addr2"] = _mac(frame[10:16])
            info["src"] = info["addr2"]
        return info

    if len(frame) < 24:
        info["truncated"] = True
        return info
    addr1 = _mac(frame[4:10])
    addr2 = _mac(frame[10:16])
    addr3 = _mac(frame[16:22])
    sequence = struct.unpack_from("<H", frame, 22)[0]
    info["addr1"] = addr1
    info["addr2"] = addr2
    info["addr3"] = addr3
    info["sequence"] = sequence >> 4
    info["fragment"] = sequence & 0x0F

    to_ds, from_ds = info["to_ds"], info["from_ds"]
    if not to_ds and not from_ds:
        info["dst"], info["src"], info["bssid"] = addr1, addr2, addr3
    elif not to_ds and from_ds:
        info["dst"], info["bssid"], info["src"] = addr1, addr2, addr3
    elif to_ds and not from_ds:
        info["bssid"], info["src"], info["dst"] = addr1, addr2, addr3
    else:
        info["dst"], info["src"] = addr3, _mac(frame[24:30]) if len(frame) >= 30 else ""
        info["bssid"] = ""

    offset = 24
    if to_ds and from_ds:
        offset = 30
    if ftype == TYPE_DATA and subtype & 0x08:      # QoS variants carry two more bytes
        if len(frame) >= offset + 2:
            qos = struct.unpack_from("<H", frame, offset)[0]
            info["tid"] = qos & 0x000F
        offset += 2
    info["body_offset"] = offset

    if ftype == TYPE_MANAGEMENT:
        _parse_management_body(info, frame, offset, subtype)
    if info.get("src"):
        info["src_vendor"] = oui_lookup(info["src"])
    return info


def _parse_management_body(info, frame, offset, subtype):
    if subtype in (8, 5):                      # beacon, probe response
        if len(frame) < offset + 12:
            return
        _timestamp, interval, capability = struct.unpack_from("<QHH", frame, offset)
        info["beacon_interval"] = interval
        info["privacy"] = bool(capability & 0x0010)
        info["ess"] = bool(capability & 0x0001)
        info["short_preamble"] = bool(capability & 0x0020)
        _parse_elements(info, frame, offset + 12)
    elif subtype in (0, 2):                    # association / reassociation request
        _parse_elements(info, frame, offset + 4)
    elif subtype in (1, 3):                    # association / reassociation response
        if len(frame) >= offset + 6:
            _capability, status, _aid = struct.unpack_from("<HHH", frame, offset)
            info["status_code"] = status
            info["status"] = STATUS_CODES.get(status, "status %d" % status)
        _parse_elements(info, frame, offset + 6)
    elif subtype == 4:                         # probe request
        _parse_elements(info, frame, offset)
    elif subtype in (10, 12):                  # disassociation, deauthentication
        if len(frame) >= offset + 2:
            reason = struct.unpack_from("<H", frame, offset)[0]
            info["reason_code"] = reason
            info["reason"] = REASON_CODES.get(reason, "reason %d" % reason)
    elif subtype == 11:                        # authentication
        if len(frame) >= offset + 6:
            algorithm, sequence, status = struct.unpack_from("<HHH", frame, offset)
            info["auth_algorithm"] = {0: "open", 1: "shared-key", 2: "fast-transition",
                                      3: "SAE"}.get(algorithm, "algorithm %d" % algorithm)
            info["auth_sequence"] = sequence
            info["status_code"] = status
            info["status"] = STATUS_CODES.get(status, "status %d" % status)


def _parse_elements(info, frame, offset):
    """Walk the tagged information elements at the end of a management frame."""
    security = []
    standards = []
    while offset + 2 <= len(frame):
        element_id = frame[offset]
        length = frame[offset + 1]
        value = frame[offset + 2:offset + 2 + length]
        if len(value) < length:
            break
        offset += 2 + length
        if element_id == 0:
            info["ssid"] = value.decode("utf-8", "replace").rstrip("\x00")
            info["hidden"] = len(value) == 0 or set(value) == {0}
        elif element_id == 3 and length >= 1:
            info["channel"] = value[0]
        elif element_id == 7 and length >= 2:
            info["country"] = value[:2].decode("ascii", "replace").strip()
        elif element_id == 11 and length >= 5:
            stations, utilization = struct.unpack("<HB", value[:3])
            info["stations"] = stations
            info["utilization_pct"] = round(100.0 * utilization / 255.0, 1)
        elif element_id == 45:
            standards.append("n")
        elif element_id == 48:
            security.append("WPA2/WPA3")
            info.update(_parse_rsn(value))
        elif element_id == 61 and length >= 1:
            info.setdefault("channel", value[0])
            if "n" not in standards:
                standards.append("n")
        elif element_id in (191, 192):
            if "ac" not in standards:
                standards.append("ac")
        elif element_id == 255 and length >= 1 and value[0] in (35, 36):
            if "ax" not in standards:
                standards.append("ax")
        elif element_id == 221 and length >= 4:
            if value[:4] == b"\x00\x50\xf2\x01":
                security.append("WPA")
    if standards:
        info["standards"] = standards
    if security:
        info.setdefault("security", []).extend(
            s for s in security if s not in info.get("security", []))
    elif "security" not in info:
        info["security"] = ["WEP"] if info.get("privacy") else ["open"]


AKM_SUITES = {1: "802.1X/Enterprise", 2: "PSK", 5: "802.1X-SHA256", 6: "PSK-SHA256",
              8: "SAE", 9: "FT-SAE", 11: "802.1X-SUITE-B", 18: "OWE"}
CIPHER_SUITES = {1: "WEP-40", 2: "TKIP", 4: "CCMP-128", 5: "WEP-104", 8: "GCMP-128",
                 9: "GCMP-256", 10: "CCMP-256"}


def _parse_rsn(value):
    """Pull the cipher and authentication suites out of an RSN element."""
    out = {}
    try:
        if len(value) < 8:
            return out
        offset = 2                                  # version
        group = value[offset:offset + 4]
        out["group_cipher"] = CIPHER_SUITES.get(group[3], "suite %d" % group[3])
        offset += 4
        count = struct.unpack_from("<H", value, offset)[0]
        offset += 2
        pairwise = []
        for _ in range(min(count, 8)):
            suite = value[offset:offset + 4]
            if len(suite) < 4:
                return out
            pairwise.append(CIPHER_SUITES.get(suite[3], "suite %d" % suite[3]))
            offset += 4
        out["pairwise_ciphers"] = pairwise
        count = struct.unpack_from("<H", value, offset)[0]
        offset += 2
        akms = []
        for _ in range(min(count, 8)):
            suite = value[offset:offset + 4]
            if len(suite) < 4:
                return out
            akms.append(AKM_SUITES.get(suite[3], "akm %d" % suite[3]))
            offset += 4
        out["akm_suites"] = akms
    except (struct.error, IndexError):
        return out
    return out


def decode(data, linktype):
    """Decode one captured wireless frame. `linktype` is the pcap DLT."""
    fields = {}
    offset = 0
    if linktype == 127:                       # IEEE802_11_RADIOTAP
        fields, offset = parse_radiotap(data)
    elif linktype != 105:                     # IEEE802_11
        return None
    frame = data[offset:]
    if fields.get("has_fcs") and len(frame) > 4:
        frame = frame[:-4]
    info = parse_dot11(frame)
    info.update({k: v for k, v in fields.items() if k not in ("flags",)})
    return info


def summary(info):
    """One-line description of a wireless frame."""
    bits = [info.get("subtype", info.get("type", "?"))]
    if info.get("ssid") is not None:
        bits.append('"%s"' % (info["ssid"] or "<hidden>"))
    source = info.get("src") or info.get("addr2") or ""
    dest = info.get("dst") or info.get("addr1") or ""
    if source or dest:
        bits.append("%s -> %s" % (source or "?", dest or "?"))
    if info.get("channel"):
        bits.append("ch %s" % info["channel"])
    if info.get("signal_dbm") is not None:
        bits.append("%d dBm" % info["signal_dbm"])
    if info.get("retry"):
        bits.append("[retry]")
    if info.get("reason"):
        bits.append("reason: %s" % info["reason"])
    if info.get("status") and info.get("status") != "success":
        bits.append("status: %s" % info["status"])
    return " ".join(str(b) for b in bits)


# --- capture-wide analysis --------------------------------------------------


class Survey(object):
    """Aggregate decoded 802.11 frames into an AP/client inventory with findings.

    A monitor-mode capture contains everything a Wi-Fi scan would tell you and more:
    who is beaconing, how loudly, how much of the air is retries, and who is being
    kicked off and why.
    """

    def __init__(self):
        self.frames = 0
        self.decoded = 0
        self.retries = 0
        self.bad_fcs = 0
        self.first_ts = None
        self.last_ts = None
        self.access_points = {}
        self.clients = {}
        self.channels = {}
        self.deauths = {}
        self.frame_types = {}

    def add(self, info, timestamp=None):
        if info is None:
            return
        self.frames += 1
        if info.get("type") in ("management", "control", "data"):
            self.decoded += 1
        if timestamp is not None:
            self.first_ts = timestamp if self.first_ts is None else min(self.first_ts, timestamp)
            self.last_ts = timestamp if self.last_ts is None else max(self.last_ts, timestamp)
        key = "%s/%s" % (info.get("type", "?"), info.get("subtype", "?"))
        self.frame_types[key] = self.frame_types.get(key, 0) + 1
        if info.get("retry"):
            self.retries += 1
        if info.get("bad_fcs"):
            self.bad_fcs += 1

        channel = info.get("channel")
        if channel:
            entry = self.channels.setdefault(channel, {"frames": 0, "bssids": set()})
            entry["frames"] += 1
            if info.get("bssid"):
                entry["bssids"].add(info["bssid"])

        if info.get("subtype") in ("beacon", "probe-response") and info.get("bssid"):
            self._add_ap(info, timestamp)
        elif info.get("subtype") in ("deauthentication", "disassociation"):
            self._add_deauth(info)
        self._add_client(info, timestamp)

    def _add_ap(self, info, timestamp):
        bssid = info["bssid"]
        ap = self.access_points.setdefault(bssid, {
            "bssid": bssid, "ssid": info.get("ssid", ""), "beacons": 0,
            "signals": [], "channel": info.get("channel"), "band": info.get("band", ""),
            "security": info.get("security", []), "standards": info.get("standards", []),
            "vendor": oui_lookup(bssid), "stations": None, "utilization_pct": None,
            "beacon_interval": info.get("beacon_interval"), "hidden": info.get("hidden", False),
            "first_seen": timestamp, "last_seen": timestamp, "country": info.get("country", ""),
        })
        ap["beacons"] += 1
        if info.get("ssid"):
            ap["ssid"] = info["ssid"]
        if info.get("channel"):
            ap["channel"] = info["channel"]
        if info.get("band"):
            ap["band"] = info["band"]
        if info.get("signal_dbm") is not None:
            ap["signals"].append(info["signal_dbm"])
        for field in ("stations", "utilization_pct", "beacon_interval", "country"):
            if info.get(field) is not None and info.get(field) != "":
                ap[field] = info[field]
        if info.get("security"):
            ap["security"] = info["security"]
        if info.get("standards"):
            ap["standards"] = info["standards"]
        if timestamp is not None:
            ap["last_seen"] = timestamp
            if ap["first_seen"] is None:
                ap["first_seen"] = timestamp

    def _add_deauth(self, info):
        key = (info.get("src", ""), info.get("dst", ""), info.get("reason", ""))
        entry = self.deauths.setdefault(key, {
            "src": key[0], "dst": key[1], "reason": key[2],
            "reason_code": info.get("reason_code"), "count": 0,
            "subtype": info.get("subtype"),
        })
        entry["count"] += 1

    def _add_client(self, info, timestamp):
        source = info.get("src")
        if not source or source == info.get("bssid"):
            return
        if info.get("subtype") in ("beacon", "probe-response"):
            return
        client = self.clients.setdefault(source, {
            "mac": source, "vendor": oui_lookup(source), "frames": 0,
            "signals": [], "bssids": set(), "probes": set(), "retries": 0,
        })
        client["frames"] += 1
        if info.get("retry"):
            client["retries"] += 1
        if info.get("signal_dbm") is not None:
            client["signals"].append(info["signal_dbm"])
        if info.get("bssid"):
            client["bssids"].add(info["bssid"])
        if info.get("subtype") == "probe-request" and info.get("ssid"):
            client["probes"].add(info["ssid"])

    # -- reporting --

    def ap_list(self):
        out = []
        for ap in self.access_points.values():
            signals = ap["signals"]
            entry = dict(ap)
            entry.pop("signals", None)
            entry["signal_dbm"] = round(sum(signals) / len(signals), 1) if signals else None
            entry["signal_max"] = max(signals) if signals else None
            entry["signal_min"] = min(signals) if signals else None
            out.append(entry)
        return sorted(out, key=lambda a: a["signal_dbm"] if a["signal_dbm"] is not None else -999,
                      reverse=True)

    def client_list(self):
        out = []
        for client in self.clients.values():
            signals = client["signals"]
            entry = dict(client)
            entry.pop("signals", None)
            entry["bssids"] = sorted(client["bssids"])
            entry["probes"] = sorted(client["probes"])
            entry["signal_dbm"] = round(sum(signals) / len(signals), 1) if signals else None
            entry["retry_pct"] = round(100.0 * client["retries"] / client["frames"], 1) \
                if client["frames"] else 0.0
            out.append(entry)
        return sorted(out, key=lambda c: c["frames"], reverse=True)

    def to_networks(self):
        """AP inventory in the shape `nettool.wifi.analyze` expects, so a capture can
        drive the same channel-congestion analysis as a live scan."""
        networks = []
        for ap in self.ap_list():
            networks.append({
                "ssid": ap["ssid"], "bssid": ap["bssid"], "channel": ap["channel"],
                "band": ap["band"] or (band_of(ap.get("freq", 0)) if ap.get("freq") else ""),
                "freq": ap.get("freq"), "signal_dbm": ap["signal_dbm"],
                "utilization_pct": ap["utilization_pct"], "stations": ap["stations"],
                "security": ap["security"], "standards": ap["standards"],
                "width_mhz": 20, "associated": False,
            })
        return networks

    def duration(self):
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)

    def retry_pct(self):
        return round(100.0 * self.retries / self.frames, 1) if self.frames else 0.0

    def findings(self):
        out = []
        retry = self.retry_pct()
        if self.frames >= 50:
            if retry > 25:
                out.append(("critical", "%.0f%% of frames are retransmissions - the air is "
                                        "congested or the signal is marginal." % retry))
            elif retry > 12:
                out.append(("warn", "%.0f%% of frames are retransmissions." % retry))
        if self.bad_fcs and self.frames:
            share = 100.0 * self.bad_fcs / self.frames
            if share > 5:
                out.append(("warn", "%.0f%% of frames failed their checksum - interference "
                                    "or a capture radio at the edge of range." % share))
        total_deauths = sum(entry["count"] for entry in self.deauths.values())
        if total_deauths:
            level = "critical" if total_deauths > 20 else "warn"
            worst = max(self.deauths.values(), key=lambda e: e["count"])
            out.append((level, "%d deauth/disassoc frames seen; the most common is "
                               "\"%s\" (%d times, %s -> %s)."
                        % (total_deauths, worst["reason"], worst["count"],
                           worst["src"] or "?", worst["dst"] or "?")))
        hidden = [ap for ap in self.access_points.values() if ap.get("hidden")]
        if hidden:
            out.append(("info", "%d hidden SSID(s) beaconing." % len(hidden)))
        open_aps = [ap for ap in self.access_points.values()
                    if ap.get("security") == ["open"]]
        if open_aps:
            out.append(("info", "%d open network(s): %s"
                        % (len(open_aps),
                           ", ".join(sorted(ap["ssid"] or "(hidden)" for ap in open_aps)))))
        if not self.access_points and self.frames:
            out.append(("info", "No beacons in this capture - it may not be a monitor-mode "
                                "capture, or the radio was on another channel."))
        if not out:
            out.append(("ok", "Nothing alarming in this capture."))
        return out

    def report(self):
        return {
            "frames": self.frames,
            "duration": round(self.duration(), 2),
            "retry_pct": self.retry_pct(),
            "bad_fcs": self.bad_fcs,
            "frame_types": dict(sorted(self.frame_types.items(),
                                       key=lambda kv: kv[1], reverse=True)),
            "channels": {ch: {"frames": data["frames"], "bssids": len(data["bssids"])}
                         for ch, data in sorted(self.channels.items())},
            "access_points": self.ap_list(),
            "clients": self.client_list(),
            "deauths": sorted(self.deauths.values(), key=lambda e: e["count"], reverse=True),
            "findings": self.findings(),
        }


def survey_pcap(path):
    """Decode a monitor-mode capture file into a Survey."""
    from .pcap import PcapReader

    survey = Survey()
    with PcapReader(path) as reader:
        if reader.linktype not in (105, 127):
            raise ValueError(
                "%s is not a wireless capture (link type %d). Monitor-mode captures use "
                "radiotap (127) or 802.11 (105)." % (path, reader.linktype))
        for timestamp, data, _orig in reader:
            survey.add(decode(data, reader.linktype), timestamp)
    return survey
