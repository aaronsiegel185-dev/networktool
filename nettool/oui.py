"""MAC address vendor lookup.

Uses a system OUI database when one is installed (wireshark/nmap/ieee-data ship
one), and falls back to a small built-in table of prefixes that show up
constantly on enterprise and home LANs.
"""

import os
import re

_SYSTEM_DBS = [
    "/usr/share/wireshark/manuf",
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/share/ieee-data/oui.txt",
    "/var/lib/ieee-data/oui.txt",
    "/usr/share/misc/oui.txt",
]

BUILTIN = {
    "000000": "Xerox", "000c29": "VMware", "005056": "VMware", "001c14": "VMware",
    "000569": "VMware", "080027": "VirtualBox", "525400": "QEMU/KVM",
    "00155d": "Microsoft Hyper-V", "0050f2": "Microsoft", "001dd8": "Microsoft",
    "02420a": "Docker", "0242ac": "Docker",
    "00000c": "Cisco", "000142": "Cisco", "0001c7": "Cisco", "00036b": "Cisco",
    "000b46": "Cisco", "001b0d": "Cisco", "0026cb": "Cisco", "00e0fe": "Cisco",
    "6400f1": "Cisco", "c4b9cd": "Cisco", "f8b7e2": "Cisco", "e8b748": "Cisco",
    "001018": "Broadcom", "001bc5": "Broadcom",
    "0004f2": "Polycom", "000fe2": "Huawei", "001882": "Huawei", "781dba": "Huawei",
    "00095b": "Netgear", "000fb5": "Netgear", "20e52a": "Netgear", "9c3dcf": "Netgear",
    "001cf0": "D-Link", "1cbdb9": "D-Link", "0022b0": "D-Link",
    "001e58": "TP-Link", "50c7bf": "TP-Link", "a42bb0": "TP-Link", "9c5322": "TP-Link",
    "ec086b": "TP-Link", "6466b3": "TP-Link",
    "0018e7": "Cameo/Ubiquiti", "002722": "Ubiquiti", "24a43c": "Ubiquiti",
    "44d9e7": "Ubiquiti", "788a20": "Ubiquiti", "802aa8": "Ubiquiti", "fcecda": "Ubiquiti",
    "e063da": "Ubiquiti", "687251": "Ubiquiti", "dc9fdb": "Ubiquiti",
    "b4fbe4": "Ubiquiti", "f09fc2": "Ubiquiti", "0418d6": "Ubiquiti", "245a4c": "Ubiquiti",
    "001a1e": "Aruba/HPE", "6cf37f": "Aruba/HPE", "94b40f": "Aruba/HPE",
    "000883": "HP", "001560": "HP", "3464a9": "HP", "9457a5": "HP", "b499ba": "HP",
    "001279": "HP", "00306e": "HP", "ac162d": "HP",
    "001a4b": "HP", "d89d67": "HP", "70106f": "HP",
    "000c42": "MikroTik", "4c5e0c": "MikroTik", "6c3b6b": "MikroTik", "e48d8c": "MikroTik",
    "2cc81b": "MikroTik", "dc2c6e": "MikroTik", "744d28": "MikroTik", "48a98a": "MikroTik",
    "001bfc": "Asus", "1c872c": "Asus", "2c4d54": "Asus", "b06ebf": "Asus", "d850e6": "Asus",
    "000e8f": "Sercomm", "0026f2": "Netgear", "001aa0": "Dell", "00188b": "Dell",
    "18fb7b": "Dell", "b8ca3a": "Dell", "d094662": "Dell", "f8bc12": "Dell",
    "001517": "Intel", "001b21": "Intel", "3c9709": "Intel", "7c7a91": "Intel",
    "a0a8cd": "Intel", "e4b318": "Intel", "8c164d": "Intel", "94e6f7": "Intel",
    "001124": "Apple", "0017f2": "Apple", "003ee1": "Apple", "0c4de9": "Apple",
    "3c0754": "Apple", "40a6d9": "Apple", "6c709f": "Apple", "a45e60": "Apple",
    "ac87a3": "Apple", "b8e856": "Apple", "d0817a": "Apple", "f0dbf8": "Apple",
    "001632": "Samsung", "0021d1": "Samsung", "5c0a5b": "Samsung", "8425db": "Samsung",
    "d0176a": "Samsung", "f8042e": "Samsung",
    "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi", "e45f01": "Raspberry Pi",
    "2ccf67": "Raspberry Pi", "d83add": "Raspberry Pi", "28cdc1": "Raspberry Pi",
    "18fe34": "Espressif", "240ac4": "Espressif", "3c71bf": "Espressif",
    "5ccf7f": "Espressif", "807d3a": "Espressif", "a020a6": "Espressif",
    "ecfabc": "Espressif", "84f3eb": "Espressif",
    "0007ab": "Samsung Electronics", "00051b": "Magic Control",
    "001b63": "Apple", "704d7b": "Asus", "acde48": "Private (randomized)",
    "0050c2": "IEEE Registration Authority",
    "000e0c": "Intel", "001d09": "Dell", "84d8c9": "Sagemcom", "0026b8": "Actiontec",
    "001dbe": "Zyxel", "5cf4ab": "Zyxel", "0013f7": "SMC", "001e2a": "Netgear",
    "0090a9": "Western Digital", "00904c": "Epigram/Broadcom",
    "001a11": "Google", "3c5ab4": "Google", "f4f5d8": "Google", "6466b3f": "Google",
    "d8eb97": "TRENDnet", "0080c8": "D-Link", "000d93": "Apple",
    "001e8c": "Asus", "e0cb4e": "Asus", "00248c": "Asus",
    "0011d8": "Asus", "3497f6": "Asus", "0c9d92": "Asus",
    "001ff3": "Apple", "000393": "Apple", "8863df": "Apple", "9803d8": "Apple",
    "0060b0": "HP", "441ea1": "HP", "00110a": "HP",
    "1866da": "Dell", "c81f66": "Dell", "509a4c": "Dell",
    "000acd": "Sunrise Telecom", "0004ac": "IBM", "00096b": "IBM",
    "0021f6": "Oracle/Sun", "0003ba": "Sun", "00144f": "Oracle",
    "000e58": "Sonos", "347e5c": "Sonos", "5cae7c": "Sonos", "b8e937": "Sonos",
    "18b430": "Nest", "641666": "Nest", "d8eb46": "Nest",
    "6854fd": "Amazon", "747548": "Amazon", "ac63be": "Amazon", "fcd2b6": "Amazon",
    "0024e4": "Withings", "e0763e": "Amazon", "44650d": "Amazon",
    "001788": "Philips Hue", "ecb5fa": "Philips", "0017880": "Philips",
    "001132": "Synology", "0011321": "Synology", "0c9d92s": "Synology",
    "00089b": "ICP Electronics", "24bcf8": "Huawei", "b4b686": "HP",
    "8c1f64": "IEEE Registration Authority",
}

_cache = None


def _load_system_db():
    table = {}
    for path in _SYSTEM_DBS:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # wireshark manuf / nmap prefixes: "00:00:0C  Cisco" or "000000 Xerox"
                    m = re.match(r"^([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){2,5}|[0-9A-Fa-f]{6})"
                                 r"(?:/\d+)?\s+(.+)$", line)
                    if m:
                        prefix = m.group(1).replace(":", "").lower()[:6]
                        name = m.group(2).split("\t")[0].strip()
                        table.setdefault(prefix, name)
                        continue
                    # ieee oui.txt: "00-00-0C   (hex)\t\tCISCO SYSTEMS, INC."
                    m = re.match(r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$",
                                 line)
                    if m:
                        table.setdefault(m.group(1).replace("-", "").lower(), m.group(2).strip())
        except OSError:
            continue
        if table:
            break
    return table


def lookup(mac):
    """Return a vendor string for a MAC address, or '' when unknown."""
    global _cache
    if not mac:
        return ""
    clean = re.sub(r"[^0-9A-Fa-f]", "", str(mac)).lower()
    if len(clean) < 6:
        return ""
    prefix = clean[:6]
    if _cache is None:
        _cache = _load_system_db()
    if prefix in _cache:
        return _cache[prefix]
    if prefix in BUILTIN:
        return BUILTIN[prefix]
    # Locally administered / randomized addresses have bit 1 of the first octet set.
    try:
        first = int(clean[0:2], 16)
    except ValueError:
        return ""
    if first & 0x02:
        return "(locally administered / randomized)"
    return ""


def is_multicast(mac):
    clean = re.sub(r"[^0-9A-Fa-f]", "", str(mac))
    return len(clean) >= 2 and (int(clean[0:2], 16) & 0x01) == 1
