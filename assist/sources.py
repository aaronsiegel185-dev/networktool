"""Sources: the files a notebook is grounded in.

A model cannot read a pcap, a 90 MB log or a screen recording. What it can read
is a careful rendering of one, so every source is ingested once - copied in,
classified, and turned into text the model can actually reason about - and that
rendering is kept beside the original.

The original is never replaced by its rendering. Both are kept, so a claim the
model makes about a capture can be checked against the capture itself.

Rendering a pcap is done by Network Tool's own analyzer, which means Assist
reports exactly what the Analyse tab reports. There is one implementation of
"what is in this capture", not two that can disagree.
"""

import json
import os

from . import media

# A rendering has to fit in the model's context alongside everything else, and
# a local model's context is not generous. These are per-source budgets; the
# notebook applies its own ceiling across all of them.
MAX_DIGEST = 6000
MAX_TEXT_LINES = 400
MAX_LINE = 500

# Extensions worth trusting when the bytes are ambiguous. Capture files are
# sniffed properly below; this is for the text-ish kinds, where the extension
# is the only thing that distinguishes a log from a config.
TEXT_EXTENSIONS = {
    ".txt": "text", ".log": "log", ".md": "text", ".csv": "table",
    ".json": "json", ".yaml": "config", ".yml": "config", ".conf": "config",
    ".cfg": "config", ".ini": "config", ".xml": "text", ".tsv": "table",
}

PCAP_MAGIC = (
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",      # pcap, either endianness
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",      # pcap, nanosecond
    b"\x0a\x0d\x0d\x0a",                            # pcapng
)


class SourceError(Exception):
    pass


def classify(path):
    """What kind of source this is, from its bytes first and its name second."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(16)
    except OSError as exc:
        raise SourceError("cannot read %s: %s" % (path, exc.strerror or exc))

    if head.startswith(PCAP_MAGIC):
        return "capture"
    # media.sniff knows images by magic and asks ffprobe about video.
    kind = media.sniff(path)
    if kind == "image":
        return "screenshot"
    if kind == "video":
        return "recording"

    extension = os.path.splitext(path)[1].lower()
    if extension in TEXT_EXTENSIONS:
        return TEXT_EXTENSIONS[extension]
    # Anything that decodes as UTF-8 and is mostly printable is worth reading.
    if _looks_textual(path):
        return "text"
    return "other"


def _looks_textual(path, probe=4096):
    try:
        with open(path, "rb") as handle:
            chunk = handle.read(probe)
    except OSError:
        return False
    if not chunk or b"\x00" in chunk:
        return False
    try:
        chunk.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


# --- rendering -------------------------------------------------------------

def digest(path, kind=None):
    """Render a source as text the model can reason about.

    Returns (text, note). The note is a one-line description for the person
    looking at the source list, and is deliberately short.
    """
    kind = kind or classify(path)
    if kind == "capture":
        return _digest_capture(path)
    if kind == "screenshot":
        return "", _describe_image(path)
    if kind == "recording":
        return "", _describe_video(path)
    if kind in ("text", "log", "json", "config", "table"):
        return _digest_text(path, kind)
    return "", "%s (not readable as text)" % _size(path)


def _describe_image(path):
    info = media.describe(path)
    width, height = info.get("width"), info.get("height")
    if width and height:
        return "screenshot, %d x %d" % (width, height)
    # Without ffprobe the dimensions are simply unknown; the size still tells
    # someone scanning the source list which screenshot this is.
    return "screenshot, %s" % _size(path)


def _describe_video(path):
    info = media.describe(path)
    parts = []
    if info.get("duration_s"):
        parts.append("%.0fs" % info["duration_s"])
    if info.get("width") and info.get("height"):
        parts.append("%d x %d" % (info["width"], info["height"]))
    return "recording, %s" % ", ".join(parts) if parts else "screen recording"


def _digest_capture(path):
    """A capture, through Network Tool's analyzer, as prose.

    Imported here rather than at module scope: Assist must remain usable on a
    machine where only the Assist part is installed, and a notebook with no
    captures in it should not require the network side to be importable.
    """
    try:
        from nettool.analyze import analyze_pcap
    except ImportError:
        return "", "packet capture (Network Tool is not installed, so it was not read)"

    try:
        analysis = analyze_pcap(path)
    except Exception as exc:
        return "", "packet capture (could not be read: %s)" % exc

    lines = ["PACKET CAPTURE: %s" % os.path.basename(path)]
    duration = analysis.duration()
    lines.append("%d packets, %s, over %.1f seconds."
                 % (analysis.packets, _bytes(analysis.bytes), duration))

    hierarchy = analysis.protocol_hierarchy()
    if hierarchy:
        top = ", ".join("%s %d%%" % (row["layers"], round(row["packets_pct"]))
                        for row in hierarchy[:8])
        lines.append("Protocols by share of packets: %s." % top)

    # One level of conversation, not three. The analyzer tracks ethernet, IP
    # and transport separately, and listing all of them says the same traffic
    # three times over - which wastes the context the model has to reason in.
    conversations = (analysis.conversation_list(kind="tcp", top=6)
                     + analysis.conversation_list(kind="udp", top=4))
    conversations.sort(key=lambda row: row["bytes"], reverse=True)
    if not conversations:
        conversations = analysis.conversation_list(kind="ipv4", top=8)
    if conversations:
        lines.append("")
        lines.append("Busiest conversations:")
        for row in conversations[:8]:
            protocol = (" %s" % row["protocol"]) if row.get("protocol") else ""
            lines.append("  %s <-> %s  %d packets, %s%s"
                         % (row["a"], row["b"], row["packets"],
                            _bytes(row["bytes"]), protocol))

    tcp = analysis.tcp_report()
    if tcp["segments"]:
        lines.append("")
        lines.append("TCP: %d segments across %d flows, %d%% retransmitted, "
                     "%d resets, %d zero-window."
                     % (tcp["segments"], tcp["flows"], round(tcp["retransmission_pct"]),
                        tcp["resets"], tcp["zero_window"]))
        if tcp["handshake_ms_avg"] is not None:
            lines.append("  handshake %.0f ms average, %.0f ms worst."
                         % (tcp["handshake_ms_avg"], tcp["handshake_ms_max"]))
        if tcp["unanswered_syns"]:
            lines.append("  no answer from: %s"
                         % ", ".join(entry["to"] for entry in tcp["unanswered_syns"][:8]))

    dns = analysis.dns_report()
    if dns["queries"]:
        lines.append("")
        lines.append("DNS: %d queries, %d answered, %d unanswered."
                     % (dns["queries"], dns["answered"], dns["unanswered"]))
        if dns["latency_ms_avg"] is not None:
            lines.append("  %.0f ms average, %.0f ms worst."
                         % (dns["latency_ms_avg"], dns["latency_ms_max"]))
        if dns["failures"]:
            lines.append("  failures: %s"
                         % ", ".join("%s %s" % (name, code)
                                     for name, code in list(dns["failures"].items())[:5]))

    findings = analysis.findings()
    if findings:
        lines.append("")
        lines.append("What the analyzer flagged:")
        for severity, text in findings:
            lines.append("  [%s] %s" % (severity, text))

    note = "%d packets, %.0fs" % (analysis.packets, duration)
    return _clip("\n".join(lines)), note


def _digest_text(path, kind):
    """A text file, head and tail, with the middle said to be missing.

    Cutting the middle rather than the end matters for logs: the last lines are
    usually where the failure is. The budget is in characters, not lines,
    because one 500-character line costs as much as ten short ones - trimming
    by line count alone and clipping afterwards would throw away the tail that
    this is all for.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError as exc:
        raise SourceError("cannot read %s: %s" % (path, exc.strerror or exc))

    total = len(lines)
    trimmed = [line[:MAX_LINE] for line in lines]
    header = "%s: %s (%d lines, %s)" % (
        kind.upper(), os.path.basename(path), total, _size(path))
    budget = MAX_DIGEST - len(header) - 100          # room for the marker

    if sum(len(line) + 1 for line in trimmed) <= budget and total <= MAX_TEXT_LINES:
        return "\n".join([header, ""] + trimmed), "%d lines" % total

    # The tail gets a third of the budget and is taken first, so it is never
    # the part that gets squeezed out.
    tail, used = [], 0
    for line in reversed(trimmed):
        if used + len(line) + 1 > budget // 3 or len(tail) >= MAX_TEXT_LINES // 3:
            break
        tail.insert(0, line)
        used += len(line) + 1

    head, used_head = [], 0
    for line in trimmed[:total - len(tail)]:
        if used_head + len(line) + 1 > budget - used or len(head) >= MAX_TEXT_LINES:
            break
        head.append(line)
        used_head += len(line) + 1

    omitted = total - len(head) - len(tail)
    body = head
    if omitted > 0:
        body = body + ["", "... %d lines omitted from the middle ..." % omitted, ""]
    body = body + tail
    return "\n".join([header, ""] + body), "%d lines" % total


def _clip(text, limit=MAX_DIGEST):
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... rendering truncated ..."


def _size(path):
    try:
        return _bytes(os.path.getsize(path))
    except OSError:
        return "unknown size"


def _bytes(count):
    value = float(count)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return "%.0f %s" % (value, unit) if unit == "B" else "%.1f %s" % (value, unit)
        value /= 1024
    return "%.1f GB" % value
