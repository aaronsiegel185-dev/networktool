"""Working a ticket with a model that runs on this machine."""

import os
from urllib.parse import urlparse

from . import config, context as contextmod, llm, media
from .privacy import no_egress

SYSTEM_PROMPT = """\
You are the troubleshooting half of Toolbox, a network and systems tool. You run \
entirely on this person's own machine; nothing they tell you leaves it.

You are given a ticket, what the machine reports about itself, and sometimes \
screenshots or frames from a screen recording. The measurements come from \
Network Tool, the diagnostics half of the same software, and they are real \
readings from this machine rather than guesses.

How to answer:
- Lead with the most likely cause and why the evidence points there.
- Name the specific numbers you are reasoning from. "Retries are 25%" beats \
"the signal looks poor".
- Give the next concrete step, as a command where there is one. Commands \
starting `nettool` are available on this machine.
- Say plainly when the evidence does not reach a conclusion, and name the one \
measurement that would settle it.
- Do not invent readings. If something was not gathered, say so.
"""


def build_messages(ticket, system_prompt=SYSTEM_PROMPT, image_limit=6):
    """The conversation as the model will see it, newest question last."""
    messages = [{"role": "system", "content": system_prompt}]

    summary = contextmod.summarise(ticket.record.get("context") or {})
    opening = ["TICKET: %s" % ticket.title]
    if ticket.record.get("body"):
        opening.append("")
        opening.append(ticket.record["body"])
    if summary:
        opening.append("")
        opening.append("WHAT THIS MACHINE REPORTS:")
        opening.append(summary)
    attachments = ticket.attachments
    if attachments:
        opening.append("")
        opening.append("ATTACHED: %s" % ", ".join(
            "%s (%s)" % (entry["stored"], entry.get("kind", "file"))
            for entry in attachments))

    # Images ride on the first user turn, where the ticket is described. A local
    # vision model handles a handful well and degrades quickly beyond that, so
    # the newest few are kept rather than everything ever attached.
    images = ticket.image_paths(limit=image_limit)
    messages.append(llm.message("user", "\n".join(opening), images=images))

    for entry in ticket.messages:
        role = entry.get("role")
        if role not in ("user", "assistant"):
            continue
        messages.append({"role": role, "content": entry.get("text", "")})
    return messages


def pick_model(ticket, settings):
    """Vision only when there is something to look at."""
    if ticket.has_images():
        return settings.get("vision_model", config.DEFAULT_VISION_MODEL), True
    return settings.get("text_model", config.DEFAULT_TEXT_MODEL), False


def ask(ticket, question=None, settings=None, on_token=None, stream=True):
    """Put the ticket to the model and record what it says.

    The whole exchange happens inside the egress guard, so a stray connection
    anywhere but the model server fails loudly instead of quietly succeeding.
    """
    settings = settings or config.load()
    if question:
        ticket.add_message("user", question)

    model, used_vision = pick_model(ticket, settings)
    messages = build_messages(ticket)
    endpoint = settings["endpoint"]
    host = urlparse(endpoint).hostname or "127.0.0.1"

    with no_egress(allow=[host]):
        client = llm.Client(endpoint, allow_lan=settings.get("allow_lan", False))
        answer = client.chat(model, messages,
                             temperature=settings.get("temperature", 0.2),
                             stream=stream, on_token=on_token)

    ticket.add_message("assistant", answer)
    return {"answer": answer, "model": model, "vision": used_vision,
            "endpoint": endpoint}


def attach(ticket, path, note="", frames=6):
    """Add a screenshot or a video to a ticket.

    A video is not stored as a video for the model's purposes - it is sampled
    into frames, and both the frames and the original are kept so the evidence
    is not quietly replaced by an interpretation of it.
    """
    kind = media.sniff(path)
    staging = os.path.join(ticket.directory, "work")
    added = []

    if kind == "image":
        prepared = media.shrink(path, staging)
        entry = ticket.add_attachment(prepared, kind="screenshot", note=note)
        entry["source"] = os.path.abspath(path)
        ticket.save()
        added.append(entry)
    elif kind == "video":
        original = ticket.add_attachment(path, kind="video", note=note)
        added.append(original)
        for frame in media.extract_frames(path, staging, count=frames):
            entry = ticket.add_attachment(
                frame["path"], kind="frame",
                note="%s at %.1fs" % (os.path.basename(path), frame["at_s"]))
            added.append(entry)
    else:
        added.append(ticket.add_attachment(path, kind="file", note=note))

    if os.path.isdir(staging):
        for name in os.listdir(staging):
            try:
                os.remove(os.path.join(staging, name))
            except OSError:
                pass
        try:
            os.rmdir(staging)
        except OSError:
            pass
    return added


def doctor(settings=None):
    """Everything someone needs to know before trusting this with a ticket."""
    from .privacy import describe_egress

    settings = settings or config.load()
    endpoint = settings["endpoint"]
    report = {
        "endpoint": endpoint,
        "egress": describe_egress(endpoint, allow_lan=settings.get("allow_lan", False)),
        "ffmpeg": media.have_ffmpeg(),
        "data_dir": config.data_dir(),
        "models": {"text": settings.get("text_model"),
                   "vision": settings.get("vision_model")},
    }
    try:
        host = urlparse(endpoint).hostname or "127.0.0.1"
        with no_egress(allow=[host]):
            client = llm.Client(endpoint, allow_lan=settings.get("allow_lan", False))
            available = client.models()
        report["server"] = "reachable"
        report["available_models"] = available
        report["missing_models"] = [
            name for name in (settings.get("text_model"), settings.get("vision_model"))
            if name and name not in available]
    except Exception as exc:
        report["server"] = "unreachable"
        report["server_error"] = str(exc)
        report["available_models"] = []
        report["missing_models"] = []
    return report
