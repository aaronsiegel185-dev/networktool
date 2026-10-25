"""Working a notebook with a model that runs on this machine."""

import os
from urllib.parse import urlparse

from . import config, context as contextmod, llm, media
from .privacy import no_egress

# How much of the prompt the sources may take between them. A local model's
# context is not generous, and a notebook with twenty files in it must still
# leave room for the conversation and the machine's own measurements.
SOURCE_BUDGET = 24000

SYSTEM_PROMPT = """\
You are the troubleshooting half of Toolbox, a network and systems tool. You run \
entirely on this person's own machine; nothing they tell you leaves it.

You are given a notebook: a question, the sources the person added to it, and \
what the machine reports about itself. A notebook filed under a client also \
carries standing context about that client's setup - firewall addresses, server \
names, how the sites are wired. That was written down ahead of time, not \
measured today: use it to interpret what you are seeing, but never report it \
back as a reading you took. Sources can be packet captures, logs, \
config files, screenshots or frames from a screen recording. Captures and logs \
have been rendered into text for you, by the same analyzer the person can run \
themselves - so what you are reading is a real reading of their file, not a \
guess about it.

Reason from the sources in front of you. Name the source you are drawing on, \
by filename, so the person can check it. If a source would settle the question \
and is not here, say which one to add.

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


# A client's reference material must not crowd out the evidence for the ticket
# in hand. It gets its own slice of the budget rather than competing for all of
# it: an asset list is useful background, but never at the cost of the capture
# someone just took.
CLIENT_SOURCE_BUDGET = SOURCE_BUDGET // 3


def _fit(holder, budget):
    """Enabled text sources, newest first until the budget runs out.

    Newest first because the file someone just added is the one they are asking
    about. Anything that does not fit is named but not included, so the model
    knows there is more than it was shown rather than assuming it has seen
    everything.
    """
    blocks, omitted, used = [], [], 0
    for entry in reversed(holder.enabled_sources()):
        text = entry.get("digest") or ""
        if not text:
            continue                      # images carry no text; they go as images
        if used + len(text) > budget:
            omitted.append(entry["stored"])
            continue
        blocks.append(text)
        used += len(text)
    blocks.reverse()
    omitted.reverse()
    return blocks, omitted


def source_blocks(notebook, budget=SOURCE_BUDGET):
    """This notebook's own sources."""
    return _fit(notebook, budget)


def client_blocks(client, budget=CLIENT_SOURCE_BUDGET):
    """A client's standing reference material."""
    if client is None:
        return [], []
    return _fit(client, budget)


def build_messages(notebook, system_prompt=SYSTEM_PROMPT, image_limit=6,
                   with_images=True):
    """The conversation as the model will see it, newest question last."""
    messages = [{"role": "system", "content": system_prompt}]

    client = notebook.client()
    opening = ["NOTEBOOK: %s" % notebook.title]
    if client:
        opening.append("CLIENT: %s" % client.name)
    if notebook.record.get("body"):
        opening.append("")
        opening.append(notebook.record["body"])

    # The client goes in before the evidence: it is the frame you read the
    # evidence through, not another exhibit.
    if client:
        standing = client.standing_context()
        if standing:
            opening.append("")
            opening.append(standing)
        client_text, client_omitted = client_blocks(client)
        for block in client_text:
            opening.append("")
            opening.append("=" * 60)
            opening.append("STANDING REFERENCE, kept on file for %s:" % client.name)
            opening.append(block)
        if client_omitted:
            opening.append("")
            opening.append("Also on file for this client, not shown here: %s."
                           % ", ".join(client_omitted))

    summary = contextmod.summarise(notebook.record.get("context") or {})
    if summary:
        opening.append("")
        opening.append("WHAT THIS MACHINE REPORTS:")
        opening.append(summary)

    enabled = notebook.enabled_sources()
    if enabled:
        opening.append("")
        opening.append("SOURCES IN THIS NOTEBOOK: %s" % ", ".join(
            "%s (%s)" % (entry["stored"], entry.get("kind", "file"))
            for entry in enabled))

    blocks, omitted = source_blocks(notebook)
    for block in blocks:
        opening.append("")
        opening.append("=" * 60)
        opening.append(block)
    if omitted:
        opening.append("")
        opening.append("Not shown here, for space: %s. Say if you need one of "
                       "them and it can be the only source switched on."
                       % ", ".join(omitted))

    # Images ride on the first user turn, where the notebook is described. A
    # local vision model handles a handful well and degrades quickly beyond
    # that, so the newest few are kept rather than everything ever added. A
    # client's images come first, so the ticket's own always survive the cap.
    images = []
    if with_images:
        if client:
            images.extend(client.image_paths(limit=max(1, image_limit // 3)))
        images.extend(notebook.image_paths(limit=image_limit))
        images = images[-image_limit:]
    if enabled and not with_images and notebook.has_images():
        # Sending images to a text model gets them ignored at best and an error
        # at worst. Say so instead, so the answer does not pretend to have
        # looked at a screenshot it never saw.
        opening.append("")
        opening.append("You cannot see the images in this notebook: no vision "
                       "model is set up. Say so rather than guessing at their "
                       "contents, and ask for what they show in words.")

    messages.append(llm.message("user", "\n".join(opening), images=images))

    for entry in notebook.messages:
        role = entry.get("role")
        if role not in ("user", "assistant"):
            continue
        messages.append({"role": role, "content": entry.get("text", "")})
    return messages


def pick_model(notebook, settings):
    """Vision only when there is something to look at, and something to look with.

    A vision model can be deliberately absent - it is the larger download by
    far - so an empty setting means text only rather than a broken request.
    """
    vision = settings.get("vision_model") or ""
    client = notebook.client()
    has_images = notebook.has_images() or (client is not None and client.has_images())
    if has_images and vision:
        return vision, True
    return settings.get("text_model") or config.DEFAULT_TEXT_MODEL, False


def ask(notebook, question=None, settings=None, on_token=None, stream=True):
    """Put the notebook to the model and record what it says.

    The whole exchange happens inside the egress guard, so a stray connection
    anywhere but the model server fails loudly instead of quietly succeeding.
    """
    settings = settings or config.load()
    if question:
        notebook.add_message("user", question)

    model, used_vision = pick_model(notebook, settings)
    messages = build_messages(notebook, with_images=used_vision)
    endpoint = settings["endpoint"]
    host = urlparse(endpoint).hostname or "127.0.0.1"

    with no_egress(allow=[host]):
        client = llm.Client(endpoint, allow_lan=settings.get("allow_lan", False))
        answer = client.chat(model, messages,
                             temperature=settings.get("temperature", 0.2),
                             stream=stream, on_token=on_token)

    notebook.add_message("assistant", answer)
    return {"answer": answer, "model": model, "vision": used_vision,
            "endpoint": endpoint}


def add_source(notebook, path, note="", frames=6):
    """Bring a file into a notebook and clean up after the rendering.

    The notebook does the real work; this exists to sweep the staging
    directory, which holds shrunk screenshots and extracted frames that have
    already been copied in under their own names.
    """
    entry = notebook.add_source(path, note=note, frames=frames)
    staging = os.path.join(notebook.directory, "work")
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
    return entry


def _connector_report():
    """Where each documentation connector points, for `doctor`.

    Imported late and guarded: a broken connector configuration must not stop
    someone finding out whether their model server is reachable.
    """
    try:
        from . import connectors

        return connectors.describe_all()
    except Exception:
        return []


def doctor(settings=None):
    """Everything someone needs to know before trusting this with a notebook."""
    from .privacy import describe_egress

    settings = settings or config.load()
    endpoint = settings["endpoint"]
    report = {
        "endpoint": endpoint,
        "egress": describe_egress(endpoint, allow_lan=settings.get("allow_lan", False)),
        "ffmpeg": media.have_ffmpeg(),
        "data_dir": config.data_dir(),
        "connectors": _connector_report(),
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
