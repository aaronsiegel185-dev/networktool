"""Notebooks: a question, the files it is grounded in, and the conversation.

One directory per notebook, holding a JSON record, the sources themselves and
anything derived from them. Plain files rather than a database, because the
contents are the user's own evidence and they should be able to read, copy,
back up or delete them without this tool.

A notebook's sources are the whole of what the model is told. Nothing is pulled
in behind the user's back, each source can be switched off without deleting it,
and what the model was given is recoverable from the record afterwards.
"""

import datetime
import json
import os
import shutil

from . import media, sources as sourcemod
from .config import data_dir

# Kinds that a vision model can look at directly, as opposed to ones that are
# rendered into text before they are sent.
VISUAL_KINDS = ("screenshot", "frame")


class NotebookError(Exception):
    pass


def notebooks_dir():
    return os.path.join(data_dir(), "notebooks")


def _slug(text, limit=40):
    import re
    cleaned = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return cleaned[:limit] or "notebook"


def new_id(title):
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return "%s-%s" % (stamp, _slug(title))


class Notebook(object):
    def __init__(self, record, directory):
        self.record = record
        self.directory = directory

    # --- fields ----------------------------------------------------------

    @property
    def id(self):
        return self.record["id"]

    @property
    def title(self):
        return self.record.get("title", "")

    @property
    def messages(self):
        return self.record.setdefault("messages", [])

    @property
    def sources(self):
        return self.record.setdefault("sources", [])

    @property
    def source_dir(self):
        return os.path.join(self.directory, "sources")

    def path_of(self, entry):
        return os.path.join(self.source_dir, entry["stored"])

    def enabled_sources(self):
        """Sources switched on, in the order they were added."""
        return [entry for entry in self.sources if entry.get("enabled", True)]

    def has_images(self):
        return any(entry.get("kind") in VISUAL_KINDS
                   for entry in self.enabled_sources())

    def image_paths(self, limit=None):
        """Enabled images, newest last, capped so a long notebook still fits."""
        paths = [self.path_of(entry) for entry in self.enabled_sources()
                 if entry.get("kind") in VISUAL_KINDS]
        return paths[-limit:] if limit else paths

    # --- changes ---------------------------------------------------------

    def add_message(self, role, text, images=()):
        self.messages.append({
            "role": role,
            "text": text,
            "images": list(images),
            "at": datetime.datetime.now().isoformat(timespec="seconds"),
        })
        self.save()

    def add_source(self, path, note="", kind=None, parent=None, frames=6):
        """Bring a file in, and render it into something the model can read.

        The original is copied, never moved: it stays wherever the user keeps
        it. A screen recording also yields frames, registered as their own
        sources so they can be switched off one at a time.
        """
        if not os.path.isfile(path):
            raise NotebookError("no such file: %s" % path)
        kind = kind or sourcemod.classify(path)

        stored_path = path
        if kind == "screenshot":
            # Shrinking before storing keeps the notebook directory a sane size
            # and is what gets sent anyway; the user's own copy is untouched.
            stored_path = media.shrink(path, os.path.join(self.directory, "work"))

        entry = self._store(stored_path, kind, original=path, parent=parent)
        text, auto_note = sourcemod.digest(self.path_of(entry), kind)
        entry["digest"] = text
        entry["note"] = note or auto_note
        self.save()

        if kind == "recording":
            self._add_frames(entry, frames=frames)
        return entry

    def _add_frames(self, entry, frames=6):
        """Sample a recording into stills, kept alongside the recording itself.

        Both are kept: the frames are what the model can look at, the recording
        is the evidence, and one is not allowed to quietly replace the other.
        """
        try:
            extracted = media.extract_frames(
                self.path_of(entry), os.path.join(self.directory, "work"),
                count=frames)
        except media.MediaError as exc:
            entry["note"] = "%s (no frames: %s)" % (entry.get("note", "recording"), exc)
            self.save()
            return []
        made = []
        for frame in extracted:
            child = self._store(frame["path"], "frame", original=frame["path"],
                                parent=entry["stored"])
            child["note"] = "%s at %.1fs" % (entry["stored"], frame["at_s"])
            made.append(child)
        self.save()
        return made

    def _store(self, path, kind, original, parent=None):
        os.makedirs(self.source_dir, exist_ok=True)
        name = os.path.basename(path)
        stored = name
        index = 1
        while os.path.exists(os.path.join(self.source_dir, stored)):
            root, extension = os.path.splitext(name)
            stored = "%s-%d%s" % (root, index, extension)
            index += 1
        shutil.copy2(path, os.path.join(self.source_dir, stored))
        entry = {
            "stored": stored,
            "original": os.path.abspath(original),
            "kind": kind,
            "note": "",
            "digest": "",
            "enabled": True,
            "parent": parent,
            "bytes": os.path.getsize(path),
            "at": datetime.datetime.now().isoformat(timespec="seconds"),
        }
        self.sources.append(entry)
        return entry

    def find_source(self, name):
        """A source by stored name, or by the name the user actually typed."""
        for entry in self.sources:
            if entry["stored"] == name:
                return entry
        matches = [entry for entry in self.sources
                   if entry["stored"].startswith(name)
                   or os.path.basename(entry.get("original", "")) == name]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise NotebookError("%r matches %d sources: %s"
                                % (name, len(matches),
                                   ", ".join(m["stored"] for m in matches)))
        raise NotebookError("no source called %r in this notebook" % name)

    def set_source_enabled(self, name, enabled):
        """Switch a source on or off. A recording carries its frames with it."""
        entry = self.find_source(name)
        entry["enabled"] = bool(enabled)
        for child in self.sources:
            if child.get("parent") == entry["stored"]:
                child["enabled"] = bool(enabled)
        self.save()
        return entry

    def remove_source(self, name):
        """Delete a source and anything derived from it, file and all."""
        entry = self.find_source(name)
        doomed = [entry] + [child for child in self.sources
                            if child.get("parent") == entry["stored"]]
        for victim in doomed:
            path = self.path_of(victim)
            if os.path.exists(path):
                os.remove(path)
            self.sources.remove(victim)
        self.save()
        return len(doomed)

    def set_context(self, context):
        self.record["context"] = context
        self.save()

    def set_status(self, status):
        self.record["status"] = status
        self.save()

    def save(self):
        os.makedirs(self.directory, exist_ok=True)
        self.record["updated"] = datetime.datetime.now().isoformat(timespec="seconds")
        with open(os.path.join(self.directory, "notebook.json"), "w") as handle:
            json.dump(self.record, handle, indent=2)

    def detail(self):
        """The record, plus where each source actually lives.

        Paths are resolved on read rather than written into notebook.json, so a
        notebook directory stays portable between machines and home directories.
        """
        record = dict(self.record)
        record["directory"] = self.directory
        record["sources"] = [dict(entry, path=self.path_of(entry))
                             for entry in self.sources]
        return record

    def summary(self):
        enabled = self.enabled_sources()
        return {
            "id": self.id,
            "title": self.title,
            "status": self.record.get("status", "open"),
            "created": self.record.get("created", ""),
            "updated": self.record.get("updated", ""),
            "messages": len(self.messages),
            "sources": len(self.sources),
            "sources_on": len(enabled),
            "directory": self.directory,
        }


def create(title, body="", directory=None):
    identifier = new_id(title)
    target = directory or os.path.join(notebooks_dir(), identifier)
    record = {
        "id": identifier,
        "title": title,
        "body": body,
        "status": "open",
        "created": datetime.datetime.now().isoformat(),
        "sources": [],
        "messages": [],
        "context": {},
    }
    notebook = Notebook(record, target)
    notebook.save()
    return notebook


def load(identifier):
    directory = (identifier if os.path.isdir(identifier)
                 else os.path.join(notebooks_dir(), identifier))
    path = os.path.join(directory, "notebook.json")
    if not os.path.exists(path):
        raise NotebookError("no notebook called %r" % identifier)
    with open(path) as handle:
        record = json.load(handle)
    return Notebook(record, directory)


def listing():
    """Every notebook, newest first."""
    migrate_tickets()
    root = notebooks_dir()
    if not os.path.isdir(root):
        return []
    found = []
    for name in os.listdir(root):
        try:
            found.append(load(os.path.join(root, name)).summary())
        except (NotebookError, ValueError, OSError):
            continue
    found.sort(key=lambda entry: entry.get("created", ""), reverse=True)
    return found


# --- migration -------------------------------------------------------------

def migrate_tickets():
    """Carry forward notebooks written when they were still called tickets.

    Assist stored tickets with attachments before it stored notebooks with
    sources. Someone who used that should not lose their work to a rename, so
    the old layout is moved across once, in place, and the old directory is
    left empty rather than deleted.
    """
    old_root = os.path.join(data_dir(), "tickets")
    if not os.path.isdir(old_root):
        return 0
    moved = 0
    for name in sorted(os.listdir(old_root)):
        old = os.path.join(old_root, name)
        record_path = os.path.join(old, "ticket.json")
        if not os.path.exists(record_path):
            continue
        new = os.path.join(notebooks_dir(), name)
        if os.path.exists(new):
            continue
        os.makedirs(notebooks_dir(), exist_ok=True)
        shutil.move(old, new)

        with open(os.path.join(new, "ticket.json")) as handle:
            record = json.load(handle)
        attachments = record.pop("attachments", [])
        record["sources"] = [
            {"stored": entry.get("stored", ""),
             "original": entry.get("original", ""),
             # The old kinds were only ever media; anything else was "file".
             "kind": {"screenshot": "screenshot", "frame": "frame",
                      "video": "recording"}.get(entry.get("kind"), "other"),
             "note": entry.get("note", ""),
             "digest": "",
             "enabled": True,
             "parent": None,
             "bytes": entry.get("bytes", 0),
             "at": entry.get("at", "")}
            for entry in attachments
        ]
        old_files = os.path.join(new, "attachments")
        if os.path.isdir(old_files):
            os.rename(old_files, os.path.join(new, "sources"))

        notebook = Notebook(record, new)
        # Render what came across, so migrated sources are as useful as new
        # ones rather than silently contributing nothing.
        for entry in notebook.sources:
            path = notebook.path_of(entry)
            if entry["kind"] == "other" and os.path.exists(path):
                entry["kind"] = sourcemod.classify(path)
            if os.path.exists(path):
                text, note = sourcemod.digest(path, entry["kind"])
                entry["digest"] = text
                entry["note"] = entry["note"] or note
        notebook.save()
        os.remove(os.path.join(new, "ticket.json"))
        moved += 1
    return moved
