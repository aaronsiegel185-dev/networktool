"""What notebooks and clients have in common: a directory that holds sources.

A notebook's sources are the evidence for one question. A client's sources are
standing reference - the network diagram, the firewall export, the asset list -
that bears on every question you ever ask about them. Mechanically they are the
same thing, so they are the same code, and a client's reference material gets
the same rendering, the same switches and the same budget as a notebook's.
"""

import datetime
import json
import os
import re
import shutil

from . import media, sources as sourcemod

# Kinds a vision model can look at directly, as opposed to ones that are
# rendered into text before they are sent.
VISUAL_KINDS = ("screenshot", "frame")


class StoreError(Exception):
    pass


def slug(text, limit=40, fallback="item"):
    cleaned = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return cleaned[:limit] or fallback


class SourceHolder(object):
    """A record on disk with a `sources` list and a directory beside it.

    Subclasses provide `record`, `directory`, the name of the JSON file, and
    the error class their callers expect: someone working with notebooks should
    get a NotebookError, not a StoreError they have never heard of.
    """

    FILENAME = "record.json"
    ERROR = StoreError

    def __init__(self, record, directory):
        self.record = record
        self.directory = directory

    # --- fields ----------------------------------------------------------

    @property
    def id(self):
        return self.record["id"]

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
        """Enabled images, newest last, capped so a long record still fits."""
        paths = [self.path_of(entry) for entry in self.enabled_sources()
                 if entry.get("kind") in VISUAL_KINDS]
        return paths[-limit:] if limit else paths

    # --- changes ---------------------------------------------------------

    def add_source(self, path, note="", kind=None, parent=None, frames=6):
        """Bring a file in, and render it into something the model can read.

        The original is copied, never moved: it stays wherever the user keeps
        it. A screen recording also yields frames, registered as their own
        sources so they can be switched off one at a time.
        """
        if not os.path.isfile(path):
            raise self.ERROR("no such file: %s" % path)
        kind = kind or sourcemod.classify(path)

        stored_path = path
        if kind == "screenshot":
            # Shrinking before storing keeps the directory a sane size and is
            # what gets sent anyway; the user's own copy is untouched.
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
            raise self.ERROR("%r matches %d sources: %s"
                             % (name, len(matches),
                                ", ".join(m["stored"] for m in matches)))
        raise self.ERROR("no source called %r here" % name)

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

    def tidy_staging(self):
        """Sweep shrunk screenshots and extracted frames already copied in."""
        staging = os.path.join(self.directory, "work")
        if not os.path.isdir(staging):
            return
        for name in os.listdir(staging):
            try:
                os.remove(os.path.join(staging, name))
            except OSError:
                pass
        try:
            os.rmdir(staging)
        except OSError:
            pass

    def save(self):
        os.makedirs(self.directory, exist_ok=True)
        self.record["updated"] = datetime.datetime.now().isoformat(timespec="seconds")
        with open(os.path.join(self.directory, self.FILENAME), "w") as handle:
            json.dump(self.record, handle, indent=2)

    def source_detail(self):
        """Sources with their real paths, resolved on read.

        Paths are not written into the record, so a directory stays portable
        between machines and home directories.
        """
        return [dict(entry, path=self.path_of(entry)) for entry in self.sources]
