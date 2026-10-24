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

from . import sources as sourcemod
from .config import data_dir
from .store import SourceHolder, StoreError, slug as _slugify

# Kinds that a vision model can look at directly, as opposed to ones that are
# rendered into text before they are sent.
VISUAL_KINDS = ("screenshot", "frame")


class NotebookError(StoreError):
    """Raised for notebook problems.

    It subclasses StoreError so a caller can catch either, and so the shared
    source machinery's errors surface as notebook errors to anyone who only
    knows about notebooks.
    """


def notebooks_dir():
    return os.path.join(data_dir(), "notebooks")


def _slug(text, limit=40):
    return _slugify(text, limit, fallback="notebook")


def new_id(title):
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return "%s-%s" % (stamp, _slug(title))


class Notebook(SourceHolder):
    FILENAME = "notebook.json"
    ERROR = NotebookError

    @property
    def title(self):
        return self.record.get("title", "")

    @property
    def messages(self):
        return self.record.setdefault("messages", [])

    @property
    def client_id(self):
        """The client this notebook belongs to, or None."""
        return self.record.get("client") or None

    def set_client(self, client_id):
        """File this notebook under a client, or under none."""
        self.record["client"] = client_id or None
        self.save()

    def add_message(self, role, text, images=()):
        self.messages.append({
            "role": role,
            "text": text,
            "images": list(images),
            "at": datetime.datetime.now().isoformat(timespec="seconds"),
        })
        self.save()

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
        """The record, plus where each source actually lives, plus the client.

        The client is expanded rather than left as an id: whatever reads this -
        the app, a person, a script - wants the name and the standing context,
        not a directory name to go and look up.
        """
        record = dict(self.record)
        record["directory"] = self.directory
        record["sources"] = self.source_detail()
        record["client"] = self.client_id
        client = self.client()
        record["client_detail"] = client.detail() if client else None
        return record

    def client(self):
        """The client record, or None. Missing clients are not an error here.

        A notebook whose client directory was deleted should still open and
        still answer questions; it has simply lost its standing context.
        """
        from . import clients

        if not self.client_id:
            return None
        try:
            return clients.load(self.client_id)
        except StoreError:
            return None

    def summary(self, client_names=None):
        """A row for a listing. `client_names` saves re-reading every client."""
        enabled = self.enabled_sources()
        name = ""
        if self.client_id:
            if client_names is not None:
                name = client_names.get(self.client_id, self.client_id)
            else:
                client = self.client()
                name = client.name if client else self.client_id
        return {
            "id": self.id,
            "title": self.title,
            "status": self.record.get("status", "open"),
            "created": self.record.get("created", ""),
            "updated": self.record.get("updated", ""),
            "messages": len(self.messages),
            "sources": len(self.sources),
            "sources_on": len(enabled),
            "client": self.client_id or "",
            "client_name": name,
            "directory": self.directory,
        }


def create(title, body="", directory=None, client=None):
    identifier = new_id(title)
    target = directory or os.path.join(notebooks_dir(), identifier)
    record = {
        "id": identifier,
        "title": title,
        "body": body,
        "status": "open",
        "client": client or None,
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


def listing(client=None):
    """Every notebook, newest first, optionally only one client's."""
    from . import clients

    migrate_tickets()
    root = notebooks_dir()
    if not os.path.isdir(root):
        return []
    # One pass over the clients rather than one read per notebook.
    names = {entry["id"]: entry["name"] for entry in clients.listing()}
    found = []
    for name in os.listdir(root):
        try:
            notebook = load(os.path.join(root, name))
        except (StoreError, ValueError, OSError):
            continue
        if client is not None and notebook.client_id != client:
            continue
        found.append(notebook.summary(client_names=names))
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
