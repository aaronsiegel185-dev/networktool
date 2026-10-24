"""Tickets: the problem, what the machine knows about it, and the conversation.

One directory per ticket, holding a JSON record and the attachments. Plain files
rather than a database, because the contents are the user's own evidence and
they should be able to read, copy, back up or delete them without this tool.
"""

import datetime
import json
import os
import re
import shutil

from .config import data_dir


class TicketError(Exception):
    pass


def tickets_dir():
    return os.path.join(data_dir(), "tickets")


def _slug(text, limit=40):
    cleaned = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return cleaned[:limit] or "ticket"


def new_id(title):
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return "%s-%s" % (stamp, _slug(title))


class Ticket(object):
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
    def attachments(self):
        return self.record.setdefault("attachments", [])

    @property
    def attachment_dir(self):
        return os.path.join(self.directory, "attachments")

    def has_images(self):
        return any(entry.get("kind") in ("screenshot", "frame")
                   for entry in self.attachments)

    def image_paths(self, limit=None):
        """Attached images, newest last, capped so a long ticket still fits."""
        paths = [os.path.join(self.attachment_dir, entry["stored"])
                 for entry in self.attachments
                 if entry.get("kind") in ("screenshot", "frame")]
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

    def add_attachment(self, path, kind="file", note=""):
        """Copy a file in. The original is left alone."""
        if not os.path.isfile(path):
            raise TicketError("no such file: %s" % path)
        os.makedirs(self.attachment_dir, exist_ok=True)
        name = os.path.basename(path)
        stored = name
        index = 1
        while os.path.exists(os.path.join(self.attachment_dir, stored)):
            root, extension = os.path.splitext(name)
            stored = "%s-%d%s" % (root, index, extension)
            index += 1
        shutil.copy2(path, os.path.join(self.attachment_dir, stored))
        entry = {
            "stored": stored,
            "original": os.path.abspath(path),
            "kind": kind,
            "note": note,
            "bytes": os.path.getsize(path),
            "at": datetime.datetime.now().isoformat(timespec="seconds"),
        }
        self.attachments.append(entry)
        self.save()
        return entry

    def set_context(self, context):
        self.record["context"] = context
        self.save()

    def set_status(self, status):
        self.record["status"] = status
        self.save()

    def save(self):
        os.makedirs(self.directory, exist_ok=True)
        self.record["updated"] = datetime.datetime.now().isoformat(timespec="seconds")
        with open(os.path.join(self.directory, "ticket.json"), "w") as handle:
            json.dump(self.record, handle, indent=2)

    def detail(self):
        """The record, plus where each attachment actually lives.

        The paths are resolved on read rather than written into ticket.json, so
        a ticket directory stays portable between machines and home directories.
        """
        record = dict(self.record)
        record["directory"] = self.directory
        record["attachments"] = [
            dict(entry, path=os.path.join(self.attachment_dir, entry["stored"]))
            for entry in self.attachments
        ]
        return record

    def summary(self):
        return {
            "id": self.id,
            "title": self.title,
            "status": self.record.get("status", "open"),
            "created": self.record.get("created", ""),
            "updated": self.record.get("updated", ""),
            "messages": len(self.messages),
            "attachments": len(self.attachments),
            "directory": self.directory,
        }


def create(title, body="", directory=None):
    identifier = new_id(title)
    target = directory or os.path.join(tickets_dir(), identifier)
    record = {
        "id": identifier,
        "title": title,
        "body": body,
        "status": "open",
        "created": datetime.datetime.now().isoformat(),
        "messages": [],
        "attachments": [],
        "context": {},
    }
    ticket = Ticket(record, target)
    ticket.save()
    return ticket


def load(identifier):
    directory = (identifier if os.path.isdir(identifier)
                 else os.path.join(tickets_dir(), identifier))
    path = os.path.join(directory, "ticket.json")
    try:
        with open(path, "r") as handle:
            record = json.load(handle)
    except OSError:
        raise TicketError("no such ticket: %s" % identifier)
    except ValueError as exc:
        raise TicketError("%s is damaged: %s" % (path, exc))
    return Ticket(record, directory)


def listing():
    """Every ticket, newest first.

    Sorted on the stored timestamp rather than the directory name: the id only
    has second resolution so it reads well, which leaves two tickets made in
    the same second sorting alphabetically by their title.
    """
    root = tickets_dir()
    if not os.path.isdir(root):
        return []
    found = []
    for name in sorted(os.listdir(root)):
        try:
            found.append(load(os.path.join(root, name)).summary())
        except TicketError:
            continue
    found.sort(key=lambda entry: (entry.get("created", ""), entry["id"]), reverse=True)
    return found
