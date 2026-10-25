"""Clients: who a notebook is for, and what is permanently true about them.

A ticket is about one afternoon. A client is about the infrastructure that was
there before the ticket and will be there after it - the firewall addresses, the
core switch names, the ISP, the VPN concentrator, the fact that site B is on a
different subnet than everyone assumes.

Writing that down once and having it reach every future question is the whole
point. Facts you write here are standing context: they go into the prompt for
every notebook filed under this client, marked as standing rather than as
evidence from the ticket in hand, because the model should not report a firewall
address as something it observed today.

A client can also hold sources - a network diagram, a firewall config export, an
asset list - which work exactly like a notebook's, through the same code.
"""

import datetime
import json
import os
import shutil

from .config import data_dir
from .store import SourceHolder, StoreError, slug


class ClientError(StoreError):
    pass


def clients_dir():
    return os.path.join(data_dir(), "clients")


class Client(SourceHolder):
    FILENAME = "client.json"
    ERROR = ClientError

    @property
    def name(self):
        return self.record.get("name", self.id)

    @property
    def notes(self):
        return self.record.get("notes", "")

    @property
    def facts(self):
        """Ordered [{label, value}]. A label may appear more than once.

        Most of what someone writes here is plural - two firewalls, six
        servers, three sites - so a label maps to a list rather than one value.
        """
        return self.record.setdefault("facts", [])

    # --- changes ---------------------------------------------------------

    def set_name(self, name):
        self.record["name"] = name
        self.save()

    def set_notes(self, notes):
        self.record["notes"] = notes
        self.save()

    def append_note(self, text):
        existing = self.notes
        self.record["notes"] = (existing + "\n" + text).strip() if existing else text
        self.save()

    def add_fact(self, label, value, origin="hand", save=True):
        """Record a fact. The same label may hold several values.

        An exact repeat is ignored rather than stored twice: re-running a setup
        script should not leave the same firewall address in the prompt four
        times.

        `origin` is where it came from - "hand" for something typed, or a
        connector's name. It is what lets a re-sync replace what it brought
        last time without touching anything a person wrote.
        """
        label = (label or "").strip()
        value = (value or "").strip()
        if not label:
            raise ClientError("a fact needs a label, as label=value")
        for entry in self.facts:
            if entry["label"] == label and entry["value"] == value:
                return entry
        entry = {"label": label, "value": value, "origin": origin}
        self.facts.append(entry)
        if save:
            self.save()
        return entry

    def replace_facts_from(self, origin, facts):
        """Swap in everything one connector knows, leaving the rest alone.

        A sync must never quietly delete something a person took the trouble to
        type, so this only removes facts it put there itself last time.
        """
        kept = [entry for entry in self.facts
                if entry.get("origin", "hand") != origin]
        before = len(kept)
        # `kept` becomes the live list, so its length has to be taken first.
        self.record["facts"] = kept
        for fact in facts:
            self.add_fact(fact["label"], fact["value"], origin=origin, save=False)
        self.save()
        return len(self.facts) - before

    # --- connectors ------------------------------------------------------

    @property
    def links(self):
        """Which company this client is in each documentation system."""
        return self.record.setdefault("links", {})

    def link(self, connector, company_id, company_name=""):
        self.links[connector] = {"company_id": company_id,
                                 "company_name": company_name}
        self.save()
        return self.links[connector]

    def unlink(self, connector):
        self.links.pop(connector, None)
        self.record.setdefault("synced", {}).pop(connector, None)
        self.save()

    def record_sync(self, connector, detail):
        self.record.setdefault("synced", {})[connector] = detail
        self.save()

    @property
    def synced(self):
        return self.record.setdefault("synced", {})

    def forget(self, label, value=None):
        """Drop a fact: every value under a label, or one exact pair."""
        before = len(self.facts)
        self.record["facts"] = [
            entry for entry in self.facts
            if not (entry["label"] == label
                    and (value is None or entry["value"] == value))
        ]
        self.save()
        return before - len(self.record["facts"])

    def hand_facts(self):
        """Only the facts someone typed, as opposed to ones a sync brought."""
        return [entry for entry in self.facts
                if entry.get("origin", "hand") == "hand"]

    def grouped_facts(self):
        """[(label, [values])], in the order the labels were first written."""
        order, grouped = [], {}
        for entry in self.facts:
            if entry["label"] not in grouped:
                order.append(entry["label"])
                grouped[entry["label"]] = []
            grouped[entry["label"]].append(entry["value"])
        return [(label, grouped[label]) for label in order]

    # --- reading ---------------------------------------------------------

    def standing_context(self):
        """The client as prose for the prompt, or "" when there is nothing.

        Said as standing context, not as a reading: the model must not report a
        firewall address as something it measured this afternoon.
        """
        lines = []
        for label, values in self.grouped_facts():
            lines.append("  %s: %s" % (label, ", ".join(values)))
        if self.notes:
            if lines:
                lines.append("")
            lines.append("  " + "\n  ".join(self.notes.splitlines()))
        if not lines:
            return ""
        return "\n".join([
            "STANDING CONTEXT FOR %s" % self.name,
            "(What is permanently true about this client's setup. It was written "
            "down ahead of time, not measured today, so treat it as background "
            "rather than as evidence from this ticket.)",
        ] + lines)

    def detail(self):
        record = dict(self.record)
        record["directory"] = self.directory
        record["sources"] = self.source_detail()
        record["facts"] = list(self.facts)
        record["grouped_facts"] = [
            {"label": label,
             "values": values,
             # A label is "synced" when nothing under it was typed by hand, so
             # the app can show it as something a connector maintains.
             "origin": _origin_of(self.facts, label)}
            for label, values in self.grouped_facts()
        ]
        record["links"] = dict(self.links)
        record["synced"] = dict(self.synced)
        return record

    def summary(self, notebook_counts=None):
        return {
            "id": self.id,
            "name": self.name,
            "facts": len(self.facts),
            "sources": len(self.sources),
            "links": sorted(self.links),
            "notebooks": (notebook_counts or {}).get(self.id, 0),
            "created": self.record.get("created", ""),
            "updated": self.record.get("updated", ""),
            "directory": self.directory,
        }


def _origin_of(facts, label):
    """Where a label's values came from: "hand" if any of them were typed."""
    origins = {entry.get("origin", "hand") for entry in facts
               if entry["label"] == label}
    if "hand" in origins or not origins:
        return "hand"
    return sorted(origins)[0]


# --- module level ----------------------------------------------------------

def new_id(name):
    return slug(name, fallback="client")


def create(name, notes="", directory=None):
    identifier = new_id(name)
    target = directory or os.path.join(clients_dir(), identifier)
    if os.path.exists(os.path.join(target, Client.FILENAME)):
        raise ClientError("there is already a client called %r" % identifier)
    record = {
        "id": identifier,
        "name": name,
        "notes": notes,
        "facts": [],
        "sources": [],
        "links": {},
        "synced": {},
        "created": datetime.datetime.now().isoformat(),
    }
    client = Client(record, target)
    client.save()
    return client


def load(identifier):
    """A client by id, by directory, or by the name someone typed."""
    directory = (identifier if os.path.isdir(identifier)
                 else os.path.join(clients_dir(), identifier))
    path = os.path.join(directory, Client.FILENAME)
    if not os.path.exists(path):
        found = resolve(identifier)
        if found is None:
            raise ClientError("no client called %r" % identifier)
        return found
    with open(path) as handle:
        record = json.load(handle)
    return Client(record, directory)


def resolve(text):
    """Find a client by id or by name, case-insensitively. None if unsure.

    Typing "acme" should reach "Acme Corp" without anyone having to remember
    the slug, but an ambiguous prefix must not silently pick one.
    """
    wanted = (text or "").strip().lower()
    if not wanted:
        return None
    root = clients_dir()
    if not os.path.isdir(root):
        return None
    exact, partial = [], []
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name, Client.FILENAME)
        if not os.path.exists(path):
            continue
        try:
            with open(path) as handle:
                record = json.load(handle)
        except (ValueError, OSError):
            continue
        client = Client(record, os.path.join(root, name))
        if client.id.lower() == wanted or client.name.lower() == wanted:
            exact.append(client)
        elif client.id.lower().startswith(wanted) or wanted in client.name.lower():
            partial.append(client)
    if exact:
        return exact[0]
    if len(partial) == 1:
        return partial[0]
    if len(partial) > 1:
        raise ClientError("%r matches %d clients: %s"
                          % (text, len(partial),
                             ", ".join(client.id for client in partial)))
    return None


def listing():
    """Every client, by name."""
    root = clients_dir()
    if not os.path.isdir(root):
        return []
    counts = notebook_counts()
    found = []
    for name in sorted(os.listdir(root)):
        try:
            found.append(load(os.path.join(root, name)).summary(counts))
        except (StoreError, ValueError, OSError):
            continue
    found.sort(key=lambda entry: entry["name"].lower())
    return found


def notebook_counts():
    """How many notebooks each client has, counted without loading them all."""
    from .notebooks import notebooks_dir, Notebook

    counts = {}
    root = notebooks_dir()
    if not os.path.isdir(root):
        return counts
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name, Notebook.FILENAME)
        if not os.path.exists(path):
            continue
        try:
            with open(path) as handle:
                record = json.load(handle)
        except (ValueError, OSError):
            continue
        client = record.get("client")
        if client:
            counts[client] = counts.get(client, 0) + 1
    return counts


def remove(identifier, keep_notebooks=True):
    """Delete a client. Its notebooks are kept and simply lose their client.

    Deleting a client must never take a year of someone's tickets with it, so
    the default unfiles them rather than removing them.
    """
    from .notebooks import listing as notebook_listing, load as load_notebook

    client = load(identifier)
    orphaned = 0
    for entry in notebook_listing(client=client.id):
        notebook = load_notebook(entry["id"])
        if keep_notebooks:
            notebook.set_client(None)
            orphaned += 1
        else:
            shutil.rmtree(notebook.directory, ignore_errors=True)
    shutil.rmtree(client.directory, ignore_errors=True)
    return orphaned
