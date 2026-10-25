"""A folder of documentation on this machine, or on a share you have mounted.

No network, no API key, no account. If your documentation is a directory of
markdown, a git checkout of runbooks, or a mounted share, this is the connector
that keeps the original promise completely intact: nothing leaves, because
nothing is ever sent anywhere.

A client is linked to a subdirectory, which is the usual shape - one folder per
customer.
"""

import os

from .. import connectors
from .http import ConnectorError

# Extensions worth reading. Everything else in the folder is left alone rather
# than guessed at.
READABLE = (".md", ".markdown", ".txt", ".rst", ".conf", ".cfg", ".ini",
            ".yaml", ".yml", ".json", ".csv", ".log")
MAX_FILES = 100
MAX_BYTES = 2 * 1024 * 1024


class Folder(connectors.Connector):
    NAME = "folder"
    LABEL = "Folder"
    HELP = "A directory of documentation on this machine - no network at all"
    COMPANY_WORD = "folder"
    NEEDS_URL = False
    NEEDS_TOKEN = False

    def __init__(self, config):
        super().__init__(config)
        self.root = os.path.expanduser(self.config.get("path") or "")

    def check(self):
        if not self.root:
            raise ConnectorError("no folder configured")
        if not os.path.isdir(self.root):
            raise ConnectorError("%s is not a directory" % self.root)
        return True, "reading %s, %s in it" % (
            self.root, connectors.plural(len(self.companies()), "folder"))

    def companies(self, query=""):
        if not os.path.isdir(self.root):
            return []
        found = []
        for name in sorted(os.listdir(self.root)):
            if name.startswith(".") or not os.path.isdir(os.path.join(self.root, name)):
                continue
            if query and query.lower() not in name.lower():
                continue
            found.append({"id": name, "name": name})
        return found

    def fetch(self, link):
        name = link.get("company_id")
        if not name:
            raise ConnectorError("this client is not linked to a folder yet")
        directory = os.path.join(self.root, name)
        if not os.path.isdir(directory):
            raise ConnectorError("%s no longer exists" % directory)
        documents = []
        for path in _walk(directory):
            try:
                if os.path.getsize(path) > MAX_BYTES:
                    continue
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
            except OSError:
                continue
            if not text.strip():
                continue
            relative = os.path.relpath(path, directory)
            documents.append({
                "name": relative.replace(os.sep, "-"),
                "text": "# %s\n\n%s" % (relative, text),
                "url": path,
            })
            if len(documents) >= MAX_FILES:
                break
        return {"documents": documents, "facts": []}


def _walk(directory):
    for root, dirs, files in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        for name in sorted(files):
            if name.startswith("."):
                continue
            if os.path.splitext(name)[1].lower() in READABLE:
                yield os.path.join(root, name)
