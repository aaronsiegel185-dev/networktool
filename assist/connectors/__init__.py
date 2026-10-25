"""Connectors: pulling a client's documentation in, once, so it can be used offline.

The rule the rest of Assist lives by is that nothing leaves this machine. A
documentation connector is the one place that has to reach outwards, so it is
built to be the narrowest possible exception:

* A sync talks to exactly one declared host, enforced by the egress guard, and
  nothing else - not a redirect, not a library, not a mistyped URL.
* What goes out is a request naming the client and an API token. The notebook,
  the capture, the screenshots and the question never go anywhere near it.
* What comes back is cached as the client's own sources. After a sync, asking
  the model touches loopback and nothing else. The documentation becomes
  offline evidence rather than a live dependency.
* `doctor` names every configured connector and says whether its host is on
  this machine, on your network, or out on the internet.

A self-hosted server on your own network keeps the original promise intact. A
hosted one does not, so it has to be allowed explicitly, once, and is reported
as such every time afterwards.
"""

import json
import os

from ..config import data_dir
from .http import ConnectorError, Session, read_token

__all__ = ["ConnectorError", "Connector", "available", "get", "load_config",
           "save_config", "configured", "describe_all"]


def plural(count, word):
    """"1 company", "2 companies" - these words are shown to people."""
    if count == 1:
        return "1 %s" % word
    if word.endswith("y") and not word.endswith(("ay", "ey", "oy", "uy")):
        return "%d %sies" % (count, word[:-1])
    if word.endswith(("s", "x", "ch", "sh")):
        return "%d %ses" % (count, word)
    return "%d %ss" % (count, word)


class Connector(object):
    """One documentation system.

    Subclasses say how to reach it, how to find a client in it, and what to
    bring back. They never decide whether reaching it is allowed - that is
    settled once at setup and recorded.
    """

    NAME = ""
    LABEL = ""
    # What someone has to supply to set it up.
    NEEDS_URL = True
    NEEDS_TOKEN = True
    #: One line shown by `connector list`, and in the app.
    HELP = ""
    #: What a "company" is called in this system, for readable messages.
    COMPANY_WORD = "company"

    def __init__(self, config):
        self.config = dict(config or {})
        self.url = (self.config.get("url") or "").rstrip("/")

    # --- to implement ----------------------------------------------------

    def check(self):
        """(ok, detail): is this reachable, and as whom."""
        raise NotImplementedError

    def companies(self, query=""):
        """[{id, name}] matching a search, for linking a client."""
        raise NotImplementedError

    def fetch(self, link):
        """What to bring back for a linked client.

        Returns {"documents": [{"name", "text", "url"}],
                 "facts": [{"label", "value"}]}.
        """
        raise NotImplementedError

    # --- shared ----------------------------------------------------------

    def token(self):
        return read_token(value=self.config.get("token"),
                          path=self.config.get("token_file"),
                          env=self.config.get("token_env"))

    def session(self, headers=None):
        if not self.url:
            raise ConnectorError("%s has no URL configured" % self.LABEL)
        return Session(self.url, headers=headers)

    def host(self):
        from urllib.parse import urlparse

        return urlparse(self.url).hostname or ""


# --- registry --------------------------------------------------------------

def available():
    """Every connector this build knows how to speak to, by name."""
    from . import bookstack, folder, hudu, netbox

    return {
        hudu.Hudu.NAME: hudu.Hudu,
        netbox.NetBox.NAME: netbox.NetBox,
        bookstack.BookStack.NAME: bookstack.BookStack,
        folder.Folder.NAME: folder.Folder,
    }


def get(name, config=None):
    """A configured connector by name."""
    registry = available()
    if name not in registry:
        raise ConnectorError("no connector called %r. Available: %s"
                             % (name, ", ".join(sorted(registry))))
    if config is None:
        config = load_config().get(name)
        if config is None:
            raise ConnectorError(
                "%s is not set up. Run: toolbox assist connector add %s --url ..."
                % (name, name))
    return registry[name](config)


# --- configuration ---------------------------------------------------------

def config_path():
    return os.path.join(data_dir(), "connectors.json")


def load_config():
    try:
        with open(config_path()) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def save_config(config):
    path = config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        json.dump(config, handle, indent=2)
    # It can hold an API token when someone passed one inline rather than in a
    # file, so it is not left readable by everyone on the machine.
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def configured():
    """Names of the connectors that have been set up."""
    return sorted(load_config())


def describe_all():
    """Every configured connector and where it points, for `doctor`."""
    from ..privacy import describe_host

    registry = available()
    out = []
    for name, config in sorted(load_config().items()):
        cls = registry.get(name)
        label = cls.LABEL if cls else name
        if cls is not None and not cls.NEEDS_URL:
            # A folder on this machine has no host to reason about.
            out.append({
                "name": name, "label": label,
                "url": config.get("path", ""), "host": "",
                "classification": "local", "where": "on this machine",
                "leaves_machine": False, "allow_public": False,
                "resolves_to": [],
            })
            continue
        described = describe_host(config.get("url", ""), label=label)
        described["name"] = name
        described["allow_public"] = bool(config.get("allow_public"))
        out.append(described)
    return out
