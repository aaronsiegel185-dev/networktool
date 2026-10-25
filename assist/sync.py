"""Bringing a client's documentation in, so it can be used without the network.

A sync is the one outward-facing thing Assist does, and it is deliberately a
separate step rather than something that happens while you are asking a
question. What goes out is a request naming the client and an API token; what
comes back is written to the client's own directory as ordinary sources.

After it has run, asking the model touches loopback and nothing else. The
documentation is cached evidence, not a live dependency - which also means a
sync failing never stops you working a ticket.
"""

import os
import shutil
import tempfile

from . import connectors
from .connectors.http import ConnectorError

# Fetched documents are stored with this prefix so a later sync can replace
# exactly what it wrote before, and never a file someone added by hand.
PREFIX = "doc--"


def stored_name(connector, document_name):
    cleaned = "".join(c if c.isalnum() or c in "-_." else "-"
                      for c in document_name).strip("-")
    return "%s%s--%s" % (PREFIX, connector, cleaned or "document")


def is_synced(entry, connector=None):
    """Was this source brought in by a sync rather than added by hand."""
    name = entry.get("stored", "")
    if not name.startswith(PREFIX):
        return False
    if connector is None:
        return True
    return name.startswith("%s%s--" % (PREFIX, connector))


def sync_client(client, connector_name=None, on_progress=None):
    """Pull everything the linked documentation systems know about a client.

    Returns a list of per-connector results. One connector failing does not
    stop the others: a Hudu outage should not cost you the NetBox facts.
    """
    say = on_progress or (lambda *_: None)
    wanted = [connector_name] if connector_name else sorted(client.links)
    if not wanted:
        raise ConnectorError(
            "%s is not linked to any documentation yet. Link it with: "
            "toolbox assist connector link <connector> %s" % (client.name, client.id))

    results = []
    for name in wanted:
        link = client.links.get(name)
        if not link:
            results.append({"connector": name, "ok": False,
                            "error": "%s is not linked to %s" % (client.name, name)})
            continue
        try:
            results.append(_sync_one(client, name, link, say))
        except ConnectorError as exc:
            results.append({"connector": name, "ok": False, "error": str(exc)})
        except Exception as exc:                     # noqa: BLE001 - reported, not swallowed
            results.append({"connector": name, "ok": False,
                            "error": "%s: %s" % (type(exc).__name__, exc)})
    return results


def _sync_one(client, name, link, say):
    connector = connectors.get(name)
    say(name, "asking %s about %s" % (connector.LABEL,
                                      link.get("company_name") or link.get("company_id")))
    payload = connector.fetch(link)
    documents = payload.get("documents") or []
    facts = payload.get("facts") or []

    # Everything this connector left last time goes, so a document deleted at
    # the far end stops being quoted back here as though it still existed.
    removed = 0
    for entry in list(client.sources):
        if is_synced(entry, name):
            client.remove_source(entry["stored"])
            removed += 1

    staging = tempfile.mkdtemp(prefix="assist-sync-")
    added = 0
    try:
        for document in documents:
            text = document.get("text") or ""
            if not text.strip():
                continue
            filename = stored_name(name, document.get("name") or "document")
            path = os.path.join(staging, filename)
            header = document.get("url")
            body = ("Source: %s\n\n%s" % (header, text)) if header else text
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(body)
            entry = client.add_source(path, note="from %s" % connector.LABEL)
            added += 1
            say(name, "  %s" % entry["stored"])
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    client.tidy_staging()

    changed = client.replace_facts_from(name, facts)
    detail = {
        "connector": name,
        "label": connector.LABEL,
        "ok": True,
        "company": link.get("company_name") or str(link.get("company_id")),
        "documents": added,
        "replaced": removed,
        "facts": len(facts),
        "fact_change": changed,
        "host": connector.host(),
    }
    import datetime

    client.record_sync(name, dict(detail,
                                  at=datetime.datetime.now().isoformat(timespec="seconds")))
    return detail
