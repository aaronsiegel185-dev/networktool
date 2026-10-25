"""Hudu: IT documentation, as used by most people who run other people's networks.

The API is at /api/v1 on the Hudu server, authenticated with an `x-api-key`
header. Articles carry HTML, so they are flattened to text on the way in.

Asset layouts are where the useful specifics usually live - the firewall with
its WAN address, the switch with its management IP - so assets are read as
facts rather than as prose, and articles are read as documents.
"""

from .. import connectors
from .http import ConnectorError
from .htmltext import to_text

# Field names that are worth lifting out of an asset as a fact. Hudu lets
# anyone name their own fields, so this matches loosely and anything unmatched
# still arrives as part of the asset's text.
FACT_HINTS = ("ip", "address", "hostname", "host name", "fqdn", "serial",
              "model", "subnet", "vlan", "gateway", "wan", "lan", "url",
              "firmware", "version", "isp", "circuit", "account")


class Hudu(connectors.Connector):
    NAME = "hudu"
    LABEL = "Hudu"
    HELP = "IT documentation: articles, assets and passwords (passwords are never read)"
    COMPANY_WORD = "company"

    def headers(self):
        token = self.token()
        if not token:
            raise ConnectorError(
                "Hudu needs an API key. Make one under Admin > API Keys, put it "
                "in a file, and run: toolbox assist connector add hudu "
                "--url https://your.hudu --token-file ~/.hudu-key")
        return {"x-api-key": token, "Accept": "application/json"}

    def _api(self):
        return connectors.Session(self.url.rstrip("/") + "/api/v1",
                                  headers=self.headers())

    def check(self):
        session = self._api()
        rows = session.get("/companies", {"page": 1})
        companies = _rows(rows, "companies")
        return True, "reached %s, %s visible" % (
            self.host(), connectors.plural(len(companies), self.COMPANY_WORD))

    def companies(self, query=""):
        session = self._api()
        rows = session.paged("/companies", {"search": query or None},
                             extract=lambda payload: _rows(payload, "companies"))
        found = [{"id": row.get("id"), "name": row.get("name", "")} for row in rows]
        if query:
            wanted = query.lower()
            narrowed = [row for row in found if wanted in row["name"].lower()]
            if narrowed:
                return narrowed
        return found

    def fetch(self, link):
        company_id = link.get("company_id")
        if not company_id:
            raise ConnectorError("this client is not linked to a Hudu company yet")
        session = self._api()
        documents, facts = [], []

        articles = session.paged(
            "/articles", {"company_id": company_id},
            extract=lambda payload: _rows(payload, "articles"))
        for article in articles:
            text = to_text(article.get("content") or "")
            if not text:
                continue
            documents.append({
                "name": _filename(article.get("name") or "article", "md"),
                "text": "# %s\n\n%s" % (article.get("name") or "Article", text),
                "url": article.get("url") or "",
            })

        assets = session.paged(
            "/companies/%s/assets" % company_id, None,
            extract=lambda payload: _rows(payload, "assets"))
        for asset in assets:
            name = asset.get("name") or "asset"
            lines, fields = [], asset.get("fields") or []
            for field in fields:
                label = (field.get("label") or "").strip()
                value = field.get("value")
                if not label or value in (None, "", []):
                    continue
                # Hudu returns a password field's value only when the key is
                # allowed to read it. Not reading them at all is the safer
                # default: a documentation sync has no business pulling
                # credentials into a notebook.
                if _is_secret(field):
                    continue
                rendered = _flatten(value)
                lines.append("%s: %s" % (label, rendered))
                if _is_facty(label):
                    facts.append({"label": ("%s %s" % (name, label)).strip(),
                                  "value": rendered})
            if lines:
                documents.append({
                    "name": _filename(name, "txt"),
                    "text": "%s (%s)\n%s" % (name, asset.get("asset_type") or "asset",
                                             "\n".join(lines)),
                    "url": asset.get("url") or "",
                })
        return {"documents": documents, "facts": facts}


def _is_secret(field):
    kind = (field.get("field_type") or "").lower()
    label = (field.get("label") or "").lower()
    return ("password" in kind or "password" in label
            or "secret" in label or "api key" in label)


def _is_facty(label):
    low = label.lower()
    return any(hint in low for hint in FACT_HINTS)


def _flatten(value):
    if isinstance(value, list):
        return ", ".join(_flatten(item) for item in value)
    if isinstance(value, dict):
        for key in ("name", "label", "value"):
            if key in value:
                return str(value[key])
        return ", ".join("%s=%s" % (k, v) for k, v in sorted(value.items()))
    return str(value).strip()


def _rows(payload, key):
    """Hudu wraps lists in a key; some deployments return a bare list."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        rows = payload.get(key)
        if isinstance(rows, list):
            return rows
        for value in payload.values():
            if isinstance(value, list):
                return value
    return []


def _filename(name, extension):
    cleaned = "".join(c if c.isalnum() or c in "-_ ." else "-" for c in name)
    cleaned = "-".join(cleaned.split()) or "document"
    return "%s.%s" % (cleaned[:60], extension)
