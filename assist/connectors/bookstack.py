"""BookStack: open-source documentation, organised into shelves, books and pages.

Authenticates with `Authorization: Token <id>:<secret>`. BookStack has no idea
what a client is, so a client is linked to a book (or a shelf), and that book's
pages come across as documents.
"""

from .. import connectors
from .http import ConnectorError
from .htmltext import to_text


class BookStack(connectors.Connector):
    NAME = "bookstack"
    LABEL = "BookStack"
    HELP = "Open-source wiki: a book (or shelf) per client, pages as documents"
    COMPANY_WORD = "book"

    def headers(self):
        token = self.token()
        if not token:
            raise ConnectorError(
                "BookStack needs a token as id:secret, from your profile's API "
                "Tokens section. Put it in a file and run: toolbox assist "
                "connector add bookstack --url https://wiki.example.com "
                "--token-file ~/.bookstack-token")
        if ":" not in token:
            raise ConnectorError(
                "a BookStack token is the id and the secret joined by a colon, "
                "like 'abc123:def456'. The file has only one of the two.")
        return {"Authorization": "Token %s" % token, "Accept": "application/json"}

    def _api(self):
        return connectors.Session(self.url.rstrip("/") + "/api",
                                  headers=self.headers())

    def check(self):
        session = self._api()
        payload = session.get("/books", {"count": 1})
        total = payload.get("total")
        if total is None:
            return True, "reached %s" % self.host()
        return True, "reached %s, %s visible" % (
            self.host(), connectors.plural(total, "book"))

    def companies(self, query=""):
        session = self._api()
        payload = session.get("/books", {"count": 100,
                                         "filter[name:like]": "%%%s%%" % query
                                         if query else None})
        rows = payload.get("data") or []
        return [{"id": row.get("id"), "name": row.get("name", "")} for row in rows]

    def fetch(self, link):
        book_id = link.get("company_id")
        if not book_id:
            raise ConnectorError("this client is not linked to a BookStack book yet")
        session = self._api()
        listing = session.get("/pages", {"filter[book_id]": book_id, "count": 100})
        documents = []
        for row in listing.get("data") or []:
            page = session.get("/pages/%s" % row.get("id"))
            text = to_text(page.get("html") or "") or (page.get("markdown") or "")
            if not text.strip():
                continue
            name = page.get("name") or row.get("name") or "page"
            documents.append({
                "name": _filename(name),
                "text": "# %s\n\n%s" % (name, text),
                "url": "%s/books/%s/page/%s" % (self.url, row.get("book_slug", ""),
                                                page.get("slug", "")),
            })
        return {"documents": documents, "facts": []}


def _filename(name):
    cleaned = "".join(c if c.isalnum() or c in "-_ ." else "-" for c in name)
    return "%s.md" % ("-".join(cleaned.split())[:60] or "page")
