"""HTML into readable text, for documentation that is stored as markup.

Hudu articles and BookStack pages come back as HTML. A model reads the text far
better than the tags, and the tags cost context that the text needs, so this
flattens one into the other - keeping the structure that carries meaning
(headings, list items, table rows, links) and dropping the rest.

Deliberately small and dependency-free rather than a full renderer: it only has
to be right about documentation, and documentation is mostly headings, lists
and tables.
"""

from html.parser import HTMLParser

# Tags whose content is markup machinery, not prose.
SKIP = {"script", "style", "head", "meta", "link", "noscript", "svg"}
BLOCK = {"p", "div", "section", "article", "header", "footer", "br",
         "tr", "ul", "ol", "dl", "blockquote", "pre", "figure"}
HEADINGS = {"h1", "h2", "h3", "h4", "h5", "h6"}


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.skipping = 0
        self._href = None

    def handle_starttag(self, tag, attrs):
        if tag in SKIP:
            self.skipping += 1
            return
        if self.skipping:
            return
        if tag in HEADINGS:
            self._break(2)
            self.parts.append("## ")
        elif tag in ("li",):
            self._break(1)
            self.parts.append("- ")
        elif tag in ("td", "th"):
            if self.parts and not self.parts[-1].endswith(("\n", " ")):
                self.parts.append(" | ")
        elif tag in BLOCK:
            self._break(1)
        elif tag == "a":
            self._href = dict(attrs).get("href")

    def handle_endtag(self, tag):
        if tag in SKIP:
            self.skipping = max(0, self.skipping - 1)
            return
        if self.skipping:
            return
        if tag == "a" and self._href:
            # Keep the target only when it adds something the text does not.
            target = self._href
            self._href = None
            if target.startswith(("http://", "https://")):
                tail = "".join(self.parts[-3:])
                if target not in tail:
                    self.parts.append(" <%s>" % target)
        elif tag in HEADINGS or tag in BLOCK:
            self._break(1)

    def handle_data(self, data):
        if self.skipping:
            return
        text = data.replace("\xa0", " ")
        if not text.strip():
            # Whitespace between tags still separates words.
            if self.parts and not self.parts[-1].endswith((" ", "\n")):
                self.parts.append(" ")
            return
        self.parts.append(" ".join(text.split()) if "\n" in text else text)

    def _break(self, count):
        while self.parts and self.parts[-1] == " ":
            self.parts.pop()
        existing = 0
        for part in reversed(self.parts):
            if part == "\n":
                existing += 1
            else:
                break
        for _ in range(max(0, count - existing)):
            self.parts.append("\n")

    def result(self):
        text = "".join(self.parts)
        lines = [line.rstrip() for line in text.splitlines()]
        out, blanks = [], 0
        for line in lines:
            if line:
                blanks = 0
                out.append(line)
            else:
                blanks += 1
                if blanks < 2:
                    out.append("")
        return "\n".join(out).strip()


def to_text(html):
    """Readable text from an HTML fragment. Never raises on bad markup."""
    if not html:
        return ""
    parser = _Text()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        # Malformed markup in one article must not fail a whole sync; whatever
        # was parsed before the trouble is still worth having.
        pass
    return parser.result()
