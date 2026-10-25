"""Fetching from a documentation server, without leaving the machine twice.

Every request goes through the egress guard with exactly one host allowed, so a
documentation sync cannot turn into a connection to anywhere else - not by a
redirect, not by a library that decided to check for updates, not by a URL
someone pasted wrong.
"""

import json
import os
import stat
import urllib.error
import urllib.parse
import urllib.request

from ..privacy import EgressBlocked, no_egress

TIMEOUT = 30
# A documentation server can hold a great deal. Paging forever on a misread
# response shape would hang a sync, so there is a ceiling.
MAX_PAGES = 50


class ConnectorError(Exception):
    pass


def read_token(value=None, path=None, env=None):
    """A token from a file, an environment variable, or given outright.

    A file is preferred and is checked for being readable by other people: an
    API key that can read a client's whole documentation does not belong in a
    world-readable file, and saying so once here is better than everyone
    remembering.
    """
    if path:
        expanded = os.path.expanduser(path)
        try:
            mode = os.stat(expanded).st_mode
        except OSError as exc:
            raise ConnectorError("cannot read the token file %s: %s"
                                 % (path, exc.strerror or exc))
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            raise ConnectorError(
                "%s is readable by other users. This file holds an API key for "
                "your documentation. Run: chmod 600 %s" % (path, path))
        with open(expanded) as handle:
            token = handle.read().strip()
        if not token:
            raise ConnectorError("%s is empty" % path)
        return token
    if env:
        token = os.environ.get(env, "").strip()
        if token:
            return token
    if value:
        return value.strip()
    return ""


class Session(object):
    """HTTP against one declared host, and nothing else.

    The host is fixed at construction. Everything this makes a request to is
    checked against it, and the guard is held for the duration of each call, so
    there is no window in which a redirect could take the connection elsewhere.
    """

    def __init__(self, base_url, headers=None, timeout=TIMEOUT):
        self.base_url = base_url.rstrip("/")
        parsed = urllib.parse.urlparse(self.base_url)
        if parsed.scheme not in ("http", "https"):
            raise ConnectorError("%s is not an http(s) URL" % base_url)
        if not parsed.hostname:
            raise ConnectorError("%s has no host" % base_url)
        self.host = parsed.hostname
        self.headers = dict(headers or {})
        self.timeout = timeout

    def get(self, path, params=None):
        """One GET, as JSON. Raises ConnectorError with something readable."""
        url = self._url(path, params)
        request = urllib.request.Request(url, headers=self.headers)
        # A redirect to another host would be a connection this sync never
        # declared, so the guard is what stops it rather than a policy here.
        opener = urllib.request.build_opener(_SameHostRedirects(self.host))
        try:
            with no_egress(allow=[self.host],
                           purpose="the documentation server you configured"):
                with opener.open(request, timeout=self.timeout) as response:
                    body = response.read()
        except EgressBlocked:
            raise
        except urllib.error.HTTPError as exc:
            raise ConnectorError(_http_message(exc, url))
        except urllib.error.URLError as exc:
            raise ConnectorError("could not reach %s: %s" % (self.host, exc.reason))
        except OSError as exc:
            raise ConnectorError("could not reach %s: %s" % (self.host, exc))
        if not body:
            return {}
        try:
            return json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            raise ConnectorError(
                "%s did not return JSON. Check the URL points at the API root "
                "and not at the web interface." % url)

    def paged(self, path, params=None, page_param="page", start=1,
              extract=None):
        """Every page of a list endpoint, flattened.

        Stops when a page comes back empty or repeats the previous one, which
        is what a server that ignores the page parameter looks like.
        """
        collected, seen_first = [], None
        for index in range(MAX_PAGES):
            query = dict(params or {})
            query[page_param] = start + index
            payload = self.get(path, query)
            rows = extract(payload) if extract else payload
            if not isinstance(rows, list) or not rows:
                break
            marker = _marker(rows[0])
            if index and marker is not None and marker == seen_first:
                break                      # the page parameter is being ignored
            seen_first = marker
            collected.extend(rows)
        return collected

    def follow(self, path, params=None, results_key="results", next_key="next"):
        """A list endpoint that hands back the URL of the next page.

        NetBox works this way. The next URL is only followed when it is on the
        same host, so a sync still cannot be redirected off the machine it was
        pointed at.
        """
        collected = []
        url = self._url(path, params)
        for _ in range(MAX_PAGES):
            payload = self._get_absolute(url)
            rows = payload.get(results_key) or []
            collected.extend(rows)
            following = payload.get(next_key)
            if not following:
                break
            if urllib.parse.urlparse(following).hostname != self.host:
                break
            url = following
        return collected

    def _get_absolute(self, url):
        saved, self.base_url = self.base_url, ""
        try:
            return self.get(url)
        finally:
            self.base_url = saved

    def _url(self, path, params=None):
        url = path if path.startswith("http") else "%s/%s" % (self.base_url,
                                                              path.lstrip("/"))
        if params:
            clean = {key: value for key, value in params.items() if value is not None}
            if clean:
                joiner = "&" if "?" in url else "?"
                url = url + joiner + urllib.parse.urlencode(clean)
        return url


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse a redirect that leaves the host this sync was pointed at."""

    def __init__(self, host):
        self.host = host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlparse(newurl).hostname != self.host:
            raise ConnectorError(
                "%s redirected to %s, which is a different server. Nothing was "
                "sent there." % (self.host, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _marker(row):
    if isinstance(row, dict):
        for key in ("id", "slug", "url", "name"):
            if key in row:
                return row[key]
    return None


def _http_message(exc, url):
    if exc.code == 401:
        return ("%s rejected the API token (401). Check the token is current "
                "and has read access." % url)
    if exc.code == 403:
        return ("%s refused the request (403). The token is valid but lacks "
                "permission for this, or an IP allowlist is in the way." % url)
    if exc.code == 404:
        return ("%s was not found (404). Check the base URL - it should be the "
                "server root, not the API path." % url)
    return "%s returned HTTP %s" % (url, exc.code)
