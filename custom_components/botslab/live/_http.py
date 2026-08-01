"""Blocking HTTP surface for the live transport.

The live pipeline runs entirely inside a worker thread (raw UDP/TCP sockets with tight timing
loops), so its handful of HTTPS calls have to be synchronous — there is no event loop to await
on. :class:`Http` is the seam that keeps them that way while still letting the caller choose the
underlying client: Home Assistant asks integrations to send all outgoing HTTP through its shared
aiohttp session, so ``live/manager.py`` injects a session-backed transport that bridges each call
to the loop. :class:`UrllibHttp` is the stdlib fallback used when the transport runs outside Home
Assistant (unit tests, standalone scripts). TLS is verified normally either way.

Subclasses implement :meth:`Http.request` only; URL/query building, form encoding and JSON
decoding are shared so every transport puts the identical bytes on the wire.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

TIMEOUT = 15  # seconds, per request

_FORM = "application/x-www-form-urlencoded"


def _url(base: str, params: dict[str, str] | None) -> str:
    if not params:
        return base
    sep = "&" if "?" in base else "?"
    return base + sep + urllib.parse.urlencode(params)


def _body(data: dict[str, str] | str | None) -> bytes | None:
    if isinstance(data, str):
        return data.encode()
    if data is not None:
        return urllib.parse.urlencode(data).encode()
    return None


class Http:
    """Blocking HTTP client used by the live transport."""

    def request(self, method: str, url: str, *, body: bytes | None,
                headers: dict[str, str]) -> bytes:
        """Perform the request and return the raw response body.

        Implementations raise :class:`OSError` (or a subclass) for transport and HTTP-status
        failures, matching what the callers already handle.
        """
        raise NotImplementedError

    def get_json(self, url: str, *, params: dict[str, str] | None = None,
                 headers: dict[str, str] | None = None) -> dict:
        """GET and parse JSON."""
        return json.loads(self.request("GET", _url(url, params), body=None,
                                       headers=dict(headers or {})))

    def get_text(self, url: str, *, params: dict[str, str] | None = None,
                 headers: dict[str, str] | None = None) -> str:
        """GET and return the raw body as text."""
        return self.request("GET", _url(url, params), body=None,
                            headers=dict(headers or {})).decode("utf-8", "replace")

    def post_json(self, url: str, *, params: dict[str, str] | None = None,
                  data: dict[str, str] | str | None = None,
                  headers: dict[str, str] | None = None) -> dict:
        """POST a form/body and parse the JSON response."""
        body = _body(data)
        head = dict(headers or {})
        if body is not None and not any(k.lower() == "content-type" for k in head):
            head["Content-Type"] = _FORM  # what urllib would have defaulted to
        return json.loads(self.request("POST", _url(url, params), body=body, headers=head))


class UrllibHttp(Http):
    """Stdlib transport — used when the live package runs without Home Assistant."""

    def request(self, method: str, url: str, *, body: bytes | None,
                headers: dict[str, str]) -> bytes:
        """Send via ``urllib.request``; raises ``URLError``/``HTTPError`` (both OSError)."""
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.read()


DEFAULT_HTTP = UrllibHttp()
