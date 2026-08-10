"""Turn address-bar text into a URL bruhswer is willing to hand the browser.

Address-bar text is USER input, but it is still treated as untrusted (brief SS36): it
ends up as an argv element passed to a browser process, so anything that is not clearly
an http(s) URL or a search must be refused rather than guessed at.

Refused by construction: file:, javascript:, data:, vbscript:, about: (except the one
literal bruhswer itself uses), UNC paths, drive letters, control characters, and
anything with an embedded newline.
"""

from __future__ import annotations

import re
from urllib.parse import quote_plus, urlparse

# Edge's configured default. bruhswer does NOT implement a search backend (brief SS7) -
# it navigates to the search engine's normal URL, which is ordinary browsing.
SEARCH_URL = "https://www.bing.com/search?q={query}"

BLANK = "about:blank"

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_LOOKS_LIKE_HOST = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
    r"(?::\d{1,5})?(?:/.*)?$"
)
_LOOKS_LIKE_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?(?:/.*)?$")
_LOCALHOST = re.compile(r"^localhost(?::\d{1,5})?(?:/.*)?$", re.I)

_FORBIDDEN_SCHEMES = ("file:", "javascript:", "data:", "vbscript:", "blob:",
                      "chrome:", "edge:", "view-source:", "ftp:", "ws:", "wss:")


class RefusedURL(ValueError):
    """The address bar text cannot be turned into something safe to navigate to."""


def normalise(text: str) -> str:
    """Return an http(s) URL, or raise RefusedURL.

    Anything that is not recognisably a URL becomes a search, which is what a browser
    address bar does and what brief SS7 asks for.
    """
    raw = (text or "").strip()
    if not raw:
        raise RefusedURL("nothing entered")
    if _CONTROL.search(raw):
        raise RefusedURL("control characters are not allowed in an address")

    if raw == BLANK:
        return BLANK

    lowered = raw.lower()
    for scheme in _FORBIDDEN_SCHEMES:
        if lowered.startswith(scheme):
            raise RefusedURL(f"bruhswer will not open {scheme} addresses")

    # UNC path or Windows drive letter - never a web address.
    if raw.startswith("\\\\") or re.match(r"^[a-zA-Z]:[\\/]", raw):
        raise RefusedURL("that looks like a file path, not a web address")

    if lowered.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        if not parsed.netloc:
            raise RefusedURL("that address has no site name")
        return raw

    # Bare host, IPv4 or localhost typed without a scheme -> assume https.
    if (_LOOKS_LIKE_HOST.match(raw) or _LOOKS_LIKE_IPV4.match(raw)
            or _LOCALHOST.match(raw)):
        if " " in raw:
            return search(raw)
        return "https://" + raw

    return search(raw)


def search(query: str) -> str:
    return SEARCH_URL.format(query=quote_plus(query.strip()))


def is_search(text: str) -> bool:
    """For UI hinting only. Never used to decide what gets navigated to."""
    try:
        return normalise(text).startswith(SEARCH_URL.split("{")[0])
    except RefusedURL:
        return False


def display_host(url: str) -> str:
    """Short, safe label for the security indicator. Never echoes a full URL."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""
    return parsed.netloc or ""
