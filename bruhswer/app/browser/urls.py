"""Turn address-bar text into a URL bruhswer is willing to hand the browser.

Address-bar text is user input and is still untrusted: it becomes an argv element on a
browser process, so anything not clearly an http(s) URL or a search is refused rather
than guessed at. Refused by construction: file:, javascript:, data:, vbscript:, about:
(except the one literal bruhswer uses), UNC paths, drive letters, control characters.
"""

from __future__ import annotations

import re
from urllib.parse import quote_plus, urlparse

SEARCH_URL = "https://www.bing.com/search?q={query}"

BLANK = "about:blank"

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

# Invisible or text-reordering characters: they change what an address LOOKS like
# without changing what it RESOLVES to, which is the whole mechanism of a spoof. Only
# the explicit-scheme branch needed this - the search branch percent-encodes them.
#
#   U+00AD soft hyphen           U+061C Arabic letter mark
#   U+200B-U+200D zero-width     U+200E, U+200F LTR/RTL marks
#   U+202A-U+202E embed/override U+2028, U+2029 line/paragraph separator
#   U+2066-U+2069 isolates       U+FEFF BOM
#
# Escaped, not pasted: the real characters would be unreviewable in this source.
#
# Does NOT detect homoglyphs. A Cyrillic 'a' is an ordinary visible letter and passes.
# Refusing every non-ASCII host would break internationalised domains, and a partial
# homoglyph table would be a false claim of protection.
_DECEPTIVE = re.compile(
    "[\u00ad\u061c\u200b-\u200f\u202a-\u202e\u2028\u2029\u2066-\u2069\ufeff]")
_LOOKS_LIKE_HOST = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
    r"(?::\d{1,5})?(?:/.*)?$"
)
_LOOKS_LIKE_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?(?:/.*)?$")
_LOCALHOST = re.compile(r"^localhost(?::\d{1,5})?(?:/.*)?$", re.I)

_FORBIDDEN_SCHEMES = ("file:", "javascript:", "data:", "vbscript:", "blob:",
                      "chrome:", "edge:", "about:", "view-source:", "ftp:",
                      "ws:", "wss:")


class RefusedURL(ValueError):
    """The address bar text cannot be turned into something safe to navigate to."""


def normalise(text: str) -> str:
    """Return an http(s) URL, or raise RefusedURL. Unrecognised text becomes a search."""
    raw = (text or "").strip()
    if not raw:
        raise RefusedURL("nothing entered")
    if _CONTROL.search(raw):
        raise RefusedURL("control characters are not allowed in an address")
    # Before the scheme branches, so it covers the http(s) path that returns `raw`
    # unchanged. Refused, not stripped: silently removing a character changes where
    # the user goes without telling them.
    if _DECEPTIVE.search(raw):
        raise RefusedURL(
            "that address contains invisible or text-reversing characters, which are "
            "used to disguise where a link really goes")

    if raw == BLANK:
        return BLANK

    lowered = raw.lower()
    for scheme in _FORBIDDEN_SCHEMES:
        if lowered.startswith(scheme):
            raise RefusedURL(f"bruhswer will not open {scheme} addresses")

    if raw.startswith("\\\\") or re.match(r"^[a-zA-Z]:[\\/]", raw):
        raise RefusedURL("that looks like a file path, not a web address")

    if lowered.startswith(("http://", "https://")):
        # urlparse raises ValueError on some inputs - an IPv6 literal with a zone id
        # is the easy one. Uncaught it reaches Tk; everything here is a refusal.
        try:
            parsed = urlparse(raw)
            netloc = parsed.netloc
        except ValueError as exc:
            raise RefusedURL("that address could not be parsed as a web address") from exc
        if not netloc:
            raise RefusedURL("that address has no site name")
        # "https://www.paypal.com@evil.example/login" is a valid URL whose SITE is
        # evil.example, and the part read first is decorative.
        if "@" in netloc:
            raise RefusedURL(
                "that address hides the real site name behind a '@'. The site it "
                "would actually open is the part after the '@'")
        return raw

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
