"""Turn address-bar text into an http(s) URL or a search, or refuse it. file:,
javascript:, data:, UNC paths, drive letters and control characters are refused."""

from __future__ import annotations

import re
from urllib.parse import quote_plus, urlparse

SEARCH_URL = "https://www.bing.com/search?q={query}"

BLANK = "about:blank"

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

# Invisible and text-reordering characters (soft hyphen, zero-width, bidi marks and
# overrides, isolates, BOM) change how an address looks, not where it goes. Homoglyphs
# are NOT detected: a partial table would be a false claim.
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
    # Refused, not stripped: stripping changes the destination silently.
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
        # urlparse raises ValueError on some inputs, e.g. an IPv6 zone id.
        try:
            parsed = urlparse(raw)
            netloc = parsed.netloc
        except ValueError as exc:
            raise RefusedURL("that address could not be parsed as a web address") from exc
        if not netloc:
            raise RefusedURL("that address has no site name")
        # "https://www.paypal.com@evil.example/" goes to evil.example.
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
