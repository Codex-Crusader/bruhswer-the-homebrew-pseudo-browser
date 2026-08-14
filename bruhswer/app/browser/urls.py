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

# Characters that are INVISIBLE or that REORDER what follows them. Refused for the same
# reason as control characters: they change what the address LOOKS like without changing
# what it RESOLVES to, which is the whole mechanism of an address-bar spoof.
#
# The hole this closes is specific, and it was in the explicit-scheme branch below:
# `normalise` returns `raw` VERBATIM for anything already starting http(s)://, so a URL
# carrying U+202E came back unchanged, with its tail visually reversed, and was handed
# to the browser. The search branch was never affected - quote_plus percent-encodes
# these - so the explicit-scheme path is the one that actually needed the guard.
#
#   U+00AD  soft hyphen                     U+061C  Arabic letter mark
#   U+200B-U+200D  zero-width space / non-joiner / joiner
#   U+200E, U+200F  LTR and RTL marks       U+202A-U+202E  embedding and override
#   U+2028, U+2029  line / paragraph separator
#   U+2066-U+2069  isolates                 U+FEFF  zero-width no-break space (BOM)
#
# Written as \u escapes ON PURPOSE. Pasting the real characters here would put invisible
# and direction-reversing text into bruhswer's own source, where it cannot be reviewed by
# reading it - the exact class of thing this constant exists to refuse.
#
# HONEST BOUNDARY, stated because an absent claim is easy to misread as a present one:
# this does NOT detect homoglyphs. "example.com" spelled with a Cyrillic 'a' (U+0430) is
# made of ordinary VISIBLE letters and passes this filter. Refusing every non-ASCII host
# would break legitimate internationalised domains, and a partial homoglyph table would
# itself be a false claim of protection. bruhswer refuses what is invisible or
# reordering; it does not claim to tell you a visible name is not a lookalike.
_DECEPTIVE = re.compile(
    "[\u00ad\u061c\u200b-\u200f\u202a-\u202e\u2028\u2029\u2066-\u2069\ufeff]")
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
    # Checked HERE, before the scheme branches, so it covers the explicit-http(s) path
    # that returns `raw` unchanged. Refusing outright rather than stripping: silently
    # removing a character changes where the user goes without telling them, and this
    # project does not guess at an address it was not given cleanly.
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

    # UNC path or Windows drive letter - never a web address.
    if raw.startswith("\\\\") or re.match(r"^[a-zA-Z]:[\\/]", raw):
        raise RefusedURL("that looks like a file path, not a web address")

    if lowered.startswith(("http://", "https://")):
        # urlparse RAISES ValueError on some inputs - an IPv6 literal with a zone id
        # ("https://[fe80::1%eth0]/") is the easy one to hit. Uncaught, that leaves
        # normalise() with two failure modes: RefusedURL, which the UI handles, and a
        # bare ValueError, which reaches Tk as an unhandled exception. Everything that
        # goes wrong in here is a refusal.
        try:
            parsed = urlparse(raw)
            netloc = parsed.netloc
        except ValueError as exc:
            raise RefusedURL("that address could not be parsed as a web address") from exc
        if not netloc:
            raise RefusedURL("that address has no site name")
        # Embedded credentials. "https://www.paypal.com@evil.example/login" is a valid
        # URL whose SITE is evil.example, and the part a person reads first is the part
        # that is decorative. bruhswer has no use for URL credentials - Edge itself
        # strips and warns on them - so this is refused rather than passed through with
        # a note nobody would see.
        if "@" in netloc:
            raise RefusedURL(
                "that address hides the real site name behind a '@'. The site it "
                "would actually open is the part after the '@'")
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
