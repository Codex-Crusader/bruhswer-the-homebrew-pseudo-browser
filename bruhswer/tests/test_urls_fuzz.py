"""Property tests for address-bar normalisation.

WHY PROPERTIES AND NOT MORE EXAMPLES
    `tests/test_security.py` already checks specific refusals: javascript:, file:, a URL
    that tries to smuggle a flag. Those are examples, and examples only ever prove the
    cases someone thought of. `urls.normalise` sits on the one path where text a human
    typed becomes an argv element handed to a browser process, so what matters is the
    INVARIANTS that must hold for every input, including the ones nobody enumerated.

    The generator here is deliberately hostile and deliberately boring: it is a fixed,
    seeded corpus rather than a random one, because a fuzz test that finds a different
    failure on every run cannot be used as a release gate. New pathological inputs get
    appended to the corpus; nothing is generated from the clock.

THE INVARIANTS
    P1  normalise() either returns a str or raises RefusedURL. No other exception type
        escapes - a ValueError or an IndexError leaking out of URL parsing would reach
        the UI as an unhandled crash.
    P2  Any returned value is http://, https://, or exactly "about:blank".
    P3  No returned value contains a control, invisible, or direction-changing char.
    P4  No returned value contains a newline or carriage return.
    P5  UNC paths, drive letters and forbidden schemes are ALWAYS refused.
    P6  Anything normalise() returns must survive edge.build_command() without raising,
        because that is where it actually goes. This is the invariant that ties the two
        modules together: a URL this module blesses and the launcher then rejects would
        be a crash on the navigate path.

WHAT THIS DOES NOT CLAIM
    Homoglyph safety. "example.com" with a Cyrillic 'a' is ordinary visible text and is
    NOT refused - see the honest-boundary note on urls._DECEPTIVE. Asserting that
    lookalikes are caught would make this file the thing it exists to prevent: a test
    whose passing implies a protection that was never built.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.browser import edge, urls  # noqa: E402

# Every character urls._DECEPTIVE refuses, written as escapes for the same reason the
# module constant is: literal invisibles in source cannot be reviewed by reading it.
DECEPTIVE_CHARS = (
    "\u00ad", "\u061c", "\u200b", "\u200c", "\u200d", "\u200e", "\u200f",
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2028", "\u2029", "\u2066", "\u2067", "\u2068", "\u2069", "\ufeff",
)

# Characters that must never appear in anything normalise() hands back.
FORBIDDEN_IN_OUTPUT = (*(chr(c) for c in range(0x20)), "\x7f", *DECEPTIVE_CHARS)

# --- the corpus -----------------------------------------------------------------
# Grouped by the reason each entry is here, so a failure says something.

ORDINARY = [
    "example.com",
    "https://example.com",
    "http://example.com/path?q=1#frag",
    "example.com:8443/x",
    "192.168.1.1",
    "localhost:5173",
    "about:blank",
    "just a search query",
    "what is 2 + 2",
    "site.co.uk/a/b/c",
]

MUST_REFUSE_SCHEME = [
    "javascript:alert(1)",
    "JavaScript:alert(1)",
    "  javascript:alert(1)",
    "file:///C:/Windows/System32/drivers/etc/hosts",
    "FILE://server/share",
    "data:text/html;base64,PHNjcmlwdD4=",
    "vbscript:msgbox(1)",
    "blob:https://example.com/uuid",
    "chrome://settings",
    "edge://settings/profiles",
    "view-source:https://example.com",
    "ftp://files.example.com",
    "ws://example.com/socket",
    "wss://example.com/socket",
]

MUST_REFUSE_PATHLIKE = [
    r"\\server\share\file.txt",
    r"\\?\C:\Windows",
    r"C:\Windows\System32",
    r"c:/windows/system32",
    r"D:\data",
]

MUST_REFUSE_EMPTY = ["", "   ", "\t", "\n", "  \r\n  "]


def _with_every_deceptive_char() -> list[str]:
    """One entry per refused character, in a place where it would actually do harm."""
    out: list[str] = []
    for ch in DECEPTIVE_CHARS:
        out.append(f"https://example.com/{ch}fdp.exe")
        out.append(f"https://exam{ch}ple.com")
        out.append(f"exam{ch}ple.com")
        out.append(f"{ch}https://example.com")
    return out


def _with_every_control_char() -> list[str]:
    out: list[str] = []
    for code in [*range(0x20), 0x7f]:
        out.append(f"https://example.com/{chr(code)}x")
        out.append(f"exam{chr(code)}ple.com")
    return out


PATHOLOGICAL = [
    # Homoglyphs. NOT expected to be refused - only expected not to crash, and not to
    # come back carrying anything from FORBIDDEN_IN_OUTPUT.
    "https://ex\u0430mple.com",          # Cyrillic a
    "\u0440\u0430\u0443\u0440\u0430l.com",
    "https://xn--80ak6aa92e.com",        # punycode, a legitimate encoding
    "\u4f8b\u5b50.\u4e2d\u56fd",         # non-latin domain
    # Structure the parser might mishandle.
    "https://",
    "http://",
    "https:///path",
    "https://@example.com",
    "https://user:pass@example.com",
    "https://example.com:99999",
    "https://[::1]:8080/",
    "https://[fe80::1%eth0]/",
    # MEASURED: each of these makes urlparse() itself raise ValueError ("Invalid IPv6
    # URL" / "does not appear to be an IPv4 or IPv6 address"). Before normalise() caught
    # it, that ValueError escaped to the caller - a second failure mode the UI does not
    # handle, reaching Tk as an unhandled exception rather than a refusal. These entries
    # are what makes P1 a real test instead of a restatement of the happy path.
    "https://[fe80::1",
    "https://[",
    "https://[]",
    "http://[::1",
    "http://[1:2:3]badbracket",
    "https://[::1]:notaport",
    "https://[v1.x]",
    "http://example.com\\@evil.com",
    "https://example.com#@evil.com",
    "//example.com",
    "///example.com",
    "....",
    "..",
    ".",
    "-",
    ":",
    "://",
    "?",
    "#",
    "%",
    "%00",
    "%2e%2e%2f",
    "a" * 4000,
    "https://example.com/" + "a" * 4000,
    "https://" + "a." * 500 + "com",
    # Scheme-adjacent text that is NOT one of the forbidden schemes.
    "httpsx://example.com",
    "nothttps://example.com",
    "mailto:someone@example.com",
    "tel:+1234567890",
    # Whitespace handling.
    "  https://example.com  ",
    "example .com",
    "example.com /path",
]

CORPUS = (ORDINARY + MUST_REFUSE_SCHEME + MUST_REFUSE_PATHLIKE + MUST_REFUSE_EMPTY
          + PATHOLOGICAL + _with_every_deceptive_char() + _with_every_control_char())


class TestNormaliseProperties(unittest.TestCase):
    """P1-P4 and P6, asserted over every corpus entry."""

    def test_corpus_is_actually_populated(self):
        """A property suite that iterates an empty list passes and proves nothing."""
        self.assertGreater(len(CORPUS), 200, f"corpus is only {len(CORPUS)} entries")

    def test_p1_only_refusedurl_escapes(self):
        for text in CORPUS:
            with self.subTest(text=text[:60]):
                try:
                    result = urls.normalise(text)
                except urls.RefusedURL:
                    continue
                except Exception as exc:            # noqa: BLE001 - that is the point  # lint: allow broad-except - catching everything IS the assertion
                    self.fail(f"{exc.__class__.__name__} escaped normalise(): {exc}")
                self.assertIsInstance(result, str)

    def test_p2_output_is_http_https_or_blank(self):
        for text in CORPUS:
            with self.subTest(text=text[:60]):
                try:
                    result = urls.normalise(text)
                except urls.RefusedURL:
                    continue
                self.assertTrue(
                    result == urls.BLANK or result.startswith(("http://", "https://")),
                    f"normalise({text[:40]!r}) returned {result[:60]!r}")

    def test_p3_output_carries_no_invisible_or_reordering_character(self):
        for text in CORPUS:
            with self.subTest(text=text[:60]):
                try:
                    result = urls.normalise(text)
                except urls.RefusedURL:
                    continue
                for ch in FORBIDDEN_IN_OUTPUT:
                    self.assertNotIn(
                        ch, result,
                        f"normalise({text[:40]!r}) leaked U+{ord(ch):04X}")

    def test_p4_output_has_no_line_break(self):
        for text in CORPUS:
            with self.subTest(text=text[:60]):
                try:
                    result = urls.normalise(text)
                except urls.RefusedURL:
                    continue
                self.assertNotIn("\n", result)
                self.assertNotIn("\r", result)

    def test_p6_every_accepted_url_survives_build_command(self):
        """The invariant that ties normalise() to where its output actually goes."""
        for text in CORPUS:
            with self.subTest(text=text[:60]):
                try:
                    result = urls.normalise(text)
                except urls.RefusedURL:
                    continue
                try:
                    argv = edge.build_command(
                        Path("msedge.exe"), Path("profile"), (), result)
                except ValueError as exc:
                    self.fail(f"normalise() accepted {text[:40]!r} -> {result[:50]!r} "
                              f"but build_command refused it: {exc}")
                self.assertEqual(argv[-1], result)


class TestNormaliseRefusals(unittest.TestCase):
    """P5, plus the specific refusals that must never silently regress."""

    def test_p5_forbidden_schemes_always_refused(self):
        for text in MUST_REFUSE_SCHEME:
            with self.subTest(text=text):
                with self.assertRaises(urls.RefusedURL):
                    urls.normalise(text)

    def test_p5_unc_and_drive_letters_always_refused(self):
        for text in MUST_REFUSE_PATHLIKE:
            with self.subTest(text=text):
                with self.assertRaises(urls.RefusedURL):
                    urls.normalise(text)

    def test_empty_input_refused(self):
        for text in MUST_REFUSE_EMPTY:
            with self.subTest(text=repr(text)):
                with self.assertRaises(urls.RefusedURL):
                    urls.normalise(text)

    def test_every_deceptive_character_is_refused_in_an_http_url(self):
        """The explicit-scheme branch returns `raw` verbatim, so this is the path that
        could actually hand a reordered address to the browser."""
        for ch in DECEPTIVE_CHARS:
            with self.subTest(char=f"U+{ord(ch):04X}"):
                with self.assertRaises(urls.RefusedURL):
                    urls.normalise(f"https://example.com/{ch}fdp.exe")

    def test_every_control_character_is_refused(self):
        for code in [*range(0x20), 0x7f]:
            with self.subTest(char=f"U+{code:04X}"):
                with self.assertRaises(urls.RefusedURL):
                    urls.normalise(f"https://example.com/{chr(code)}x")

    def test_ordinary_addresses_still_work(self):
        """The refusals must not have swallowed normal browsing."""
        self.assertEqual(urls.normalise("https://example.com"), "https://example.com")
        self.assertEqual(urls.normalise("example.com"), "https://example.com")
        self.assertEqual(urls.normalise("about:blank"), "about:blank")
        self.assertTrue(urls.normalise("hello world").startswith("https://www.bing.com"))

    def test_homoglyph_is_not_claimed_to_be_caught(self):
        """Pins the HONEST BOUNDARY as a test, so nobody later reads the deceptive-char
        filter as homoglyph protection.

        A Cyrillic lookalike is ordinary visible text: bruhswer passes it through, and
        the README/UI must not imply otherwise. If someone ever DOES build real
        confusable detection, this test failing is the signal to update the claims that
        go with it - which is the point of asserting a limitation rather than leaving
        it in a comment.
        """
        cyrillic_a = "ex\u0430mple.com"
        self.assertNotIn(cyrillic_a, ("example.com",))
        result = urls.normalise(f"https://{cyrillic_a}")
        self.assertTrue(result.startswith("https://"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
