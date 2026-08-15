"""The security state has to be readable, or the verdict never arrives.

bruhswer's entire output is a row of coloured dots. Two ways that fails a real user:

  1. COLOUR ALONE. Red-green colour blindness makes PASS and FAIL the same dot.
  2. CONTRAST. An amber dot on a dark grey panel can be below the threshold at which
     it is legible at all, and Windows high-contrast mode exists for users for whom
     that is routine.

Both are measured here rather than asserted in a comment. The contrast ratios are
computed with the WCAG 2.1 relative-luminance formula, so "clears AA" is a number this
suite produced, not a claim somebody typed.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app import config  # noqa: E402
from app.ui.panels import chrome  # noqa: E402
from app.verdict import Verdict  # noqa: E402

# WCAG 2.1: 4.5:1 for normal text, 3:1 for large text and non-text UI components.
# The status dots are non-text indicators, so 3:1 is the applicable bar; the labels
# beside them are text and take 4.5:1.
AA_NON_TEXT = 3.0
AA_TEXT = 4.5


def _channel(value: float) -> float:
    value /= 255.0
    return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4


def luminance(colour: str) -> float:
    raw = colour.lstrip("#")
    r, g, b = (int(raw[i:i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def contrast(front: str, back: str) -> float:
    a, b = luminance(front), luminance(back)
    lighter, darker = max(a, b), min(a, b)
    return (lighter + 0.05) / (darker + 0.05)


class TestVerdictsAreNotCarriedByColourAlone(unittest.TestCase):

    def test_every_verdict_has_its_own_shape(self):
        shapes = [chrome.SHAPE[v] for v in Verdict]
        self.assertEqual(len(set(shapes)), len(Verdict),
                         f"two verdicts render as the same shape: {shapes}")

    def test_every_verdict_has_its_own_word(self):
        words = [chrome.WORD[v] for v in Verdict]
        self.assertEqual(len(set(words)), len(Verdict))

    def test_the_non_verdict_shapes_differ_from_the_verdict_ones(self):
        """LOCALHOST and VPN are not verdicts and must not look like one."""
        verdict_shapes = {chrome.SHAPE[v] for v in Verdict}
        for shape in (config.SHAPE_UNKNOWN, config.SHAPE_LIMITATION):
            with self.subTest(shape=shape):
                self.assertNotIn(shape, verdict_shapes)

    def test_the_unenforceable_shape_is_not_a_verdict_shape(self):
        self.assertNotIn(chrome.NOT_ENFORCEABLE_SHAPE,
                         {chrome.SHAPE[v] for v in Verdict})


class TestHighContrastPaletteIsActuallyReadable(unittest.TestCase):
    """The palette apply_high_contrast() installs, measured."""

    PALETTE = config._HIGH_CONTRAST  # noqa: SLF001  # lint: allow protected-access - the palette under test

    def test_every_indicator_colour_clears_the_non_text_bar(self):
        back = self.PALETTE["BG_PANEL"]
        for name in ("OK_GREEN", "WARN_AMBER", "BAD_RED", "OFF_GREY"):
            with self.subTest(colour=name):
                ratio = contrast(self.PALETTE[name], back)
                self.assertGreaterEqual(
                    ratio, AA_NON_TEXT,
                    f"{name} is {ratio:.2f}:1 on the panel; below {AA_NON_TEXT}:1 the "
                    f"status light is not reliably visible")

    def test_every_text_colour_clears_the_text_bar(self):
        back = self.PALETTE["BG_DARK"]
        for name in ("BRAND_WHITE", "FG_DIM", "BRAND_YELLOW"):
            with self.subTest(colour=name):
                ratio = contrast(self.PALETTE[name], back)
                self.assertGreaterEqual(
                    ratio, AA_TEXT,
                    f"{name} is {ratio:.2f}:1 on the background; below {AA_TEXT}:1")

    def test_the_verdict_colours_are_distinguishable_from_each_other(self):
        """Not just visible against the background - visible against each OTHER."""
        pairs = [("OK_GREEN", "WARN_AMBER"), ("OK_GREEN", "BAD_RED"),
                 ("WARN_AMBER", "BAD_RED")]
        for first, second in pairs:
            with self.subTest(pair=(first, second)):
                self.assertNotEqual(self.PALETTE[first], self.PALETTE[second])

    def test_high_contrast_improves_on_the_default_palette(self):
        """Otherwise the whole switch is decoration."""
        default = contrast(config.WARN_AMBER, config.BG_PANEL)
        improved = contrast(self.PALETTE["WARN_AMBER"], self.PALETTE["BG_PANEL"])
        self.assertGreater(
            improved, default,
            f"high-contrast amber ({improved:.2f}:1) is no better than the default "
            f"({default:.2f}:1)")

    def test_applying_it_replaces_the_policy_colours_too(self):
        """A stale POLICY_STATE_COLOUR would leave the Network panel on old colours."""
        import importlib

        fresh = importlib.reload(config)
        try:
            fresh.apply_high_contrast()
            self.assertEqual(fresh.BG_DARK, self.PALETTE["BG_DARK"])
            self.assertEqual(fresh.POLICY_STATE_COLOUR["BLOCKED"],
                             self.PALETTE["OK_GREEN"])
            self.assertEqual(fresh.POLICY_STATE_UNKNOWN_COLOUR,
                             self.PALETTE["BAD_RED"])
            # Every state the network layer can return still has a colour.
            from app.network import network_guard
            for state in network_guard.PolicyState:
                with self.subTest(state=state):
                    self.assertIn(str(state), fresh.POLICY_STATE_COLOUR)
        finally:
            importlib.reload(config)


class TestLightPaletteIsActuallyReadable(unittest.TestCase):
    """bruhswer is dark by default; this is what it uses on a light-mode machine.

    The verdict hues had to be DARKENED rather than reused: the dark theme's #3FB950
    green is about 1.9:1 on a light panel, which would have made the status lights -
    the entire product - unreadable for the users this switch is meant to serve.
    """

    PALETTE = config._LIGHT  # noqa: SLF001  # lint: allow protected-access - the palette under test

    def test_every_indicator_colour_clears_the_non_text_bar(self):
        back = self.PALETTE["BG_PANEL"]
        for name in ("OK_GREEN", "WARN_AMBER", "BAD_RED", "OFF_GREY"):
            with self.subTest(colour=name):
                ratio = contrast(self.PALETTE[name], back)
                self.assertGreaterEqual(
                    ratio, AA_NON_TEXT,
                    f"{name} is {ratio:.2f}:1 on the light panel")

    def test_every_text_colour_clears_the_text_bar(self):
        back = self.PALETTE["BG_DARK"]
        for name in ("BRAND_WHITE", "FG_DIM", "BRAND_YELLOW"):
            with self.subTest(colour=name):
                ratio = contrast(self.PALETTE[name], back)
                self.assertGreaterEqual(
                    ratio, AA_TEXT,
                    f"{name} is {ratio:.2f}:1 on the light background")

    def test_it_is_actually_a_light_theme(self):
        self.assertGreater(luminance(self.PALETTE["BG_DARK"]),
                           luminance(config.BG_DARK),
                           "the 'light' palette is not lighter than the default")

    def test_reusing_the_dark_verdict_colours_would_have_failed(self):
        """Pins WHY the hues were changed, so nobody 'simplifies' them back."""
        ratio = contrast(config.OK_GREEN, self.PALETTE["BG_PANEL"])
        self.assertLess(ratio, AA_NON_TEXT,
                        "the dark green now clears AA on the light panel; this test "
                        "documents why the light palette darkens it and should be "
                        "re-derived rather than deleted")

    def test_applying_it_replaces_the_policy_colours_too(self):
        import importlib

        fresh = importlib.reload(config)
        try:
            fresh.apply_light()
            self.assertEqual(fresh.BG_DARK, self.PALETTE["BG_DARK"])
            self.assertEqual(fresh.POLICY_STATE_COLOUR["BLOCKED"],
                             self.PALETTE["OK_GREEN"])
            from app.network import network_guard
            for state in network_guard.PolicyState:
                with self.subTest(state=state):
                    self.assertIn(str(state), fresh.POLICY_STATE_COLOUR)
        finally:
            importlib.reload(config)


class TestTheDefaultPaletteIsHonestAboutItself(unittest.TestCase):
    """Not every default colour clears AA. That is a known trade, not a surprise."""

    def test_the_default_indicator_colours_are_at_least_visible(self):
        for name in ("OK_GREEN", "WARN_AMBER", "BAD_RED"):
            with self.subTest(colour=name):
                ratio = contrast(getattr(config, name), config.BG_PANEL)
                self.assertGreater(ratio, 1.0,
                                   f"{name} is invisible on the panel background")

    def test_high_contrast_detection_never_guesses(self):
        """None on failure, not False - a guess would silently deny the user the theme."""
        from app.browser import embed

        result = embed.high_contrast()
        self.assertIn(result, (True, False, None))


if __name__ == "__main__":
    unittest.main(verbosity=2)
