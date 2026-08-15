"""BrowserWindow was split into three files. These pin what the split must preserve.

Two failure modes, both silent:

  1. A mixin uses `self.something` that nothing provides. At runtime that is an
     AttributeError on a teardown path nobody exercises; statically it is one more
     warning in a list of 149, where a real typo is invisible.
  2. A WindowShell stub survives onto the assembled class - a method that raises
     NotImplementedError sitting where a real implementation was supposed to be.

The suites drive the window end to end and would eventually catch some of this. These
catch all of it, in milliseconds, without a browser.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.ui.browser_window import BrowserWindow  # noqa: E402
from app.ui.session_lifecycle import SessionLifecycleMixin  # noqa: E402
from app.ui.verification_ui import VerificationUIMixin  # noqa: E402
from app.ui.window_shell import WindowShell  # noqa: E402

_UI = _ROOT / "app" / "ui"

# The surface tests/test_browser_ui.py and tests/test_user_path.py drive. Splitting the
# class must not move any of it off BrowserWindow.
PUBLIC_SURFACE = (
    "root", "result", "hosted_hwnd", "stage", "session_badge", "controller",
    "address", "lights", "clear_placeholder", "on_navigate", "on_new_tab",
    "open_security_panel", "open_session", "close_session", "on_close", "run",
)


def _self_attributes(path: Path, class_name: str) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    cls = next(n for n in tree.body
               if isinstance(n, ast.ClassDef) and n.name == class_name)
    return {node.attr for node in ast.walk(cls)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "self"}


def _resolvable(cls: type) -> set[str]:
    """Everything an instance of `cls` can resolve, through the whole MRO."""
    names: set[str] = set()
    for klass in cls.__mro__:
        names |= set(vars(klass))
        names |= set(getattr(klass, "__annotations__", {}))
    return names


class TestEverySelfReferenceResolves(unittest.TestCase):

    def test_session_lifecycle_mixin(self):
        used = _self_attributes(_UI / "session_lifecycle.py", "SessionLifecycleMixin")
        missing = sorted(used - _resolvable(SessionLifecycleMixin))
        self.assertEqual(
            missing, [],
            f"SessionLifecycleMixin uses self.X that nothing declares: {missing}. "
            f"Add it to WindowShell, or it is a typo.")

    def test_verification_ui_mixin(self):
        used = _self_attributes(_UI / "verification_ui.py", "VerificationUIMixin")
        missing = sorted(used - _resolvable(VerificationUIMixin))
        self.assertEqual(
            missing, [],
            f"VerificationUIMixin uses self.X that nothing declares: {missing}")

    def test_browser_window_itself(self):
        used = _self_attributes(_UI / "browser_window.py", "BrowserWindow")
        missing = sorted(used - _resolvable(BrowserWindow))
        self.assertEqual(missing, [],
                         f"BrowserWindow uses self.X that nothing declares: {missing}")

    def test_the_scan_is_not_vacuous(self):
        used = _self_attributes(_UI / "session_lifecycle.py", "SessionLifecycleMixin")
        self.assertGreater(len(used), 15, "the attribute scan found almost nothing")


class TestNoStubSurvives(unittest.TestCase):
    """A WindowShell method still bound on BrowserWindow was never implemented."""

    # WindowShell's own helper, used BY the stubs. Not itself a stub, so nothing
    # overrides it and it must not be counted as a survivor.
    HELPERS = {"_unimplemented"}

    def test_every_shell_method_is_overridden(self):
        survivors = []
        for name, shell_attr in vars(WindowShell).items():
            if name.startswith("__") or not callable(shell_attr):
                continue
            if name in self.HELPERS:
                continue
            if getattr(BrowserWindow, name, None) is shell_attr:
                survivors.append(name)
        self.assertEqual(
            survivors, [],
            f"WindowShell stub(s) never implemented, and they raise "
            f"NotImplementedError if reached: {survivors}")

    def test_the_shell_declares_something_to_override(self):
        methods = [n for n, v in vars(WindowShell).items()
                   if not n.startswith("__") and callable(v)]
        self.assertGreater(len(methods), 5, "WindowShell declares almost no methods")


class TestThePublicSurfaceSurvivedTheSplit(unittest.TestCase):
    """tests/test_browser_ui.py drives these by name on the window object."""

    def test_every_pinned_name_is_reachable(self):
        available = _resolvable(BrowserWindow)
        missing = [name for name in PUBLIC_SURFACE if name not in available]
        self.assertEqual(
            missing, [],
            f"the split moved part of the surface the UI suites drive: {missing}")

    def test_the_mixins_are_actually_in_the_mro(self):
        self.assertIn(SessionLifecycleMixin, BrowserWindow.__mro__)
        self.assertIn(VerificationUIMixin, BrowserWindow.__mro__)
        self.assertIn(WindowShell, BrowserWindow.__mro__)

    def test_neither_mixin_shadows_the_other(self):
        """Two halves defining the same method would resolve by MRO order silently."""
        lifecycle = {n for n, v in vars(SessionLifecycleMixin).items()
                     if not n.startswith("__") and callable(v)}
        verification = {n for n, v in vars(VerificationUIMixin).items()
                        if not n.startswith("__") and callable(v)}
        clash = sorted(lifecycle & verification)
        self.assertEqual(clash, [],
                         f"both mixins define {clash}; one silently wins by MRO order")

    def test_the_split_actually_split_something(self):
        for name, cls in (("SessionLifecycleMixin", SessionLifecycleMixin),
                          ("VerificationUIMixin", VerificationUIMixin)):
            methods = [n for n, v in vars(cls).items()
                       if not n.startswith("__") and callable(v)]
            with self.subTest(mixin=name):
                self.assertGreater(len(methods), 5,
                                   f"{name} holds almost nothing")


if __name__ == "__main__":
    unittest.main(verbosity=2)
