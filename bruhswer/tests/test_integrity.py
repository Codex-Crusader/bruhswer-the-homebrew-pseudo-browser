"""Tests for the self-integrity manifest.

The manifest's job is to notice that bruhswer's own files are not what shipped. The
tests that matter are the three ways that can happen, and the two ways the check could
be dishonest:

  detects   a file whose CONTENTS changed
  detects   a file that is MISSING
  detects   a file that is PRESENT BUT NOT LISTED  <- the obvious way past a naive check
  honest    no manifest -> UNKNOWN, never PASS
  honest    the PASS wording does not claim protection against a targeted attacker

The tamper cases run against a temporary tree rather than the real `app/`, so the suite
never edits bruhswer's own source to prove a point.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.security import integrity  # noqa: E402
from app.verdict import Verdict  # noqa: E402


class _Tree:
    """A throwaway package tree with a manifest beside it."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        (self.root / "security").mkdir()
        (self.root / "ui" / "panels").mkdir(parents=True)
        self.manifest = self.root / "security" / "MANIFEST.sha256"

        self.files = {
            "verdict.py": b"VERDICT = 1\n",
            "security/browser_guard.py": b"def verify():\n    return []\n",
            "ui/panels/host_panel.py": b"# a UI panel is just as importable\n",
        }
        for key, data in self.files.items():
            (self.root / key).write_bytes(data)

    def write_manifest(self) -> None:
        text = integrity.format_manifest(integrity.build_manifest(self.root))
        with self.manifest.open("w", encoding="utf-8", newline="") as handle:
            handle.write(text)

    def check(self):
        return integrity.check_tree(self.root, self.manifest)

    def close(self) -> None:
        self._tmp.cleanup()


class TestManifestDetectsChange(unittest.TestCase):

    def setUp(self):
        self.tree = _Tree()
        self.tree.write_manifest()

    def tearDown(self):
        self.tree.close()

    def test_an_untouched_tree_verifies(self):
        report = self.tree.check()
        self.assertTrue(report.ok, f"clean tree reported {report.problems} problem(s)")
        self.assertEqual(report.matched, 3)

    def test_a_single_changed_byte_is_detected(self):
        target = self.tree.root / "security" / "browser_guard.py"
        target.write_bytes(b"def verify():\n    return [] # \n")
        report = self.tree.check()
        self.assertFalse(report.ok)
        self.assertEqual(report.changed, ("security/browser_guard.py",))

    def test_a_semantically_hostile_edit_is_detected(self):
        """The realistic case: a guard rewritten to always pass."""
        target = self.tree.root / "security" / "browser_guard.py"
        target.write_bytes(b"def verify():\n    return ['ALWAYS PASS']\n")
        report = self.tree.check()
        self.assertIn("security/browser_guard.py", report.changed)

    def test_a_missing_file_is_detected(self):
        (self.tree.root / "verdict.py").unlink()
        report = self.tree.check()
        self.assertFalse(report.ok)
        self.assertEqual(report.missing, ("verdict.py",))

    def test_an_unlisted_new_file_is_detected(self):
        """The obvious way past a naive manifest: add code rather than change it."""
        (self.tree.root / "ui" / "panels" / "evil.py").write_bytes(b"# new module\n")
        report = self.tree.check()
        self.assertFalse(report.ok, "a new unlisted .py file was not reported")
        self.assertEqual(report.unexpected, ("ui/panels/evil.py",))

    def test_a_ui_panel_is_covered_not_just_security_modules(self):
        """Hashing only 'security-relevant' files would be a green light over a
        fraction of what runs - every module here is imported into one process."""
        target = self.tree.root / "ui" / "panels" / "host_panel.py"
        target.write_bytes(b"# tampered\n")
        report = self.tree.check()
        self.assertIn("ui/panels/host_panel.py", report.changed)


class TestManifestHonesty(unittest.TestCase):

    def test_a_missing_manifest_is_unknown_never_pass(self):
        tree = _Tree()
        try:
            report = integrity.check_tree(tree.root, tree.manifest)
            self.assertFalse(report.manifest_present)
            self.assertFalse(report.ok)
        finally:
            tree.close()

    def test_an_empty_manifest_is_treated_as_absent_not_as_a_pass(self):
        """A zero-byte manifest must not verify a tree by matching nothing."""
        tree = _Tree()
        try:
            tree.manifest.write_text("", encoding="utf-8")
            report = integrity.check_tree(tree.root, tree.manifest)
            self.assertFalse(report.ok)
            self.assertFalse(report.manifest_present)
        finally:
            tree.close()

    def test_check_is_not_critical_so_it_cannot_block_launch(self):
        """A damaged install is worth reporting, not worth refusing to run over -
        and a targeted attacker would have regenerated the manifest anyway."""
        for check in integrity.verify():
            self.assertFalse(check.critical)
            self.assertFalse(check.blocks_launch)

    def test_pass_wording_does_not_overclaim(self):
        """The PASS text must not imply protection against someone who can also edit
        the manifest. That is the ceiling of any self-check with no external anchor."""
        checks = integrity.verify()
        self.assertEqual(len(checks), 1)
        check = checks[0]

        # The TITLE must stay narrow whatever the verdict. "self-integrity", "tamper
        # proof" and friends promise attacker resistance that no self-check can have
        # when the manifest and the checker live in the same writable directory - and
        # titles are what people actually read.
        for forbidden in ("tamper", "integrity protect", "trusted", "secure"):
            self.assertNotIn(forbidden, check.title.lower(),
                             f"title claims more than it measures: {check.title!r}")

        if check.verdict is Verdict.PASS:
            detail = check.detail.lower()
            self.assertIn("does not protect", detail,
                          "PASS text omits the limitation that anyone who can modify "
                          "the install can modify the manifest too")
            self.assertIn("modify", detail)

    def test_parse_ignores_malformed_lines_rather_than_raising(self):
        parsed = integrity.parse_manifest(
            "# comment\n\ngarbage\nabc123  real/path.py\n")
        self.assertEqual(parsed, {"real/path.py": "abc123"})

    def test_line_endings_do_not_change_the_hash(self):
        """The bug that would have made every fresh clone report FAIL.

        core.autocrlf is true in this repo and there is no .gitattributes, so git
        stores LF and checks CRLF out. A manifest built on one working copy would then
        mismatch the bytes a fresh clone produces, and a check that cries wolf on every
        clean install is worse than no check - it teaches the user to ignore it.
        """
        tree = _Tree()
        try:
            target = tree.root / "verdict.py"
            target.write_bytes(b"A = 1\nB = 2\n")
            lf_hash = integrity.hash_file(target)
            target.write_bytes(b"A = 1\r\nB = 2\r\n")
            crlf_hash = integrity.hash_file(target)
            self.assertEqual(lf_hash, crlf_hash,
                             "CRLF and LF versions of identical source hash "
                             "differently; a fresh clone would fail the manifest")
        finally:
            tree.close()

    def test_a_chunk_boundary_between_cr_and_lf_is_handled(self):
        """The normalisation reads in chunks, so a CRLF pair can straddle a boundary."""
        tree = _Tree()
        try:
            target = tree.root / "big.py"
            filler = b"x" * (integrity.config.HASH_CHUNK_BYTES - 1)
            target.write_bytes(filler + b"\r\n" + b"y" * 10)
            crlf_hash = integrity.hash_file(target)
            target.write_bytes(filler + b"\n" + b"y" * 10)
            lf_hash = integrity.hash_file(target)
            self.assertEqual(crlf_hash, lf_hash,
                             "a CRLF split across a read boundary was not normalised")
        finally:
            tree.close()

    def test_a_real_content_change_is_still_detected(self):
        """Normalising line endings must not blunt the actual check."""
        tree = _Tree()
        try:
            target = tree.root / "verdict.py"
            target.write_bytes(b"A = 1\r\n")
            before = integrity.hash_file(target)
            target.write_bytes(b"A = 2\r\n")
            self.assertNotEqual(before, integrity.hash_file(target))
        finally:
            tree.close()

    def test_manifest_format_is_deterministic(self):
        """Two runs must produce byte-identical output, or every release diff is noise
        and a real change hides in it."""
        tree = _Tree()
        try:
            first = integrity.format_manifest(integrity.build_manifest(tree.root))
            second = integrity.format_manifest(integrity.build_manifest(tree.root))
            self.assertEqual(first, second)
            self.assertNotIn("\r", first, "CRLF would make the manifest machine-specific")
        finally:
            tree.close()


class TestRealTree(unittest.TestCase):
    """One smoke test against bruhswer's actual source."""

    def test_the_shipped_manifest_covers_every_app_source_file(self):
        report = integrity.check_tree()
        if not report.manifest_present:
            self.skipTest("no manifest in this checkout; run tools/hash_manifest.py "
                          "--write")
        self.assertGreater(report.total, 20,
                           "manifest covers suspiciously few files")
        self.assertEqual(
            report.unexpected, (),
            f"source files exist that the manifest does not list: "
            f"{report.unexpected[:5]} - regenerate with tools/hash_manifest.py --write")


if __name__ == "__main__":
    unittest.main(verbosity=2)
