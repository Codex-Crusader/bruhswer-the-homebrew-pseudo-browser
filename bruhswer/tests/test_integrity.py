"""The file manifest: detects changed, missing and unlisted files; no manifest is
UNKNOWN; the wording claims no attacker resistance. Tampering uses a temporary tree."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.security import integrity  # noqa: E402
from app.verdict import UnknownReason, Verdict  # noqa: E402


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
        """Every module runs in one process, so every module is hashed."""
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

    def test_a_ruined_manifest_is_not_reported_as_an_absent_one(self):
        """A present but unusable manifest is UNKNOWN, never explained as "normal in a
        source checkout"; non-UTF-8 once raised."""
        cases = (
            ("empty", b""),
            ("unparseable", b"garbage\n"),
            ("not utf-8", b"\xff\xfe\x00\x80"),
        )
        for name, payload in cases:
            with self.subTest(manifest=name):
                tree = _Tree()
                try:
                    tree.manifest.write_bytes(payload)
                    report = integrity.check_tree(tree.root, tree.manifest)
                    self.assertFalse(report.ok)
                    self.assertFalse(report.manifest_present)
                    self.assertTrue(report.manifest_unreadable)
                finally:
                    tree.close()

        tree = _Tree()
        try:
            report = integrity.check_tree(tree.root, tree.manifest)
            self.assertFalse(report.manifest_unreadable,
                             "an absent manifest is not a damaged one")
        finally:
            tree.close()

    def test_a_ruined_manifest_reaches_the_user_as_unreadable(self):
        """Through verify(), as the panel reads it."""
        tree = _Tree()
        try:
            tree.manifest.write_bytes(b"\xff\xfe\x00\x80")
            report = integrity.check_tree(tree.root, tree.manifest)
        finally:
            tree.close()

        with mock.patch.object(integrity, "check_tree", lambda *a, **k: report):
            checks = integrity.verify()
        self.assertEqual(len(checks), 1)
        self.assertIs(checks[0].verdict, Verdict.UNKNOWN)
        self.assertIs(checks[0].unknown_reason, UnknownReason.UNREADABLE)
        self.assertNotIn("source checkout", checks[0].detail)

    def test_check_is_not_critical_so_it_cannot_block_launch(self):
        """Worth reporting, not blocking: an attacker would regenerate the manifest."""
        for check in integrity.verify():
            self.assertFalse(check.critical)
            self.assertFalse(check.blocks_launch)

    def test_pass_wording_does_not_overclaim(self):
        """The PASS text implies no protection from someone who can edit the manifest."""
        checks = integrity.verify()
        self.assertEqual(len(checks), 1)
        check = checks[0]

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
        """A CRLF checkout of LF-stored files must hash the same, or every fresh clone
        reports FAIL."""
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
        """A CRLF pair can straddle a read chunk."""
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
        """Two runs produce byte-identical output."""
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
