"""Tests for the pre-delete overwrite pass on disposable sessions.

Two things need proving, and the second matters more than the first:

  1. It works.   Bytes on disk are actually replaced, everywhere in the tree, not just
                 in a hand-picked list of filenames. A selective pass over Cookies /
                 Login Data / History would miss the -journal and -wal siblings and the
                 Local Storage LevelDB directory, and would create a false impression
                 of coverage.
  2. It is safe. The pass OPENS FILES FOR WRITING inside a tree, which makes it a
                 destructive primitive. A junction planted inside the profile must not
                 redirect it. On Windows a junction is a reparse point that is NOT a
                 symlink, so Path.is_symlink() is inert against exactly this and the
                 file-attribute test is what has to fire.

The junction test creates a real junction with mklink /J and is skipped, loudly, if
that is not possible - a silently-skipped safety test is worse than no test.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app import config  # noqa: E402
from app.sessions import session_manager  # noqa: E402

SECRET = b"cookie=super-secret-session-token-do-not-recover-me"


def _make_junction(link: Path, target: Path) -> bool:
    """Create a directory junction. True if it worked."""
    try:
        proc = subprocess.run(
            [str(config.SYSTEM32 / "cmd.exe"), "/c", "mklink", "/J",
             str(link), str(target)],
            capture_output=True, text=True, timeout=30, shell=False,
            creationflags=config.NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0 and link.exists()


class TestOverwriteTree(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()

    def tearDown(self):
        self._tmp.cleanup()

    def test_every_file_in_the_tree_is_overwritten_not_just_known_names(self):
        """The whole point of walking rather than using a filename list."""
        profile = self.root / "profile"
        (profile / "Default" / "Local Storage" / "leveldb").mkdir(parents=True)
        targets = [
            profile / "Default" / "Cookies",
            profile / "Default" / "Cookies-journal",      # the sibling a list misses
            profile / "Default" / "History",
            profile / "Default" / "History-wal",
            profile / "Default" / "Local Storage" / "leveldb" / "000003.log",
            profile / "Default" / "Web Data",
        ]
        for path in targets:
            path.write_bytes(SECRET)

        # protected-access: the overwrite walker is what this suite tests.
        report = session_manager._overwrite_tree(  # lint: allow protected-access
            profile, self.root)

        self.assertEqual(report.overwritten, len(targets))
        self.assertEqual(report.skipped, 0)
        for path in targets:
            with self.subTest(path=path.name):
                data = path.read_bytes()
                self.assertEqual(len(data), len(SECRET), "length must be preserved")
                self.assertNotEqual(data, SECRET,
                                    f"{path.name} still holds its original bytes")

    def test_large_files_are_skipped_and_counted_not_silently_ignored(self):
        profile = self.root / "profile"
        profile.mkdir()
        small = profile / "Cookies"
        small.write_bytes(SECRET)
        big = profile / "Cache_Data"
        big.write_bytes(b"x" * (config.DISPOSABLE_OVERWRITE_MAX_BYTES + 1))

        # protected-access: the overwrite walker is what this suite tests.
        report = session_manager._overwrite_tree(  # lint: allow protected-access
            profile, self.root)

        self.assertEqual(report.overwritten, 1)
        self.assertEqual(report.skipped_large, 1)
        # And the user is told, rather than the skip being invisible.
        self.assertIn("too large", report.summary())
        self.assertEqual(big.read_bytes()[:1], b"x", "large file should be untouched")

    def test_summary_names_what_was_not_covered(self):
        report = session_manager.OverwriteReport(
            overwritten=312, skipped_large=4, skipped_unreadable=2)
        summary = report.summary()
        self.assertIn("312", summary)
        self.assertIn("4", summary)
        self.assertIn("2", summary)

    def test_empty_report_produces_no_claim(self):
        self.assertEqual(session_manager.OverwriteReport().summary(), "")

    def test_zero_byte_file_counts_as_overwritten(self):
        profile = self.root / "profile"
        profile.mkdir()
        (profile / "empty").write_bytes(b"")
        # protected-access: the overwrite walker is what this suite tests.
        report = session_manager._overwrite_tree(  # lint: allow protected-access
            profile, self.root)
        self.assertEqual(report.overwritten, 1)


class TestOverwriteRefusesReparsePoints(unittest.TestCase):
    """The safety half. This pass writes to files; it must not be redirected."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()

    def tearDown(self):
        # Remove the junction before the temp dir cleanup walks it.
        link = self.root / "profile" / "escape"
        if link.exists():
            try:
                link.rmdir()
            except OSError:
                pass
        self._tmp.cleanup()

    def test_a_junction_inside_the_profile_is_not_followed(self):
        outside = self.root / "outside"
        outside.mkdir()
        victim = outside / "important.txt"
        victim.write_bytes(SECRET)

        profile = self.root / "profile"
        profile.mkdir()
        (profile / "Cookies").write_bytes(SECRET)

        link = profile / "escape"
        if not _make_junction(link, outside):
            self.skipTest("could not create a directory junction with mklink /J; "
                          "this safety test cannot run on this machine")

        # Sanity: the thing Path.is_symlink() gets wrong, pinned so the test is
        # measuring what it claims to measure.
        self.assertFalse(link.is_symlink(),
                         "expected a junction to report is_symlink() == False")

        # protected-access: the overwrite walker is what this suite tests.
        report = session_manager._overwrite_tree(  # lint: allow protected-access
            profile, self.root)

        self.assertEqual(victim.read_bytes(), SECRET,
                         "the overwrite pass wrote THROUGH a junction, outside the "
                         "profile it was given")
        self.assertGreaterEqual(report.skipped_reparse, 1,
                                "the junction was not reported as skipped")
        self.assertEqual(report.overwritten, 1, "the real file should still be done")


if __name__ == "__main__":
    unittest.main(verbosity=2)
