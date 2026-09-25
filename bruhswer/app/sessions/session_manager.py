"""SessionManager: persistent and disposable bruhswer profiles.

Disposable mode is privacy and session isolation, not a sandbox: a fresh profile,
thrown away afterwards. Deletion removes the files; it cannot promise the disk blocks
are unrecoverable or that Windows kept no copy elsewhere.
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .. import config
from ..downloads import quarantine
from ..logging_setup import get_logger

_log = get_logger("sessions")

# Session ids are generated here, hex only, and validated on the way back in.
_SESSION_ID = re.compile(r"^[0-9a-f]{16}$")

PERSISTENT = "persistent"
DISPOSABLE = "disposable"

DESTROYED_BY_DISPOSABLE = (
    "Cookies", "Cache", "localStorage", "IndexedDB", "Service workers",
    "Site permissions", "Browsing history", "Session data", "Form data",
    "Anything still sitting in this session's quarantine",
)

NOT_GUARANTEED = (
    "Files you exported from quarantine on purpose",
    "Anything the site sent to its own servers",
    "Windows-level artefacts outside the profile folder",
    "Forensic recovery of deleted disk blocks",
    # Even after the overwrite: SSD wear levelling, MFT-resident files, shadow copies
    # and the page file can all keep the old bytes.
    "That overwriting a file removed the old bytes from the physical disk",
)


@dataclass(frozen=True)
class Session:
    mode: str
    session_id: str
    profile_dir: Path
    created: datetime

    @property
    def is_disposable(self) -> bool:
        return self.mode == DISPOSABLE


def _validate_session_id(session_id: str) -> str:
    if not _SESSION_ID.match(session_id):
        raise ValueError("invalid session id")
    return session_id


def create(mode: str) -> Session:
    config.ensure_dirs()
    now = datetime.now(timezone.utc)

    if mode == PERSISTENT:
        profile = config.PROFILE_PERSISTENT
        profile.mkdir(parents=True, exist_ok=True)
        session_id = "persistent000000"
        _log.info("opened persistent session")
        return Session(PERSISTENT, session_id, profile, now)

    if mode != DISPOSABLE:
        raise ValueError("unknown session mode")

    session_id = secrets.token_hex(8)
    profile = config.PROFILE_DISPOSABLE_ROOT / session_id
    profile.mkdir(parents=True, exist_ok=False)
    _log.info("created disposable session %s", session_id)
    return Session(DISPOSABLE, session_id, profile, now)


def pending_quarantine(session: Session) -> list[Path]:
    """Files this disposable session would destroy, shown to the user beforehand."""
    if not session.is_disposable:
        return []
    folder = config.QUARANTINE / quarantine.folder_name_for(session.session_id)
    if not folder.is_dir():
        return []
    return sorted(p for p in folder.iterdir() if p.is_file())


def _safe_to_delete(candidate: Path, expected_root: Path) -> bool:
    """May this path be handed to a recursive delete? All three must hold:

      1. Not a reparse point. is_symlink() is False for a junction (measured), and a
         junction to another session's folder would pass a containment check.
      2. It resolves inside the expected root.
      3. It is not the root itself.

    The time-of-check/time-of-use gap stays open: closing it needs handle-based APIs
    Python lacks on Windows, and winning it requires already running as the user.
    """
    try:
        info = candidate.stat(follow_symlinks=False)
        if (getattr(info, "st_file_attributes", 0)
                & config.FILE_ATTRIBUTE_REPARSE_POINT):
            _log.error("refusing to delete a reparse point where a folder was expected")
            return False
        resolved = candidate.resolve()
    except OSError:
        return False

    if resolved == expected_root:
        return False
    if not resolved.is_relative_to(expected_root):
        _log.error("refusing to delete a path outside its expected root")
        return False
    return True


@dataclass(frozen=True)
class OverwriteReport:
    """What the overwrite pass did, skips included, so "312 overwritten" cannot hide
    "and 6 were not"."""

    overwritten: int = 0
    skipped_large: int = 0
    skipped_unreadable: int = 0
    skipped_reparse: int = 0

    @property
    def skipped(self) -> int:
        return self.skipped_large + self.skipped_unreadable + self.skipped_reparse

    def summary(self) -> str:
        """One clause for the destruction message, or empty if nothing was touched."""
        if not self.overwritten and not self.skipped:
            return ""
        parts = [f"{self.overwritten} file(s) were overwritten with random bytes first"]
        if self.skipped_large:
            parts.append(f"{self.skipped_large} too large to overwrite quickly")
        if self.skipped_unreadable:
            parts.append(f"{self.skipped_unreadable} could not be opened")
        if self.skipped_reparse:
            parts.append(f"{self.skipped_reparse} were links and were left alone")
        tail = "; ".join(parts[1:])
        return f" {parts[0]}" + (f" ({tail})" if tail else "") + "."


def _overwrite_tree(root: Path, expected_root: Path) -> OverwriteReport:
    """Overwrite every ordinary file under `root` with random bytes. Best effort, and
    not erasure (see NOT_GUARANTEED).

    Hand-rolled walk: this opens files for WRITING, so every directory and file is
    checked for a reparse point and re-confirmed inside `expected_root` at every level.
    A failure is never fatal; the delete is what removes the data.
    """
    counts = {"overwritten": 0, "large": 0, "unreadable": 0, "reparse": 0}

    def is_reparse(path: Path) -> bool:
        try:
            info = path.stat(follow_symlinks=False)
        except OSError:
            return True
        return bool(getattr(info, "st_file_attributes", 0)
                    & config.FILE_ATTRIBUTE_REPARSE_POINT)

    def contained(path: Path) -> bool:
        try:
            return path.resolve().is_relative_to(expected_root)
        except (OSError, ValueError):
            return False

    def walk(directory: Path) -> None:
        try:
            entries = list(directory.iterdir())
        except OSError:
            counts["unreadable"] += 1
            return

        for entry in entries:
            if is_reparse(entry):
                counts["reparse"] += 1
                _log.warning("overwrite skipped a reparse point inside the profile")
                continue
            if not contained(entry):
                counts["reparse"] += 1
                continue
            try:
                if entry.is_dir():
                    walk(entry)
                    continue
                if not entry.is_file():
                    continue
                size = entry.stat().st_size
            except OSError:
                counts["unreadable"] += 1
                continue

            if size > config.DISPOSABLE_OVERWRITE_MAX_BYTES:
                counts["large"] += 1
                continue
            if _overwrite_file(entry, size):
                counts["overwritten"] += 1
            else:
                counts["unreadable"] += 1

    walk(root)
    return OverwriteReport(counts["overwritten"], counts["large"],
                           counts["unreadable"], counts["reparse"])


def _overwrite_file(path: Path, size: int) -> bool:
    """Write `size` random bytes over one file and fsync. True if fully written."""
    if size == 0:
        return True
    try:
        with path.open("r+b") as handle:
            remaining = size
            while remaining > 0:
                chunk = min(remaining, config.OVERWRITE_CHUNK_BYTES)
                handle.write(os.urandom(chunk))
                remaining -= chunk
            handle.flush()
            os.fsync(handle.fileno())
        return True
    except OSError:
        # Usually locked by a browser process still exiting.
        return False


def destroy(session: Session) -> tuple[bool, str]:
    """Destroy a disposable profile AND its quarantine, and verify both are gone.

    The quarantine once survived while the result said "destroyed and verified gone".
    """
    if not session.is_disposable:
        return False, "Persistent sessions are not destroyed."

    _validate_session_id(session.session_id)

    root = config.PROFILE_DISPOSABLE_ROOT.resolve()
    if not _safe_to_delete(session.profile_dir, root):
        return False, ("Refused: the profile path is a link, or is outside the "
                       "disposable profile folder.")
    try:
        target = session.profile_dir.resolve()
    except OSError as exc:
        return False, f"Could not resolve the profile path: {exc.__class__.__name__}"

    quarantined = pending_quarantine(session)

    overwrite = _overwrite_tree(target, root)

    shutil.rmtree(target, ignore_errors=True)
    if target.exists():
        leftover = sum(1 for _ in target.rglob("*"))
        _log.error("disposable session %s NOT fully destroyed", session.session_id)
        return False, (f"Destruction incomplete - {leftover} item(s) remain. "
                       "Files may be locked by a still-running browser process.")

    quarantine_note = ""
    q_root = config.QUARANTINE.resolve()
    q_dir = config.QUARANTINE / quarantine.folder_name_for(session.session_id)
    if q_dir.is_dir():
        if not _safe_to_delete(q_dir, q_root):
            return False, ("Profile destroyed, but the session's quarantine folder "
                           "could not be verified as safe to delete and was kept.")
        _overwrite_tree(q_dir, q_root)
        shutil.rmtree(q_dir, ignore_errors=True)
        if q_dir.exists():
            remaining = sum(1 for _ in q_dir.rglob("*"))
            _log.error("quarantine for session %s NOT fully destroyed",
                       session.session_id)
            return False, (f"Profile destroyed, but {remaining} quarantined file(s) "
                           "could not be deleted. They are still on disk.")
        if quarantined:
            quarantine_note = (f" {len(quarantined)} quarantined download(s) were "
                               f"destroyed with it.")

    _log.info("destroyed disposable session %s (%d quarantined file(s), "
              "%d overwritten, %d skipped)", session.session_id, len(quarantined),
              overwrite.overwritten, overwrite.skipped)
    return True, ("Session profile destroyed and verified gone."
                  + quarantine_note + overwrite.summary())


def sweep_orphans() -> int:
    """Remove disposable profiles and quarantines left behind by a crash. Only folders
    named like a disposable session id are touched."""
    removed = 0

    if config.PROFILE_DISPOSABLE_ROOT.is_dir():
        p_root = config.PROFILE_DISPOSABLE_ROOT.resolve()
        for child in config.PROFILE_DISPOSABLE_ROOT.iterdir():
            if not (child.is_dir() and _SESSION_ID.match(child.name)):
                continue
            if not _safe_to_delete(child, p_root):
                continue
            shutil.rmtree(child, ignore_errors=True)
            if not child.exists():
                removed += 1

    orphan_quarantines = 0
    if config.QUARANTINE.is_dir():
        q_root = config.QUARANTINE.resolve()
        live = {c.name for c in config.PROFILE_DISPOSABLE_ROOT.iterdir()
                if c.is_dir()} if config.PROFILE_DISPOSABLE_ROOT.is_dir() else set()
        for child in config.QUARANTINE.iterdir():
            if not (child.is_dir() and _SESSION_ID.match(child.name)
                    and child.name not in live):
                continue

            if not _safe_to_delete(child, q_root):
                continue

            shutil.rmtree(child, ignore_errors=True)
            if not child.exists():
                orphan_quarantines += 1

    if removed or orphan_quarantines:
        _log.info("swept %d orphaned disposable profile(s) and %d orphaned "
                  "quarantine folder(s)", removed, orphan_quarantines)
    return removed + orphan_quarantines
