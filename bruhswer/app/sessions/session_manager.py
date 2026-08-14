"""SessionManager — persistent and disposable bruhswer profiles.

Disposable mode is a PRIVACY and SESSION-ISOLATION mechanism. It is not a sandbox and
it is not a VM (brief SS3, SS38). It gives a website a fresh, empty profile and throws
that profile away afterwards. It does not stop a browser exploit, and this module must
never claim it does.

What is destroyed is stated exactly, and what cannot be guaranteed is stated too
(brief SS35): deleting files removes the data bruhswer wrote, but it cannot promise the
underlying disk blocks are unrecoverable, nor that Windows kept no artefact elsewhere.
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
from ..logging_setup import get_logger

_log = get_logger("sessions")

# Session ids are generated here and validated on the way back in. A session id never
# comes from the browser, a URL, or a filename, and it can only ever be hex.
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
    # Spelled out because bruhswer now DOES overwrite files before deleting them, and
    # an overwrite is the single easiest thing in this field to over-read. Writing new
    # bytes to a file changes the LOGICAL contents at that path. It does not follow
    # that the physical media no longer holds the old bytes:
    #   - an SSD's controller does wear levelling, so a rewrite usually lands on a
    #     different physical page and the original is left behind until it is garbage
    #     collected, on the drive's schedule and outside anything bruhswer can see
    #   - NTFS journals metadata, and small files can live entirely inside the MFT
    #   - a copy may exist in a shadow copy, a restore point, or the page file
    # bruhswer cannot inspect any of that, so it does not claim any of it.
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
        session_id = "persistent00000"[:16].ljust(16, "0")
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
    """Files that would be destroyed along with this disposable session.

    The UI asks for this BEFORE destroying anything, so the user is told what is about
    to be lost rather than reading about it afterwards.
    """
    if not session.is_disposable:
        return []
    folder = config.QUARANTINE / _safe_session_folder(session.session_id)
    if not folder.is_dir():
        return []
    return sorted(p for p in folder.iterdir() if p.is_file())


def _safe_to_delete(candidate: Path, expected_root: Path) -> bool:
    """May this path be handed to a recursive delete?

    Three conditions, and all three are needed:

      1. It must not be a reparse point. `Path.is_dir()` FOLLOWS a directory
         junction, so a junction planted under the disposable-profile or quarantine
         root - which anything running as the user can create, including a
         compromised browser process - looks exactly like an ordinary session folder.

         MEASURED, and the reason this is not an `is_symlink()` call: on Windows,
         `Path.is_symlink()` returns FALSE for a directory junction created with
         `mklink /J`. A junction is a reparse point but not a symlink, so the
         obvious-looking check is silently inert against the exact thing it appears
         to defend against. The file-attribute test is the one that actually works,
         and it is the same idiom quarantine.py already uses before exporting a file.

         Refusing outright is stricter than resolving and checking where it lands: a
         junction aimed at ANOTHER session's folder inside the same root would pass a
         containment test while still redirecting the delete.
      2. Its resolved path must still be inside the expected root.
      3. It must not BE the root, so a bug can never escalate to wiping everything.

    ALSO MEASURED, and worth recording because it changes how bad the failure would
    be: `shutil.rmtree(junction, ignore_errors=True)` does NOT delete through the
    junction - it refuses and the error is swallowed. So the un-guarded version leaked
    no data; it simply failed to clean up while reporting nothing. These checks turn a
    silent no-op into an explicit, logged refusal, and remove the dependence on that
    rmtree behaviour staying true in a future Python.

    This cannot close the underlying time-of-check/time-of-use gap: the path could in
    principle be swapped between this returning True and rmtree running. Closing that
    needs handle-based APIs Python does not expose on Windows. Recorded as a known,
    accepted limit rather than left as a silent assumption - and an attacker who could
    win that race is already running as the user, which the threat model states is not
    defended against.
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


def _safe_session_folder(session_id: str) -> str:
    """Mirror of quarantine.quarantine_dir_for's naming, without importing it.

    Kept deliberately trivial: a session id is generated by this module and is always
    16 hex characters, so this is a defensive re-validation, not a sanitiser doing
    real work on untrusted text.
    """
    return "".join(c for c in session_id if c in "0123456789abcdef")[:32] or "session"


@dataclass(frozen=True)
class OverwriteReport:
    """Exactly what the overwrite pass did. Every field is reported to the user.

    `skipped_large` and `skipped_unreadable` are not bookkeeping - they are the
    difference between "312 files were overwritten" and "312 files were overwritten and
    6 were not". Reporting only the successes would create precisely the false
    impression of coverage that this project treats as a defect.
    """

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
    """Overwrite every ordinary file under `root` with random bytes. Best effort.

    WHAT THIS IS: a cheap extra step that makes the profile's contents unrecoverable by
    ordinary means - an undelete tool, a file browser, someone reading the free list.

    WHAT THIS IS NOT: erasure. See NOT_GUARANTEED above. The one-line version is that
    an SSD's wear levelling means the new bytes usually land on a different physical
    page and the old page survives until the drive garbage-collects it, which bruhswer
    can neither observe nor influence. This function's name says "overwrite" and not
    "wipe" or "secure delete" on purpose.

    THE DANGEROUS PART, and why the walk is hand-rolled instead of os.walk:
        This function OPENS FILES FOR WRITING inside a directory tree. That makes it a
        destructive primitive, and a reparse point anywhere in that tree would aim it
        somewhere else - a junction planted under the disposable-profile root by
        anything running as the user, including a compromised browser process, is a
        perfectly ordinary-looking folder.

        So every directory is checked for FILE_ATTRIBUTE_REPARSE_POINT before it is
        descended into, and every file is checked before it is opened, and each
        resolved path is re-confirmed to sit inside `expected_root`. This is the same
        discipline _safe_to_delete applies before rmtree, applied per entry, because
        here the check has to hold at every level rather than once at the top.

        os.walk is not used because its handling of Windows junctions depends on
        version-specific behaviour of os.scandir, and this is not a place to inherit a
        subtlety from the standard library.

    Failure is never fatal: deletion is what actually removes the data, and refusing to
    delete because an overwrite failed would trade the guarantee bruhswer HAS for one
    it does not.
    """
    # A dict rather than four `nonlocal` counters: the recursive walk below has to
    # accumulate across every level, and a plain mutable mapping keeps that explicit
    # instead of scattering rebinding rules through a nested function.
    counts = {"overwritten": 0, "large": 0, "unreadable": 0, "reparse": 0}

    def is_reparse(path: Path) -> bool:
        try:
            info = path.stat(follow_symlinks=False)
        except OSError:
            return True         # cannot tell -> treat as unsafe
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
    """Write `size` random bytes over one file. True if it was fully written.

    os.urandom rather than zeros: a run of zeros is trivially recognisable as a wiped
    region, and random bytes cost the same. flush + fsync because a buffered write that
    never reached the platter before the file was unlinked would have overwritten
    nothing at all.
    """
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
        # Locked by a still-running browser process is the common case, and it is not
        # an error worth failing the close over.
        return False


def destroy(session: Session) -> tuple[bool, str]:
    """Destroy a disposable profile AND its quarantine, and VERIFY both are gone.

    THE QUARANTINE PART IS NOT AN EXTRA. It was a measured defect: destroying a
    disposable session removed the profile and reported "destroyed and verified gone"
    while every file downloaded during that session stayed on disk forever, under
    %LOCALAPPDATA%\\BRUHWSER\\quarantine\\<session id>. Nothing ever cleaned them up -
    sweep_orphans only looked at profiles - and the quarantine panel only ever lists
    the CURRENT session's folder, so those files became invisible to the UI while
    remaining readable on disk. Web-downloaded content, surviving the session that was
    sold as disposable, with no way to see it. That is a data-exposure bug and a false
    claim at the same time, which is the defect class this project treats most
    seriously.

    Brief SS42: if deletion fails, report the failure. Never claim a session was
    destroyed when it was not.
    """
    if not session.is_disposable:
        return False, "Persistent sessions are not destroyed."

    _validate_session_id(session.session_id)

    # Confinement check. The path was built by this module, but verifying it before a
    # recursive delete costs nothing and turns a future bug into a refusal.
    root = config.PROFILE_DISPOSABLE_ROOT.resolve()
    if not _safe_to_delete(session.profile_dir, root):
        return False, ("Refused: the profile path is a link, or is outside the "
                       "disposable profile folder.")
    try:
        target = session.profile_dir.resolve()
    except OSError as exc:
        return False, f"Could not resolve the profile path: {exc.__class__.__name__}"

    # How many downloads are about to go, so the result can say so precisely rather
    # than claiming "destroyed" and leaving the user to guess what that covered.
    quarantined = pending_quarantine(session)

    # Overwrite BEFORE the delete, because after rmtree there is nothing left to write
    # over. Best effort by design: if this does nothing at all, the delete below still
    # removes the data, and that is the guarantee bruhswer actually makes.
    overwrite = _overwrite_tree(target, root)

    shutil.rmtree(target, ignore_errors=True)
    if target.exists():
        leftover = sum(1 for _ in target.rglob("*"))
        _log.error("disposable session %s NOT fully destroyed", session.session_id)
        return False, (f"Destruction incomplete - {leftover} item(s) remain. "
                       "Files may be locked by a still-running browser process.")

    # Same confinement discipline as the profile: resolve, prove it is inside the
    # quarantine root, and only then delete.
    quarantine_note = ""
    q_root = config.QUARANTINE.resolve()
    q_dir = config.QUARANTINE / _safe_session_folder(session.session_id)
    if q_dir.is_dir():
        if not _safe_to_delete(q_dir, q_root):
            return False, ("Profile destroyed, but the session's quarantine folder "
                           "could not be verified as safe to delete and was kept.")
        # The quarantine holds whole files the user downloaded from the web, so it is
        # if anything the more sensitive of the two trees. Same treatment.
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
    # The overwrite summary names what was NOT covered as well as what was. Reporting
    # only the successes would imply a completeness the pass does not have.
    return True, ("Session profile destroyed and verified gone."
                  + quarantine_note + overwrite.summary())


def sweep_orphans() -> int:
    """Remove disposable profiles, and their quarantines, left behind by a crash.

    Both halves matter. This used to sweep profiles only, so a session killed by a
    crash, a forced termination or a Windows restart left its downloads behind
    permanently - and because the quarantine panel only lists the CURRENT session,
    they were unreachable from the UI while still sitting on disk. A "disposable"
    session that leaves web-downloaded files around after a crash is not disposable.

    Only folders named like a disposable session id (16 hex characters) are touched.
    The persistent session's quarantine is named differently and is never swept, and
    an unrecognised folder is left alone rather than guessed at.
    """
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
            # A disposable-looking quarantine whose profile no longer exists is by
            # definition orphaned: its session cannot be resumed or inspected.
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
