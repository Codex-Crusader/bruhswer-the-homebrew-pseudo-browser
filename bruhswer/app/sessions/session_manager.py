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
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    try:
        info = candidate.stat(follow_symlinks=False)
        if getattr(info, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
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

    _log.info("destroyed disposable session %s (%d quarantined file(s))",
              session.session_id, len(quarantined))
    return True, ("Session profile destroyed and verified gone." + quarantine_note)


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
