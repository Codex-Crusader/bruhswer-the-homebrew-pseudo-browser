"""Download quarantine — nothing reaches the user's real folders without them saying so.

Flow (brief SS36):   website -> quarantine -> user review -> explicit export

Rules that are not negotiable:
  - bruhswer NEVER executes a downloaded file, and never opens one with the shell.
  - The webpage cannot choose the destination. The user picks it, in bruhswer's UI.
  - Export filenames are rebuilt by bruhswer from scratch. The name the site supplied
    is treated as hostile text, not as a path.
  - Path traversal, UNC paths, device names, alternate data streams, symlinks and
    reparse points are excluded by construction rather than filtered one by one.

bruhswer does not claim to detect malware. It says a file is quarantined, which is a
fact, and it does not say a file is safe, which it cannot know (brief SS37).
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .. import config
from ..logging_setup import get_logger

_log = get_logger("downloads")

# Windows reserved device names. Creating any of these can have side effects.
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
             *(f"lpt{i}" for i in range(1, 10))}

_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._ -]")

EXECUTABLE_SUFFIXES = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".psm1", ".vbs",
    ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msi", ".msp", ".hta", ".cpl", ".jar",
    ".reg", ".lnk", ".inf", ".sys", ".scf", ".appx", ".msix",
}

# --- content sniffing -----------------------------------------------------------
# An extension is a CLAIM MADE BY THE WEBSITE. It is the least trustworthy thing about
# a download, and it is what `is_executable_type` above relies on entirely: a site that
# serves a PE image named "invoice.pdf" gets no warning from a suffix check, because the
# suffix is exactly the part the site controls.
#
# So the first bytes are read too. These are FILE FORMAT signatures, not malware
# signatures, and the distinction is the whole point:
#
#   what this CAN say   "these bytes are a Windows executable image"      (a fact)
#   what it CANNOT say  "this file is malware" / "this file is safe"      (not measured)
#
# bruhswer does not scan, does not reputation-check, and does not sandbox-detonate. It
# reports the format it found and whether that format disagrees with the name. A clean
# result here means "nothing recognised", never "safe" - brief SS37, and the module
# docstring above says the same thing.
_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "Windows executable (PE)"),
    (b"\x7fELF", "ELF executable"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O fat binary"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound file (legacy Office, .msi)"),
    (b"PK\x03\x04", "ZIP container (may hold .appx, .jar, Office, or anything else)"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"#!", "script with a shebang line"),
    (b"%PDF-", "PDF document"),
)

# Formats that ARE directly loadable code on this platform. A ZIP is not on this list:
# it is a container, and calling every .zip "executable" would train the user to ignore
# the warning, which is worse than not showing one.
_EXECUTABLE_KINDS = frozenset({
    "Windows executable (PE)", "ELF executable", "Java class / Mach-O fat binary",
})


def sniff_kind(path: Path) -> str | None:
    """The file format the BYTES say this is, or None if nothing is recognised.

    Never raises, and never reads more than the signature: a quarantined file is
    hostile input, and bruhswer has no reason to pull it into memory.
    """
    try:
        with path.open("rb") as handle:
            head = handle.read(8)
    except OSError:
        return None
    if not head:
        return None
    for signature, label in _MAGIC:
        if head.startswith(signature):
            return label
    return None


@dataclass(frozen=True)
class QuarantinedFile:
    path: Path
    size: int
    modified: datetime
    # What the BYTES say (None = nothing recognised, which is not the same as "safe").
    sniffed_kind: str | None = None

    @property
    def display_name(self) -> str:
        return self.path.name

    @property
    def is_executable_type(self) -> bool:
        """The file's NAME claims an executable type. Site-controlled, so weak."""
        return self.path.suffix.lower() in EXECUTABLE_SUFFIXES

    @property
    def is_executable_content(self) -> bool:
        """The file's BYTES are directly loadable code, whatever it is called."""
        return self.sniffed_kind in _EXECUTABLE_KINDS

    @property
    def extension_mismatch(self) -> bool:
        """The bytes are executable and the name does NOT admit it.

        This is the case worth a distinct warning: `is_executable_type` alone stays
        quiet for a PE image called "invoice.pdf", because it only ever looked at the
        part of the download the website chose.

        Deliberately one-directional. An .exe whose bytes are a PE is consistent and
        already flagged by name; a .zip that sniffs as a ZIP is consistent; and an
        unrecognised format is NOT reported as a mismatch, because "bruhswer did not
        recognise these bytes" is not evidence of anything.
        """
        return self.is_executable_content and not self.is_executable_type

    @property
    def content_note(self) -> str:
        """One line for the UI. States the format, never a safety verdict."""
        if self.sniffed_kind is None:
            return "Content not recognised. That is not a clean bill of health."
        if self.extension_mismatch:
            return (f"BRUH. The name says {self.path.suffix or '(no extension)'}, "
                    f"but the bytes are a {self.sniffed_kind}.")
        return f"Content looks like: {self.sniffed_kind}."


def folder_name_for(session_id: str) -> str:
    """The on-disk quarantine folder name for a session id. Naming only, no I/O.

    The single derivation. session_manager used to keep its own copy of this logic
    (`_safe_session_folder`) to avoid importing this module, justified by a comment
    claiming a session id is "always 16 hex characters" - true for disposable sessions,
    not for the persistent one ("persistent000000"). Both of that copy's callers
    happened to be guarded to disposable sessions only, so the divergence was never
    live, but it existed behind a comment asserting it could not. Importing this one,
    rather than hand-copying it a second time, is the fix.
    """
    return _SAFE_CHARS.sub("", session_id)[:32] or "session"


def quarantine_dir_for(session_id: str) -> Path:
    target = config.QUARANTINE / folder_name_for(session_id)
    target.mkdir(parents=True, exist_ok=True)
    return target


def safe_export_name(untrusted_name: str) -> str:
    """Rebuild a filename from an untrusted one. Never returns a path, only a name.

    Everything structural is removed rather than escaped: separators, drive letters,
    traversal, streams, and leading dots. If nothing usable survives, bruhswer supplies
    its own name.
    """
    name = untrusted_name.replace("\x00", "")
    name = name.replace("\\", "/").split("/")[-1]   # drop any path structure
    name = name.split(":")[-1]                      # drop drive letters and ADS
    name = _SAFE_CHARS.sub("_", name).strip(" .")

    if not name:
        name = "download"

    stem, dot, suffix = name.rpartition(".")
    base = (stem if dot else name)
    if base.lower() in _RESERVED:
        base = f"file_{base}"
    name = f"{base}.{suffix}" if dot and suffix else base

    return name[:120]


def list_quarantine(session_id: str) -> list[QuarantinedFile]:
    folder = quarantine_dir_for(session_id)
    items: list[QuarantinedFile] = []
    for child in sorted(folder.iterdir()):
        if not child.is_file():
            continue
        try:
            stat = child.stat()
        except OSError:
            continue
        items.append(QuarantinedFile(
            child, stat.st_size,
            datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
            sniff_kind(child)))
    return items


def export(item: QuarantinedFile, destination_dir: Path) -> tuple[bool, str]:
    """Copy one quarantined file out, to a folder the USER chose.

    Refuses if the source is not inside quarantine, or is a link/reparse point. The
    copy never preserves the executable bit concept (Windows has none) and bruhswer
    does not launch the result.
    """
    quarantine_root = config.QUARANTINE.resolve()
    try:
        source = item.path.resolve(strict=True)
    except OSError as exc:
        return False, f"Source unreadable: {exc.__class__.__name__}"

    if not source.is_relative_to(quarantine_root):
        _log.error("export refused: source outside quarantine")
        return False, "Refused: that file is not inside quarantine."

    # A reparse point could redirect the read somewhere else entirely. Both halves are
    # needed: on Windows a junction is a reparse point that is NOT a symlink.
    try:
        if (os.path.islink(item.path)  # noqa: PTH114
                or (item.path.stat(follow_symlinks=False).st_file_attributes
                    & config.FILE_ATTRIBUTE_REPARSE_POINT)):
            return False, "Refused: quarantined item is a link or reparse point."
    except (OSError, AttributeError):
        pass

    try:
        dest_dir = destination_dir.resolve(strict=True)
    except OSError:
        return False, "Destination folder does not exist."
    if not dest_dir.is_dir():
        return False, "Destination is not a folder."

    # The DESTINATION gets the same reparse-point treatment as the source. The folder
    # picker hands back whatever the user selected, and a junction is a perfectly
    # ordinary-looking folder in the Windows picker - selecting one would land the
    # export somewhere the user did not choose and did not see.
    #
    # `is_symlink()` is NOT sufficient and is not used: measured in this project,
    # Path.is_symlink() returns False for a directory junction made with `mklink /J`.
    # config.FILE_ATTRIBUTE_REPARSE_POINT is the test that actually fires.
    #
    # Checked on the path AS SELECTED with follow_symlinks=False, before resolve()
    # follows the link away and destroys the evidence that there was one.
    try:
        attrs = destination_dir.stat(follow_symlinks=False).st_file_attributes
        if attrs & config.FILE_ATTRIBUTE_REPARSE_POINT:
            _log.error("export refused: destination is a reparse point")
            return False, ("Refused: that destination folder is a link or junction, "
                           "so the file would not land where it appears to.")
    except (OSError, AttributeError):
        pass

    chosen = Path(safe_export_name(source.name))
    final = dest_dir / chosen.name
    counter = 1
    while final.exists():
        final = dest_dir / f"{chosen.stem}_{counter}{chosen.suffix}"
        counter += 1
        if counter > 999:
            return False, "Could not find a free filename in that folder."

    # Belt and braces on top of safe_export_name(). That function already strips every
    # separator, so the name cannot climb out - but this asserts the RESULT rather than
    # trusting the sanitiser, which is the same discipline the profile-delete path uses.
    # If these ever disagree, the export is refused instead of landing outside the
    # folder the user picked.
    if final.parent != dest_dir:
        _log.error("export refused: final path escaped the chosen folder")
        return False, "Refused: the export path did not stay inside the chosen folder."

    try:
        shutil.copy2(source, final)
    except OSError as exc:
        _log.error("export failed: %s", exc.__class__.__name__)
        return False, f"Copy failed: {exc.__class__.__name__}"

    _log.info("exported one quarantined file (%d bytes)", source.stat().st_size)
    return True, f"Exported to {final.name}. bruhswer did not run it."


def delete(item: QuarantinedFile) -> tuple[bool, str]:
    quarantine_root = config.QUARANTINE.resolve()
    try:
        source = item.path.resolve(strict=True)
    except OSError:
        return False, "File already gone."
    if not source.is_relative_to(quarantine_root):
        return False, "Refused: that file is not inside quarantine."
    try:
        source.unlink()
    except OSError as exc:
        return False, f"Delete failed: {exc.__class__.__name__}"
    return True, "Deleted."
