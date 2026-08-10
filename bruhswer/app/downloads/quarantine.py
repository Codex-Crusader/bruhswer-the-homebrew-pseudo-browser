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


@dataclass(frozen=True)
class QuarantinedFile:
    path: Path
    size: int
    modified: datetime

    @property
    def display_name(self) -> str:
        return self.path.name

    @property
    def is_executable_type(self) -> bool:
        return self.path.suffix.lower() in EXECUTABLE_SUFFIXES


def quarantine_dir_for(session_id: str) -> Path:
    safe = _SAFE_CHARS.sub("", session_id)[:32] or "session"
    target = config.QUARANTINE / safe
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
            datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)))
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

    # A reparse point could redirect the read somewhere else entirely.
    try:
        if os.path.islink(item.path) or (item.path.stat().st_file_attributes & 0x400):
            return False, "Refused: quarantined item is a link or reparse point."
    except (OSError, AttributeError):
        pass

    try:
        dest_dir = destination_dir.resolve(strict=True)
    except OSError:
        return False, "Destination folder does not exist."
    if not dest_dir.is_dir():
        return False, "Destination is not a folder."

    final = dest_dir / safe_export_name(source.name)
    counter = 1
    while final.exists():
        final = dest_dir / f"{final.stem}_{counter}{final.suffix}"
        counter += 1
        if counter > 999:
            return False, "Could not find a free filename in that folder."

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
