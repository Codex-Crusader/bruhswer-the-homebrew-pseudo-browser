"""Download quarantine: website -> quarantine -> user review -> explicit export.

bruhswer never runs a download. The user picks the export folder. Export names are
rebuilt from scratch, so traversal, device names, streams and reparse points are
excluded by construction. bruhswer does not detect malware and never calls a file safe.
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

# Windows reserved device names.
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
             *(f"lpt{i}" for i in range(1, 10))}

_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._ -]")

EXECUTABLE_SUFFIXES = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".psm1", ".vbs",
    ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msi", ".msp", ".hta", ".cpl", ".jar",
    ".reg", ".lnk", ".inf", ".sys", ".scf", ".appx", ".msix",
}

# Not programs, so not in the set above, which also drives extension_mismatch. Disk
# images once hid their contents from Mark of the Web (before the November 2022 update).
CONTAINER_SUFFIXES = {".iso", ".img", ".vhd", ".vhdx"}

ACTIVE_DOCUMENT_SUFFIXES = {
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppsm",
    ".one", ".onepkg",
}

_TYPE_WARNINGS: tuple[tuple[set[str], str], ...] = (
    (EXECUTABLE_SUFFIXES, "this is a program. It is NOT being executed."),
    (CONTAINER_SUFFIXES, "this is a disk image. Opening it mounts a drive, and the "
                         "files inside may not be marked as downloaded."),
    (ACTIVE_DOCUMENT_SUFFIXES, "this document can run macros or embedded programs."),
)

# The extension is the website's claim, so the first bytes are read too. These are file
# FORMAT signatures, not malware signatures: no match means "not recognised", not "safe".
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

# Directly loadable code. Not ZIP: warning on every .zip would train users to ignore it.
_EXECUTABLE_KINDS = frozenset({
    "Windows executable (PE)", "ELF executable", "Java class / Mach-O fat binary",
})

_MAGIC_BYTES = max(len(signature) for signature, _label in _MAGIC)


def sniff_kind(path: Path) -> str | None:
    """The format the first bytes show, or None. Reads only the signature."""
    try:
        with path.open("rb") as handle:
            head = handle.read(_MAGIC_BYTES)
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
    sniffed_kind: str | None = None

    @property
    def display_name(self) -> str:
        return self.path.name

    @property
    def is_executable_type(self) -> bool:
        """The file's NAME claims an executable type. Site-controlled, so weak."""
        return self.path.suffix.lower() in EXECUTABLE_SUFFIXES

    @property
    def type_warning(self) -> str | None:
        """UI warning for what the NAME says this file can do, or None."""
        suffix = self.path.suffix.lower()
        for suffixes, warning in _TYPE_WARNINGS:
            if suffix in suffixes:
                return warning
        return None

    @property
    def is_executable_content(self) -> bool:
        """The file's BYTES are directly loadable code, whatever it is called."""
        return self.sniffed_kind in _EXECUTABLE_KINDS

    @property
    def extension_mismatch(self) -> bool:
        """Executable bytes under a name that does not say so ("invoice.pdf")."""
        return self.is_executable_content and not self.is_executable_type

    @property
    def content_note(self) -> str:
        """One UI line stating the format, never a safety verdict."""
        if self.sniffed_kind is None:
            return "Content not recognised. That is not a clean bill of health."
        if self.extension_mismatch:
            return (f"BRUH. The name says {self.path.suffix or '(no extension)'}, "
                    f"but the bytes are a {self.sniffed_kind}.")
        return f"Content looks like: {self.sniffed_kind}."


def folder_name_for(session_id: str) -> str:
    """The quarantine folder name for a session id. The only derivation; no I/O."""
    return _SAFE_CHARS.sub("", session_id)[:32] or "session"


def quarantine_dir_for(session_id: str) -> Path:
    target = config.QUARANTINE / folder_name_for(session_id)
    target.mkdir(parents=True, exist_ok=True)
    return target


def safe_export_name(untrusted_name: str) -> str:
    """Rebuild a filename from an untrusted one. Separators, drives, streams and leading
    dots are removed, not escaped. Never returns a path."""
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
    """Copy one quarantined file to a folder the user chose. Refuses a source outside
    quarantine and any link or reparse point."""
    quarantine_root = config.QUARANTINE.resolve()
    try:
        source = item.path.resolve(strict=True)
    except OSError as exc:
        return False, f"Source unreadable: {exc.__class__.__name__}"

    if not source.is_relative_to(quarantine_root):
        _log.error("export refused: source outside quarantine")
        return False, "Refused: that file is not inside quarantine."

    # Both tests: a junction is a reparse point but not a symlink.
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

    # A junction looks like a folder in the picker. Checked before resolve() follows it.
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

    # Assert the result instead of trusting safe_export_name().
    if final.parent != dest_dir:
        _log.error("export refused: final path escaped the chosen folder")
        return False, "Refused: the export path did not stay inside the chosen folder."

    try:
        shutil.copy2(source, final)
    except OSError as exc:
        _log.error("export failed: %s", exc.__class__.__name__)
        return False, f"Copy failed: {exc.__class__.__name__}"

    # An unmarked copy opens with no SmartScreen prompt, so it is removed instead.
    if not mark_of_the_web(final):
        try:
            final.unlink()
        except OSError as exc:
            _log.error("unmarked export could not be removed: %s",
                       exc.__class__.__name__)
            return False, (f"BRUH. {final.name} was copied, but Windows could not mark "
                           f"it as downloaded and bruhswer could not remove it. Delete "
                           f"it before you open it.")
        _log.error("export refused: destination does not keep Mark of the Web")
        return False, ("Refused: that folder's drive cannot record that the file came "
                       "from the internet, so Windows would not warn you when you open "
                       "it. Export to a folder on an NTFS drive.")

    _log.info("exported one quarantined file (%d bytes)", source.stat().st_size)
    return True, f"Exported to {final.name}. bruhswer did not run it."


def mark_of_the_web(path: Path) -> bool:
    """Write Zone.Identifier (Internet zone) on `path` and read it back. False on drives
    without alternate data streams, such as FAT32 and exFAT."""
    wanted = f"ZoneId={config.ZONE_ID_INTERNET}"
    try:
        # Not with_name(): it raises ValueError for a file named "a" ("a:" = drive).
        stream = Path(f"{path}:{config.ZONE_IDENTIFIER_STREAM}")
        with stream.open("w", encoding="ascii", newline="\r\n") as handle:
            handle.write(f"[ZoneTransfer]\n{wanted}\n")
        with stream.open(encoding="ascii") as handle:
            written = handle.read().splitlines()
    except (OSError, ValueError) as exc:
        _log.error("could not write Mark of the Web: %s", exc.__class__.__name__)
        return False
    return wanted in written


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
