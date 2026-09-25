"""Do bruhswer's own files still match the manifest they shipped with?

Drift detection (a bad copy, a partial upgrade), NOT tamper protection: whoever can
edit the code can edit the manifest beside it. Hence non-critical.

Covers bruhswer.py and app/**/*.py; an unlisted .py counts as a mismatch. Not tests/,
tools/, the interpreter or the standard library.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from .. import config
from ..logging_setup import get_logger
from ..verdict import Check, EvidenceKind, UnknownReason, Verdict

_log = get_logger("integrity")

APP_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = APP_ROOT.parent

# Not .py, so the source glob never includes the manifest.
MANIFEST_PATH = APP_ROOT / "security" / "MANIFEST.sha256"

_EXCLUDED_DIRS = ("__pycache__",)

_EXCLUDED_TOP_LEVEL = ("tests", "tools")


@dataclass(frozen=True)
class IntegrityReport:
    total: int = 0
    matched: int = 0
    changed: tuple[str, ...] = field(default_factory=tuple)
    missing: tuple[str, ...] = field(default_factory=tuple)
    unexpected: tuple[str, ...] = field(default_factory=tuple)
    # Present but unreadable: UNKNOWN, not FAIL.
    unreadable: tuple[str, ...] = field(default_factory=tuple)
    manifest_present: bool = True
    # Present but unusable, which is a finding; an absent one is normal in a checkout.
    manifest_unreadable: bool = False

    @property
    def ok(self) -> bool:
        return (self.manifest_present and not self.changed and not self.missing
                and not self.unexpected and not self.unreadable)

    @property
    def inconclusive(self) -> bool:
        """Could not finish looking: neither PASS nor FAIL."""
        return bool(self.unreadable) and not (self.changed or self.missing
                                              or self.unexpected)

    @property
    def problems(self) -> int:
        return (len(self.changed) + len(self.missing) + len(self.unexpected)
                + len(self.unreadable))


def _iter_sources(root: Path) -> list[Path]:
    """Every .py file that runs when a user launches bruhswer, sorted."""
    out: list[Path] = []
    for path in root.rglob("*.py"):
        relative = path.relative_to(root).parts
        if any(part in _EXCLUDED_DIRS for part in relative):
            continue
        if relative and relative[0] in _EXCLUDED_TOP_LEVEL:
            continue
        out.append(path)
    return sorted(out)


def _relative_key(path: Path, root: Path) -> str:
    """Posix-style relative path."""
    return path.relative_to(root).as_posix()


def hash_file(path: Path) -> str | None:
    """SHA-256 with line endings normalised, None if unreadable. Raw bytes differed on
    every CRLF checkout (measured)."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            trailing_cr = b""
            while True:
                chunk = handle.read(config.HASH_CHUNK_BYTES)
                if not chunk:
                    break
                chunk = trailing_cr + chunk
                # A chunk boundary can split a CR from its LF.
                trailing_cr = b""
                if chunk.endswith(b"\r"):
                    chunk, trailing_cr = chunk[:-1], b"\r"
                digest.update(chunk.replace(b"\r\n", b"\n"))
            if trailing_cr:
                digest.update(trailing_cr)
    except OSError:
        return None
    return digest.hexdigest()


def build_manifest(root: Path = PACKAGE_ROOT) -> dict[str, str]:
    """relative path -> sha256, for every source file under `root`."""
    manifest: dict[str, str] = {}
    for path in _iter_sources(root):
        digest = hash_file(path)
        if digest is not None:
            manifest[_relative_key(path, root)] = digest
    return manifest


def format_manifest(manifest: dict[str, str]) -> str:
    """`<sha256>  <path>` lines, sorted, LF endings."""
    return "".join(f"{digest}  {key}\n" for key, digest in sorted(manifest.items()))


def parse_manifest(text: str) -> dict[str, str]:
    """Read a manifest back, ignoring malformed lines."""
    manifest: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        digest, separator, key = stripped.partition("  ")
        if not separator or not key:
            continue
        manifest[key.strip()] = digest.strip().lower()
    return manifest


def check_tree(root: Path = PACKAGE_ROOT,
               manifest_path: Path = MANIFEST_PATH) -> IntegrityReport:
    """Compare what is on disk against the manifest. Never raises."""
    try:
        recorded = parse_manifest(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        # UnicodeDecodeError is not an OSError.
        return IntegrityReport(manifest_present=False,
                               manifest_unreadable=manifest_path.exists())

    if not recorded:
        return IntegrityReport(manifest_present=False, manifest_unreadable=True)

    on_disk = {_relative_key(p, root): p for p in _iter_sources(root)}

    changed: list[str] = []
    missing: list[str] = []
    unreadable: list[str] = []
    matched = 0

    for key, expected in sorted(recorded.items()):
        path = on_disk.get(key)
        if path is None:
            missing.append(key)
            continue
        actual = hash_file(path)
        if actual is None:
            unreadable.append(key)
        elif actual != expected:
            changed.append(key)
        else:
            matched += 1

    # Unlisted files count, or adding a module would bypass the check.
    unexpected = sorted(set(on_disk) - set(recorded))

    return IntegrityReport(
        total=len(recorded), matched=matched, changed=tuple(changed),
        missing=tuple(missing), unexpected=tuple(unexpected),
        unreadable=tuple(unreadable))


# Worded so it promises no attacker resistance.
_TITLE = "Installed files match their manifest"


def verify() -> list[Check]:
    """The non-critical `controller.integrity` check."""
    report = check_tree()

    if report.manifest_unreadable:
        return [Check(
            "controller.integrity", _TITLE, Verdict.UNKNOWN, critical=False,
            detail=("A file manifest is present beside this copy of bruhswer but "
                    "could not be read, so its files were not compared against "
                    "anything. That is damage to the manifest itself, not the normal "
                    "no-manifest case - reinstall from a known-good copy."),
            evidence=f"manifest_path={MANIFEST_PATH} present=True readable=False",
            evidence_kind=EvidenceKind.LIVE,
            unknown_reason=UnknownReason.UNREADABLE)]

    if not report.manifest_present:
        return [Check(
            "controller.integrity", _TITLE, Verdict.UNKNOWN, critical=False,
            detail=("No file manifest shipped beside this copy of bruhswer, so its "
                    "files were not compared against anything. This is normal when "
                    "running from a source checkout."),
            evidence=f"manifest_path={MANIFEST_PATH} present=False",
            evidence_kind=EvidenceKind.LIVE,
            unknown_reason=UnknownReason.NOT_APPLICABLE)]

    if report.inconclusive:
        return [Check(
            "controller.integrity", _TITLE, Verdict.UNKNOWN, critical=False,
            detail=(f"{len(report.unreadable)} of {report.total} file(s) could not be "
                    f"read, so no conclusion was reached about whether this install "
                    f"matches its manifest. Not read: "
                    f"{', '.join(report.unreadable[:3])}"
                    + (" ..." if len(report.unreadable) > 3 else "") + "."),
            evidence=f"total={report.total} matched={report.matched} "
                     f"unreadable={report.unreadable[:5]}",
            evidence_kind=EvidenceKind.LIVE,
            unknown_reason=UnknownReason.PARTIAL_EVIDENCE)]

    if report.ok:
        return [Check(
            "controller.integrity", _TITLE, Verdict.PASS, critical=False,
            detail=(f"No differences were found between the {report.total} installed "
                    f"Python file(s) and the manifest stored alongside them. This "
                    f"detects damage and incomplete updates. It does NOT protect "
                    f"against anyone able to modify this installation, who could "
                    f"change the manifest and this check with it."),
            evidence=f"total={report.total} matched={report.matched}",
            evidence_kind=EvidenceKind.LIVE)]

    parts = []
    if report.changed:
        parts.append(f"{len(report.changed)} changed")
    if report.missing:
        parts.append(f"{len(report.missing)} missing")
    if report.unexpected:
        parts.append(f"{len(report.unexpected)} not listed in the manifest")
    if report.unreadable:
        parts.append(f"{len(report.unreadable)} unreadable")
    named = ", ".join(sorted(report.changed + report.missing + report.unexpected
                             + report.unreadable)[:4])

    _log.error("installed files differ from manifest: %s", "; ".join(parts))
    return [Check(
        "controller.integrity", _TITLE, Verdict.FAIL, critical=False,
        detail=(f"The installed files differ from the manifest stored alongside them "
                f"({'; '.join(parts)}). Affected: {named}"
                + (" ..." if report.problems > 4 else "")
                + ". This can be damage, an interrupted update, or modification - "
                  "bruhswer cannot tell which. Reinstall from a known-good copy."),
        evidence=f"total={report.total} matched={report.matched} "
                 f"changed={report.changed[:5]} missing={report.missing[:5]} "
                 f"unexpected={report.unexpected[:5]} "
                 f"unreadable={report.unreadable[:5]}",
        evidence_kind=EvidenceKind.LIVE)]
