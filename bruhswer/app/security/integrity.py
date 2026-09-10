"""Do bruhswer's own files still match the manifest they shipped with?

INSTALLATION-DRIFT DETECTION: a half-finished copy, a file truncated by a disk error,
a partial upgrade that mixed two versions, untargeted malware that rewrites .py files.

It does NOT detect a targeted attacker, and nothing here may be worded as if it does.
The manifest sits beside the code it describes, and the code that reads it beside both,
so anyone who can edit `verifier.py` can edit `MANIFEST.sha256` and this file in the
same motion. That is the ceiling of any self-check with no trust anchor outside the
thing being checked. Hence the verdict is NON-CRITICAL: the failure it most likely
represents is a bad copy, not an intrusion.

Every module under `app/` is imported into the same process with the same privileges,
so hashing a hand-picked "TCB" subset would be a green light over a fraction of what
runs. Covered: `bruhswer.py` and `app/**/*.py`, with a .py file present on disk but
absent from the manifest counted as a mismatch - otherwise adding a file is the way
past the check. NOT covered: `tests/`, `tools/`, the interpreter, the standard library
and every DLL loaded. So this is not "the install is intact".
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from .. import config
from ..logging_setup import get_logger
from ..verdict import Check, EvidenceKind, UnknownReason, Verdict

_log = get_logger("integrity")

# The manifest covers app/**/*.py AND bruhswer.py: the entry point is the first code
# that runs, so leaving it unhashed would be an unchecked hole at the most load-bearing
# file in the install.
APP_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = APP_ROOT.parent

# Lives beside the code it describes. Named .sha256 rather than .py so that the glob
# can never pick up the manifest as one of its own inputs.
MANIFEST_PATH = APP_ROOT / "security" / "MANIFEST.sha256"

# Cache and build artefacts are not source and are not shipped.
_EXCLUDED_DIRS = ("__pycache__",)

# Not part of what runs when a user launches bruhswer: the regression suite and the
# build-time utilities. Excluded so that running the tests, or regenerating a manifest,
# does not report drift in a perfectly good install.
_EXCLUDED_TOP_LEVEL = ("tests", "tools")


@dataclass(frozen=True)
class IntegrityReport:
    total: int = 0
    matched: int = 0
    changed: tuple[str, ...] = field(default_factory=tuple)
    missing: tuple[str, ...] = field(default_factory=tuple)
    unexpected: tuple[str, ...] = field(default_factory=tuple)
    # Listed, present, and could NOT be read. A separate bucket from `missing`: "the
    # file is gone" is a finding, "could not open it" is a failed measurement. Drives
    # UNKNOWN, not FAIL.
    unreadable: tuple[str, ...] = field(default_factory=tuple)
    manifest_present: bool = True
    # The manifest is THERE and unusable - unreadable, not UTF-8, or parsing to
    # nothing. `manifest_present` is False for this too, but the facts differ: an
    # absent manifest is normal in a source checkout, a ruined one in an install is a
    # finding, and the check must not explain the second away as the first.
    manifest_unreadable: bool = False

    @property
    def ok(self) -> bool:
        return (self.manifest_present and not self.changed and not self.missing
                and not self.unexpected and not self.unreadable)

    @property
    def inconclusive(self) -> bool:
        """Could not finish looking. Never a PASS, and not a FAIL either."""
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
    """Posix-style relative path, so a manifest is identical on every machine."""
    return path.relative_to(root).as_posix()


def hash_file(path: Path) -> str | None:
    """SHA-256 of one source file, with line endings normalised. None if unreadable.

    Measured: git stores LF and checks CRLF out here, so hashing raw bytes would make
    every fresh clone report FAIL on a perfectly good copy. Hashing CONTENT still
    detects a changed byte, a truncation or an inserted line; it deliberately does not
    detect a pure line-ending conversion, which is not a change to the code.
    """
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            trailing_cr = b""
            while True:
                chunk = handle.read(config.HASH_CHUNK_BYTES)
                if not chunk:
                    break
                chunk = trailing_cr + chunk
                # A chunk boundary can fall between CR and LF. Hold a trailing CR back
                # so the pair is normalised as one, rather than surviving as a lone CR.
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
    """`<sha256>  <path>` lines, sorted, LF endings - stable across regenerations."""
    return "".join(f"{digest}  {key}\n" for key, digest in sorted(manifest.items()))


def parse_manifest(text: str) -> dict[str, str]:
    """Read a manifest back. Malformed lines are ignored rather than raising.

    A corrupt manifest surfaces as a pile of missing/changed entries, which is a far
    more useful report than an exception during startup verification.
    """
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
        # UnicodeDecodeError is NOT an OSError: a non-UTF-8 manifest used to escape
        # this handler and raise out of startup verification.
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
            # Exists, but could not be opened - a lock, an ACL, a bad sector. That is
            # a measurement that did not complete, not evidence the file is wrong.
            unreadable.append(key)
        elif actual != expected:
            changed.append(key)
        else:
            matched += 1

    # A .py file on disk that the manifest does not list. Counted, because otherwise
    # dropping in a new module would be the trivial way past this check.
    unexpected = sorted(set(on_disk) - set(recorded))

    return IntegrityReport(
        total=len(recorded), matched=matched, changed=tuple(changed),
        missing=tuple(missing), unexpected=tuple(unexpected),
        unreadable=tuple(unreadable))


# NOT "self-integrity", "tamper protection" or "installation is trusted": each of those
# names promises attacker resistance this check cannot have, and titles are what people
# actually read. What it honestly says is narrower and still useful.
_TITLE = "Installed files match their manifest"


def verify() -> list[Check]:
    """The `controller.integrity` check.

    Non-critical by design - see the module docstring.
    """
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
