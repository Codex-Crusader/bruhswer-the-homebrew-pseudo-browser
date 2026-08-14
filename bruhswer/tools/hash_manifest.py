"""Generate or check bruhswer's own file manifest.

    python tools/hash_manifest.py            # check, exit 1 on mismatch
    python tools/hash_manifest.py --write    # regenerate

The manifest is what `app/security/integrity.py` compares against at startup. It covers
EVERY .py file under `app/`, not a curated "security-relevant" subset - see that
module's docstring for why a subset would be a green light covering a fraction of what
actually runs in the process.

RELEASE STEP: regenerate this immediately before building the installer, after the last
source change. A manifest generated too early ships a build that reports FAIL on a
perfectly good install, which trains the user to ignore the one indicator that would
have told them their copy was damaged.

This tool is NOT part of the trusted stack at runtime. bruhswer never invokes it; it is
a build-time utility, and `app/` does not import it.
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.security import integrity  # noqa: E402


def _write() -> int:
    manifest = integrity.build_manifest()
    if not manifest:
        print("REFUSED: hashed zero files. Nothing was written.")
        return 1

    integrity.MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    # newline="" so the LF endings written by format_manifest survive on Windows.
    # Without it Python would translate them to CRLF, the manifest would differ
    # between platforms, and a file's recorded hash would depend on where the
    # manifest was generated rather than on the file.
    with integrity.MANIFEST_PATH.open("w", encoding="utf-8", newline="") as handle:
        handle.write(integrity.format_manifest(manifest))

    print(f"wrote {integrity.MANIFEST_PATH}")
    print(f"  {len(manifest)} file(s) hashed")

    # Prove the thing that was just written actually verifies. Writing a manifest and
    # not reading it back is how you ship one that fails on every install.
    report = integrity.check_tree()
    if not report.ok:
        print(f"  BUT IT DOES NOT VERIFY: {report.problems} problem(s)")
        return 1
    print(f"  verified: {report.matched}/{report.total} match")
    return 0


def _check() -> int:
    report = integrity.check_tree()
    if not report.manifest_present:
        print(f"NO MANIFEST at {integrity.MANIFEST_PATH}")
        print("Run with --write to create one.")
        return 1

    if report.ok:
        print(f"OK  {report.matched}/{report.total} file(s) match the manifest.")
        return 0

    print(f"MISMATCH  {report.matched}/{report.total} match, "
          f"{report.problems} problem(s):")
    for key in report.changed:
        print(f"  changed   {key}")
    for key in report.missing:
        print(f"  missing   {key}")
    for key in report.unexpected:
        print(f"  not listed {key}")
    return 1


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        # getattr rather than a direct call: `reconfigure` exists on TextIOWrapper
        # but not on every TextIO a stream can be, so a direct call is an unresolved
        # reference to every static checker. The behaviour is identical - the old
        # code caught AttributeError for exactly this case.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass

    if "--write" in argv:
        return _write()
    return _check()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
