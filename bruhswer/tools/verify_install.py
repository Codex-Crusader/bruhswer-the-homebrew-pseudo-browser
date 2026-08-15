"""Install the built installer, verify it, uninstall it, verify nothing is left.

    python tools\\verify_install.py ..\\installer\\Output\\bruhswer-<version>-setup.exe

Per-user, no Administrator, and it uninstalls what it installs. Run it on a machine
with no existing bruhswer install - it refuses to start if one is present, because
uninstalling somebody's real installation to satisfy a checklist would be rude.

WHY THIS EXISTS AS A SCRIPT
    The 0.9.1 release shipped with eight unticked install boxes because the check was
    manual and nobody had a machine free. The first automated attempt then PASSED its
    "no tests/ in the install" assertions while looking at a directory the installer
    never writes to - the application is nested one level down, under {app}\\bruhswer.
    A check that passes because it is looking in the wrong place is worse than no check,
    so the layout is asserted explicitly below.

WHAT IT STILL DOES NOT PROVE
    It runs on a machine that already has Python and Edge, so it cannot exercise the
    prerequisite refusals. Those need a clean Windows image and are still unverified.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import winreg
from pathlib import Path

APP = Path(os.environ["LOCALAPPDATA"]) / "Programs" / "bruhswer"
PKG = APP / "bruhswer"
START = (Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu"
         / "Programs" / "bruhswer")
USER_DATA = Path(os.environ["LOCALAPPDATA"]) / "BRUHWSER"
UNINST_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"

_results: list[bool] = []


def check(name: str, passed: bool, detail: str = "") -> None:
    _results.append(passed)
    print(f"  [{'PASS' if passed else 'FAIL'}] {name}"
          + (f"  -  {detail}" if detail else ""))


def uninstall_entries() -> list[str]:
    found = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, UNINST_KEY) as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                sub = winreg.EnumKey(key, i)
                if "bruhswer" in sub.lower():
                    found.append(sub)
    except OSError:
        pass
    return found


def _data_census() -> dict[str, tuple[int, int]]:
    """subfolder -> (file count, total bytes) under the user's bruhswer data.

    Taken before the install and again after the uninstall. Comparing the two is the
    only way this script can tell "left alone" from "deleted"; see the note in step 8.
    """
    out: dict[str, tuple[int, int]] = {}
    for name in ("profiles", "quarantine", "logs", "state"):
        folder = USER_DATA / name
        if not folder.is_dir():
            out[name] = (0, 0)
            continue
        files = [f for f in folder.rglob("*") if f.is_file()]
        out[name] = (len(files), sum(f.stat().st_size for f in files))
    return out


def _backup_user_data() -> Path | None:
    """Copy the user's bruhswer data aside before anything destructive runs.

    THIS SCRIPT UNINSTALLS FOR REAL, AGAINST THE REAL %LOCALAPPDATA%\\BRUHWSER.
    Redirecting the environment does not move it: Inno resolves {localappdata} from the
    shell folder, not from the variable. So the only place a guard can live is here.

    It is needed because the thing it guards against already happened. During 0.11.0's
    verification the silent uninstall deleted a 110 MB persistent profile, the
    quarantine and the logs, and the script reported that user data had been left alone.
    The uninstaller no longer does that, but a tool that destroys real data when one
    line of Pascal is wrong should not be relying on that line staying right.

    Returns the backup location, or None if there was nothing to copy.
    """
    if not USER_DATA.is_dir() or not any(USER_DATA.iterdir()):
        return None
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = Path(os.environ["TEMP"]) / f"bruhswer-userdata-{stamp}"
    shutil.copytree(USER_DATA, target, dirs_exist_ok=True)
    files = sum(1 for f in target.rglob("*") if f.is_file())
    size = sum(f.stat().st_size for f in target.rglob("*") if f.is_file())
    print(f"  backed up {files} file(s), {size / 1024 / 1024:.1f} MB")
    print(f"  -> {target}")
    return target


def main(setup: Path) -> int:
    print(f"bruhswer install verification\n  artifact: {setup}\n")

    print("0. Protecting the real user data this script is about to risk")
    backup = _backup_user_data()
    check("user data backed up, or there was none to back up",
          backup is not None or not USER_DATA.is_dir()
          or not any(USER_DATA.iterdir()),
          str(backup) if backup else "no existing user data")

    # BEFORE anything runs. This script installs and then uninstalls, and the uninstall
    # is the step that can destroy a real profile.
    before = _data_census()

    print("1. Pre-install state")
    if APP.exists() or uninstall_entries():
        print("  REFUSED: bruhswer is already installed. Uninstall it first; this "
              "script will not remove an installation it did not create.")
        return 2
    check("nothing installed to begin with", True, str(APP))

    print("\n2. Silent install")
    r = subprocess.run([str(setup), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
                        "/TASKS=startmenuicon"], capture_output=True, text=True)
    time.sleep(3)
    check("installer exited 0", r.returncode == 0, f"rc={r.returncode}")
    check("install directory created", APP.is_dir(), str(APP))

    wanted = ["bruhswer.py", "app", "tools"]
    present = [w for w in wanted if (PKG / w).exists()]
    check("application files present", len(present) == len(wanted),
          f"{present} under {PKG}")
    check("licence and docs shipped",
          (APP / "LICENSE").exists() and (APP / "docs").is_dir())
    check("uninstaller present",
          (APP / "uninstall").is_dir() or any(APP.glob("unins*.exe")))

    # THE FILE MANIFEST. Asserted here because this is the only place that looks at a
    # REAL install, and the failure it guards against is silent: if the .iss pattern
    # ever stops shipping non-.py files under app\, or .gitignore swallows the
    # manifest, then every installed copy reports "no manifest shipped" and the drift
    # check does nothing - while passing its entire unit suite in the dev tree, where
    # the manifest is always present.
    #
    # It is also checked for FRESHNESS, not just presence. Regenerating the manifest
    # must be the LAST build step; a manifest generated before the final source edit
    # ships a build that reports FAIL on a perfectly good install, which teaches the
    # user to ignore the one indicator that would have told them something real.
    manifest = PKG / "app" / "security" / "MANIFEST.sha256"
    check("file manifest shipped", manifest.is_file(), str(manifest))

    if manifest.is_file():
        verdict = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, sys.argv[1]); "
             "from app.security import integrity; "
             "r = integrity.check_tree(); "
             "print('OK' if r.ok else 'DRIFT', r.matched, r.total, "
             "r.changed[:3], r.missing[:3], r.unexpected[:3])",
             str(PKG)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=120, shell=False)
        out = (verdict.stdout or "").strip()
        check("installed files match the shipped manifest", out.startswith("OK"),
              out or (verdict.stderr or "")[:160])

    print("\n3. What must NOT have shipped")
    for junk in ("tests", ".venv", "profiles", "logs", ".git", "__pycache__"):
        check(f"no {junk}/ in the install",
              not (PKG / junk).exists() and not (APP / junk).exists())

    print("\n4. Registration and shortcuts")
    check("appears in Installed apps", bool(uninstall_entries()),
          str(uninstall_entries()))
    check("Start Menu shortcut created", START.exists(), str(START))

    print("\n5. The installed copy runs from a clean working directory")
    probe = subprocess.run([sys.executable, str(PKG / "bruhswer.py"), "--check"],
                           capture_output=True, text=True, cwd=str(PKG),
                           env=dict(os.environ, PYTHONIOENCODING="utf-8"), timeout=300)
    # A non-zero exit is a legitimate "launch blocked" verdict. Only the absence of the
    # report means the installed copy could not run at all.
    check("installed app produced its report", "BRUH CHECK" in (probe.stdout or ""),
          f"exit={probe.returncode}, non-zero can be a correct blocked verdict")

    print("\n6. Silent uninstall")
    unins = next(iter(APP.glob("unins*.exe")), None) or APP / "uninstall" / "unins000.exe"
    check("uninstaller found", unins.exists(), str(unins))
    if unins.exists():
        u = subprocess.run([str(unins), "/VERYSILENT", "/SUPPRESSMSGBOXES",
                            "/NORESTART"], capture_output=True, text=True)
        time.sleep(5)
        check("uninstaller exited 0", u.returncode == 0, f"rc={u.returncode}")

    print("\n7. Nothing left behind")
    left = [str(p.relative_to(APP)) for p in APP.rglob("*")][:12] if APP.exists() else []
    check("install directory removed", not APP.exists(), f"leftovers: {left}")
    check("uninstall registration removed", not uninstall_entries())
    check("Start Menu shortcut removed", not START.exists())

    print("\n8. User data untouched")
    after = _data_census()
    # PER-FOLDER, not `USER_DATA.exists()`. That is what this used to assert, and it
    # cannot fail: the uninstaller deliberately KEEPS state\ so the Host Guard rollback
    # record survives, so the root directory always exists afterwards. It printed
    # "user data left alone, not silently deleted" during 0.11.0's verification run
    # while a 110 MB persistent profile, the quarantine and the logs had just been
    # deleted by the silent uninstall.
    #
    # A check that cannot fail is worse than no check: it is a green light nobody
    # measured, which is the one defect class this project treats as a vulnerability.
    for name in ("profiles", "quarantine", "state"):
        was, now = before.get(name), after.get(name)
        check(f"{name}/ unchanged by install and uninstall", was == now,
              f"before={was} after={now}")

    # logs/ is the one folder that legitimately GROWS: step 5 runs the installed copy
    # with --check, and bruhswer logs what it did. So the assertion is that nothing was
    # REMOVED, which is the property being defended, rather than exact equality - which
    # would fail on every run and get relaxed to something meaningless.
    was_logs, now_logs = before.get("logs", (0, 0)), after.get("logs", (0, 0))
    check("logs/ not deleted (may grow; the installed app ran)",
          now_logs[0] >= was_logs[0] and now_logs[1] >= was_logs[1],
          f"before={was_logs} after={now_logs}")

    print("\n" + "=" * 66)
    failed = len(_results) - sum(_results)
    print(f"{sum(_results)} passed, {failed} failed")

    if backup is not None:
        # KEPT, not deleted, and its location printed either way. If step 8 failed then
        # this copy is the only remaining record of the user's profile, and deleting it
        # to tidy up would destroy the evidence that the check just caught something.
        print(f"\nUser data backup kept at:\n  {backup}")
        if failed:
            print("Step 8 reported a change. RESTORE FROM THE BACKUP ABOVE before "
                  "running anything else against this machine.")
        else:
            print("Nothing was lost; delete it whenever you like.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(Path(sys.argv[1]).resolve()))
