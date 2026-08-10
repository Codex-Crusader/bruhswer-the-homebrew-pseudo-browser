"""Stage 4 gate A2 — flag variants, to find the exact incompatibility.

Baseline result (a2_launch_diagnostics.py):
  Chrome : died 3.6s,  0x80000003 STATUS_BREAKPOINT
           FATAL crashpad_client_win.cc: "CreateNamedPipe: Access is denied. (0x5)"
  Edge   : died 7.7s,  0xC0000005 STATUS_ACCESS_VIOLATION, 298 log lines (tail unseen)

This script answers three questions:

  1. What does Edge's log say at the END? (the first 40 lines were startup noise)
  2. Does --disable-breakpad get past the crashpad named-pipe failure, or is the
     named-pipe restriction structural and hit again elsewhere?
  3. DIAGNOSTIC ONLY: does it survive with --no-sandbox? If a Chromium browser only
     runs inside an AppContainer when its OWN sandbox is disabled, that is a decisive
     negative result for this architecture - it would mean trading Chromium's proven
     boundary for a weaker one. --no-sandbox is being MEASURED here, never proposed.

WHAT THIS DOES TO THE HOST
--------------------------
One AppContainer profile, one dedicated data directory, both removed at the end.
No elevation, no firewall changes, no installs, no registry writes.
"""

import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from a2_launch_diagnostics import (  # noqa: E402
    CAP_INTERNET_CLIENT, ICACLS, create_profile, run_and_watch, sid_to_string,
    userenv, wt,
)

CONTAINER_NAME = "bm-s4-variants"
DATA_ROOT = os.path.join(os.environ["LOCALAPPDATA"], "BrowserMaker", "S4Variants")

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

BASE = ["--no-first-run", "--no-default-browser-check",
        "--enable-logging=stderr", "--v=1", "about:blank"]

VARIANTS = [
    ("v1 --disable-breakpad", ["--disable-breakpad"]),
    ("v2 --disable-breakpad --disable-gpu", ["--disable-breakpad", "--disable-gpu"]),
    ("v3 DIAGNOSTIC --no-sandbox", ["--disable-breakpad", "--no-sandbox"]),
]

TAIL = 26


def tail_report(title, r):
    print("\n--- %s ---" % title)
    if not r["created"]:
        print("  CreateProcessW FAILED, GetLastError=%d" % r["gle"])
        return
    if r["still_running"]:
        print("  pid %d: STILL RUNNING at end of watch window  <== SURVIVED"
              % r["pid"])
    else:
        print("  pid %d: exited after %.2fs, code=%s %s"
              % (r["pid"], r["lived_s"] or 0, r.get("exit_hex"), r.get("exit_name")))
    out = (r.get("output") or "").strip()
    lines = out.splitlines()
    if not lines:
        print("  log: <empty>")
        return
    print("  log: %d line(s); last %d:" % (len(lines), min(TAIL, len(lines))))
    for ln in lines[-TAIL:]:
        print("    | " + ln[:210])


def main():
    os.makedirs(DATA_ROOT, exist_ok=True)
    sid = create_profile(CONTAINER_NAME, [CAP_INTERNET_CLIENT])
    sid_str = sid_to_string(sid.value)
    print("Stage 4 A2 variants")
    print("container SID: %s" % sid_str)

    try:
        for bname, exe in [("Edge", EDGE), ("Chrome", CHROME)]:
            if not os.path.isfile(exe):
                continue
            for vname, extra in VARIANTS:
                print("\n" + "=" * 78)
                print("%s | %s" % (bname, vname))
                print("=" * 78)
                udd = os.path.join(DATA_ROOT, "%s_%s" % (bname, vname.split()[0]))
                os.makedirs(udd, exist_ok=True)
                subprocess.run([ICACLS, udd, "/grant", "*%s:(OI)(CI)F" % sid_str],
                               capture_output=True, text=True, timeout=60)
                args = [exe, "--user-data-dir=%s" % udd] + extra + BASE
                cmdline = " ".join('"%s"' % a if " " in a else a for a in args)
                tail_report("%s %s" % (bname, vname),
                            run_and_watch(cmdline, sid, [CAP_INTERNET_CLIENT],
                                          watch_s=18))
    finally:
        print("\n" + "=" * 78)
        print("[cleanup]")
        shutil.rmtree(DATA_ROOT, ignore_errors=True)
        print("  data root removed : %s" % (not os.path.exists(DATA_ROOT)))
        hr = userenv.DeleteAppContainerProfile(wt.LPCWSTR(CONTAINER_NAME))
        print("  profile deleted   : hr=0x%08X" % (hr & 0xFFFFFFFF))
    return 0


if __name__ == "__main__":
    sys.exit(main())
