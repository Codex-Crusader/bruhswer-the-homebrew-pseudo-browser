"""Stage 4 gates A4/A5/A6/A7 — how far does the BROWSER PROCESS token actually reach?

WHY THIS IS THE DECIDING MEASUREMENT
------------------------------------
A2 measured that this project cannot wrap a Chromium browser process in an
AppContainer. A3 measured that Chromium sandboxes its RENDERERS but runs its BROWSER
process (the broker) at MEDIUM integrity on an ordinary user token.

So the honest question for Threat Model A is no longer "how strong is our container"
- there isn't one - but:

    if an attacker reaches the browser process, what can they touch?

METHOD, AND WHY IT IS SOUND WITHOUT ELEVATION
---------------------------------------------
Running a probe *with the browser's own token* would need SE_ASSIGNPRIMARYTOKEN, i.e.
elevation, which this project's runtime must never have. Instead this script does two
things:

  PART 1  TOKEN EQUIVALENCE. Dump the browser process's token and this probe's token
          side by side - user SID, integrity, restriction state, restricted-SID count,
          group count, privilege count. If they are equivalent, then what this probe
          can reach, the browser process can reach. The equivalence is MEASURED, so
          the conclusion is not an assumption.

  PART 2  REACH PROBES from that same token class: filesystem, registry, process,
          credentials.

DATA HANDLING (brief SS55)
--------------------------
No real secret is read, printed or stored anywhere.
  - Sentinels are synthetic files this script creates in its own dedicated tree.
  - Real sensitive directories are tested for LISTABILITY ONLY. Entry COUNTS are
    reported; file names and contents are never read or printed.
  - Credential Manager is probed with a deliberately NON-MATCHING filter, so the API
    returns "not found" if access is permitted and "access denied" if it is not. This
    proves reach while enumerating nothing real.
  - The registry write test uses a key this script creates and deletes.

No elevation, no firewall changes, no installs.
"""

import ctypes
import ctypes.wintypes as wt
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from a3_stock_sandbox_measure import (  # noqa: E402
    EDGE, INVALID_HANDLE_VALUE, PROCESS_QUERY_LIMITED_INFORMATION, TOKEN_QUERY,
    TokenGroups, TokenHasRestrictions,
    _get_info, _sid_list, advapi32, all_processes, descendants, kernel32,
    ptype, sid_to_string, terminate, token_facts,
)

advapi32_c = ctypes.WinDLL("advapi32", use_last_error=True)
credui = ctypes.WinDLL("advapi32", use_last_error=True)

TokenUser = 1
TokenPrivileges = 3
TokenRestrictedSids = 11

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

SENTINEL_ROOT = os.path.join(os.environ["LOCALAPPDATA"], "BrowserMaker", "S4Sentinels")
SENTINEL_TEXT = "BM_STAGE4_SENTINEL_9c14f0a7_SYNTHETIC_NOT_A_REAL_SECRET"

# Synthetic stand-ins for the categories brief SS13/SS14/SS17 lists. Nothing here is real.
SENTINEL_FILES = [
    ("ssh_private_key", "id_ed25519"),
    ("git_credentials", ".git-credentials"),
    ("api_keys", ".env"),
    ("password_manager_db", "vault.kdbx"),
    ("crypto_wallet", "wallet.dat"),
    ("personal_document", "tax_return.txt"),
]

# Real directories, tested for LISTABILITY only. Never read, never printed by name.
REAL_DIRS = [
    ("Desktop", os.path.join(os.environ["USERPROFILE"], "Desktop")),
    ("Documents", os.path.join(os.environ["USERPROFILE"], "Documents")),
    ("Downloads", os.path.join(os.environ["USERPROFILE"], "Downloads")),
    (".ssh", os.path.join(os.environ["USERPROFILE"], ".ssh")),
    ("Credentials store", os.path.join(os.environ["APPDATA"], "Microsoft", "Credentials")),
    ("DPAPI master keys", os.path.join(os.environ["APPDATA"], "Microsoft", "Protect")),
    ("Chrome profile", os.path.join(os.environ["LOCALAPPDATA"], "Google", "Chrome", "User Data")),
    ("Edge profile", os.path.join(os.environ["LOCALAPPDATA"], "Microsoft", "Edge", "User Data")),
    ("project repo", os.getcwd()),
]


def full_token(pid):
    """Everything needed to argue token equivalence."""
    f = {"pid": pid, "user": None, "integrity": None, "is_ac": None,
         "has_restrictions": None, "restricted_sids": None,
         "groups": None, "privileges": None, "error": None}
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h or h == INVALID_HANDLE_VALUE:
        f["error"] = "OpenProcess %d" % ctypes.get_last_error()
        return f
    tok = wt.HANDLE()
    try:
        if not advapi32.OpenProcessToken(h, TOKEN_QUERY, ctypes.byref(tok)):
            f["error"] = "OpenProcessToken %d" % ctypes.get_last_error()
            return f
        base = token_facts(pid)
        f["integrity"] = base["integrity"]
        f["is_ac"] = base["is_ac"]

        b = _get_info(tok, TokenUser)
        if b:
            class TU(ctypes.Structure):
                _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wt.DWORD)]
            f["user"] = sid_to_string(ctypes.cast(b, ctypes.POINTER(TU)).contents.Sid)

        v = wt.DWORD(0)
        ret = wt.DWORD(0)
        if advapi32.GetTokenInformation(tok, TokenHasRestrictions, ctypes.byref(v),
                                        ctypes.sizeof(v), ctypes.byref(ret)):
            f["has_restrictions"] = bool(v.value)

        rb = _get_info(tok, TokenRestrictedSids)
        f["restricted_sids"] = len(_sid_list(rb)) if rb else 0
        gb = _get_info(tok, TokenGroups)
        f["groups"] = len(_sid_list(gb)) if gb else 0
        pb = _get_info(tok, TokenPrivileges)
        if pb:
            f["privileges"] = ctypes.cast(pb, ctypes.POINTER(wt.DWORD))[0]
    finally:
        if tok:
            kernel32.CloseHandle(tok)
        kernel32.CloseHandle(wt.HANDLE(h))
    return f


def make_sentinels():
    shutil.rmtree(SENTINEL_ROOT, ignore_errors=True)
    made = []
    for cat, fname in SENTINEL_FILES:
        d = os.path.join(SENTINEL_ROOT, cat)
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, fname)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(SENTINEL_TEXT + "\n")
        made.append((cat, p))
    return made


def probe_filesystem(sentinels):
    print("\n" + "=" * 78)
    print("A4 — FILESYSTEM REACH from the browser-process token class")
    print("=" * 78)
    print("\n  Synthetic sentinels (created by this script, no real data):")
    for cat, p in sentinels:
        try:
            with open(p, "r", encoding="utf-8") as fh:
                ok = SENTINEL_TEXT in fh.read()
            print("    %-22s READ OK        (content matched: %s)" % (cat, ok))
        except OSError as e:
            print("    %-22s DENIED         (%s)" % (cat, e.__class__.__name__))

    print("\n  Real user directories — LISTABILITY ONLY, contents never read:")
    for label, d in REAL_DIRS:
        if not os.path.isdir(d):
            print("    %-22s (absent on this machine)" % label)
            continue
        try:
            n = len(os.listdir(d))
            print("    %-22s LISTABLE       (%d entries; names not read)" % (label, n))
        except OSError as e:
            print("    %-22s DENIED         (%s)" % (label, e.__class__.__name__))

    print("\n  Write test into a real user directory (creates then deletes one file):")
    probe = os.path.join(os.environ["USERPROFILE"], "Documents",
                         "bm_stage4_write_probe.txt")
    try:
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write(SENTINEL_TEXT)
        os.unlink(probe)
        print("    %-22s WRITE+DELETE OK (probe file removed)" % "Documents")
    except OSError as e:
        print("    %-22s DENIED         (%s)" % ("Documents", e.__class__.__name__))


def probe_registry():
    print("\n" + "=" * 78)
    print("A5 — REGISTRY REACH")
    print("=" * 78)
    import winreg
    checks = [
        ("HKCU\\Software", winreg.HKEY_CURRENT_USER, r"Software", winreg.KEY_READ),
        ("HKCU\\...\\Run (startup)", winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Run", winreg.KEY_READ),
        ("HKLM\\...\\Winlogon", winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", winreg.KEY_READ),
    ]
    for label, root, path, acc in checks:
        try:
            with winreg.OpenKey(root, path, 0, acc) as k:
                n = winreg.QueryInfoKey(k)[1]
            print("  %-26s READ OK        (%d values; not printed)" % (label, n))
        except OSError as e:
            print("  %-26s DENIED         (%s)" % (label, e.__class__.__name__))

    print("\n  Persistence write test (creates then deletes its own value):")
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "BM_STAGE4_PROBE", 0, winreg.REG_SZ, "probe")
            winreg.DeleteValue(k, "BM_STAGE4_PROBE")
        print("  %-26s WRITE+DELETE OK  <-- persistence would be possible"
              % "HKCU\\...\\Run")
    except OSError as e:
        print("  %-26s DENIED         (%s)" % ("HKCU\\...\\Run", e.__class__.__name__))


def probe_credentials():
    print("\n" + "=" * 78)
    print("A7 — CREDENTIAL MANAGER REACH (non-matching filter; nothing enumerated)")
    print("=" * 78)
    count = wt.DWORD(0)
    pcreds = ctypes.c_void_p()
    # Deliberately impossible filter: proves whether the CALL is permitted without
    # returning any real credential.
    flt = wt.LPCWSTR("bm-stage4-nonexistent-target-*")
    ok = advapi32_c.CredEnumerateW(flt, 0, ctypes.byref(count), ctypes.byref(pcreds))
    err = ctypes.get_last_error()
    if ok:
        print("  CredEnumerateW: SUCCEEDED, %d matches (filter matches nothing real)"
              % count.value)
        advapi32_c.CredFree(pcreds)
    else:
        names = {1168: "ERROR_NOT_FOUND  -> access PERMITTED, nothing matched",
                 5: "ERROR_ACCESS_DENIED -> access REFUSED"}
        print("  CredEnumerateW: failed, GetLastError=%d  %s"
              % (err, names.get(err, "")))
    print("\n  Interpretation: ERROR_NOT_FOUND means the API was reachable and the")
    print("  filter simply matched nothing. It does NOT mean the store is empty, and")
    print("  no real credential was enumerated, read, or printed.")


def probe_processes():
    print("\n" + "=" * 78)
    print("A6 — PROCESS REACH (handles only; nothing is injected or terminated)")
    print("=" * 78)
    procs = all_processes()
    targets = []
    for p in procs:
        n = (p.get("Name") or "").lower()
        if n in ("explorer.exe", "lsass.exe", "winlogon.exe", "services.exe"):
            targets.append((p["Name"], p["ProcessId"]))
    seen = set()
    for name, pid in targets:
        if name in seen:
            continue
        seen.add(name)
        h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                 False, pid)
        if h and h != INVALID_HANDLE_VALUE:
            print("  %-16s pid %-7d OPEN OK (QUERY|VM_READ)  <-- memory readable"
                  % (name, pid))
            kernel32.CloseHandle(wt.HANDLE(h))
        else:
            print("  %-16s pid %-7d DENIED (error %d)"
                  % (name, pid, ctypes.get_last_error()))


def main():
    print("Stage 4 A4/A5/A6/A7 — browser-process token reach")

    udd = os.path.join(os.environ["LOCALAPPDATA"], "BrowserMaker", "S4Reach")
    os.makedirs(udd, exist_ok=True)
    print("\n" + "=" * 78)
    print("PART 1 — TOKEN EQUIVALENCE: browser process vs this probe")
    print("=" * 78)
    p = subprocess.Popen([EDGE, "--user-data-dir=%s" % udd, "--no-first-run",
                          "--no-default-browser-check", "about:blank"], close_fds=True)
    time.sleep(14)
    procs = all_processes()
    tree = [x for x in procs if x["ProcessId"] == p.pid] + descendants(procs, p.pid)
    browser_pid = None
    renderer_pid = None
    for x in tree:
        t = ptype(x.get("CommandLine", ""))
        if t == "browser" and browser_pid is None:
            browser_pid = x["ProcessId"]
        if t == "renderer" and renderer_pid is None:
            renderer_pid = x["ProcessId"]

    rows = [("this probe (control)", full_token(os.getpid()))]
    if browser_pid:
        rows.append(("Edge BROWSER process", full_token(browser_pid)))
    if renderer_pid:
        rows.append(("Edge renderer", full_token(renderer_pid)))

    print("\n  %-22s %-9s %-6s %-8s %-9s %-7s %s"
          % ("PROCESS", "INTEGRITY", "IS_AC", "HASRESTR", "RESTR_SID", "GROUPS", "PRIVS"))
    print("  " + "-" * 88)
    for label, t in rows:
        print("  %-22s %-9s %-6s %-8s %-9s %-7s %s"
              % (label, t["integrity"], t["is_ac"], t["has_restrictions"],
                 t["restricted_sids"], t["groups"], t["privileges"]))
    print("\n  user SIDs:")
    for label, t in rows:
        print("    %-22s %s" % (label, t["user"]))

    print("\n  [cleanup] terminating the Edge tree started by this script")
    terminate([x["ProcessId"] for x in tree])
    time.sleep(2)
    shutil.rmtree(udd, ignore_errors=True)

    print("\n" + "=" * 78)
    print("PART 2 — REACH PROBES")
    print("=" * 78)
    sentinels = make_sentinels()
    try:
        probe_filesystem(sentinels)
        probe_registry()
        probe_credentials()
        probe_processes()
    finally:
        shutil.rmtree(SENTINEL_ROOT, ignore_errors=True)
        print("\n[cleanup] sentinel tree removed: %s"
              % (not os.path.exists(SENTINEL_ROOT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
