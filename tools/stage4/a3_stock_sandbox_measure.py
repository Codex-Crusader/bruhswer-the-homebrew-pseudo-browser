"""Stage 4 gate A3 — what does Chromium's OWN Windows sandbox actually give us?

WHY THIS MATTERS
----------------
A2 measured that neither Edge nor Chrome survives inside an AppContainer created by
this project. So the "wrap the browser process in an AppContainer" design is not
available. Before concluding anything about the architecture, the honest question is:

    what is the ACTUAL token boundary Chromium already establishes for its own child
    processes on THIS machine and THESE browser builds?

The brief (SS6) says: "Do not assume that 'AppContainer' means 'fully isolated'.
Document the exact boundary." That applies just as much to Chromium's sandbox as to
one we build. So this measures, per process:

  - process type (browser / renderer / gpu-process / utility / crashpad-handler)
  - is the token an AppContainer token?
  - the package SID, if any
  - LPAC vs ordinary AppContainer, detected from the token's groups:
        S-1-15-2-1 ALL APPLICATION PACKAGES            -> ordinary AppContainer
        S-1-15-2-2 ALL RESTRICTED APPLICATION PACKAGES -> LPAC (Less Privileged)
  - integrity level
  - whether the token is restricted (has restricting SIDs)
  - the capability SIDs actually held

WHAT THIS DOES TO THE HOST
--------------------------
Launches each browser NORMALLY (ordinary user token, no AppContainer) against a
dedicated user-data-dir, reads token metadata, then terminates only the processes it
started. The user's own running browser is never touched: attribution is by walking
the parent chain from the PID this script created, not by process name.

No elevation, no firewall changes, no installs, no registry writes.
"""

import ctypes
import ctypes.wintypes as wt
import json
import os
import shutil
import subprocess
import sys
import time

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

INVALID_HANDLE_VALUE = wt.HANDLE(-1).value
PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
PROCESS_TERMINATE = 0x00000001
TOKEN_QUERY = 0x00000008

TokenGroups = 2
TokenHasRestrictions = 21
TokenIntegrityLevel = 25
TokenIsAppContainer = 29
TokenCapabilities = 30
TokenAppContainerSid = 31

INTEGRITY_NAMES = {0x0000: "UNTRUSTED", 0x1000: "LOW", 0x2000: "MEDIUM",
                   0x2100: "MEDIUM_PLUS", 0x3000: "HIGH", 0x4000: "SYSTEM"}

SID_ALL_APP_PACKAGES = "S-1-15-2-1"
SID_ALL_RESTRICTED_APP_PACKAGES = "S-1-15-2-2"

# Documented Windows capability SIDs, so the output is readable rather than numeric.
CAP_NAMES = {
    "S-1-15-3-1": "internetClient",
    "S-1-15-3-2": "internetClientServer",
    "S-1-15-3-3": "privateNetworkClientServer",
    "S-1-15-3-4": "picturesLibrary",
    "S-1-15-3-5": "videosLibrary",
    "S-1-15-3-6": "musicLibrary",
    "S-1-15-3-7": "documentsLibrary",
    "S-1-15-3-8": "enterpriseAuthentication",
    "S-1-15-3-9": "sharedUserCertificates",
    "S-1-15-3-10": "removableStorage",
    "S-1-15-3-11": "appointments",
    "S-1-15-3-12": "contacts",
}

DATA_ROOT = os.path.join(os.environ["LOCALAPPDATA"], "BrowserMaker", "S4Stock")
SYS32 = os.path.join(os.environ["SystemRoot"], "System32")
POWERSHELL = os.path.join(SYS32, "WindowsPowerShell", "v1.0", "powershell.exe")

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wt.DWORD)]


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", SID_AND_ATTRIBUTES)]


class TOKEN_APPCONTAINER_INFORMATION(ctypes.Structure):
    _fields_ = [("TokenAppContainer", ctypes.c_void_p)]


kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.CloseHandle.argtypes = [wt.HANDLE]
advapi32.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wt.DWORD)
advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wt.DWORD]


def sid_to_string(psid):
    out = ctypes.c_wchar_p()
    if not psid or not advapi32.ConvertSidToStringSidW(ctypes.c_void_p(psid),
                                                       ctypes.byref(out)):
        return None
    return out.value


def _get_info(tok, cls):
    need = wt.DWORD(0)
    advapi32.GetTokenInformation(tok, cls, None, 0, ctypes.byref(need))
    if not need.value:
        return None
    buf = ctypes.create_string_buffer(need.value)
    ret = wt.DWORD(0)
    if not advapi32.GetTokenInformation(tok, cls, buf, need, ctypes.byref(ret)):
        return None
    return buf


def _sid_list(buf):
    """Decode a TOKEN_GROUPS-shaped buffer into a list of SID strings."""
    if buf is None:
        return []
    count = ctypes.cast(buf, ctypes.POINTER(wt.DWORD))[0]
    if not count:
        return []

    class TG(ctypes.Structure):
        _fields_ = [("GroupCount", wt.DWORD),
                    ("Groups", SID_AND_ATTRIBUTES * count)]

    tg = ctypes.cast(buf, ctypes.POINTER(TG)).contents
    return [s for s in (sid_to_string(tg.Groups[i].Sid) for i in range(count)) if s]


def token_facts(pid):
    f = {"pid": pid, "is_ac": None, "pkg": None, "lpac": None, "integrity": None,
         "restricted": None, "caps": [], "error": None}
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h or h == INVALID_HANDLE_VALUE:
        f["error"] = "OpenProcess %d" % ctypes.get_last_error()
        return f
    tok = wt.HANDLE()
    try:
        if not advapi32.OpenProcessToken(h, TOKEN_QUERY, ctypes.byref(tok)):
            f["error"] = "OpenProcessToken %d" % ctypes.get_last_error()
            return f

        v = wt.DWORD(0)
        ret = wt.DWORD(0)
        if advapi32.GetTokenInformation(tok, TokenIsAppContainer, ctypes.byref(v),
                                        ctypes.sizeof(v), ctypes.byref(ret)):
            f["is_ac"] = bool(v.value)
        v = wt.DWORD(0)
        if advapi32.GetTokenInformation(tok, TokenHasRestrictions, ctypes.byref(v),
                                        ctypes.sizeof(v), ctypes.byref(ret)):
            f["restricted"] = bool(v.value)

        b = _get_info(tok, TokenAppContainerSid)
        if b:
            info = ctypes.cast(b, ctypes.POINTER(TOKEN_APPCONTAINER_INFORMATION)).contents
            f["pkg"] = sid_to_string(info.TokenAppContainer)

        b = _get_info(tok, TokenIntegrityLevel)
        if b:
            lab = ctypes.cast(b, ctypes.POINTER(TOKEN_MANDATORY_LABEL)).contents
            cnt = advapi32.GetSidSubAuthorityCount(ctypes.c_void_p(lab.Label.Sid))
            rid = advapi32.GetSidSubAuthority(ctypes.c_void_p(lab.Label.Sid),
                                              cnt[0] - 1)[0]
            f["integrity"] = INTEGRITY_NAMES.get(rid, "0x%04X" % rid)

        groups = _sid_list(_get_info(tok, TokenGroups))
        if SID_ALL_RESTRICTED_APP_PACKAGES in groups:
            f["lpac"] = True
        elif SID_ALL_APP_PACKAGES in groups:
            f["lpac"] = False

        f["caps"] = [CAP_NAMES.get(s, s) for s in _sid_list(_get_info(tok, TokenCapabilities))]
    finally:
        if tok:
            kernel32.CloseHandle(tok)
        kernel32.CloseHandle(wt.HANDLE(h))
    return f


# CONSTANT PowerShell script - fixed literal, nothing interpolated.
PS_ALL = ("@(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,"
          "Name,CommandLine) | ConvertTo-Json -Depth 3 -Compress")


def all_processes():
    r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", PS_ALL],
                       capture_output=True, text=True, timeout=120)
    out = (r.stdout or "").strip()
    if not out:
        return []
    try:
        d = json.loads(out)
    except json.JSONDecodeError:
        return []
    return d if isinstance(d, list) else [d]


def descendants(procs, root_pid):
    """Processes whose ancestor chain reaches root_pid. Attribution by lineage, so the
    user's own already-running browser can never be included or terminated."""
    by_parent = {}
    for p in procs:
        by_parent.setdefault(p.get("ParentProcessId"), []).append(p)
    out, stack = [], [root_pid]
    seen = {root_pid}
    while stack:
        cur = stack.pop()
        for c in by_parent.get(cur, []):
            pid = c["ProcessId"]
            if pid in seen:
                continue
            seen.add(pid)
            out.append(c)
            stack.append(pid)
    return out


def ptype(cmdline):
    if not cmdline:
        return "?"
    for t in cmdline.split():
        if t.startswith("--type="):
            return t[len("--type="):]
    return "browser"


def terminate(pids):
    for pid in pids:
        h = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if h and h != INVALID_HANDLE_VALUE:
            kernel32.TerminateProcess(wt.HANDLE(h), 1)
            kernel32.CloseHandle(wt.HANDLE(h))


def measure(label, exe):
    print("=" * 100)
    print("STOCK SANDBOX: %s" % label)
    print("=" * 100)
    if not os.path.isfile(exe):
        print("  not present\n")
        return
    udd = os.path.join(DATA_ROOT, label.replace(" ", "_"))
    os.makedirs(udd, exist_ok=True)
    args = [exe, "--user-data-dir=%s" % udd, "--no-first-run",
            "--no-default-browser-check", "about:blank"]
    p = subprocess.Popen(args, close_fds=True)
    print("  launched pid %d (ordinary token, no AppContainer)" % p.pid)
    time.sleep(15)

    procs = all_processes()
    mine = [x for x in procs if x["ProcessId"] == p.pid] + descendants(procs, p.pid)
    print("  process tree size: %d\n" % len(mine))

    hdr = ("%-7s %-18s %-6s %-6s %-9s %-6s %s"
           % ("PID", "TYPE", "IS_AC", "LPAC", "INTEGRITY", "RESTR", "CAPABILITIES"))
    print("  " + hdr)
    print("  " + "-" * 96)
    rows = []
    for x in sorted(mine, key=lambda y: y["ProcessId"]):
        t = token_facts(x["ProcessId"])
        ty = ptype(x.get("CommandLine", ""))
        rows.append((x["ProcessId"], ty, t))
        caps = ", ".join(t["caps"][:4]) if t["caps"] else "-"
        if t["caps"] and len(t["caps"]) > 4:
            caps += " (+%d)" % (len(t["caps"]) - 4)
        print("  %-7s %-18s %-6s %-6s %-9s %-6s %s"
              % (x["ProcessId"], ty[:18], t["is_ac"], t["lpac"], t["integrity"],
                 t["restricted"], caps))
        if t["error"]:
            print("          note: %s" % t["error"])

    pkgs = sorted({t["pkg"] for _, _, t in rows if t["pkg"]})
    if pkgs:
        print("\n  distinct package SIDs observed:")
        for s in pkgs:
            print("    %s" % s)

    print("\n  [cleanup] terminating %d process(es) started by this script" % len(mine))
    terminate([x["ProcessId"] for x in mine])
    time.sleep(2)
    print()


def main():
    os.makedirs(DATA_ROOT, exist_ok=True)
    try:
        measure("Microsoft Edge", EDGE)
        measure("Google Chrome", CHROME)
    finally:
        shutil.rmtree(DATA_ROOT, ignore_errors=True)
        print("[cleanup] data root removed: %s" % (not os.path.exists(DATA_ROOT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
