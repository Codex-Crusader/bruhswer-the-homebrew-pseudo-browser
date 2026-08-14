"""Stage 4 gates A1/A2/A3 spike — can a real Chromium browser run inside an
AppContainer, and do its renderer processes stay sandboxed?

WHY THIS RUNS BEFORE ANYTHING ELSE
----------------------------------
Every other Stage 4 gate depends on the answer.

Chromium's own Windows sandbox works by having the *browser process* (the broker),
holding an ordinary user token, create heavily restricted tokens - including
AppContainer/LowBox tokens - for its renderer and utility children. Putting the broker
itself inside an AppContainer may prevent it doing that, because an AppContainer
restricts exactly the object-namespace, registry and named-pipe access a broker needs.

Two failure modes matter and they look identical from the screen:

  1. the browser does not start at all                       -> architecture blocked
  2. the browser starts but renderers come up UNSANDBOXED    -> STRICTLY WORSE than
     stock Chrome, because we would have removed Chromium's boundary and replaced it
     with a weaker one

A browser window appearing is NOT evidence the sandbox survived. This script therefore
measures from the HOST side: process tree, token AppContainer SID, token integrity
level, and the renderer command lines.

WHAT THIS DOES TO THE HOST
--------------------------
Creates one AppContainer profile, creates a dedicated data directory under
%LOCALAPPDATA%, grants that directory to the container SID ONLY (never to
ALL APPLICATION PACKAGES, which would grant every AppContainer on the machine),
launches the browser, inspects it, terminates it, then deletes the profile and the
directory. No elevation. No firewall changes. No installs. No registry writes.

SECURITY NOTES ON THIS CODE
---------------------------
- No shell, no eval/exec, no dynamic code generation. subprocess is always given an
  explicit argument list with shell=False.
- Every executable launched is a fixed absolute path.
- The single PowerShell invocation runs a CONSTANT script authored in this file. No
  value from the environment, the browser, or any input is interpolated into it.
- Nothing here reads or writes real user data. The only path written is the dedicated
  data directory this script creates and deletes.
"""

import ctypes
import ctypes.wintypes as wt
import json
import os
import shutil
import subprocess
import sys
import time

# --- Win32 plumbing -----------------------------------------------------------
userenv = ctypes.WinDLL("userenv", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

INVALID_HANDLE_VALUE = wt.HANDLE(-1).value

EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_UNICODE_ENVIRONMENT = 0x00000400
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
SE_GROUP_ENABLED = 0x00000004

PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
PROCESS_TERMINATE = 0x00000001
TOKEN_QUERY = 0x00000008

TokenIntegrityLevel = 25
TokenIsAppContainer = 29
TokenAppContainerSid = 31

INTEGRITY_NAMES = {
    0x0000: "UNTRUSTED", 0x1000: "LOW", 0x2000: "MEDIUM",
    0x2100: "MEDIUM_PLUS", 0x3000: "HIGH", 0x4000: "SYSTEM",
}

# Well-known Windows capability SIDs.
CAP_INTERNET_CLIENT = "S-1-15-3-1"

CONTAINER_NAME = "bm-s4-browser-spike"
DATA_ROOT = os.path.join(os.environ["LOCALAPPDATA"], "BrowserMaker", "S4Spike")

ICACLS = os.path.join(os.environ["SystemRoot"], "System32", "icacls.exe")
POWERSHELL = os.path.join(os.environ["SystemRoot"], "System32",
                          "WindowsPowerShell", "v1.0", "powershell.exe")

BROWSERS = [
    ("Microsoft Edge",
     r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    ("Google Chrome",
     r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wt.DWORD)]


class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", ctypes.c_void_p),
        ("Capabilities", ctypes.POINTER(SID_AND_ATTRIBUTES)),
        ("CapabilityCount", wt.DWORD),
        ("Reserved", wt.DWORD),
    ]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wt.DWORD), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR),
        ("lpTitle", wt.LPWSTR), ("dwX", wt.DWORD), ("dwY", wt.DWORD),
        ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD), ("dwXCountChars", wt.DWORD),
        ("dwYCountChars", wt.DWORD), ("dwFillAttribute", wt.DWORD),
        ("dwFlags", wt.DWORD), ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
        ("lpReserved2", ctypes.c_void_p), ("hStdInput", wt.HANDLE),
        ("hStdOutput", wt.HANDLE), ("hStdError", wt.HANDLE),
    ]


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE),
                ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD)]


class TOKEN_APPCONTAINER_INFORMATION(ctypes.Structure):
    _fields_ = [("TokenAppContainer", ctypes.c_void_p)]


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", SID_AND_ATTRIBUTES)]


# Explicit prototypes. Without these ctypes assumes c_int returns and silently
# truncates 64-bit handles and pointers - a real correctness bug, not a style point.
kernel32.CreateFileW.restype = wt.HANDLE
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.TerminateProcess.argtypes = [wt.HANDLE, ctypes.c_uint]
advapi32.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wt.DWORD)
advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wt.DWORD]


def sid_to_string(psid) -> str:
    out = ctypes.c_wchar_p()
    if not advapi32.ConvertSidToStringSidW(ctypes.c_void_p(psid), ctypes.byref(out)):
        return "<ConvertSidToStringSid failed>"
    s = out.value
    kernel32.LocalFree(ctypes.c_void_p(ctypes.cast(out, ctypes.c_void_p).value))
    # c_wchar_p.value is Optional. The conversion above succeeded, so it is set - but
    # this function promises a str, so the fallback is stated rather than assumed.
    return s if s is not None else "<empty SID string>"


def string_to_sid(s: str) -> ctypes.c_void_p:
    psid = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(wt.LPCWSTR(s), ctypes.byref(psid)):
        raise ctypes.WinError(ctypes.get_last_error())
    return psid


def create_profile(name: str, caps: list) -> ctypes.c_void_p:
    sid = ctypes.c_void_p()
    cap_sids = [string_to_sid(c) for c in caps]
    arr = (SID_AND_ATTRIBUTES * max(len(cap_sids), 1))()
    for i, cs in enumerate(cap_sids):
        arr[i].Sid = cs
        arr[i].Attributes = SE_GROUP_ENABLED

    hr = userenv.CreateAppContainerProfile(
        wt.LPCWSTR(name), wt.LPCWSTR(name), wt.LPCWSTR("Stage 4 A2/A3 spike"),
        arr if cap_sids else None, wt.DWORD(len(cap_sids)), ctypes.byref(sid))
    if hr != 0:
        if hr & 0xFFFF == 0xB7:  # already exists
            if userenv.DeriveAppContainerSidFromAppContainerName(
                    wt.LPCWSTR(name), ctypes.byref(sid)) != 0:
                raise OSError("DeriveAppContainerSidFromAppContainerName failed")
        else:
            raise OSError("CreateAppContainerProfile failed hr=0x%08X" % (hr & 0xFFFFFFFF))
    return sid


def launch_in_appcontainer(cmdline: str, container_sid, caps: list, cwd=None):
    """CreateProcessW with a SECURITY_CAPABILITIES attribute. Returns PROCESS_INFORMATION."""
    cap_sids = [string_to_sid(c) for c in caps]
    arr = (SID_AND_ATTRIBUTES * max(len(cap_sids), 1))()
    for i, cs in enumerate(cap_sids):
        arr[i].Sid = cs
        arr[i].Attributes = SE_GROUP_ENABLED

    sec = SECURITY_CAPABILITIES()
    sec.AppContainerSid = container_sid
    sec.Capabilities = ctypes.cast(arr, ctypes.POINTER(SID_AND_ATTRIBUTES)) if cap_sids else None
    sec.CapabilityCount = len(cap_sids)
    sec.Reserved = 0

    size = ctypes.c_size_t(0)
    kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value)
    if not kernel32.InitializeProcThreadAttributeList(buf, 1, 0, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not kernel32.UpdateProcThreadAttribute(
            buf, 0, ctypes.c_size_t(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES),
            ctypes.byref(sec), ctypes.sizeof(sec), None, None):
        raise ctypes.WinError(ctypes.get_last_error())

    si = STARTUPINFOEXW()
    si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
    si.lpAttributeList = ctypes.cast(buf, ctypes.c_void_p)
    pi = PROCESS_INFORMATION()

    ok = kernel32.CreateProcessW(
        None, ctypes.create_unicode_buffer(cmdline), None, None, False,
        EXTENDED_STARTUPINFO_PRESENT, None,
        wt.LPCWSTR(cwd) if cwd else None, ctypes.byref(si), ctypes.byref(pi))
    err = ctypes.get_last_error()
    kernel32.DeleteProcThreadAttributeList(buf)
    if not ok:
        raise OSError("CreateProcessW failed, GetLastError=%d" % err)
    return pi


def token_facts(pid: int) -> dict:
    """Read AppContainer SID and integrity level for a PID. Host-side measurement."""
    # Annotated: without it the literal below fixes the value type as int | None from
    # its first entries, and every later string or bool written into it reads as a type
    # error. This is a measurement record with deliberately mixed value types.
    facts: dict[str, object] = {"pid": pid, "opened": False, "is_appcontainer": None,
                                "package_sid": None, "integrity": None}
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h or h == INVALID_HANDLE_VALUE:
        facts["error"] = "OpenProcess failed (%d)" % ctypes.get_last_error()
        return facts
    facts["opened"] = True
    tok = wt.HANDLE()
    try:
        if not advapi32.OpenProcessToken(h, TOKEN_QUERY, ctypes.byref(tok)):
            facts["error"] = "OpenProcessToken failed (%d)" % ctypes.get_last_error()
            return facts

        is_ac = wt.DWORD(0)
        ret = wt.DWORD(0)
        if advapi32.GetTokenInformation(tok, TokenIsAppContainer, ctypes.byref(is_ac),
                                        ctypes.sizeof(is_ac), ctypes.byref(ret)):
            facts["is_appcontainer"] = bool(is_ac.value)

        need = wt.DWORD(0)
        advapi32.GetTokenInformation(tok, TokenAppContainerSid, None, 0, ctypes.byref(need))
        if need.value:
            b = ctypes.create_string_buffer(need.value)
            if advapi32.GetTokenInformation(tok, TokenAppContainerSid, b, need,
                                            ctypes.byref(ret)):
                info = ctypes.cast(b, ctypes.POINTER(TOKEN_APPCONTAINER_INFORMATION)).contents
                if info.TokenAppContainer:
                    facts["package_sid"] = sid_to_string(info.TokenAppContainer)

        need = wt.DWORD(0)
        advapi32.GetTokenInformation(tok, TokenIntegrityLevel, None, 0, ctypes.byref(need))
        if need.value:
            b = ctypes.create_string_buffer(need.value)
            if advapi32.GetTokenInformation(tok, TokenIntegrityLevel, b, need,
                                            ctypes.byref(ret)):
                lab = ctypes.cast(b, ctypes.POINTER(TOKEN_MANDATORY_LABEL)).contents
                psid = lab.Label.Sid
                cnt = advapi32.GetSidSubAuthorityCount(ctypes.c_void_p(psid))
                idx = cnt[0] - 1
                rid = advapi32.GetSidSubAuthority(ctypes.c_void_p(psid), idx)[0]
                facts["integrity"] = INTEGRITY_NAMES.get(rid, "0x%04X" % rid)
    finally:
        if tok:
            kernel32.CloseHandle(tok)
        kernel32.CloseHandle(wt.HANDLE(h))
    return facts


# CONSTANT PowerShell script. Nothing is interpolated into it - it is a fixed string
# literal, so it cannot become an injection vector.
PS_LIST_PROCS = (
    "@(Get-CimInstance Win32_Process -Filter \"Name='msedge.exe' or Name='chrome.exe'\" |"
    " Select-Object ProcessId,ParentProcessId,Name,CommandLine) |"
    " ConvertTo-Json -Depth 3 -Compress"
)


def list_browser_processes() -> list:
    r = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", PS_LIST_PROCS],
        capture_output=True, text=True, timeout=60)
    out = (r.stdout or "").strip()
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else [data]


def chromium_process_type(cmdline: str) -> str:
    if not cmdline:
        return "?"
    for tok in cmdline.split():
        if tok.startswith("--type="):
            return tok[len("--type="):]
    return "browser"


def grant_container(path: str, sid_str: str) -> str:
    """Grant the SPECIFIC container SID full control on path.

    Deliberately not 'ALL APPLICATION PACKAGES' (S-1-15-2-1): that would grant every
    AppContainer on the machine and would be a real weakening of the host.
    """
    r = subprocess.run(
        [ICACLS, path, "/grant", "*%s:(OI)(CI)F" % sid_str],
        capture_output=True, text=True, timeout=60)
    return (r.stdout or "").strip() + (("\n" + r.stderr.strip()) if r.stderr.strip() else "")


def terminate(pids: list):
    for pid in pids:
        h = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if h and h != INVALID_HANDLE_VALUE:
            kernel32.TerminateProcess(wt.HANDLE(h), 1)
            kernel32.CloseHandle(wt.HANDLE(h))


def spike_one(label: str, exe: str, sid, sid_str: str) -> dict:
    print("=" * 78)
    print("BROWSER UNDER TEST: %s" % label)
    print("  exe: %s" % exe)
    print("=" * 78)
    result = {"browser": label, "exe": exe, "launched": False}

    if not os.path.isfile(exe):
        print("  NOT PRESENT ON DISK - skipped")
        result["error"] = "not present"
        return result

    udd = os.path.join(DATA_ROOT, label.replace(" ", "_"))
    os.makedirs(udd, exist_ok=True)
    print("\n[setup] dedicated user-data-dir: %s" % udd)
    print("[setup] icacls grant to container SID only:")
    for line in grant_container(udd, sid_str).splitlines():
        print("        " + line)

    # Fixed argument list. --user-data-dir points ONLY at the dedicated directory, so
    # no existing user profile is touched. about:blank loads no remote content.
    args = [
        exe,
        "--user-data-dir=%s" % udd,
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-features=msEdgeWelcomePage",
        "about:blank",
    ]
    cmdline = " ".join('"%s"' % a if " " in a else a for a in args)
    print("\n[launch] inside AppContainer %s" % sid_str)
    print("[launch] cmdline: %s" % cmdline)

    try:
        pi = launch_in_appcontainer(cmdline, sid, [CAP_INTERNET_CLIENT])
    except OSError as e:
        print("\n  *** LAUNCH FAILED: %s" % e)
        result["error"] = str(e)
        return result

    result["launched"] = True
    result["launch_pid"] = pi.dwProcessId
    print("  CreateProcessW OK, pid=%d" % pi.dwProcessId)

    print("\n[wait] 14s for the process tree to establish...")
    time.sleep(14)

    procs = [p for p in list_browser_processes()
             if p.get("CommandLine") and udd in p["CommandLine"]]
    print("\n[measure] browser processes attributable to this user-data-dir: %d"
          % len(procs))

    rows = []
    for p in sorted(procs, key=lambda x: x["ProcessId"]):
        t = token_facts(p["ProcessId"])
        ptype = chromium_process_type(p.get("CommandLine", ""))
        nosandbox = "--no-sandbox" in (p.get("CommandLine") or "")
        rows.append({
            "pid": p["ProcessId"], "ppid": p["ParentProcessId"], "type": ptype,
            "is_ac": t.get("is_appcontainer"), "pkg": t.get("package_sid"),
            "integrity": t.get("integrity"), "no_sandbox_flag": nosandbox,
            "err": t.get("error"),
        })

    print("\n  %-7s %-7s %-12s %-6s %-9s %-12s %s"
          % ("PID", "PPID", "TYPE", "ISAC", "INTEGRITY", "NO_SANDBOX", "PACKAGE SID"))
    print("  " + "-" * 96)
    for r in rows:
        print("  %-7s %-7s %-12s %-6s %-9s %-12s %s"
              % (r["pid"], r["ppid"], r["type"], r["is_ac"], r["integrity"],
                 r["no_sandbox_flag"], (r["pkg"] or "-")))
        if r["err"]:
            print("          note: %s" % r["err"])

    result["rows"] = rows
    kernel32.CloseHandle(pi.hProcess)
    kernel32.CloseHandle(pi.hThread)

    print("\n[cleanup] terminating %d process(es)" % len(rows))
    terminate([r["pid"] for r in rows])
    time.sleep(2)
    return result


def main():
    print("Stage 4 A1/A2/A3 spike - AppContainer + Chromium")
    print("Container name: %s" % CONTAINER_NAME)
    print("Data root:      %s\n" % DATA_ROOT)

    os.makedirs(DATA_ROOT, exist_ok=True)
    sid = create_profile(CONTAINER_NAME, [CAP_INTERNET_CLIENT])
    sid_str = sid_to_string(sid.value)
    print("AppContainer profile created.")
    print("  package SID: %s\n" % sid_str)

    results = []
    try:
        for label, exe in BROWSERS:
            results.append(spike_one(label, exe, sid, sid_str))
            print()
    finally:
        print("=" * 78)
        print("[cleanup] removing data root and AppContainer profile")
        shutil.rmtree(DATA_ROOT, ignore_errors=True)
        print("  data root removed: %s" % (not os.path.exists(DATA_ROOT)))
        hr = userenv.DeleteAppContainerProfile(wt.LPCWSTR(CONTAINER_NAME))
        print("  DeleteAppContainerProfile hr=0x%08X" % (hr & 0xFFFFFFFF))

    print("\n" + "=" * 78)
    print("SPIKE SUMMARY")
    print("=" * 78)
    for r in results:
        if not r.get("launched"):
            print("%-16s LAUNCH FAILED / SKIPPED: %s" % (r["browser"], r.get("error")))
            continue
        rows = r.get("rows", [])
        rend = [x for x in rows if x["type"] == "renderer"]
        allac = rows and all(x["is_ac"] for x in rows)
        print("%-16s processes=%d renderers=%d all_in_appcontainer=%s"
              % (r["browser"], len(rows), len(rend), allac))
    return 0


if __name__ == "__main__":
    sys.exit(main())
