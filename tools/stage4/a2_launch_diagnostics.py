"""Stage 4 gate A2 diagnostics — WHY does a Chromium browser die inside an AppContainer?

The A2/A3 spike showed CreateProcessW succeeding and then zero surviving processes for
both Edge and Chrome. "It didn't work" is not a finding. This script establishes the
mechanism.

It measures four things, in order:

  A. POSITIVE CONTROL  - a trivial program (System32 curl.exe) in the same container.
                         If this also dies, the harness is broken, not the browser.
  B. INSTALL DIR ACLs  - whether the container can even read the browser's own files.
  C. EXIT TIMING/CODE  - poll GetExitCodeProcess and record how long the process lived
                         and what it returned. NTSTATUS codes are decoded.
  D. CHROMIUM LOGGING  - relaunch with --enable-logging=stderr --v=1 and capture stderr
                         through an inherited handle.

WHAT THIS DOES TO THE HOST
--------------------------
One AppContainer profile, one dedicated data directory, both removed at the end. No
elevation, no firewall changes, no installs, no registry writes, no user data touched.

SECURITY NOTES
--------------
No shell, no eval/exec. Fixed absolute executable paths, literal argument lists.
"""

import ctypes
import ctypes.wintypes as wt
import os
import shutil
import subprocess
import sys
import tempfile
import time

userenv = ctypes.WinDLL("userenv", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

INVALID_HANDLE_VALUE = wt.HANDLE(-1).value
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
STARTF_USESTDHANDLES = 0x00000100
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
SE_GROUP_ENABLED = 0x00000004
HANDLE_FLAG_INHERIT = 0x00000001
STILL_ACTIVE = 259

CAP_INTERNET_CLIENT = "S-1-15-3-1"
CONTAINER_NAME = "bm-s4-diag"
DATA_ROOT = os.path.join(os.environ["LOCALAPPDATA"], "BrowserMaker", "S4Diag")

SYS32 = os.path.join(os.environ["SystemRoot"], "System32")
CURL = os.path.join(SYS32, "curl.exe")
ICACLS = os.path.join(SYS32, "icacls.exe")

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

# Common NTSTATUS values a failing sandboxed process returns.
NTSTATUS = {
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC0000142: "STATUS_DLL_INIT_FAILED",
    0xC0000135: "STATUS_DLL_NOT_FOUND",
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0xC000007B: "STATUS_INVALID_IMAGE_FORMAT",
    0xC0000017: "STATUS_NO_MEMORY",
    0xC000009A: "STATUS_INSUFFICIENT_RESOURCES",
    0xC0000018: "STATUS_CONFLICTING_ADDRESSES",
    0xC0000409: "STATUS_STACK_BUFFER_OVERRUN",
    0xC0000374: "STATUS_HEAP_CORRUPTION",
    0x80000003: "STATUS_BREAKPOINT",
}


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wt.DWORD)]


class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [("AppContainerSid", ctypes.c_void_p),
                ("Capabilities", ctypes.POINTER(SID_AND_ATTRIBUTES)),
                ("CapabilityCount", wt.DWORD), ("Reserved", wt.DWORD)]


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


kernel32.CreateFileW.restype = wt.HANDLE
kernel32.CloseHandle.argtypes = [wt.HANDLE]


def string_to_sid(s):
    psid = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(wt.LPCWSTR(s), ctypes.byref(psid)):
        raise ctypes.WinError(ctypes.get_last_error())
    return psid


def sid_to_string(psid):
    out = ctypes.c_wchar_p()
    if not advapi32.ConvertSidToStringSidW(ctypes.c_void_p(psid), ctypes.byref(out)):
        return "<failed>"
    return out.value


def create_profile(name, caps):
    sid = ctypes.c_void_p()
    cs = [string_to_sid(c) for c in caps]
    arr = (SID_AND_ATTRIBUTES * max(len(cs), 1))()
    for i, c in enumerate(cs):
        arr[i].Sid = c
        arr[i].Attributes = SE_GROUP_ENABLED
    hr = userenv.CreateAppContainerProfile(
        wt.LPCWSTR(name), wt.LPCWSTR(name), wt.LPCWSTR("Stage 4 A2 diagnostics"),
        arr, wt.DWORD(len(cs)), ctypes.byref(sid))
    if hr != 0:
        if hr & 0xFFFF == 0xB7:
            userenv.DeriveAppContainerSidFromAppContainerName(wt.LPCWSTR(name),
                                                              ctypes.byref(sid))
        else:
            raise OSError("CreateAppContainerProfile hr=0x%08X" % (hr & 0xFFFFFFFF))
    return sid


def run_and_watch(cmdline, sid, caps, watch_s=20.0, capture=True, cwd=None):
    """Launch in the AppContainer, poll for exit, return timing/exit code/output."""
    cs = [string_to_sid(c) for c in caps]
    arr = (SID_AND_ATTRIBUTES * max(len(cs), 1))()
    for i, c in enumerate(cs):
        arr[i].Sid = c
        arr[i].Attributes = SE_GROUP_ENABLED

    sec = SECURITY_CAPABILITIES()
    sec.AppContainerSid = sid
    sec.Capabilities = ctypes.cast(arr, ctypes.POINTER(SID_AND_ATTRIBUTES))
    sec.CapabilityCount = len(cs)
    sec.Reserved = 0

    size = ctypes.c_size_t(0)
    kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value)
    kernel32.InitializeProcThreadAttributeList(buf, 1, 0, ctypes.byref(size))
    if not kernel32.UpdateProcThreadAttribute(
            buf, 0, ctypes.c_size_t(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES),
            ctypes.byref(sec), ctypes.sizeof(sec), None, None):
        raise ctypes.WinError(ctypes.get_last_error())

    h_out = None
    path = None
    si = STARTUPINFOEXW()
    si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
    si.lpAttributeList = ctypes.cast(buf, ctypes.c_void_p)

    if capture:
        fd, path = tempfile.mkstemp(prefix="bm_s4_", suffix=".log")
        os.close(fd)
        h_out = kernel32.CreateFileW(wt.LPCWSTR(path), 0x40000000, 0x00000003,
                                     None, 3, 0, None)
        kernel32.SetHandleInformation(wt.HANDLE(h_out), HANDLE_FLAG_INHERIT,
                                      HANDLE_FLAG_INHERIT)
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES
        si.StartupInfo.hStdOutput = h_out
        si.StartupInfo.hStdError = h_out

    pi = PROCESS_INFORMATION()
    t0 = time.time()
    ok = kernel32.CreateProcessW(None, ctypes.create_unicode_buffer(cmdline),
                                 None, None, bool(capture),
                                 EXTENDED_STARTUPINFO_PRESENT, None,
                                 wt.LPCWSTR(cwd) if cwd else None,
                                 ctypes.byref(si), ctypes.byref(pi))
    err = ctypes.get_last_error()
    if h_out:
        kernel32.CloseHandle(wt.HANDLE(h_out))
    kernel32.DeleteProcThreadAttributeList(buf)

    res = {"created": bool(ok), "gle": err, "pid": pi.dwProcessId if ok else None}
    if not ok:
        if path:
            os.unlink(path)
        return res

    code = wt.DWORD(STILL_ACTIVE)
    lived = None
    deadline = t0 + watch_s
    while time.time() < deadline:
        kernel32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
        if code.value != STILL_ACTIVE:
            lived = time.time() - t0
            break
        time.sleep(0.2)

    res["still_running"] = code.value == STILL_ACTIVE
    res["exit_code"] = None if res["still_running"] else code.value
    res["lived_s"] = lived
    if res["exit_code"] is not None:
        u = res["exit_code"] & 0xFFFFFFFF
        res["exit_hex"] = "0x%08X" % u
        res["exit_name"] = NTSTATUS.get(u, "")

    if res["still_running"]:
        kernel32.TerminateProcess(pi.hProcess, 1)
    kernel32.CloseHandle(pi.hProcess)
    kernel32.CloseHandle(pi.hThread)

    if path:
        time.sleep(0.5)
        try:
            with open(path, "r", errors="replace") as f:
                res["output"] = f.read().strip()
        except OSError:
            res["output"] = ""
        try:
            os.unlink(path)
        except OSError:
            pass
    return res


def report(title, r):
    print("\n--- %s ---" % title)
    if not r["created"]:
        print("  CreateProcessW FAILED, GetLastError=%d" % r["gle"])
        return
    print("  pid            : %d" % r["pid"])
    if r["still_running"]:
        print("  STILL RUNNING after watch window (terminated by harness)")
    else:
        print("  exited after   : %.2f s" % (r["lived_s"] or 0))
        print("  exit code      : %d  %s  %s"
              % (r["exit_code"], r.get("exit_hex", ""), r.get("exit_name", "")))
    out = (r.get("output") or "").strip()
    if out:
        lines = out.splitlines()
        print("  captured output: %d line(s)" % len(lines))
        for ln in lines[:40]:
            print("    | " + ln[:200])
        if len(lines) > 40:
            print("    | ... (%d more)" % (len(lines) - 40))
    else:
        print("  captured output: <empty>")


def show_acl(path):
    r = subprocess.run([ICACLS, path], capture_output=True, text=True, timeout=60)
    for ln in (r.stdout or "").splitlines():
        s = ln.strip()
        if "APPLICATION PACKAGES" in s or s.startswith(path):
            print("    " + s)


def main():
    print("Stage 4 A2 launch diagnostics")
    os.makedirs(DATA_ROOT, exist_ok=True)
    sid = create_profile(CONTAINER_NAME, [CAP_INTERNET_CLIENT])
    sid_str = sid_to_string(sid.value)
    print("container SID: %s" % sid_str)

    try:
        # ---- A. positive control -------------------------------------------------
        print("\n" + "=" * 78)
        print("A. POSITIVE CONTROL - trivial program in the same container")
        print("=" * 78)
        report("curl.exe --version (AppContainer)",
               run_and_watch('"%s" --version' % CURL, sid, [CAP_INTERNET_CLIENT],
                             watch_s=15))

        # ---- B. install directory ACLs -------------------------------------------
        print("\n" + "=" * 78)
        print("B. CAN THE CONTAINER READ THE BROWSERS' OWN FILES?")
        print("=" * 78)
        for name, d in [("Edge", os.path.dirname(EDGE)),
                        ("Chrome", os.path.dirname(CHROME))]:
            print("\n  %s install dir: %s" % (name, d))
            show_acl(d)

        # ---- C/D. browsers with Chromium logging ---------------------------------
        for name, exe in [("Microsoft Edge", EDGE), ("Google Chrome", CHROME)]:
            if not os.path.isfile(exe):
                continue
            print("\n" + "=" * 78)
            print("C/D. %s inside AppContainer, with Chromium logging" % name)
            print("=" * 78)
            udd = os.path.join(DATA_ROOT, name.replace(" ", "_"))
            os.makedirs(udd, exist_ok=True)
            subprocess.run([ICACLS, udd, "/grant", "*%s:(OI)(CI)F" % sid_str],
                           capture_output=True, text=True, timeout=60)
            args = [exe, "--user-data-dir=%s" % udd, "--no-first-run",
                    "--no-default-browser-check", "--enable-logging=stderr", "--v=1",
                    "about:blank"]
            cmdline = " ".join('"%s"' % a if " " in a else a for a in args)
            print("  cmdline: %s" % cmdline)
            report(name, run_and_watch(cmdline, sid, [CAP_INTERNET_CLIENT],
                                       watch_s=20))
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
