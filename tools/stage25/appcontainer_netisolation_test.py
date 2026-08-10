"""Stage 2.5 gate B7-pre: does AppContainer network isolation actually hold?

WHY THIS EXISTS
---------------
Stage 2 gate G3 failed because WSL's guest->host traffic was SNAT'd to the host's own
IP, so guest-scoped Hyper-V Firewall rules never matched it.

The proposed QEMU+WHPX backend uses SLIRP user-mode networking, where guest packets
become ordinary Windows sockets issued *by the QEMU process*. That makes per-process
host-side enforcement possible in principle. But Windows Firewall does NOT filter
loopback traffic, so if the QEMU process can still reach 127.0.0.1 we have reproduced
G3 in a new costume.

The proposed fix is to run QEMU inside an AppContainer holding only the
`internetClient` capability. AppContainers are documented to block loopback by default
and to require `privateNetworkClientServer` for RFC1918 access.

This script tests that property with a TRIVIAL program (System32 curl.exe), NOT with
QEMU, so the AppContainer behaviour is isolated from QEMU's own behaviour.

WHAT IT DOES TO THE HOST
------------------------
Creates one AppContainer profile, runs curl.exe a few times, deletes the profile.
No elevation. No firewall changes. No installs. Listeners bind to high ports and are
torn down. Nothing persists.

SECURITY NOTES ON THIS CODE
---------------------------
- No shell, no eval/exec, no dynamic code generation.
- The only executable launched is a fixed absolute path to System32\\curl.exe.
- All URLs are literals defined in this file. Nothing is taken from input.
"""

import ctypes
import ctypes.wintypes as wt
import http.server
import os
import socket
import sys
import tempfile
import threading

# --- Win32 plumbing -----------------------------------------------------------
userenv = ctypes.WinDLL("userenv", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

EXTENDED_STARTUPINFO_PRESENT = 0x00080000
STARTF_USESTDHANDLES = 0x00000100
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
SE_GROUP_ENABLED = 0x00000004
HANDLE_FLAG_INHERIT = 0x00000001
INFINITE = 0xFFFFFFFF

# Well-known Windows capability SIDs.
CAP_INTERNET_CLIENT = "S-1-15-3-1"           # outbound to the internet
CAP_PRIVATE_NETWORK = "S-1-15-3-3"           # RFC1918 / local subnet access


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


def _sid_from_string(s: str) -> ctypes.c_void_p:
    psid = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(wt.LPCWSTR(s), ctypes.byref(psid)):
        raise ctypes.WinError(ctypes.get_last_error())
    return psid


def create_profile(name: str, caps: list[str]) -> ctypes.c_void_p:
    """Create (or reuse) an AppContainer profile and return its SID."""
    sid = ctypes.c_void_p()
    cap_sids = [_sid_from_string(c) for c in caps]
    arr = (SID_AND_ATTRIBUTES * len(cap_sids))()
    for i, cs in enumerate(cap_sids):
        arr[i].Sid = cs
        arr[i].Attributes = SE_GROUP_ENABLED

    hr = userenv.CreateAppContainerProfile(
        wt.LPCWSTR(name), wt.LPCWSTR(name), wt.LPCWSTR("bm stage2.5 net isolation test"),
        arr if cap_sids else None, wt.DWORD(len(cap_sids)), ctypes.byref(sid))
    if hr != 0:
        # 0x800700B7 == already exists; fall back to deriving the SID.
        if hr & 0xFFFF == 0xB7:
            if userenv.DeriveAppContainerSidFromAppContainerName(
                    wt.LPCWSTR(name), ctypes.byref(sid)) != 0:
                raise OSError(f"DeriveAppContainerSid failed hr=0x{hr:08X}")
        else:
            raise OSError(f"CreateAppContainerProfile failed hr=0x{hr:08X}")
    return sid


def run_in_appcontainer(cmdline: str, container_sid, caps: list[str], timeout_ms=20000):
    """Run cmdline inside the AppContainer; return (exit_code, captured_output).

    Output is captured via an INHERITED HANDLE rather than a path, so the container
    does not need filesystem ACLs on the output location.
    """
    cap_sids = [_sid_from_string(c) for c in caps]
    arr = (SID_AND_ATTRIBUTES * max(len(cap_sids), 1))()
    for i, cs in enumerate(cap_sids):
        arr[i].Sid = cs
        arr[i].Attributes = SE_GROUP_ENABLED

    sec_caps = SECURITY_CAPABILITIES()
    sec_caps.AppContainerSid = container_sid
    sec_caps.Capabilities = ctypes.cast(arr, ctypes.POINTER(SID_AND_ATTRIBUTES)) if cap_sids else None
    sec_caps.CapabilityCount = len(cap_sids)
    sec_caps.Reserved = 0

    # Build the attribute list carrying the security capabilities.
    size = ctypes.c_size_t(0)
    kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value)
    if not kernel32.InitializeProcThreadAttributeList(buf, 1, 0, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not kernel32.UpdateProcThreadAttribute(
            buf, 0, ctypes.c_size_t(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES),
            ctypes.byref(sec_caps), ctypes.sizeof(sec_caps), None, None):
        raise ctypes.WinError(ctypes.get_last_error())

    # Temp file for stdout/stderr, opened inheritable.
    fd, path = tempfile.mkstemp(prefix="bm_ac_", suffix=".txt")
    os.close(fd)
    GENERIC_WRITE, FILE_SHARE_RW, OPEN_EXISTING = 0x40000000, 0x00000003, 3
    h_out = kernel32.CreateFileW(wt.LPCWSTR(path), GENERIC_WRITE, FILE_SHARE_RW,
                                 None, OPEN_EXISTING, 0, None)
    if h_out == wt.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    kernel32.SetHandleInformation(wt.HANDLE(h_out), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)

    si = STARTUPINFOEXW()
    si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES
    si.StartupInfo.hStdOutput = h_out
    si.StartupInfo.hStdError = h_out
    si.lpAttributeList = ctypes.cast(buf, ctypes.c_void_p)
    pi = PROCESS_INFORMATION()

    ok = kernel32.CreateProcessW(
        None, ctypes.create_unicode_buffer(cmdline), None, None, True,
        EXTENDED_STARTUPINFO_PRESENT, None, None, ctypes.byref(si), ctypes.byref(pi))
    err = ctypes.get_last_error()
    kernel32.CloseHandle(wt.HANDLE(h_out))
    if not ok:
        kernel32.DeleteProcThreadAttributeList(buf)
        os.unlink(path)
        raise OSError(f"CreateProcessW failed, GetLastError={err}")

    kernel32.WaitForSingleObject(pi.hProcess, timeout_ms)
    code = wt.DWORD()
    kernel32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
    kernel32.CloseHandle(pi.hProcess)
    kernel32.CloseHandle(pi.hThread)
    kernel32.DeleteProcThreadAttributeList(buf)

    with open(path, "r", errors="replace") as f:
        out = f.read().strip()
    os.unlink(path)
    return code.value, out


# --- test harness -------------------------------------------------------------
class _Quiet(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"REACHED")

    def log_message(self, *a):
        pass


def start_listener(bind_ip: str, port: int):
    srv = http.server.HTTPServer((bind_ip, port), _Quiet)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


CURL = os.path.join(os.environ["SystemRoot"], "System32", "curl.exe")
LOOPBACK_PORT = 18080
LAN_PORT = 18081


def probe(label: str, url: str, sid, caps):
    cmd = f'"{CURL}" -s -m 6 -o NUL -w "HTTP_%{{http_code}}" {url}'
    try:
        code, out = run_in_appcontainer(cmd, sid, caps)
    except OSError as e:
        print(f"  {label:<34} LAUNCH FAILED: {e}")
        return
    # curl exit 0 = success; 7 = couldn't connect; 28 = timeout; 52 = empty reply
    verdict = "REACHABLE" if code == 0 else f"BLOCKED (curl exit {code})"
    print(f"  {label:<34} {verdict:<28} raw={out!r}")


def main():
    lan_ip = socket.gethostbyname(socket.gethostname())
    print(f"host LAN IP detected: {lan_ip}")
    start_listener("127.0.0.1", LOOPBACK_PORT)
    start_listener(lan_ip, LAN_PORT)
    print(f"listeners up on 127.0.0.1:{LOOPBACK_PORT} and {lan_ip}:{LAN_PORT}\n")

    # ROUTER is a genuine REMOTE LAN peer. The host's own LAN IP is a loopback case at
    # the network stack level, so it does not prove remote-LAN blocking on its own.
    # Single predetermined address, taken from the Stage 2 survey. No scanning.
    ROUTER = "10.0.0.1"
    targets = [
        ("loopback  127.0.0.1", f"http://127.0.0.1:{LOOPBACK_PORT}/"),
        (f"host-own-ip {lan_ip}", f"http://{lan_ip}:{LAN_PORT}/"),
        (f"REMOTE LAN router {ROUTER}", f"http://{ROUTER}/"),
        ("internet  1.1.1.1", "https://1.1.1.1/"),
    ]

    print("=== CONTROL: no AppContainer (ordinary process) ===")
    import subprocess
    for label, url in targets:
        r = subprocess.run([CURL, "-s", "-m", "6", "-o", os.devnull,
                            "-w", "HTTP_%{http_code}", url],
                           capture_output=True, text=True)
        v = "REACHABLE" if r.returncode == 0 else f"blocked (curl exit {r.returncode})"
        print(f"  {label:<34} {v:<28} raw={r.stdout.strip()!r}")

    for name, caps, note in [
        ("bm-test-inet", [CAP_INTERNET_CLIENT], "internetClient ONLY (proposed design)"),
        ("bm-test-inet-priv", [CAP_INTERNET_CLIENT, CAP_PRIVATE_NETWORK],
         "internetClient + privateNetworkClientServer (comparison)"),
    ]:
        print(f"\n=== APPCONTAINER: {note} ===")
        try:
            sid = create_profile(name, caps)
        except OSError as e:
            print(f"  profile creation failed: {e}")
            continue
        for label, url in targets:
            probe(label, url, sid, caps)
        hr = userenv.DeleteAppContainerProfile(wt.LPCWSTR(name))
        print(f"  [cleanup] DeleteAppContainerProfile({name}) hr=0x{hr & 0xFFFFFFFF:08X}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
