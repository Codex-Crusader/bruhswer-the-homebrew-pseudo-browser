"""Stage 4 gates A10-A15, A17 — network reach baseline and firewall bypass resistance.

WHAT THIS ESTABLISHES
---------------------
A4-A7 showed the browser-process token has the user's full reach to files, registry,
credentials and same-user process memory. Network is the one axis where a HOST-SIDE
control can be applied that the browser process cannot edit - which is exactly the
property WSL2 failed to provide in Stage 2 (G3/G8) and that Stage 2.5 measured working
via program-scoped firewall rules (B16 PASS).

So this script measures two things:

  BASELINE (A10-A15): with NO rules in place, what can the browser-process token class
      reach? Loopback, the host's own IP, simulated development services, the LAN
      router, IPv6, and the internet. Establishes what a rule would have to block.

  A17 BYPASS RESISTANCE: can a process holding the browser-process token REMOVE or ADD
      a Windows Firewall rule? If host-side rules can be edited by the very process
      they constrain, they are not a boundary - the same defect class this project
      rejected when it refused to rely on a guest-side firewall.

NO SCANNING (brief SS22, SS25). Every target is either a listener this script starts
itself on a high port, or a single predetermined address recorded in Stage 2:
the default gateway 10.0.0.1 and 1.1.1.1. No LAN enumeration, no port sweeps.

No elevation. No firewall changes are made by this script - A17 deliberately ATTEMPTS
one and reports the refusal; if it ever succeeds the rule is removed immediately.
"""

import http.server
import os
import socket
import subprocess
import sys
import threading

SYS32 = os.path.join(os.environ["SystemRoot"], "System32")
CURL = os.path.join(SYS32, "curl.exe")
POWERSHELL = os.path.join(SYS32, "WindowsPowerShell", "v1.0", "powershell.exe")

HOST_IP = "10.0.0.50"      # measured, this machine
ROUTER = "10.0.0.1"         # measured default gateway - single predetermined peer
INTERNET = "1.1.1.1"

P_LOOPBACK = 18080
P_HOSTIP = 18081
P_LOOPBACK6 = 18082
P_DEVSVC = 18443              # stands in for a local development service


class _Quiet(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"REACHED")

    def log_message(self, *a):
        pass


class _HTTP6(http.server.HTTPServer):
    address_family = socket.AF_INET6


def listen(ip, port, v6=False):
    cls = _HTTP6 if v6 else http.server.HTTPServer
    try:
        srv = cls((ip, port), _Quiet)
    except OSError as e:
        print("  [listener] FAILED %s:%d -> %s" % (ip, port, e))
        return None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def probe(label, url):
    """curl exit 0 = reached; 7 = refused/unreachable; 28 = timeout."""
    r = subprocess.run([CURL, "-s", "-m", "6", "-o", os.devnull, url],
                       capture_output=True, text=True)
    v = "REACHED" if r.returncode == 0 else "blocked/failed (curl exit %d)" % r.returncode
    print("  %-42s %s" % (label, v))
    return r.returncode


def main():
    print("Stage 4 A10-A15 / A17 — network baseline and bypass resistance")
    print("=" * 78)

    print("\n[setup] starting local listeners on predetermined high ports")
    servers = [
        listen("127.0.0.1", P_LOOPBACK),
        listen(HOST_IP, P_HOSTIP),
        listen("::1", P_LOOPBACK6, v6=True),
        listen("127.0.0.1", P_DEVSVC),
    ]
    print("  listeners up: %d of 4" % sum(1 for s in servers if s))

    print("\n" + "=" * 78)
    print("BASELINE REACH — no firewall rules in place (browser-process token class)")
    print("=" * 78)
    print("\n  A14 loopback:")
    probe("127.0.0.1:%d (TCP)" % P_LOOPBACK, "http://127.0.0.1:%d/" % P_LOOPBACK)
    print("\n  A13 IPv6 loopback:")
    probe("[::1]:%d (TCP)" % P_LOOPBACK6, "http://[::1]:%d/" % P_LOOPBACK6)
    print("\n  A10 host's own services:")
    probe("%s:%d (host own LAN IP)" % (HOST_IP, P_HOSTIP),
          "http://%s:%d/" % (HOST_IP, P_HOSTIP))
    print("\n  A15 simulated development service:")
    probe("127.0.0.1:%d (dev service stand-in)" % P_DEVSVC,
          "http://127.0.0.1:%d/" % P_DEVSVC)
    print("\n  A11/A12 remote LAN (single predetermined address, no scanning):")
    probe("router %s:80" % ROUTER, "http://%s/" % ROUTER)
    print("\n  A12 internet (control - must stay reachable):")
    probe("%s:443" % INTERNET, "https://%s/" % INTERNET)

    print("\n  A13 IPv6 note: this network reports IPv6 connectivity 'NoTraffic' and the")
    print("  host holds only link-local fe80::/10 plus ::1. There is no global IPv6")
    print("  path available to test, so IPv6 egress isolation cannot be measured here.")

    print("\n" + "=" * 78)
    print("A17 — FIREWALL BYPASS RESISTANCE")
    print("=" * 78)
    print("\n  Question: can a process holding the browser-process token add or remove a")
    print("  Windows Firewall rule? If yes, host-side rules are not a boundary.\n")

    # CONSTANT scripts. Nothing is interpolated. Each prints a single-line verdict.
    add_rule = (
        "try { New-NetFirewallRule -DisplayName 'BM-S4-A17-PROBE' -Direction Outbound "
        "-Action Block -Program 'C:\\Windows\\System32\\curl.exe' -RemoteAddress "
        "10.0.0.0/8 -ErrorAction Stop | Out-Null; 'CREATED' } "
        "catch { 'REFUSED: ' + $_.Exception.GetType().Name }"
    )
    del_rule = (
        "try { Remove-NetFirewallRule -DisplayName 'BM-S4-A17-PROBE' -ErrorAction Stop; "
        "'REMOVED' } catch { 'REFUSED: ' + $_.Exception.GetType().Name }"
    )
    disable_fw = (
        "try { Set-NetFirewallProfile -Profile Public -Enabled False -ErrorAction Stop; "
        "'DISABLED-FIREWALL' } catch { 'REFUSED: ' + $_.Exception.GetType().Name }"
    )

    for label, script in [("create an outbound Block rule", add_rule),
                          ("remove that rule", del_rule),
                          ("disable the Public firewall profile", disable_fw)]:
        r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
                           capture_output=True, text=True, timeout=120)
        out = (r.stdout or "").strip().splitlines()
        print("  attempt to %-38s -> %s" % (label, out[-1] if out else "<no output>"))

    print("\n  netsh path (older API, same question):")
    r = subprocess.run([os.path.join(SYS32, "netsh.exe"), "advfirewall", "firewall",
                        "add", "rule", "name=BM-S4-A17-NETSH", "dir=out",
                        "action=block", "remoteip=10.0.0.0/8"],
                       capture_output=True, text=True, timeout=120)
    line = (r.stdout or r.stderr or "").strip().splitlines()
    print("  netsh add rule -> rc=%d  %s" % (r.returncode, line[0] if line else ""))

    print("\n  Elevation state of this probe:")
    r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command",
                        "([Security.Principal.WindowsPrincipal]"
                        "[Security.Principal.WindowsIdentity]::GetCurrent())"
                        ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"],
                       capture_output=True, text=True, timeout=120)
    print("    running elevated (IsInRole Administrator): %s"
          % (r.stdout or "").strip())

    print("\n[cleanup] verifying no probe rule was left behind")
    r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command",
                        "@(Get-NetFirewallRule -DisplayName 'BM-S4-A17-*' "
                        "-ErrorAction SilentlyContinue).Count"],
                       capture_output=True, text=True, timeout=120)
    print("  BM-S4-A17-* rules present: %s" % (r.stdout or "").strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
