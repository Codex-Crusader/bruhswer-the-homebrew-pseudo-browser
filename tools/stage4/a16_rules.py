"""Stage 4 gate A16 — rule management half. REQUIRES ELEVATION.

Split from the probe half deliberately. The first attempt ran both in one elevated
process and every Edge probe returned an empty DOM *including the baseline*, so the
probe was broken rather than the firewall. Chromium does not behave normally when
launched from an elevated parent.

Splitting also models reality: firewall policy is administrator-owned (gate A17
measured that the browser cannot change it), while the browser itself runs unelevated.

Usage:  a16_rules.py create|remove|status <logfile>

Creates or removes exactly three outbound Block rules named BM-S4-A16-*, scoped by
-Program to the Edge executable. Touches nothing else: no firewall profile changes, no
Defender/SmartScreen/CFA changes, no services, no persistence.
"""

import ctypes
import os
import subprocess
import sys

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
POWERSHELL = os.path.join(os.environ["SystemRoot"], "System32",
                          "WindowsPowerShell", "v1.0", "powershell.exe")
HOST_IP = "10.0.0.50"
PREFIX = "BM-S4-A16"

RULES = [
    ("%s-edge-deny-loopback" % PREFIX, "127.0.0.1"),
    ("%s-edge-deny-hostip" % PREFIX, HOST_IP),
    ("%s-edge-deny-rfc1918" % PREFIX,
     "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16"),
]

READBACK = (
    "Get-NetFirewallRule -DisplayName '%s-*' -ErrorAction SilentlyContinue | "
    "ForEach-Object { $a=$_ | Get-NetFirewallAddressFilter; "
    "$p=$_ | Get-NetFirewallApplicationFilter; "
    "'{0,-34} enabled={1} action={2} remote={3} program={4}' -f "
    "$_.DisplayName,$_.Enabled,$_.Action,($a.RemoteAddress -join ','),$p.Program }"
    % PREFIX
)
COUNT = ("@(Get-NetFirewallRule -DisplayName '%s-*' "
         "-ErrorAction SilentlyContinue).Count" % PREFIX)


class _Tee:
    def __init__(self, path):
        self.f = open(path, "w", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, s):
        self.stdout.write(s)
        self.f.write(s)
        self.f.flush()

    def flush(self):
        self.stdout.flush()
        self.f.flush()


def ps(script):
    r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=180)
    return (r.stdout or "").strip()


def main():
    if len(sys.argv) < 2:
        print("usage: a16_rules.py create|remove|status [logfile]")
        return 1
    action = sys.argv[1]
    if len(sys.argv) > 2:
        sys.stdout = _Tee(sys.argv[2])

    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("REFUSING TO RUN: requires elevation.")
        return 2

    print("A16 rule management — action=%s" % action)
    print("=" * 78)

    if action == "create":
        n = ps(COUNT)
        print("pre-existing %s-* rules: %s   (must be 0)" % (PREFIX, n))
        if n.strip() not in ("0", ""):
            print("ABORT: rules with this prefix already exist; refusing to touch them.")
            return 3
        for name, addr in RULES:
            out = ps("try { New-NetFirewallRule -DisplayName '%s' -Direction Outbound "
                     "-Action Block -Program '%s' -RemoteAddress %s -Profile Any "
                     "-Enabled True -ErrorAction Stop | Out-Null; 'created' } "
                     "catch { 'FAILED: ' + $_.Exception.Message }" % (name, EDGE, addr))
            print("  %-34s %s" % (name, out))
        print("\nreadback:")
        print(ps(READBACK))
        print("\n*** RULES ARE NOW ACTIVE. Run a16_rules.py remove to revert. ***")

    elif action == "remove":
        print(ps("Get-NetFirewallRule -DisplayName '%s-*' -ErrorAction "
                 "SilentlyContinue | Remove-NetFirewallRule; 'removed'" % PREFIX))
        print("%s-* rules remaining: %s   (must be 0)" % (PREFIX, ps(COUNT)))

    elif action == "status":
        print("%s-* rules present: %s" % (PREFIX, ps(COUNT)))
        print(ps(READBACK))
    else:
        print("unknown action")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
