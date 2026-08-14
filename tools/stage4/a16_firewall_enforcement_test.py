"""Stage 4 gate A16 — does a -Program scoped firewall rule actually stop THE BROWSER?

REQUIRES ELEVATION. Refuses to run otherwise.

WHY IT MATTERS
--------------
A2 measured that this project cannot wrap a Chromium browser in an AppContainer.
Stage 2.5's two-layer network design depended on AppContainer for exactly one thing:
blocking loopback and the host's own IP, because Windows Firewall is documented not to
filter loopback. Losing AppContainer means that layer is gone, and the open question is
whether the firewall alone can cover it.

A17 already measured that the browser cannot edit these rules. This gate measures
whether the rules DO anything to the browser in the first place.

PROBE
-----
`msedge.exe --headless=new --dump-dom <url>`, verified usable beforehand: the DOM
contains a unique marker on success and a Chromium error page (ERR_*) on failure. Same
executable as the browser, so the -Program rule applies identically. Exit code is NOT a
signal - Edge returns 0 even when it renders an error page - so the verdict is taken
from the DOM.

BEFORE / DURING / AFTER, exactly as Stage 2.5 gate B16, because that sequence is what
makes a block attributable to the rule and to nothing else.

HOST CHANGES
------------
Creates three outbound Block rules named BM-S4-A16-*, scoped by -Program to the Edge
executable, and removes all of them in a finally block, then verifies zero remain.
Nothing else is modified: no firewall profile changes, no Defender/SmartScreen/CFA
changes, no services, no persistence, no registry security changes.
"""

import ctypes
import http.server
import os
import shutil
import subprocess
import sys
import threading

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
SYS32 = os.path.join(os.environ["SystemRoot"], "System32")
POWERSHELL = os.path.join(SYS32, "WindowsPowerShell", "v1.0", "powershell.exe")
CURL = os.path.join(SYS32, "curl.exe")

HOST_IP = "10.0.0.50"
ROUTER = "10.0.0.1"
P_LOOPBACK = 18080
P_HOSTIP = 18081
MARKER = "BM_S4_A16_MARKER_7d2c"

DATA_ROOT = os.path.join(os.environ["LOCALAPPDATA"], "BrowserMaker", "S4A16")
PREFIX = "BM-S4-A16"

# Rule definitions. Every value is a literal authored here; nothing is derived from
# input, the browser, or the network.
RULES = [
    ("%s-edge-deny-loopback" % PREFIX, "127.0.0.1"),
    ("%s-edge-deny-hostip" % PREFIX, HOST_IP),
    ("%s-edge-deny-rfc1918" % PREFIX,
     "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16"),
]


class _H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(("<html><body>%s</body></html>" % MARKER).encode())

    def log_message(self, *a):
        pass


def ps(script):
    r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=180)
    return (r.stdout or "").strip()


def edge_probe(url, udd, timeout=60):
    """Returns (verdict, detail). Verdict is REACHED / BLOCKED / UNCLEAR."""
    args = [EDGE, "--headless=new", "--disable-gpu", "--user-data-dir=%s" % udd,
            "--no-first-run", "--no-default-browser-check", "--dump-dom", url]
    try:
        r = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return "UNCLEAR", "probe timed out"
    dom = r.stdout or ""
    if MARKER in dom:
        return "REACHED", "marker present"
    for code in ("ERR_NETWORK_ACCESS_DENIED", "ERR_CONNECTION_REFUSED",
                 "ERR_CONNECTION_TIMED_OUT", "ERR_ADDRESS_UNREACHABLE",
                 "ERR_CONNECTION_RESET", "ERR_NAME_NOT_RESOLVED",
                 "ERR_CONNECTION_FAILED", "ERR_EMPTY_RESPONSE"):
        if code in dom:
            return "BLOCKED", code
    if "<title>" in dom and len(dom) > 200:
        return "REACHED", "content returned (%d bytes, no marker expected)" % len(dom)
    return "UNCLEAR", "dom %d bytes" % len(dom)


def curl_probe(url):
    r = subprocess.run([CURL, "-s", "-m", "6", "-o", os.devnull, url],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    return "REACHED" if r.returncode == 0 else "blocked (curl exit %d)" % r.returncode


TARGETS = [
    ("loopback   127.0.0.1:%d" % P_LOOPBACK, "http://127.0.0.1:%d/" % P_LOOPBACK),
    ("host-own-ip %s:%d" % (HOST_IP, P_HOSTIP), "http://%s:%d/" % (HOST_IP, P_HOSTIP)),
    ("REMOTE LAN router %s" % ROUTER, "http://%s/" % ROUTER),
    ("internet   1.1.1.1", "https://1.1.1.1/"),
]


def phase(name, tag):
    print("\n--- %s ---" % name)
    udd = os.path.join(DATA_ROOT, tag)
    shutil.rmtree(udd, ignore_errors=True)
    os.makedirs(udd, exist_ok=True)
    for label, url in TARGETS:
        v, d = edge_probe(url, udd)
        print("  EDGE  %-30s %-8s %s" % (label, v, d))
    # curl is NOT covered by the -Program rule; it shows the rule is scoped to the
    # browser and did not become a machine-wide block.
    print("  curl  %-30s %s  (control: must be unaffected)"
          % ("router %s" % ROUTER, curl_probe("http://%s/" % ROUTER)))
    shutil.rmtree(udd, ignore_errors=True)


class _Tee:
    """Elevated processes open their own console, so the transcript is also written to
    a file the unelevated session can read back."""

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


def main():
    if len(sys.argv) > 1:
        sys.stdout = _Tee(sys.argv[1])

    # ctypes.WinDLL(...) rather than ctypes.windll.X. Identical at runtime, but
    # `windll` is declared only for win32 in the type stubs, so every checker
    # reports it as an unresolved reference. The explicit form is also what the
    # rest of this codebase already uses (see app/browser/embed.py).
    if not ctypes.WinDLL("shell32").IsUserAnAdmin():
        print("REFUSING TO RUN: this script requires elevation.")
        return 2

    print("Stage 4 A16 — host-side firewall enforcement against the browser")
    print("=" * 78)
    pre = ps("@(Get-NetFirewallRule -DisplayName '%s-*' "
             "-ErrorAction SilentlyContinue).Count" % PREFIX)
    print("pre-existing %s-* rules: %s   (must be 0)" % (PREFIX, pre))
    if pre.strip() not in ("0", ""):
        print("ABORT: rules with this prefix already exist; refusing to touch them.")
        return 3

    os.makedirs(DATA_ROOT, exist_ok=True)
    srv1 = http.server.HTTPServer(("127.0.0.1", P_LOOPBACK), _H)
    srv2 = http.server.HTTPServer((HOST_IP, P_HOSTIP), _H)
    for s in (srv1, srv2):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    print("listeners up on 127.0.0.1:%d and %s:%d" % (P_LOOPBACK, HOST_IP, P_HOSTIP))

    try:
        phase("BASELINE — no rules", "before")

        print("\n--- creating %d rules ---" % len(RULES))
        for name, addr in RULES:
            out = ps("try { New-NetFirewallRule -DisplayName '%s' -Direction Outbound "
                     "-Action Block -Program '%s' -RemoteAddress %s -Profile Any "
                     "-Enabled True -ErrorAction Stop | Out-Null; 'created' } "
                     "catch { 'FAILED: ' + $_.Exception.Message }"
                     % (name, EDGE, addr))
            print("  %-34s %s" % (name, out))
        print("\n  readback:")
        print(ps("Get-NetFirewallRule -DisplayName '%s-*' | ForEach-Object { "
                 "$a=$_ | Get-NetFirewallAddressFilter; "
                 "$p=$_ | Get-NetFirewallApplicationFilter; "
                 "'{0,-34} enabled={1} action={2} remote={3} program={4}' -f "
                 "$_.DisplayName,$_.Enabled,$_.Action,"
                 "($a.RemoteAddress -join ','),$p.Program }" % PREFIX))

        phase("WITH RULES ACTIVE", "during")
    finally:
        print("\n--- cleanup: removing all %s-* rules ---" % PREFIX)
        print(ps("Get-NetFirewallRule -DisplayName '%s-*' -ErrorAction "
                 "SilentlyContinue | Remove-NetFirewallRule; 'removed'" % PREFIX))
        left = ps("@(Get-NetFirewallRule -DisplayName '%s-*' "
                  "-ErrorAction SilentlyContinue).Count" % PREFIX)
        print("  %s-* rules remaining: %s   (must be 0)" % (PREFIX, left))

    phase("AFTER CLEANUP — rules removed", "after")
    shutil.rmtree(DATA_ROOT, ignore_errors=True)
    print("\n[cleanup] data root removed: %s" % (not os.path.exists(DATA_ROOT)))
    print("\nA rule-attributable block requires: REACHED before, BLOCKED during,")
    print("REACHED after. Anything else is not attributable to the rule.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
