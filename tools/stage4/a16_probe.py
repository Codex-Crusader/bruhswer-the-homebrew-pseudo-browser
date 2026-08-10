"""Stage 4 gate A16 — probe half. Runs UNELEVATED, which is how the browser really runs.

Invoked three times: before the rules exist, while they are active, and after they are
removed. A block is only attributable to a rule if the sequence is
REACHED -> BLOCKED -> REACHED.

Probe is `msedge.exe --headless=new --dump-dom <url>`. Exit code is NOT a signal - Edge
returns 0 even when it renders an error page - so the verdict comes from the DOM:
a unique marker for success, a Chromium ERR_* error page for failure.

curl.exe is probed alongside as a scope control: the rules name msedge.exe only, so
curl must stay unaffected in every phase. If curl ever changes, the rule was not
program-scoped and the result is void.

Unelevated. Creates and deletes its own listeners and profile directories. No firewall
changes of any kind.
"""

import http.server
import os
import shutil
import subprocess
import sys
import threading

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
CURL = os.path.join(os.environ["SystemRoot"], "System32", "curl.exe")

HOST_IP = "10.0.0.50"
ROUTER = "10.0.0.1"
P_LOOPBACK = 18080
P_HOSTIP = 18081
MARKER = "BM_S4_A16_MARKER_7d2c"
DATA_ROOT = os.path.join(os.environ["LOCALAPPDATA"], "BrowserMaker", "S4A16p")

ERR_CODES = ("ERR_NETWORK_ACCESS_DENIED", "ERR_CONNECTION_REFUSED",
             "ERR_CONNECTION_TIMED_OUT", "ERR_ADDRESS_UNREACHABLE",
             "ERR_CONNECTION_RESET", "ERR_NAME_NOT_RESOLVED",
             "ERR_CONNECTION_FAILED", "ERR_EMPTY_RESPONSE",
             "ERR_BLOCKED_BY_CLIENT", "ERR_ACCESS_DENIED")


class _H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(("<html><body>%s</body></html>" % MARKER).encode())

    def log_message(self, *a):
        pass


def edge_probe(url, udd, timeout=70):
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
    for code in ERR_CODES:
        if code in dom:
            return "BLOCKED", code
    if len(dom) > 400:
        return "REACHED", "content returned (%d bytes)" % len(dom)
    return "UNCLEAR", "dom %d bytes" % len(dom)


def curl_probe(url):
    r = subprocess.run([CURL, "-s", "-m", "6", "-o", os.devnull, url],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    return "REACHED" if r.returncode == 0 else "blocked (curl exit %d)" % r.returncode


TARGETS = [
    ("loopback    127.0.0.1:%d" % P_LOOPBACK, "http://127.0.0.1:%d/" % P_LOOPBACK),
    ("host-own-ip %s:%d" % (HOST_IP, P_HOSTIP), "http://%s:%d/" % (HOST_IP, P_HOSTIP)),
    ("REMOTE LAN  router %s" % ROUTER, "http://%s/" % ROUTER),
    ("internet    1.1.1.1", "https://1.1.1.1/"),
]


def main():
    phase = sys.argv[1] if len(sys.argv) > 1 else "PHASE"
    srv1 = http.server.HTTPServer(("127.0.0.1", P_LOOPBACK), _H)
    srv2 = http.server.HTTPServer((HOST_IP, P_HOSTIP), _H)
    for s in (srv1, srv2):
        threading.Thread(target=s.serve_forever, daemon=True).start()

    udd = os.path.join(DATA_ROOT, phase)
    shutil.rmtree(udd, ignore_errors=True)
    os.makedirs(udd, exist_ok=True)

    print("=" * 74)
    print("A16 PROBE — phase: %s   (unelevated)" % phase)
    print("=" * 74)
    for label, url in TARGETS:
        v, d = edge_probe(url, udd)
        print("  EDGE  %-30s %-8s %s" % (label, v, d))
    print("  curl  %-30s %-8s (scope control: must never change)"
          % ("router %s" % ROUTER, curl_probe("http://%s/" % ROUTER)))
    print("  curl  %-30s %-8s (scope control: must never change)"
          % ("internet 1.1.1.1", curl_probe("https://1.1.1.1/")))

    for s in (srv1, srv2):
        s.shutdown()
    shutil.rmtree(udd, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
