"""Feasibility check: can headless Edge act as a network probe for gate A16?

A16 needs to know whether a -Program scoped firewall rule blocks THE BROWSER (not a
stand-in like curl.exe) from reaching loopback, the host's own IP, the LAN and the
internet. Detecting that server-side only works for listeners we control; it cannot
tell us whether the browser still reached the internet.

`msedge.exe --headless=new --dump-dom <url>` prints the resolved DOM and exits, which
gives a clean success/failure signal for ANY url. Same executable, so a -Program rule
applies identically. This script checks the probe works before an elevated run is spent
on it.

Unelevated. No firewall changes. One local listener, torn down at the end.
"""

import http.server
import os
import subprocess
import sys
import threading

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
PORT = 18090
MARKER = "BM_S4_HEADLESS_MARKER_4a91"


class _H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(("<html><body>%s</body></html>" % MARKER).encode())

    def log_message(self, *a):
        pass


def probe(url, udd, timeout=45):
    args = [EDGE, "--headless=new", "--disable-gpu", "--user-data-dir=%s" % udd,
            "--no-first-run", "--no-default-browser-check", "--dump-dom", url]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "TIMEOUT", ""
    return "rc=%d" % r.returncode, (r.stdout or "")[:400]


def main():
    srv = http.server.HTTPServer(("127.0.0.1", PORT), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    udd = os.path.join(os.environ["LOCALAPPDATA"], "BrowserMaker", "S4Headless")
    os.makedirs(udd, exist_ok=True)

    print("Headless Edge probe feasibility check\n" + "=" * 60)

    for label, url in [("local listener", "http://127.0.0.1:%d/" % PORT),
                       ("internet 1.1.1.1", "https://1.1.1.1/"),
                       ("closed port (negative control)", "http://127.0.0.1:18099/")]:
        rc, out = probe(url, udd)
        hit = MARKER in out
        body = out.replace("\n", " ")[:110]
        print("\n  %-32s %s" % (label, rc))
        print("     marker present : %s" % hit)
        print("     dom head       : %s" % body)

    import shutil
    shutil.rmtree(udd, ignore_errors=True)
    print("\nIf 'local listener' shows the marker and the closed port does not, headless")
    print("Edge is a usable A16 probe with a reliable positive AND negative signal.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
