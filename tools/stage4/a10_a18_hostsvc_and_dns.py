"""Stage 4 — completes A10 with real host services, and measures A18/A19 (secure DNS).

PART 1 (A10, A14, A15): the host-exposure audit found SMB (445) and RPC (135) listening
on the wildcard address, and A16 measured that no host-side control can stop the browser
reaching 127.0.0.1 or the host's own IP 10.0.0.50. That combination is exactly the
failure Stage 2 measured on WSL2 (gates G3/G8), so it must be tested directly rather
than inferred.

Test is a bare TCP connect, immediately closed. No SMB or RPC protocol exchange, no
authentication attempt, no NTLM. Establishing reachability is the whole point; going
further would be unnecessary and intrusive.

PART 2 (A18/A19): the audit also found NextDNS listening on 127.0.0.1:65008, so the DNS
path on this machine is NOT the plain configuration the earlier survey suggested. What
the browser actually does must be measured, not assumed. Cloudflare's
https://1.1.1.1/help is a diagnostic endpoint that reports whether the querying client
reached it over DNS-over-HTTPS; headless Edge renders it and the DOM is inspected.

Unelevated. No host changes. No firewall changes.
"""

import os
import re
import shutil
import socket
import subprocess
import sys

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
HOST_IP = "10.0.0.50"
DATA_ROOT = os.path.join(os.environ["LOCALAPPDATA"], "BrowserMaker", "S4Dns")

TCP_TARGETS = [
    ("loopback SMB", "127.0.0.1", 445),
    ("host-own-IP SMB", HOST_IP, 445),
    ("loopback RPC endpoint mapper", "127.0.0.1", 135),
    ("host-own-IP RPC endpoint mapper", HOST_IP, 135),
    ("host-own-IP NetBIOS session", HOST_IP, 139),
    ("loopback PyCharm service", "127.0.0.1", 63342),
    ("loopback NextDNS", "127.0.0.1", 65008),
]


def tcp_connect(ip, port, timeout=4.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return "CONNECTED"
    except socket.timeout:
        return "timeout"
    except OSError as e:
        return "refused/failed (errno %s)" % getattr(e, "errno", "?")
    finally:
        s.close()


def edge_dump(url, udd, timeout=90):
    args = [EDGE, "--headless=new", "--disable-gpu", "--user-data-dir=%s" % udd,
            "--no-first-run", "--no-default-browser-check", "--dump-dom", url]
    try:
        r = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return ""
    return r.stdout or ""


def main():
    print("=" * 74)
    print("PART 1 — A10/A14/A15: can the browser-process token reach host services?")
    print("=" * 74)
    print("Bare TCP connect, closed immediately. No protocol exchange, no auth.\n")
    for label, ip, port in TCP_TARGETS:
        print("  %-34s %s:%-6d %s" % (label, ip, port, tcp_connect(ip, port)))

    print("\n  Reminder from A16: no host-side control in this architecture can block")
    print("  127.0.0.1 or %s for the browser. Anything CONNECTED above is" % HOST_IP)
    print("  reachable by a compromised browser process with no available mitigation.")

    print("\n" + "=" * 74)
    print("PART 2 — A18/A19: is the browser's DNS encrypted?")
    print("=" * 74)
    udd = os.path.join(DATA_ROOT, "doh")
    shutil.rmtree(udd, ignore_errors=True)
    os.makedirs(udd, exist_ok=True)

    dom = edge_dump("https://1.1.1.1/help", udd)
    print("  cloudflare diagnostic DOM: %d bytes" % len(dom))
    if not dom:
        print("  UNKNOWN - no DOM returned; no DNS claim can be made.")
    else:
        for key in ("Using DNS over HTTPS (DoH)", "Using DNS over TLS (DoT)",
                    "Connected to 1.1.1.1", "Using Warp", "AS Name", "Your IP"):
            m = re.search(re.escape(key) + r"\s*(?:</[^>]+>\s*)*[:\-]?\s*"
                          r"(?:<[^>]+>\s*)*([A-Za-z0-9 .()\-]{0,40})", dom)
            if m:
                val = " ".join(m.group(1).split())
                if key == "Your IP":
                    val = "<redacted - public IP not recorded>"
                print("    %-28s %s" % (key, val or "<empty>"))
        low = dom.lower()
        print("\n    raw indicator scan:")
        for token in ("doh</span>", "\"doh\"", "dns over https", "dot</span>"):
            print("      %-20s present=%s" % (token, token in low))

    shutil.rmtree(DATA_ROOT, ignore_errors=True)
    print("\n  Note: this measures the BROWSER's resolver path only. Per brief §29 it")
    print("  says nothing about anonymity - destination IPs, timing and volume remain")
    print("  visible to the local network regardless of DNS encryption.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
