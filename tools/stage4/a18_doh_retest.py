"""Stage 4 gates A18/A19 — secure DNS, retested correctly.

The first attempt dumped the Cloudflare diagnostic DOM while it still read
"AS Name: Checking...", i.e. before its asynchronous probes had finished. The "No"
values it showed could therefore have been placeholder defaults rather than results,
and reporting them would have been inventing a measurement.

`--virtual-time-budget` makes headless Chromium fast-forward timers and wait for
pending work before the DOM is dumped, which is the documented way to capture a
settled page. This run also checks the OS-level DNS configuration, because the host
audit found NextDNS listening on 127.0.0.1:65008 - so the resolver path on this
machine is not the plain DHCP configuration the earlier survey implied.

Unelevated. Read-only. No host changes, no DNS configuration changes.
"""

import os
import re
import shutil
import subprocess
import sys

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
DATA_ROOT = os.path.join(os.environ["LOCALAPPDATA"], "BrowserMaker", "S4Doh")
POWERSHELL = os.path.join(os.environ["SystemRoot"], "System32",
                          "WindowsPowerShell", "v1.0", "powershell.exe")


def edge_dump(url, udd, budget_ms=20000, timeout=150):
    args = [EDGE, "--headless=new", "--disable-gpu", "--user-data-dir=%s" % udd,
            "--no-first-run", "--no-default-browser-check",
            "--virtual-time-budget=%d" % budget_ms, "--dump-dom", url]
    try:
        r = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return ""
    return r.stdout or ""


def field(dom, label):
    """Cloudflare renders these as adjacent table/spans; take the next short value."""
    m = re.search(re.escape(label) + r"(?:\s*|<[^>]*>)*([A-Za-z0-9 .()\-]{1,40})", dom)
    return " ".join(m.group(1).split()) if m else None


def ps(script):
    r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=120)
    return (r.stdout or "").strip()


def main():
    print("=" * 74)
    print("A18/A19 — OS-level DNS configuration")
    print("=" * 74)
    print("\nWindows DoH server table (Get-DnsClientDohServerAddress):")
    print(ps("$d = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue; "
             "if ($d) { $d | ForEach-Object { '  {0,-24} auto={1} template={2}' -f "
             "$_.ServerAddress, $_.AllowFallbackToUdp, $_.DohTemplate } } "
             "else { '  <none configured>' }"))
    print("\nPer-interface encryption state (netsh dns show encryption):")
    out = ps("netsh dns show encryption")
    for ln in out.splitlines():
        if ln.strip():
            print("  " + ln.rstrip())
    print("\nEffective DNS servers on the active interface:")
    print(ps("Get-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' | ForEach-Object { "
             "'  family={0} servers={1}' -f $_.AddressFamily, "
             "($_.ServerAddresses -join ', ') }"))
    print("\nNextDNS presence (found listening on 127.0.0.1:65008 in the host audit):")
    print(ps("$p = Get-Process -Name 'NextDNS*' -ErrorAction SilentlyContinue; "
             "if ($p) { $p | ForEach-Object { '  process={0} pid={1} path={2}' -f "
             "$_.ProcessName, $_.Id, $_.Path } } else { '  <not running>' }"))

    print("\n" + "=" * 74)
    print("A18/A19 — what the BROWSER actually does, page allowed to settle")
    print("=" * 74)
    udd = os.path.join(DATA_ROOT, "doh")
    shutil.rmtree(udd, ignore_errors=True)
    os.makedirs(udd, exist_ok=True)

    dom = edge_dump("https://1.1.1.1/help", udd)
    print("\n  DOM: %d bytes" % len(dom))
    settled = "Checking" not in dom
    print("  page settled (no 'Checking...' placeholders): %s" % settled)
    if not settled:
        print("  *** STILL UNSETTLED — no DNS verdict may be taken from this run. ***")
    for label in ("Using DNS over HTTPS (DoH)", "Using DNS over TLS (DoT)",
                  "Connected to 1.1.1.1", "Using Warp", "AS Name"):
        print("    %-28s %s" % (label, field(dom, label)))

    shutil.rmtree(DATA_ROOT, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
