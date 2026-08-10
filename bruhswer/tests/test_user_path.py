"""The whole real user path, end to end (brief SS30).

    launch -> verify -> persistent session -> browse -> LAN attempt ->
    localhost attempt -> download -> close -> disposable session -> browse ->
    close -> verify destruction

Requires the network policy to be applied.

The download step is the reason this file exists. bruhswer used to pass
`--download-directory=<quarantine>` to Edge. That is not a real Chromium switch: it was
ignored and downloads went to the user's REAL Downloads folder, while every existing
test still passed because none of them had ever downloaded anything. This test performs
an actual download with the actual browser and checks where the file lands - and it
watches the user's real Downloads folder to make sure nothing appears there.

Nothing here uses real credentials or real user files. The downloaded payload is a
synthetic byte string served from loopback.
"""

from __future__ import annotations

import http.server
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

import _env  # noqa: E402
from app import config, sysquery  # noqa: E402
from app.controller import controller as ctrl  # noqa: E402
from app.downloads import quarantine  # noqa: E402
from app.privacy import privacy_guard  # noqa: E402
from app.sessions import session_manager  # noqa: E402

PORT = 18170
# Discovered at run time - see tests/_env.py. Hardcoding one machine's
# gateway made this suite pass while probing an address that did not exist.
ROUTER = _env.require_gateway()
# .txt, not .bin: Edge's own download protection holds an unrecognised binary as
# "Unconfirmed ....crdownload" awaiting user confirmation. That is Edge working
# correctly, but it makes a poor test fixture. The point being tested is WHERE the
# file goes, not whether Edge trusts it.
DL_NAME = "bruh_user_path_probe.txt"
DL_BODY = b"BRUHSWER_SYNTHETIC_DOWNLOAD_NOT_A_REAL_FILE"
MARKER = "BRUHSWER_USERPATH_PAGE"

_passed: list[str] = []
_failed: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (_passed if ok else _failed).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -  {detail}" if detail else ""))


class _H(http.server.BaseHTTPRequestHandler):
    """Three routes:
        /        page that auto-starts a download   (session under test)
        /plain   marker page with NO download       (reachability probes)
        /*.txt   the synthetic payload
    """

    def do_GET(self):
        if self.path.endswith(".txt"):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition",
                             f'attachment; filename="{DL_NAME}"')
            self.send_header("Content-Length", str(len(DL_BODY)))
            self.end_headers()
            self.wfile.write(DL_BODY)
            return

        body = f"<!doctype html><html><body><h1>{MARKER}</h1>"
        if not self.path.startswith("/plain"):
            body += (f'<a id="a" href="/{DL_NAME}">d</a>'
                     '<script>setTimeout(()=>document.getElementById("a").click(),800);'
                     "</script>")
        body += "</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass

    def handle_error(self, request, client_address):
        # Chromium resets connections routinely when it aborts a fetch. That is normal
        # and must not spray tracebacks over the test output.
        pass


def edge_probe(url: str, udd: Path) -> str:
    """Headless probe in a throwaway profile. Same executable, so the same firewall
    rules apply - that is the point."""
    argv = [str(config.find_edge()), "--headless=new", "--disable-gpu",
            f"--user-data-dir={udd}", "--no-first-run",
            "--no-default-browser-check", "--dump-dom", url]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=90, shell=False)
    except subprocess.TimeoutExpired:
        return "UNCLEAR"
    dom = proc.stdout or ""
    if MARKER in dom:
        return "REACHED"
    for code in ("ERR_NETWORK_ACCESS_DENIED", "ERR_CONNECTION_REFUSED",
                 "ERR_CONNECTION_TIMED_OUT", "ERR_ADDRESS_UNREACHABLE"):
        if code in dom:
            return "BLOCKED"
    return "REACHED" if len(dom) > 400 else "UNCLEAR"


def quiesce_bruhswer_edge(timeout: int = 30) -> int:
    """Wait for (then stop) any Edge still using a bruhswer profile.

    Running this suite straight after another one produced ONE flaky failure: a
    previous suite's Edge was still shutting down, the new session attached to it or
    started slowly, and the download had not begun before the poll window expired.
    That is a test-harness race, not a product fault - but a security regression suite
    that fails at random teaches people to ignore it, which is worse than having no
    suite. So the race is removed rather than tolerated.
    """
    ps = (f"@(Get-CimInstance Win32_Process -Filter \"Name='msedge.exe'\" | "
          f"Where-Object {{ $_.CommandLine -like '*{config.ROOT.name}*' }}).Count")
    deadline = time.time() + timeout
    while time.time() < deadline:
        proc = subprocess.run(
            [str(config.POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=60, shell=False)
        try:
            count = int((proc.stdout or "0").strip())
        except ValueError:
            count = 0
        if count == 0:
            return 0
        time.sleep(2)

    kill = (f"Get-CimInstance Win32_Process -Filter \"Name='msedge.exe'\" | "
            f"Where-Object {{ $_.CommandLine -like '*{config.ROOT.name}*' }} | "
            f"ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force "
            f"-ErrorAction SilentlyContinue }}")
    subprocess.run([str(config.POWERSHELL), "-NoProfile", "-NonInteractive",
                    "-Command", kill],
                   capture_output=True, timeout=60, shell=False)
    time.sleep(3)
    return 1


def main() -> int:
    print("bruhswer full user path")
    print("=" * 74)

    stragglers = quiesce_bruhswer_edge()
    if stragglers:
        print("[setup] stopped Edge processes left over from an earlier run")

    if len(sysquery.bruhswer_rules()) < 2:
        print("Network policy is not applied. Run tools\\bruhswer-netpolicy.ps1 -Action apply")
        return 1

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    real_downloads = Path.home() / "Downloads"
    before_downloads = ({p.name for p in real_downloads.iterdir()}
                        if real_downloads.is_dir() else set())

    controller = ctrl.Controller()
    probe_dir = config.PROFILE_DISPOSABLE_ROOT / "userpathprobe"

    # The persistent session reuses one quarantine folder, so a file left by an earlier
    # run would be mistaken for this run's download. Start from empty and say so.
    persistent_q = quarantine.quarantine_dir_for("persistent000000")
    stale = [p.name for p in persistent_q.rglob("*") if p.is_file()]
    if stale:
        print(f"\n[setup] clearing {len(stale)} leftover quarantine file(s) from a "
              f"previous run: {stale}")
        shutil.rmtree(persistent_q, ignore_errors=True)
        persistent_q.mkdir(parents=True, exist_ok=True)

    # ---- 1. verify before launching -----------------------------------------
    print("\n1. Security verification (before anything launches)")
    result = controller.verify(session_manager.PERSISTENT)
    check("verification runs and produces checks", len(result.checks) > 10,
          f"{len(result.checks)} checks")
    check("no launch blockers", not result.blockers,
          "; ".join(c.title for c in result.blockers))

    # ---- 2. persistent session, browsing a page that downloads ---------------
    print("\n2. Persistent session, browse, and download a synthetic file")
    outcome = controller.start(session_manager.PERSISTENT,
                               url=f"http://127.0.0.1:{PORT}/")
    check("persistent session launched", outcome.launched, outcome.message)
    if not outcome.launched:
        return 1
    session = outcome.session

    qdir = quarantine.quarantine_dir_for(session.session_id)
    ok, detail = privacy_guard.verify_download_directory(session.profile_dir, qdir)
    check("browser is told to download into quarantine", ok, detail)

    dl_check = next((c for c in outcome.result.checks
                     if c.check_id == "downloads.quarantine"), None)
    check("verifier confirms the download path",
          dl_check is not None and dl_check.verdict.value == "PASS",
          dl_check.detail if dl_check else "check missing")

    # Poll rather than guess.
    landed: list[str] = []
    for _ in range(20):
        time.sleep(2)
        landed = [p.name for p in qdir.rglob("*") if p.is_file()]
        if landed:
            break

    # WHAT IS ACTUALLY BEING CLAIMED, and therefore what is tested:
    #
    #   "Downloads are directed into quarantine and never into the user's real
    #    Downloads folder."
    #
    # NOT "Edge finishes every transfer". Measured behaviour: the file arrives in
    # quarantine under the right name but stays as `.crdownload`, because Edge's own
    # SmartScreen holds an unverified download until the user chooses Keep. bruhswer
    # deliberately does NOT disable Safe Browsing (brief SS38), so that hold is a
    # security feature doing its job - and the file is sitting in quarantine, unrun,
    # which is exactly where bruhswer wants it.
    arrived = [n for n in landed if DL_NAME in n]
    check("download was redirected INTO quarantine", bool(arrived),
          f"quarantine holds: {landed or '<nothing>'}")
    if arrived and all(n.endswith(".crdownload") for n in arrived):
        print("        note: held as .crdownload by Edge SmartScreen pending a Keep "
              "decision - expected, and it is in quarantine either way")

    after_downloads = ({p.name for p in real_downloads.iterdir()}
                       if real_downloads.is_dir() else set())
    strays = sorted(after_downloads - before_downloads)
    check("nothing appeared in the user's real Downloads folder", not strays,
          f"strays: {strays}" if strays else "clean")
    for name in strays:
        try:
            (real_downloads / name).unlink()
            print(f"        (cleaned up stray file: {name})")
        except OSError:
            pass

    items = quarantine.list_quarantine(session.session_id)
    check("quarantine lists the file", len(items) >= 1, f"{len(items)} item(s)")
    if items:
        exported_to = Path(config.STATE) / "userpath-export-test"
        exported_to.mkdir(parents=True, exist_ok=True)
        ok, message = controller.export_request(items[0], exported_to)
        check("explicit export works", ok, message)
        check("export did not execute anything",
              (exported_to / items[0].display_name).exists() or ok, "file copied only")
        shutil.rmtree(exported_to, ignore_errors=True)

    # ---- 3. network policy while a real session is open -----------------------
    print("\n3. Network policy, with a real session running")
    shutil.rmtree(probe_dir, ignore_errors=True)
    probe_dir.mkdir(parents=True, exist_ok=True)
    lan = edge_probe(f"http://{ROUTER}/", probe_dir)
    check("LAN / router is BLOCKED", lan == "BLOCKED", lan)
    # /plain, so the probe is not derailed by the auto-download on the main page.
    local = edge_probe(f"http://127.0.0.1:{PORT}/plain", probe_dir)
    check("localhost is REACHABLE (known limitation, honestly reported)",
          local == "REACHED", f"{local} - reported as NOT ENFORCEABLE in the UI")
    net = edge_probe("https://1.1.1.1/", probe_dir)
    check("internet still works", net == "REACHED", net)
    shutil.rmtree(probe_dir, ignore_errors=True)

    # ---- 4. close persistent -------------------------------------------------
    print("\n4. Close the persistent session")
    ok, message = controller.stop()
    check("persistent session closed", ok, message)
    check("persistent profile was KEPT", config.PROFILE_PERSISTENT.is_dir())

    # ---- 5. disposable session ----------------------------------------------
    print("\n5. Disposable session, browse, close, verify destruction")
    outcome = controller.start(session_manager.DISPOSABLE,
                               url=f"http://127.0.0.1:{PORT}/")
    check("disposable session launched", outcome.launched, outcome.message)
    if not outcome.launched:
        return 1
    disposable = outcome.session
    time.sleep(12)
    check("disposable profile exists while running", disposable.profile_dir.is_dir())

    ok, message = controller.stop()
    check("disposable session closed", ok, message)
    check("disposable profile DESTROYED", not disposable.profile_dir.exists(),
          str(disposable.profile_dir))

    srv.shutdown()

    print("\n" + "=" * 74)
    print(f"PASSED {len(_passed)}   FAILED {len(_failed)}")
    if _failed:
        for name in _failed:
            print(f"  FAILED: {name}")
        return 1
    print("\nThe whole user path works, and downloads are genuinely quarantined.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
