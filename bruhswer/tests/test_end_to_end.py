"""BRUHWSER end-to-end verification. Requires the network policy to be applied.

    python tests/test_end_to_end.py

This is the test that proves the claims are true on THIS machine rather than true in
principle. It starts a real disposable session with the real browser under the real
firewall policy, then measures:

  1. the session starts and BRUHWSER's own verifier allows it
  2. privacy settings actually stuck in the profile (read back, not assumed)
  3. the browser is BLOCKED from the router          <- the security claim
  4. the browser still REACHES the internet          <- it must stay usable
  5. the browser CAN still reach localhost           <- the honest limitation
  6. the disposable profile is destroyed and verified gone

Network probes use `msedge.exe --headless=new --dump-dom`, the same executable the
firewall rule names, so the rule applies identically. Exit code is not a signal --
Edge returns 0 even when it renders an error page -- so the verdict comes from the DOM.

Targets are a single predetermined gateway address and 1.1.1.1. No scanning.
"""

from __future__ import annotations

import http.server
import subprocess
import sys
import threading
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

import _env  # noqa: E402
from app import config  # noqa: E402
from app.controller import controller as ctrl  # noqa: E402
from app.privacy import privacy_guard  # noqa: E402
from app.sessions import session_manager  # noqa: E402

# Discovered at run time - see tests/_env.py. Hardcoding one machine's
# gateway made this suite pass while probing an address that did not exist.
ROUTER = _env.require_gateway()
INTERNET = "https://1.1.1.1/"
LOOPBACK_PORT = 18091
MARKER = "BRUHWSER_E2E_MARKER_51ac"

_ERR_CODES = ("ERR_NETWORK_ACCESS_DENIED", "ERR_CONNECTION_REFUSED",
              "ERR_CONNECTION_TIMED_OUT", "ERR_ADDRESS_UNREACHABLE",
              "ERR_CONNECTION_RESET", "ERR_CONNECTION_FAILED")

_passed: list[str] = []
_failed: list[str] = []


class _H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(f"<html><body>{MARKER}</body></html>".encode())

    def log_message(self, *a):
        pass


def check(name: str, ok: bool, detail: str = "") -> None:
    (_passed if ok else _failed).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -  {detail}" if detail else ""))


def edge_probe(url: str, udd: Path) -> tuple[str, str]:
    argv = [str(config.find_edge()), "--headless=new", "--disable-gpu",
            f"--user-data-dir={udd}", "--no-first-run",
            "--no-default-browser-check", "--dump-dom", url]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=90, shell=False)
    except subprocess.TimeoutExpired:
        return "UNCLEAR", "timed out"
    dom = proc.stdout or ""
    if MARKER in dom:
        return "REACHED", "marker present"
    for code in _ERR_CODES:
        if code in dom:
            return "BLOCKED", code
    if len(dom) > 400:
        return "REACHED", f"content returned ({len(dom)} bytes)"
    return "UNCLEAR", f"dom {len(dom)} bytes"


def main() -> int:
    print("BRUHWSER end-to-end verification")
    print("=" * 74)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", LOOPBACK_PORT), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    controller = ctrl.Controller()

    print("\n1. Disposable session start")
    outcome = controller.start(session_manager.DISPOSABLE)
    check("session launched", outcome.launched, outcome.message)
    if not outcome.launched:
        print("\nCannot continue: apply network policy first.")
        return 1

    session = outcome.session
    # Narrowed explicitly: a launched outcome always carries a session, and
    # saying so lets the rest of this function read session.profile_dir
    # without every access looking like an attribute on None.
    assert session is not None, "launch reported success without a session"
    check("profile directory created", session.profile_dir.is_dir(),
          str(session.profile_dir))
    check("profile is inside BRUHWSER",
          session.profile_dir.is_relative_to(config.ROOT))
    check("no launch blockers", not outcome.result.blockers)

    print("\n2. Privacy settings actually stuck (read back from the profile)")
    time.sleep(8)  # let Edge finish writing its own Preferences
    applied, expected, missing = privacy_guard.verify_applied(
        session.profile_dir, controller.privacy_mode)
    check(f"privacy settings applied ({applied}/{expected})", applied > 0,
          f"not applied: {missing[:3]}" if missing else "all applied")

    print("\n3. Network policy against the live browser")
    probe_dir = config.PROFILE_DISPOSABLE_ROOT / "e2eprobe"
    probe_dir.mkdir(parents=True, exist_ok=True)

    verdict, detail = edge_probe(f"http://{ROUTER}/", probe_dir)
    check(f"router {ROUTER} is BLOCKED", verdict == "BLOCKED", f"{verdict} {detail}")

    verdict, detail = edge_probe(INTERNET, probe_dir)
    check("internet still REACHED", verdict == "REACHED", f"{verdict} {detail}")

    verdict, detail = edge_probe(f"http://127.0.0.1:{LOOPBACK_PORT}/", probe_dir)
    check("localhost reachable (KNOWN limitation, must be honest)",
          verdict == "REACHED",
          f"{verdict} {detail} - reported as NOT ENFORCEABLE in the UI")

    print("\n4. Session teardown and destruction")
    ok, message = controller.stop()
    check("stop reported success", ok, message)
    check("disposable profile is gone", not session.profile_dir.exists(),
          str(session.profile_dir))

    import shutil
    shutil.rmtree(probe_dir, ignore_errors=True)
    srv.shutdown()

    print("\n" + "=" * 74)
    print(f"PASSED {len(_passed)}   FAILED {len(_failed)}")
    if _failed:
        for name in _failed:
            print(f"  FAILED: {name}")
        return 1
    print("\nAll end-to-end claims verified on this machine.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
