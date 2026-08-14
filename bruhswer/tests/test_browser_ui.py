"""The real user workflow, driven through the bruhswer application itself (brief SS33).

    launch -> verification -> browser opens -> address bar -> real site ->
    second tab -> security panel -> download -> quarantine -> real Downloads untouched
    -> disposable session -> close -> profile destroyed -> relaunch

Requires the network policy to be applied.

This drives the actual `BrowserWindow`, not a mock. It pumps the Tk event loop by hand
instead of calling mainloop() so the workflow can be asserted step by step.

The window-hosting assertion is the interesting one: it checks with the OS that Edge's
window really is a child of bruhswer's frame, rather than trusting that SetParent was
called. Same rule as everywhere else in this project - verify the actual state.
"""

from __future__ import annotations

import ctypes
import http.server
import shutil
import sys
import threading
import time
from ctypes import wintypes as wt
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from app import config, sysquery  # noqa: E402
from app.browser import embed, tokens, urls  # noqa: E402
from app.downloads import quarantine  # noqa: E402
from app.sessions import session_manager  # noqa: E402

PORT = 18180
DL_NAME = "bruh_ui_probe.txt"
DL_BODY = b"BRUHSWER_UI_SYNTHETIC_DOWNLOAD"
MARKER = "BRUHSWER_UI_PAGE"

_passed: list[str] = []
_failed: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (_passed if ok else _failed).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -  {detail}" if detail else ""))


class _BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wt.DWORD), ("biWidth", ctypes.c_long),
                ("biHeight", ctypes.c_long), ("biPlanes", wt.WORD),
                ("biBitCount", wt.WORD), ("biCompression", wt.DWORD),
                ("biSizeImage", wt.DWORD), ("biXPelsPerMeter", ctypes.c_long),
                ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", wt.DWORD),
                ("biClrImportant", wt.DWORD)]


class _BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", _BITMAPINFOHEADER), ("bmiColors", wt.DWORD * 3)]


def _distinct_colours(hwnd: int | None, step: int = 17) -> int | None:
    """Distinct colours sampled from a window's client area, or None if unreadable.

    PrintWindow with PW_RENDERFULLCONTENT asks the window to draw itself into our DC,
    so this reads what the window renders rather than what happens to be on top of it
    on screen. That matters: a plain screen grab would pass or fail depending on which
    window had focus when the suite ran.
    """
    if not hwnd:
        return None
    # ctypes.WinDLL(...) rather than ctypes.windll.X. Identical at runtime, but
    # `windll` is declared only for win32 in the type stubs, so every checker
    # reports it as an unresolved reference. The explicit form is also what the
    # rest of this codebase already uses (see app/browser/embed.py).
    gdi = ctypes.WinDLL("gdi32")
    rect = wt.RECT()
    embed.USER32.GetClientRect(wt.HWND(hwnd), ctypes.byref(rect))
    width, height = rect.right, rect.bottom
    if width < 50 or height < 50:
        return None

    src = embed.USER32.GetWindowDC(wt.HWND(hwnd))
    mem = gdi.CreateCompatibleDC(src)
    bmp = gdi.CreateCompatibleBitmap(src, width, height)
    previous = gdi.SelectObject(mem, bmp)
    printed = embed.USER32.PrintWindow(wt.HWND(hwnd), mem, 0x00000002)  # FULLCONTENT

    info = _BITMAPINFO()
    info.bmiHeader.biSize = ctypes.sizeof(_BITMAPINFOHEADER)
    info.bmiHeader.biWidth = width
    info.bmiHeader.biHeight = -height          # negative: top-down rows
    info.bmiHeader.biPlanes = 1
    info.bmiHeader.biBitCount = 32
    info.bmiHeader.biCompression = 0           # BI_RGB
    buf = ctypes.create_string_buffer(width * height * 4)
    # GetDIBits requires the bitmap NOT be selected into a DC. Leaving it selected
    # happens to work here, but when GDI does refuse it returns 0 and writes nothing -
    # and a zero-filled buffer looks exactly like a blank window, which would fail this
    # assertion for a browser that is painting perfectly.
    gdi.SelectObject(mem, previous)
    got = gdi.GetDIBits(mem, bmp, 0, height, buf, ctypes.byref(info), 0)

    raw = buf.raw
    seen = set()
    for y in range(0, height, step):
        row = y * width * 4
        for x in range(0, width, step):
            i = row + x * 4
            seen.add(raw[i:i + 3])

    gdi.DeleteObject(bmp)
    gdi.DeleteDC(mem)
    embed.USER32.ReleaseDC(wt.HWND(hwnd), src)
    # None means "could not read", which is NOT the same as "blank" and must never be
    # reported as a paint failure.
    if not printed or not got:
        return None
    return len(seen)


_hits: dict[str, int] = {"page": 0, "file": 0}


class _H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Server-side evidence. The window title is a poor signal - Edge overwrites it
        # with its own UI ("Restore pages", download bubbles), so a title check tests
        # Edge's chrome rather than whether the page was actually fetched.
        _hits["file" if self.path.endswith(".txt") else "page"] += 1
        if self.path.endswith(".txt"):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{DL_NAME}"')
            self.send_header("Content-Length", str(len(DL_BODY)))
            self.end_headers()
            self.wfile.write(DL_BODY)
            return
        body = f"<!doctype html><html><head><title>{MARKER}</title></head><body>" \
               f"<h1>{MARKER}</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass

    def handle_error(self, request, client_address):
        pass


def pump(win, seconds: float) -> None:
    """Run the Tk event loop for a while without blocking in mainloop()."""
    end = time.time() + seconds
    while time.time() < end:
        win.root.update()
        time.sleep(0.05)


def pump_until(win, predicate, timeout: float) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        win.root.update()
        if predicate():
            return True
        time.sleep(0.15)
    return False


def main() -> int:
    print("bruhswer browser UI - real user workflow")
    print("=" * 74)

    if len(sysquery.bruhswer_rules()) < 2:
        print("Network policy is not applied. Run tools\\bruhswer-netpolicy.ps1 -Action apply")
        return 1

    # --- URL handling is pure logic; check it before opening anything ------------
    print("\n0. Address bar input handling")
    for bad in ("file:///C:/Windows/win.ini", "javascript:alert(1)",
                r"\\attacker\share\x", "data:text/html,<script>", "C:\\Windows"):
        try:
            urls.normalise(bad)
            check(f"refuses {bad[:28]}", False, "was accepted")
        except urls.RefusedURL:
            check(f"refuses {bad[:28]}", True)
    check("bare domain becomes https",
          urls.normalise("example.com") == "https://example.com")
    check("a phrase becomes a search",
          urls.normalise("bruh what is a moai").startswith("https://"))
    check("full url passes through",
          urls.normalise("https://example.com/x") == "https://example.com/x")

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    real_downloads = Path.home() / "Downloads"
    before = ({p.name for p in real_downloads.iterdir()}
              if real_downloads.is_dir() else set())

    from app.ui.browser_window import BrowserWindow  # noqa: E402

    print("\n1. Launch bruhswer and verify")
    win = BrowserWindow()
    started = pump_until(win, lambda: win.result is not None, 90)
    check("security verification ran", started,
          f"{len(win.result.checks) if win.result else 0} checks")
    result = win.result
    check("no launch blockers", result is not None and not result.blockers)

    print("\n2. Browser window opens and is hosted inside bruhswer")
    hosted = pump_until(win, lambda: win.hosted_hwnd is not None, 90)
    check("edge window hosted", hosted, f"hwnd={win.hosted_hwnd}")
    if hosted:
        parent = embed.USER32.GetParent(win.hosted_hwnd)
        stage = win.stage.winfo_id()
        check("OS confirms it is a child of bruhswer's frame",
              int(parent) == int(stage), f"parent={parent} stage={stage}")
        check("session badge shows a session",
              "BRUH" in win.session_badge.cget("text"),
              win.session_badge.cget("text"))

        # THE HOSTED WINDOW ACTUALLY PAINTS.
        #
        # Everything above proves the window is PARENTED. None of it proves anything is
        # drawn in it. A completely blank grey stage - which was seen during development
        # - passed every other assertion in this project, so "the browser is hosted" was
        # never evidence that the user could see a page.
        #
        # Counts distinct colours sampled across the client area. A blank surface is one
        # or two; a rendered page is hundreds. Threshold is deliberately far below what
        # any real page produces, so it fails on "nothing rendered", not on "the page is
        # plain". Stdlib only - GDI through ctypes, no new dependency.
        colours = _distinct_colours(win.hosted_hwnd)
        check("the hosted window actually paints something",
              colours is not None and colours >= 8,
              f"{colours} distinct colours sampled (blank would be 1-2)"
              if colours is not None else
              "COULD NOT READ the surface - this is UNKNOWN, not proof of a blank "
              "window, but an unreadable check proves nothing and does not pass")

    print("\n2b. Renderer sandbox is MEASURED, not asserted")
    # This check used to be a hardcoded PASS quoting a measurement from one machine.
    # It must now come from the live renderer tokens, and must say UNKNOWN when there
    # is nothing running rather than inventing a green light.
    session = win.controller.session
    assert session is not None, "no session while measuring renderers"
    renderers = embed.renderer_pids_for_profile(session.profile_dir)
    # None means the QUERY failed; [] means it ran and found none. Those became
    # different return values so that a PowerShell hiccup could stop being reported as
    # "no browser session is running". `len(None)` would raise here, so the two are
    # separated before anything counts them.
    check("the renderer query itself succeeded", renderers is not None,
          "None = bruhswer could not ask Windows, which is not the same as zero")
    renderers = renderers or []
    check("renderer processes found to measure", len(renderers) > 0,
          f"{len(renderers)} renderer(s)")
    facts = tokens.summarise_renderers(renderers)
    check("their tokens were readable", facts["measured"] > 0, str(facts))
    check("every renderer runs at UNTRUSTED integrity",
          facts["measured"] > 0 and facts["untrusted"] == facts["measured"],
          f"{facts['untrusted']}/{facts['measured']} untrusted, "
          f"{facts['appcontainer']} in an AppContainer")

    result = win.controller.verify()
    sandbox = next((c for c in result.checks if c.check_id == "browser.sandbox"), None)
    check("verifier reports the measured result",
          sandbox is not None and sandbox.verdict.value == "PASS",
          sandbox.detail[:80] if sandbox else "check missing")

    print("\n3. Address bar navigation to a real page")
    _hits["page"] = 0
    win.clear_placeholder()
    win.address.delete(0, "end")
    win.address.insert(0, f"http://127.0.0.1:{PORT}/")
    win.on_navigate()
    fetched = pump_until(win, lambda: _hits["page"] > 0, 60)
    check("navigated and the browser actually fetched the page", fetched,
          f"server saw {_hits['page']} request(s)")

    print("\n4. Second tab")
    win.on_new_tab()
    pump(win, 8)
    check("new tab opened without a new window",
          win.hosted_hwnd is not None and embed.is_alive(win.hosted_hwnd))

    print("\n5. Security panel opens and reflects real state")
    win.open_security_panel()
    pump(win, 3)
    check("BRUH panel opened", len(win.root.winfo_children()) > 0)
    check("localhost light is amber, never green",
          win.lights["LOCALHOST"].cget("fg") == config.WARN_AMBER)
    check("VPN light is off, never green",
          win.lights["VPN"].cget("fg") == config.OFF_GREY)
    for extra in win.root.winfo_children():
        if isinstance(extra, type(win.root)) or extra.winfo_class() == "Toplevel":
            extra.destroy()

    print("\n6. Download goes to quarantine, not the real Downloads folder")
    dl_session = win.controller.session
    assert dl_session is not None, "no session while checking downloads"
    session_id = dl_session.session_id
    qdir = quarantine.quarantine_dir_for(session_id)
    for stale in qdir.rglob("*"):
        if stale.is_file():
            stale.unlink()
    win.address.delete(0, "end")
    win.address.insert(0, f"http://127.0.0.1:{PORT}/{DL_NAME}")
    win.on_navigate()
    landed = pump_until(win, lambda: any(DL_NAME in p.name for p in qdir.rglob("*")
                                         if p.is_file()), 60)
    names = [p.name for p in qdir.rglob("*") if p.is_file()]
    check("download landed in quarantine", landed, f"{names or '<nothing>'}")
    after = ({p.name for p in real_downloads.iterdir()}
             if real_downloads.is_dir() else set())
    strays = sorted(after - before)
    check("real Downloads folder untouched", not strays, f"strays: {strays}")
    for name in strays:
        try:
            (real_downloads / name).unlink()
        except OSError:
            pass

    print("\n7. Disposable session")
    win.open_session(session_manager.DISPOSABLE)
    disp_ok = pump_until(win, lambda: win.controller.session is not None
                         and win.controller.session.is_disposable, 90)
    check("disposable session started", disp_ok)
    disposable = win.controller.session
    check("badge says DISPOSABLE",
          "DISPOSABLE" in win.session_badge.cget("text"),
          win.session_badge.cget("text"))
    pump_until(win, lambda: win.hosted_hwnd is not None, 90)
    pump(win, 6)

    print("\n8. Close the session and verify destruction")
    win.close_session()
    pump(win, 6)
    check("disposable profile destroyed",
          disposable is not None and not disposable.profile_dir.exists(),
          str(disposable.profile_dir) if disposable else "")

    print("\n9. Close bruhswer and relaunch")
    win.on_close()
    time.sleep(3)
    win2 = BrowserWindow()
    ok2 = pump_until(win2, lambda: win2.result is not None, 90)
    result2 = win2.result
    check("relaunch verifies cleanly",
          ok2 and result2 is not None and not result2.blockers)
    hosted2 = pump_until(win2, lambda: win2.hosted_hwnd is not None, 90)
    check("relaunch opens a browser again", hosted2)
    win2.on_close()
    time.sleep(2)

    srv.shutdown()
    shutil.rmtree(config.PROFILE_DISPOSABLE_ROOT / "preview", ignore_errors=True)

    print("\n" + "=" * 74)
    print(f"PASSED {len(_passed)}   FAILED {len(_failed)}")
    if _failed:
        for name in _failed:
            print(f"  FAILED: {name}")
        return 1
    print("\nWE GOOD  -  the whole workflow works inside bruhswer itself.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
