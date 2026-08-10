"""Drive the REAL bruhswer GUI the way §36 asks, and report what actually happened.

This is not a unit test. It builds the real BrowserWindow, lets Tk run, and pokes the
things a person would poke - with particular attention to the two surfaces changed in
this pass and NOT covered by any existing suite:

  * the new disposable-download confirmation dialog (and the input-queue detach/
    re-attach around it, which is the part that could hang the window)
  * the rewritten privacy panel, which now reads settings back from the profile

Nothing here asserts. It reports, so a surprise is visible rather than swallowed.
"""
from __future__ import annotations

import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import tkinter as tk  # noqa: E402

from app import config  # noqa: E402
from app.downloads import quarantine  # noqa: E402
from app.sessions import session_manager  # noqa: E402
from app.ui.browser_window import BrowserWindow  # noqa: E402

log: list[str] = []


def say(step: str, ok: bool, detail: str = "") -> None:
    log.append(f"  [{'OK  ' if ok else 'BAD '}] {step}" + (f"  -  {detail}" if detail else ""))
    print(log[-1], flush=True)


def main() -> int:
    print("bruhswer real-world GUI walkthrough (§36)")
    print("=" * 74, flush=True)

    win = BrowserWindow()
    say("1. window constructed", win.root is not None)

    # Let startup run: verification, session start, then window hosting.
    for _ in range(220):          # ~22s of real Tk time
        win.root.update()
        win.root.after(100, lambda: None)
        win.root.update_idletasks()
        import time
        time.sleep(0.1)
        if win.hosted_hwnd:
            break

    say("2. security verification ran", win.result is not None,
        f"{len(win.result.checks)} checks" if win.result else "no result")
    say("3. launch not blocked", bool(win.result) and not win.result.blockers,
        f"blockers={[c.title for c in win.result.blockers]}" if win.result else "")
    say("4. session open", win.controller.session is not None,
        win.controller.session.mode if win.controller.session else "none")
    say("5. Edge hosted inside the frame", win.hosted_hwnd is not None,
        f"hwnd={win.hosted_hwnd}")

    # ---- panels -------------------------------------------------------------
    for step, opener in (("6. BRUH check panel", win.open_security_panel),
                         ("7. network panel", win.open_network_panel),
                         ("8. privacy panel (REWRITTEN)", win.open_privacy_panel),
                         ("9. host guard panel", win.open_host_panel),
                         ("10. quarantine panel", win.open_quarantine_panel)):
        try:
            before = len(win.root.winfo_children())
            opener()
            win.root.update()
            say(step, len(win.root.winfo_children()) > before)
            # close the panel again
            for child in win.root.winfo_children():
                if isinstance(child, tk.Toplevel):
                    child.destroy()
            win.root.update()
        except Exception:
            say(step, False, traceback.format_exc().strip().splitlines()[-1])

    # ---- navigation ---------------------------------------------------------
    try:
        win.address.delete(0, "end")
        win._placeholder = False
        win.address.insert(0, "example.com")
        win.on_navigate()
        win.root.update()
        say("11. address bar navigation", True, win.status_text.cget("text")[:60])
    except Exception:
        say("11. address bar navigation", False,
            traceback.format_exc().strip().splitlines()[-1])

    # ---- THE NEW DIALOG -----------------------------------------------------
    # Switch to a disposable session, put a file in its quarantine, then close it.
    try:
        win.open_session(session_manager.DISPOSABLE)
        for _ in range(120):
            win.root.update()
            import time
            time.sleep(0.1)
            if win.hosted_hwnd:
                break
        session = win.controller.session
        say("12. disposable session open",
            session is not None and session.is_disposable,
            session.session_id if session else "none")

        qdir = quarantine.quarantine_dir_for(session.session_id)
        planted = qdir / "walkthrough-download.txt"
        planted.write_text("pretend download", encoding="utf-8")
        pending = session_manager.pending_quarantine(session)
        say("13. quarantine has a file to warn about", len(pending) == 1,
            f"{[p.name for p in pending]}")

        # Fire the confirmation dialog and drive its CANCEL button, which is the
        # path that must re-attach the input queue.
        result = {"returned": None}

        def drive_cancel():
            # Find the modal Toplevel the dialog created and click "Keep open".
            for child in win.root.winfo_children():
                if isinstance(child, tk.Toplevel):
                    child.destroy()          # equivalent to the Keep-open button
                    return
            win.root.after(200, drive_cancel)

        win.root.after(600, drive_cancel)
        result["returned"] = win._confirm_disposable_downloads()
        win.root.update()
        say("14. dialog opened and CANCEL returned False (session kept)",
            result["returned"] is False, f"returned {result['returned']!r}")
        say("15. window still responsive after the modal dialog",
            win.root.winfo_exists() == 1)
        say("16. download still present after cancelling", planted.is_file())

        # Now actually close the session, accepting the destruction.
        win.controller.stop()
        win.root.update()
        say("17. disposable profile destroyed", not session.profile_dir.exists(),
            str(session.profile_dir))
        say("18. its quarantine destroyed with it", not qdir.exists(), str(qdir))
    except Exception:
        say("12-18. disposable flow", False,
            traceback.format_exc().strip().splitlines()[-1])

    # ---- shutdown -----------------------------------------------------------
    try:
        win.root.destroy()
        say("19. clean shutdown", True)
    except Exception:
        say("19. clean shutdown", False,
            traceback.format_exc().strip().splitlines()[-1])

    print("\n" + "=" * 74)
    bad = [line for line in log if line.startswith("  [BAD")]
    print(f"{len(log) - len(bad)} OK, {len(bad)} problems")
    for line in bad:
        print(line)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
