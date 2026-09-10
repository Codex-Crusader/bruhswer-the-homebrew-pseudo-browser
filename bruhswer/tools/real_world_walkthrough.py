"""Drive the REAL bruhswer GUI and report what actually happened.

Not a unit test: it builds the real BrowserWindow, lets Tk run, and pokes what a person
would poke. Nothing here asserts - it reports, so a surprise is visible rather than
swallowed.
"""
from __future__ import annotations

import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import tkinter as tk  # noqa: E402

from app import config  # noqa: E402
from app.browser import embed  # noqa: E402
from app.downloads import quarantine  # noqa: E402
from app.sessions import session_manager  # noqa: E402
from app.ui.browser_window import BrowserWindow  # noqa: E402

HOST_TIMEOUT_S = 22.0
PANEL_TIMEOUT_S = 20.0
REVERIFY_TIMEOUT_S = 40.0

# The confirmation dialog, identified by title so nothing else can be driven in its
# place. See drive_cancel.
DIALOG_TITLE = f"{config.MOAI} bruhswer"

log: list[str] = []


def say(step: str, ok: bool, detail: str = "") -> None:
    log.append(f"  [{'OK  ' if ok else 'BAD '}] {step}"
               + (f"  -  {detail}" if detail else ""))
    print(log[-1], flush=True)


def toplevels(win) -> list[tk.Toplevel]:
    return [c for c in win.root.winfo_children() if isinstance(c, tk.Toplevel)]


def pump_until(win, seconds: float, ready) -> bool:
    """Run Tk until `ready()` or the deadline. True if it became ready."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        win.root.update()
        if ready():
            return True
        time.sleep(0.1)
    return ready()


def wait_for_host(win) -> bool:
    return pump_until(win, HOST_TIMEOUT_S, lambda: win.hosted_hwnd is not None)


def open_panel(win, opener, timeout: float = PANEL_TIMEOUT_S) -> bool:
    """Open one panel, wait for its window, then close it again.

    open_security_panel runs a 5.5s verification off the Tk thread first, so the old
    look-once check could never pass - and the panel that arrived afterwards was left
    parented to root, where drive_cancel destroyed it INSTEAD of the dialog and hung
    the run at step 14. Steps 6 and 27 both did this; 27 reported True regardless.
    """
    before = {str(c) for c in toplevels(win)}
    opener()
    appeared = pump_until(
        win, timeout, lambda: bool({str(c) for c in toplevels(win)} - before))
    for child in toplevels(win):
        child.destroy()
    win.root.update()
    return appeared


def main() -> int:
    print("bruhswer real-world GUI walkthrough (§36)")
    print("=" * 74, flush=True)

    win = BrowserWindow()
    say("1. window constructed", win.root is not None)

    wait_for_host(win)

    result = win.result
    say("2. security verification ran", result is not None,
        f"{len(result.checks)} checks" if result else "no result")
    say("3. launch not blocked", result is not None and not result.blockers,
        f"blockers={[c.title for c in result.blockers]}" if result else "")
    say("4. session open", win.controller.session is not None,
        win.controller.session.mode if win.controller.session else "none")
    say("5. Edge hosted inside the frame", win.hosted_hwnd is not None,
        f"hwnd={win.hosted_hwnd}")

    # ---- panels -------------------------------------------------------------
    for step, opener in (("6. BRUH check panel", win.open_security_panel),
                         ("7. network panel", win.open_network_panel),
                         ("8. privacy panel", win.open_privacy_panel),
                         ("9. host guard panel", win.open_host_panel),
                         ("10. quarantine panel", win.open_quarantine_panel)):
        try:
            say(step, open_panel(win, opener))
        # broad-except: a harness reports failures, it does not die on them
        except Exception:  # lint: allow broad-except
            say(step, False, traceback.format_exc().strip().splitlines()[-1])

    # ---- navigation ---------------------------------------------------------
    try:
        win.address.delete(0, "end")
        # protected-access: drives the real window's internals on purpose
        win._placeholder = False  # lint: allow protected-access
        win.address.insert(0, "example.com")
        win.on_navigate()
        win.root.update()
        say("11. address bar navigation", True, win.status_text.cget("text")[:60])
    # broad-except: a harness reports failures, it does not die on them
    except Exception:  # lint: allow broad-except
        say("11. address bar navigation", False,
            traceback.format_exc().strip().splitlines()[-1])

    # ---- the disposable-download confirmation dialog -------------------------
    try:
        win.open_session(session_manager.DISPOSABLE)
        wait_for_host(win)
        session = win.controller.session
        assert session is not None, "no session after opening one"
        say("12. disposable session open", session.is_disposable, session.session_id)

        qdir = quarantine.quarantine_dir_for(session.session_id)
        planted = qdir / "walkthrough-download.txt"
        planted.write_text("pretend download", encoding="utf-8")
        pending = session_manager.pending_quarantine(session)
        say("13. quarantine has a file to warn about", len(pending) == 1,
            f"{[p.name for p in pending]}")

        # Destroying the dialog is equivalent to its Keep-open button. Matched BY
        # TITLE: any other Toplevel still on screen is not the dialog, and destroying
        # one in its place leaves the modal wait blocked forever.
        def drive_cancel():
            for child in toplevels(win):
                if child.title() == DIALOG_TITLE:
                    child.destroy()
                    return
            win.root.after(200, drive_cancel)

        win.root.after(600, drive_cancel)
        # protected-access: drives the real window's internals on purpose.
        returned = win._confirm_disposable_downloads()  # lint: allow protected-access
        win.root.update()
        say("14. dialog opened and CANCEL returned False (session kept)",
            returned is False, f"returned {returned!r}")
        say("15. window still responsive after the modal dialog",
            win.root.winfo_exists() == 1)
        say("16. download still present after cancelling", planted.is_file())

        win.controller.stop()
        win.root.update()
        say("17. disposable profile destroyed", not session.profile_dir.exists(),
            str(session.profile_dir))
        say("18. its quarantine destroyed with it", not qdir.exists(), str(qdir))
    # broad-except: a harness reports failures, it does not die on them
    except Exception:  # lint: allow broad-except
        say("12-18. disposable flow", False,
            traceback.format_exc().strip().splitlines()[-1])

    # ---- threads, Win32 registrations and widgets no unit suite can reach -----
    try:
        win.open_session(session_manager.PERSISTENT)
        wait_for_host(win)

        # A green PANIC light over an unregistered hotkey is a promise bruhswer
        # cannot keep, so the indicator is checked against the registration.
        # protected-access: drives the real window's internals on purpose
        armed = win._panic_hotkey.available  # lint: allow protected-access
        hint = win.panic_hint.cget("text")
        say("20. panic key registered", armed,
            win._panic_hotkey.status_text)  # lint: allow protected-access
        say("21. panic indicator agrees with reality",
            (armed and hint == config.PANIC_HOTKEY_LABEL)
            or (not armed and hint == "UNAVAILABLE"),
            f"armed={armed} hint={hint!r}")

        say("22. re-verification worker alive",
            win._verifier._thread is not None  # lint: allow protected-access
            and win._verifier._thread.is_alive())  # lint: allow protected-access
        say("23. drain callback scheduled",
            win._drain_job is not None)  # lint: allow protected-access

        # The whole feature: the lights must stop being a launch-time snapshot, so a
        # SECOND pass has to land from the worker and reach the widgets.
        live = win.controller.session
        assert live is not None, "no session to re-verify"
        win._verifier.submit(  # lint: allow protected-access
            win.controller.verification_request(live.mode))
        first = win.result
        applied = pump_until(win, REVERIFY_TIMEOUT_S,
                             lambda: win.result is not None and win.result is not first)
        say("24. a worker verification reached the UI", applied,
            f"{len(win.result.checks)} checks" if win.result else "none")

        ids = {c.check_id for c in (win.result.checks if win.result else [])}
        say("25. integrity check present", "controller.integrity" in ids)
        say("26. ipv6 effect check present", "net.rule.ipv6.effect" in ids)

        for name, opener in (("BRUH", win.open_security_panel),
                             ("network", win.open_network_panel),
                             ("privacy", win.open_privacy_panel),
                             ("host", win.open_host_panel),
                             ("quarantine", win.open_quarantine_panel)):
            try:
                say(f"27.{name} panel renders with the new checks",
                    open_panel(win, opener))
            # broad-except: a harness reports failures, it does not die on them
            except Exception:  # lint: allow broad-except
                say(f"27.{name} panel renders with the new checks", False,
                    traceback.format_exc().strip().splitlines()[-1])

        # Both directions: shown when an account is attached, hidden when not.
        account = [c for c in win.result.checks
                   if c.check_id == "privacy.account"] if win.result else []
        shown = bool(win.account_banner.winfo_ismapped())
        expected = bool(account) and account[0].verdict.value == "FAIL"
        say("28. account banner matches the measurement", shown == expected,
            f"shown={shown} verdict="
            f"{account[0].verdict if account else 'none'}")

        # The panic path on a real session. It terminates Edge, so it goes last.
        session = win.controller.session
        profile = session.profile_dir if session else None
        # protected-access: drives the real window's internals on purpose
        win._on_panic()  # lint: allow protected-access
        win.root.update()
        say("29. panic stopped the session", win.controller.session is None,
            win.status_text.cget("text")[:70])
        say("30. window survived the panic", win.root.winfo_exists() == 1)
        if profile is not None:
            time.sleep(1.0)
            remaining = embed.attributed_edge_processes(profile)
            say("31. no attributed browser process left",
                remaining is not None and len(remaining) == 0,
                f"remaining={remaining}")
        say("32. panic released the hotkey",
            not win._panic_hotkey.available)  # lint: allow protected-access

        # close_session() used to release the hotkey and leave the PANIC dot green
        # with the hint still reading Ctrl+Shift+End.
        win.open_session(session_manager.PERSISTENT)
        wait_for_host(win)
        # protected-access: drives the real window's internals on purpose
        armed_before = win._panic_hotkey.available  # lint: allow protected-access
        win.close_session()
        win.root.update()
        say("32b. panic indicator honest after close_session",
            # protected-access: drives the real window's internals on purpose
            (not win._panic_hotkey.available)  # lint: allow protected-access
            and win.panic_hint.cget("text") == "UNAVAILABLE",
            f"armed_before={armed_before} "
            # protected-access: drives the real window's internals on purpose
            f"after={win._panic_hotkey.available} "  # lint: allow protected-access
            # protected-access: drives the real window's internals on purpose
            f"hint={win.panic_hint.cget('text')!r}")  # lint: allow protected-access
    # broad-except: a harness reports failures, it does not die on them
    except Exception:  # lint: allow broad-except
        say("20-32. hardening-pass surfaces", False,
            traceback.format_exc().strip().splitlines()[-1])

    # ---- shutdown -----------------------------------------------------------
    try:
        win.root.destroy()
        say("33. clean shutdown", True)
    # broad-except: a harness reports failures, it does not die on them
    except Exception:  # lint: allow broad-except
        say("33. clean shutdown", False,
            traceback.format_exc().strip().splitlines()[-1])

    print("\n" + "=" * 74)
    bad = [line for line in log if line.startswith("  [BAD")]
    print(f"{len(log) - len(bad)} OK, {len(bad)} problems")
    for line in bad:
        print(line)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
