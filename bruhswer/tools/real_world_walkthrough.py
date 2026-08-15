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
from app.browser import embed  # noqa: E402
from app.downloads import quarantine  # noqa: E402
from app.sessions import session_manager  # noqa: E402
from app.ui.browser_window import BrowserWindow  # noqa: E402

log: list[str] = []


def say(step: str, ok: bool, detail: str = "") -> None:
    log.append(f"  [{'OK  ' if ok else 'BAD '}] {step}"
               + (f"  -  {detail}" if detail else ""))
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
        assert session is not None, "no session after opening one"
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
        dialog_outcome: dict[str, bool | None] = {"returned": None}

        def drive_cancel():
            # Find the modal Toplevel the dialog created and click "Keep open".
            for child in win.root.winfo_children():
                if isinstance(child, tk.Toplevel):
                    child.destroy()          # equivalent to the Keep-open button
                    return
            win.root.after(200, drive_cancel)

        win.root.after(600, drive_cancel)
        # protected-access: drives the real window's internals on purpose.
        dialog_outcome["returned"] = (
            win._confirm_disposable_downloads())  # lint: allow protected-access
        win.root.update()
        say("14. dialog opened and CANCEL returned False (session kept)",
            dialog_outcome["returned"] is False,
            f"returned {dialog_outcome['returned']!r}")
        say("15. window still responsive after the modal dialog",
            win.root.winfo_exists() == 1)
        say("16. download still present after cancelling", planted.is_file())

        # Now actually close the session, accepting the destruction.
        win.controller.stop()
        win.root.update()
        say("17. disposable profile destroyed", not session.profile_dir.exists(),
            str(session.profile_dir))
        say("18. its quarantine destroyed with it", not qdir.exists(), str(qdir))
    # broad-except: a harness reports failures, it does not die on them
    except Exception:  # lint: allow broad-except
        say("12-18. disposable flow", False,
            traceback.format_exc().strip().splitlines()[-1])

    # ---- surfaces added in the hardening pass --------------------------------
    # None of these existed when this script was written, and none of them is
    # reachable from the unit suites: they are threads, Win32 registrations and
    # widgets that only exist once a real window is up.
    try:
        win.open_session(session_manager.PERSISTENT)
        for _ in range(120):
            win.root.update()
            import time
            time.sleep(0.1)
            if win.hosted_hwnd:
                break

        # 20. The panic key. Its INDICATOR must match reality - a green PANIC light
        # over an unregistered hotkey is a promise bruhswer cannot keep.
        # protected-access: drives the real window's internals on purpose
        armed = win._panic_hotkey.available  # lint: allow protected-access
        hint = win.panic_hint.cget("text")
        say("20. panic key registered", armed,
            win._panic_hotkey.status_text)  # lint: allow protected-access
        say("21. panic indicator agrees with reality",
            (armed and hint == config.PANIC_HOTKEY_LABEL)
            or (not armed and hint == "UNAVAILABLE"),
            f"armed={armed} hint={hint!r}")

        # 22. Re-verification is actually running, not just constructed.
        say("22. re-verification worker alive",
            win._verifier._thread is not None  # lint: allow protected-access
            and win._verifier._thread.is_alive())  # lint: allow protected-access
        say("23. drain callback scheduled",
            win._drain_job is not None)  # lint: allow protected-access

        # 24. Wait for a SECOND verification pass to land from the worker and be
        # applied to the widgets. This is the whole feature: the lights must stop
        # being a launch-time snapshot.
        live = win.controller.session
        assert live is not None, "no session to re-verify"
        win._verifier.submit(  # lint: allow protected-access
            win.controller.verification_request(live.mode))
        applied = False
        import time
        deadline = time.time() + 40
        first = win.result
        while time.time() < deadline:
            win.root.update()
            time.sleep(0.1)
            if win.result is not None and win.result is not first:
                applied = True
                break
        say("24. a worker verification reached the UI", applied,
            f"{len(win.result.checks)} checks" if win.result else "none")

        # 25. The new checks must be VISIBLE, not just present in the result.
        ids = {c.check_id for c in (win.result.checks if win.result else [])}
        say("25. integrity check present", "controller.integrity" in ids)
        say("26. ipv6 effect check present", "net.rule.ipv6.effect" in ids)

        # 27. Every panel must still render with the new checks in the result.
        for name, opener in (("BRUH", win.open_security_panel),
                             ("network", win.open_network_panel),
                             ("privacy", win.open_privacy_panel),
                             ("host", win.open_host_panel),
                             ("quarantine", win.open_quarantine_panel)):
            try:
                opener()
                win.root.update()
                for child in win.root.winfo_children():
                    if isinstance(child, tk.Toplevel):
                        child.destroy()
                win.root.update()
                say(f"27.{name} panel renders with the new checks", True)
            # broad-except: a harness reports failures, it does not die on them
            except Exception:  # lint: allow broad-except
                say(f"27.{name} panel renders with the new checks", False,
                    traceback.format_exc().strip().splitlines()[-1])

        # 28. The account banner must agree with the measured verdict, in both
        # directions - shown when an account is attached, hidden when not.
        account = [c for c in win.result.checks
                   if c.check_id == "privacy.account"] if win.result else []
        shown = bool(win.account_banner.winfo_ismapped())
        expected = bool(account) and account[0].verdict.value == "FAIL"
        say("28. account banner matches the measurement", shown == expected,
            f"shown={shown} verdict="
            f"{account[0].verdict if account else 'none'}")

        # 29. THE PANIC PATH ITSELF, on a real session with a real hosted browser.
        # This terminates Edge, so it is deliberately the last thing done.
        session = win.controller.session
        profile = session.profile_dir if session else None
        # protected-access: drives the real window's internals on purpose
        win._on_panic()  # lint: allow protected-access
        win.root.update()
        say("29. panic stopped the session", win.controller.session is None,
            win.status_text.cget("text")[:70])
        say("30. window survived the panic", win.root.winfo_exists() == 1)
        if profile is not None:
            import time
            time.sleep(1.0)
            remaining = embed.attributed_edge_processes(profile)
            say("31. no attributed browser process left",
                remaining is not None and len(remaining) == 0,
                f"remaining={remaining}")
        say("32. panic released the hotkey",
            not win._panic_hotkey.available)  # lint: allow protected-access

        # 32b. THE INDICATOR MUST FOLLOW THE HOTKEY, on every path that releases it.
        # close_session() used to stop the listener and leave the PANIC dot green with
        # the hint still reading Ctrl+Shift+End - a light promising an escape hatch
        # that had already been unregistered.
        win.open_session(session_manager.PERSISTENT)
        for _ in range(120):
            win.root.update()
            import time
            time.sleep(0.1)
            if win.hosted_hwnd:
                break
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
