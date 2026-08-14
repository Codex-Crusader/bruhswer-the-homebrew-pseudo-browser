"""Run the whole bruhswer regression suite in order, and report one verdict.

    python tests/run_all.py

Brief SS29: "A future change must not be allowed to silently weaken an existing
control." This is the gate that enforces that. It runs the suites in dependency order
and exits non-zero if any of them fails.

Suites that need the network policy applied say so and are reported as SKIPPED rather
than silently passing - a suite that quietly does nothing is worse than one that fails.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))

from app import config, sysquery  # noqa: E402

SUITES = [
    ("unit / static analysis", "test_security.py", False),
    # Both of these are pure and need no network policy and no browser, so they run
    # early: a URL-normalisation or overclaim regression should fail the suite in
    # milliseconds rather than after the multi-minute browser suites.
    ("address bar properties", "test_urls_fuzz.py", False),
    ("overclaim regressions", "test_overclaim_regressions.py", False),
    ("runtime re-verification", "test_reverification.py", False),
    ("disposable overwrite", "test_disposable_overwrite.py", False),
    ("file manifest", "test_integrity.py", False),
    ("panic key / account settings", "test_panic_and_account.py", False),
    ("persistent profile", "test_persistent_profile.py", False),
    ("end-to-end session", "test_end_to_end.py", True),
    ("network regression (SS12/SS13)", "test_network_regression.py", True),
    ("localhost attack surface", "test_localhost_surface.py", True),
    ("full user path (SS30)", "test_user_path.py", True),
    ("browser UI workflow (SS33)", "test_browser_ui.py", True),
]


def main() -> int:
    # Same reason as bruhswer.py's _use_utf8_stdio: under CI, and under any plain
    # redirection, stdout is a pipe and Python falls back to the legacy ANSI codepage.
    # The suite used to die on its own banner before running a single test.
    for stream in (sys.stdout, sys.stderr):
        # getattr rather than a direct call: `reconfigure` exists on TextIOWrapper
        # but not on every TextIO a stream can be, so a direct call is an unresolved
        # reference to every static checker. The behaviour is identical - the old
        # code caught AttributeError for exactly this case.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass

    print(f"{config.MOAI} bruhswer regression suite")
    print("=" * 74)

    policy_applied = len(sysquery.bruhswer_rules()) >= 2
    if not policy_applied:
        print("\nNetwork policy is NOT applied - suites that need it will be SKIPPED.")
        print("Apply it with: tools\\bruhswer-netpolicy.ps1 -Action apply\n")

    rows: list[tuple[str, str, float]] = []
    failures = 0
    skipped = 0

    for label, script, needs_policy in SUITES:
        if needs_policy and not policy_applied:
            rows.append((label, "SKIPPED", 0.0))
            skipped += 1
            continue

        print(f"\n>>> {label}")
        start = time.perf_counter()
        # The child's own stdout is a pipe too, so it picks the legacy ANSI codepage
        # exactly as this script did. Reading the pipe back as UTF-8 while the child
        # writes cp1252 would mangle any non-ASCII a suite reports - so tell the child
        # what encoding to use rather than guessing at the far end.
        child_env = dict(os.environ, PYTHONIOENCODING="utf-8")
        proc = subprocess.run([sys.executable, str(_HERE / script)],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", shell=False, env=child_env)
        elapsed = time.perf_counter() - start

        # BOTH streams, for the same reason the failure scan below already reads both:
        # `unittest` writes "Ran N tests" and "OK" to STDERR, while the older
        # hand-rolled suites print "PASSED n FAILED n" to stdout. Scanning stdout only
        # meant every unittest-based suite reported a blank line under its name - it
        # passed, and the run showed no evidence that it had. This project's own rule
        # is to take counts from the run output, so a runner that prints no counts
        # quietly defeats it.
        combined = ((proc.stdout or "") + "\n" + (proc.stderr or "")).splitlines()
        summary = [ln for ln in combined
                   if "PASSED" in ln or ln.startswith("Ran ") or ln.startswith("OK")]
        for line in summary[-2:]:
            print(f"    {line.strip()}")

        if proc.returncode == 0:
            rows.append((label, "PASS", elapsed))
        else:
            rows.append((label, "FAIL", elapsed))
            failures += 1
            # BOTH streams. test_security.py runs unittest, which writes "FAIL: test_x"
            # and its summary to STDERR, so a stdout-only scan concluded a perfectly
            # ordinary assertion failure had "crashed" - replacing one misleading
            # report with a different one.
            reported = 0
            for line in ((proc.stdout or "") + "\n" + (proc.stderr or "")).splitlines():
                stripped = line.strip()
                if (stripped.startswith(("FAILED:", "FAIL:", "FAILED ("))
                        or "[FAIL]" in stripped):
                    print(f"    {stripped}")
                    reported += 1

            # A suite that CRASHES fails without ever printing an assertion, and its
            # traceback goes to stderr - which was captured and then thrown away, so
            # the operator saw "FAIL" and nothing else. That happened, and the only
            # way to learn anything was to re-run the suite by hand, by which point it
            # passed. Evidence that exists must not be discarded.
            if not reported:
                tail = [ln for ln in (proc.stderr or "").splitlines() if ln.strip()]
                print(f"    no assertion failed - suite exited {proc.returncode}, "
                      f"so it crashed. Last stderr:")
                for line in (tail[-12:] or ["    <stderr was empty too>"]):
                    print(f"      {line.strip()[:160]}")

    print("\n" + "=" * 74)
    for label, verdict, elapsed in rows:
        print(f"  {verdict:<8} {label:<36} {elapsed:6.1f}s")

    print("=" * 74)
    if failures:
        print(f"REGRESSION FAILED - {failures} suite(s) failed. Do not ship.")
        return 1
    if skipped:
        print(f"All run suites passed, but {skipped} were SKIPPED. That is not a "
              f"full pass.")
        return 2
    print("WE GOOD  -  every suite passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
