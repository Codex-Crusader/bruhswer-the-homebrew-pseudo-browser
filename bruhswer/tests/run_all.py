"""Run the whole bruhswer regression suite in order, and report one verdict.

    python tests/run_all.py

Runs the suites in order and exits non-zero if any fails. Suites that need the network
policy are reported SKIPPED without it, never passed.
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
    # Fast pure suites first, so a regression fails in milliseconds.
    ("address bar properties", "test_urls_fuzz.py", False),
    ("overclaim regressions", "test_overclaim_regressions.py", False),
    ("evidence model", "test_evidence_model.py", False),
    ("accessibility / contrast", "test_accessibility.py", False),
    ("window surface after split", "test_window_surface.py", False),
    ("session races / stale UI", "test_session_races.py", False),
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
    # As in bruhswer.py: a piped stdout falls back to the ANSI codepage.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass

    print(f"{config.MOAI} bruhswer regression suite")
    print("=" * 74)

    policy_applied = len(sysquery.bruhswer_rules().value) >= 2
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
        # Tell the child to write UTF-8, or its piped output arrives as cp1252.
        child_env = dict(os.environ, PYTHONIOENCODING="utf-8")
        proc = subprocess.run([sys.executable, str(_HERE / script)],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", shell=False, env=child_env)
        elapsed = time.perf_counter() - start

        # Both streams: unittest writes its counts to stderr, the older suites to stdout.
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
            reported = 0
            for line in ((proc.stdout or "") + "\n" + (proc.stderr or "")).splitlines():
                stripped = line.strip()
                if (stripped.startswith(("FAILED:", "FAIL:", "FAILED ("))
                        or "[FAIL]" in stripped):
                    print(f"    {stripped}")
                    reported += 1

            # A crash prints no assertion; show its stderr rather than just "FAIL".
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
