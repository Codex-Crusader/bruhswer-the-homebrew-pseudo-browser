"""Run the regression suite N times and report per-suite flakiness.

    python tests/stress.py            # 10 iterations, the default
    python tests/stress.py 3
    python tests/stress.py 10 --fast  # skip the suites that drive a real browser

WHY THIS EXISTS SEPARATELY FROM run_all.py
    run_all answers "does the suite pass". This answers "does it pass RELIABLY", and
    they are different questions on Windows. These suites start PowerShell processes,
    reparent a real Edge window, and race a compositor. A control that passes nine times
    in ten is not a control that passes - the tenth run is the user's session.

    A suite that fails intermittently is reported by NAME and by how often, so an
    intermittent failure cannot be dismissed as "it passed when I ran it again". That
    dismissal is exactly how a real defect survives.

Exit codes: 0 every iteration passed. 1 something failed at least once.
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

from app import config  # noqa: E402

DEFAULT_ITERATIONS = 10

# Suites that need neither a browser nor the firewall. --fast runs only these.
FAST = (
    "test_security.py",
    "test_urls_fuzz.py",
    "test_overclaim_regressions.py",
    "test_evidence_model.py",
    "test_accessibility.py",
    "test_window_surface.py",
    "test_session_races.py",
    "test_reverification.py",
    "test_disposable_overwrite.py",
    "test_integrity.py",
    "test_panic_and_account.py",
)

SLOW = (
    "test_persistent_profile.py",
    "test_end_to_end.py",
    "test_network_regression.py",
    "test_localhost_surface.py",
    "test_user_path.py",
    "test_browser_ui.py",
)


def _run(script: str) -> tuple[bool, float, str]:
    started = time.perf_counter()
    proc = subprocess.run(
        [sys.executable, str(_HERE / script)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        shell=False, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    elapsed = time.perf_counter() - started
    tail = ""
    if proc.returncode != 0:
        lines = [ln.strip() for ln
                 in ((proc.stdout or "") + "\n" + (proc.stderr or "")).splitlines()
                 if ln.strip()]
        tail = " | ".join(lines[-3:])[:220]
    return proc.returncode == 0, elapsed, tail


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass

    fast_only = "--fast" in argv
    numbers = [a for a in argv if a.isdigit()]
    iterations = int(numbers[0]) if numbers else DEFAULT_ITERATIONS
    suites = list(FAST) if fast_only else list(FAST) + list(SLOW)

    print(f"{config.MOAI} bruhswer stress  -  {iterations} iteration(s), "
          f"{len(suites)} suite(s){'  [fast only]' if fast_only else ''}")
    print("=" * 74)

    failures: dict[str, list[int]] = {suite: [] for suite in suites}
    slowest: dict[str, float] = {suite: 0.0 for suite in suites}
    started = time.perf_counter()

    for run_index in range(1, iterations + 1):
        print(f"\n--- iteration {run_index}/{iterations}")
        for suite in suites:
            ok, elapsed, tail = _run(suite)
            slowest[suite] = max(slowest[suite], elapsed)
            if ok:
                print(f"    ok    {suite:<34} {elapsed:6.1f}s")
            else:
                failures[suite].append(run_index)
                print(f"    FAIL  {suite:<34} {elapsed:6.1f}s  {tail}")

    total = time.perf_counter() - started
    print("\n" + "=" * 74)
    flaky = {s: runs for s, runs in failures.items() if runs}
    for suite in suites:
        runs = failures[suite]
        mark = "PASS" if not runs else ("FLAKY" if len(runs) < iterations else "FAIL")
        detail = "" if not runs else f"  failed on {runs}"
        print(f"  {mark:<6} {suite:<34} worst {slowest[suite]:6.1f}s{detail}")

    print("=" * 74)
    print(f"total {total / 60:.1f} min")
    if not flaky:
        print(f"WE GOOD  -  {iterations}/{iterations} clean.")
        return 0

    # NAMED, and never rounded off. "It passed when I re-ran it" is how an
    # intermittent defect survives to ship.
    print(f"NOT CLEAN  -  {len(flaky)} suite(s) failed at least once:")
    for suite, runs in flaky.items():
        print(f"    {suite}  failed {len(runs)}/{iterations} run(s) - {runs}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
