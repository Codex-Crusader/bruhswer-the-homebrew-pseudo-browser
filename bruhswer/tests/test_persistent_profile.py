"""Does the PERSISTENT profile survive a second launch?

Chromium rewrites Preferences on exit, which could undo the privacy settings on every
launch after the first. Start, close, start again, read back. Also: hardening a
populated profile twice is idempotent.

    python tests/test_persistent_profile.py
"""

from __future__ import annotations

import shutil
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from app import config  # noqa: E402
from app.controller import controller as ctrl  # noqa: E402
from app.privacy import privacy_guard  # noqa: E402
from app.security import browser_guard  # noqa: E402
from app.sessions import session_manager  # noqa: E402

_passed: list[str] = []
_failed: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (_passed if ok else _failed).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -  {detail}" if detail else ""))


def one_cycle(controller: ctrl.Controller, label: str) -> tuple[int, int, list[str]]:
    outcome = controller.start(session_manager.PERSISTENT)
    check(f"{label}: session launched", outcome.launched, outcome.message)
    if not outcome.launched:
        return 0, 0, ["launch blocked"]

    time.sleep(12)
    ok, message = controller.stop()
    check(f"{label}: session closed", ok, message)
    time.sleep(4)

    applied, expected, missing = privacy_guard.verify_applied(
        config.PROFILE_PERSISTENT, controller.privacy_mode)
    return applied, expected, missing


def main() -> int:
    print("BRUHWSER persistent-profile verification")
    print("=" * 74)

    if config.PROFILE_PERSISTENT.exists():
        print("\n[setup] removing existing persistent profile for a clean test")
        shutil.rmtree(config.PROFILE_PERSISTENT, ignore_errors=True)

    controller = ctrl.Controller()

    print("\n1. FIRST launch (fresh profile)")
    applied1, expected1, missing1 = one_cycle(controller, "first")
    check(f"first launch: settings applied ({applied1}/{expected1})",
          applied1 == expected1 and expected1 > 0,
          f"missing: {missing1[:3]}" if missing1 else "all applied")

    print("\n2. SECOND launch (profile already written by Edge's shutdown)")
    applied2, expected2, missing2 = one_cycle(controller, "second")
    check(f"second launch: settings STILL applied ({applied2}/{expected2})",
          applied2 == expected2 and expected2 > 0,
          f"missing: {missing2[:5]}" if missing2 else "all applied")

    print("\n3. THIRD launch (confirms it is stable, not a one-off)")
    applied3, expected3, missing3 = one_cycle(controller, "third")
    check(f"third launch: settings STILL applied ({applied3}/{expected3})",
          applied3 == expected3 and expected3 > 0,
          f"missing: {missing3[:5]}" if missing3 else "all applied")

    print("\n4. ACL hardening is idempotent on a POPULATED profile")
    size = sum(1 for _ in config.PROFILE_PERSISTENT.rglob("*"))
    print(f"   profile now contains {size} items")
    for attempt in (1, 2):
        ok, message = browser_guard.harden_profile_dir(config.PROFILE_PERSISTENT)
        check(f"harden attempt {attempt} on populated profile", ok, message)

    print("\n5. The verifier agrees, on the persistent profile")
    result = controller.verify(session_manager.PERSISTENT)
    privacy_check = next(
        (c for c in result.checks if c.check_id == "privacy.settings"), None)
    check("verifier reports privacy settings applied",
          privacy_check is not None and privacy_check.verdict.value == "PASS",
          privacy_check.detail if privacy_check else "check missing")
    check("no launch blockers on persistent mode", not result.blockers,
          "; ".join(c.title for c in result.blockers))

    print("\n" + "=" * 74)
    print(f"PASSED {len(_passed)}   FAILED {len(_failed)}")
    if _failed:
        for name in _failed:
            print(f"  FAILED: {name}")
        return 1
    print("\nPersistent mode holds its privacy settings across launches.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
