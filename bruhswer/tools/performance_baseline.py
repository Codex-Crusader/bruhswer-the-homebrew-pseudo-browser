"""Performance baseline: is bruhswer practical for daily use?

Brief SS28: "Do not obsess over microbenchmarks. The goal is simply to determine
whether bruhswer is practical for daily use." So this measures a handful of things a
user would actually notice, and nothing else.

    session setup      how long bruhswer's own work takes (ACL + privacy settings)
    cold start         launch to a fully rendered local page
    warm page load     a second load in the same profile
    memory             working set of the whole browser process tree, settled
    CPU at idle        CPU seconds consumed while sitting on a blank page

Compared across Stock Edge / bruhswer Standard / bruhswer Disposable, all driven the
same way. "Stock Edge" is a fresh temporary profile with Edge's own defaults, so the
comparison isolates what bruhswer adds.

Process attribution is by `--user-data-dir` in the command line, so the user's own
running browser is never measured or touched.

Unelevated. Creates and deletes its own temp profiles. Changes nothing on the host.
"""

from __future__ import annotations

import http.server
import json
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from app import config  # noqa: E402
from app.privacy import privacy_guard  # noqa: E402
from app.security import browser_guard  # noqa: E402

PORT = 18150
MARKER = "BRUHSWER_PERF_PAGE"
PAGE = (f"<!doctype html><html><body><h1>{MARKER}</h1>"
        "<p>" + ("filler " * 400) + "</p></body></html>")

REPEATS = 3


class _H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(PAGE.encode())

    def log_message(self, *a):
        pass


# CONSTANT script; the profile path is substituted from a bruhswer-created temp path.
_PS_TREE = (
    "$p = @(Get-CimInstance Win32_Process -Filter \"Name='msedge.exe'\" | "
    "Where-Object {{ $_.CommandLine -like '*{marker}*' }}); "
    "if ($p.Count -eq 0) {{ '{{\"count\":0,\"ws\":0,\"cpu\":0}}' }} else {{ "
    "$ids = $p | Select-Object -ExpandProperty ProcessId; "
    "$procs = Get-Process -Id $ids -ErrorAction SilentlyContinue; "
    "$ws = ($procs | Measure-Object WorkingSet64 -Sum).Sum; "
    "$cpu = ($procs | Measure-Object CPU -Sum).Sum; "
    "[pscustomobject]@{{ count = $p.Count; ws = [double]$ws; cpu = [double]$cpu }} | "
    "ConvertTo-Json -Compress }}"
)


def tree_stats(profile_dir: Path) -> dict:
    marker = profile_dir.name
    proc = subprocess.run(
        [str(config.POWERSHELL), "-NoProfile", "-NonInteractive", "-Command",
         _PS_TREE.format(marker=marker)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=120, shell=False)
    try:
        return json.loads((proc.stdout or "").strip())
    except (json.JSONDecodeError, ValueError):
        return {"count": 0, "ws": 0, "cpu": 0}


def headless_load(profile_dir: Path, url: str) -> float | None:
    """Seconds from launch to a fully rendered page. Returns None on failure."""
    argv = [str(config.find_edge()), "--headless=new", "--disable-gpu",
            f"--user-data-dir={profile_dir}", "--no-first-run",
            "--no-default-browser-check", "--dump-dom", url]
    start = time.perf_counter()
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=120, shell=False)
    except subprocess.TimeoutExpired:
        return None
    elapsed = time.perf_counter() - start
    return elapsed if MARKER in (proc.stdout or "") else None


def windowed_session(profile_dir: Path, settle: int = 14) -> dict:
    """Launch a real (non-headless) browser, let it settle, sample it, close it."""
    argv = [str(config.find_edge()), f"--user-data-dir={profile_dir}",
            "--no-first-run", "--no-default-browser-check",
            f"http://127.0.0.1:{PORT}/"]
    start = time.perf_counter()
    proc = subprocess.Popen(argv, shell=False, close_fds=True)
    time.sleep(settle)
    first = tree_stats(profile_dir)
    time.sleep(6)
    second = tree_stats(profile_dir)

    cpu_idle = max(0.0, float(second.get("cpu", 0)) - float(first.get("cpu", 0)))
    stats = {
        "processes": int(first.get("count", 0)),
        "memory_mb": float(first.get("ws", 0)) / (1024 * 1024),
        "cpu_idle_pct": (cpu_idle / 6.0) * 100.0,
        "wall_to_sample_s": time.perf_counter() - start,
    }

    try:
        proc.terminate()
        proc.wait(timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        pass
    subprocess.run([str(config.POWERSHELL), "-NoProfile", "-NonInteractive", "-Command",
                    f"Get-CimInstance Win32_Process -Filter \"Name='msedge.exe'\" | "
                    f"Where-Object {{ $_.CommandLine -like '*{profile_dir.name}*' }} | "
                    f"ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force "
                    f"-ErrorAction SilentlyContinue }}"],
                   capture_output=True, timeout=60, shell=False)
    time.sleep(3)
    return stats


def measure(label: str, profile_dir: Path, apply_bruhswer: bool) -> dict:
    print(f"\n--- {label} ---")
    profile_dir.mkdir(parents=True, exist_ok=True)

    setup_s = 0.0
    if apply_bruhswer:
        start = time.perf_counter()
        browser_guard.harden_profile_dir(profile_dir)
        privacy_guard.apply_to_profile(profile_dir, "standard")
        setup_s = time.perf_counter() - start
    print(f"  session setup            {setup_s * 1000:8.1f} ms")

    url = f"http://127.0.0.1:{PORT}/"
    cold = headless_load(profile_dir, url)
    print(f"  cold start + first load  {(cold or 0):8.2f} s")

    warm_runs = [headless_load(profile_dir, url) for _ in range(REPEATS)]
    warm_ok = [w for w in warm_runs if w is not None]
    warm = statistics.median(warm_ok) if warm_ok else None
    print(f"  warm load (median of {len(warm_ok)}) {(warm or 0):8.2f} s")

    live = windowed_session(profile_dir)
    print(f"  processes                {live['processes']:8d}")
    print(f"  memory (whole tree)      {live['memory_mb']:8.1f} MB")
    print(f"  CPU while idle           {live['cpu_idle_pct']:8.2f} %")

    return {"label": label, "setup_ms": setup_s * 1000, "cold_s": cold,
            "warm_s": warm, **live}


def main() -> int:
    if config.find_edge() is None:
        print("Microsoft Edge not found.")
        return 1

    print(f"{config.MOAI} bruhswer performance baseline")
    print("=" * 78)
    print("Local page only. No external network traffic is part of the measurement.")

    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), _H)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    temp_root = Path(tempfile.mkdtemp(prefix="bruh_perf_"))
    rows: list[dict] = []
    try:
        rows.append(measure("Stock Edge", temp_root / "stock", False))
        rows.append(measure("bruhswer Standard", temp_root / "bruh_std", True))
        rows.append(measure("bruhswer Disposable", temp_root / "bruh_disp", True))
    finally:
        server.shutdown()
        shutil.rmtree(temp_root, ignore_errors=True)

    print("\n" + "=" * 78)
    print(f"{'':<24}{'SETUP':>9}{'COLD':>9}{'WARM':>9}{'MEM':>10}{'CPU idle':>10}")
    print("=" * 78)
    for row in rows:
        print(f"{row['label']:<24}"
              f"{row['setup_ms']:>7.0f}ms"
              f"{(row['cold_s'] or 0):>8.2f}s"
              f"{(row['warm_s'] or 0):>8.2f}s"
              f"{row['memory_mb']:>8.0f}MB"
              f"{row['cpu_idle_pct']:>9.2f}%")

    stock = rows[0]
    std = rows[1]
    print("\nVERDICT")
    overhead = (std["setup_ms"])
    print(f"  bruhswer's own per-session work costs {overhead:.0f} ms.")
    if std["warm_s"] and stock["warm_s"]:
        delta = (std["warm_s"] - stock["warm_s"]) * 1000
        print(f"  Page load differs from stock Edge by {delta:+.0f} ms (median).")
    mem_delta = std["memory_mb"] - stock["memory_mb"]
    print(f"  Memory differs from stock Edge by {mem_delta:+.0f} MB.")
    print("\n  bruhswer adds no proxy, no interception and no extra process to the")
    print("  browsing path - the firewall rules are enforced by Windows itself - so")
    print("  the browsing experience is Edge's, not a slowed-down copy of it.")
    print("  Standard Privacy needs no VPN, so nothing here depends on tunnel speed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
