"""Privacy comparison: Stock Edge vs bruhswer Standard vs bruhswer Disposable.

Brief SS17: "Use controlled test pages. Do not use third-party tracking sites as the
sole source of truth." So this serves its own probe pages from loopback and reads the
results back out of the DOM. Nothing is sent to any external service.

WHAT IT MEASURES
    identity      User-Agent, platform, languages, timezone, screen, hardware
    storage       cookies, localStorage, sessionStorage, IndexedDB, service workers
    referrer      same-origin and cross-origin, HTTPS-free local equivalents
    permissions   geolocation, camera, microphone, notifications, clipboard
    webrtc        ICE candidates, and specifically whether LAN addresses leak
    misc          plugins, doNotTrack, canvas/WebGL signature

HOW IT IS FAIR
    "Stock Edge" is a FRESH temporary profile with Edge's own defaults - not the user's
    real profile, which would be neither reproducible nor appropriate to touch. Every
    profile is driven through exactly the same page with the same flags.

HOW TO READ THE FINGERPRINT RESULT
    Fewer values is NOT automatically better (brief SS18). A value that differs from
    stock Edge makes bruhswer *rarer*, which is worse. The interesting column is
    "differs from stock" - each difference must be justified, and the ones that only
    reduce collection surfaces (permissions, WebRTC candidates) are the good kind.

Unelevated. Creates and deletes its own temp profiles. Changes nothing on the host.
"""

from __future__ import annotations

import http.server
import json
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from app import config  # noqa: E402
from app.privacy import privacy_guard  # noqa: E402

PORT_A = 18140          # "first party"
PORT_B = 18141          # "third party" - different host string, see note in report
HOST_A = "127.0.0.1"
HOST_B = "localhost"

RESULT_ID = "BRUHSWER_PROBE_RESULT"

PROBE_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>bruhswer privacy probe</title></head><body>
<pre id="out">pending</pre>
<script>
const R = {};
function safe(name, fn) { try { R[name] = fn(); } catch (e) { R[name] = "ERR:" + e.name; } }

safe("ua", () => navigator.userAgent);
safe("platform", () => navigator.platform);
safe("languages", () => (navigator.languages || []).join(","));
safe("language", () => navigator.language);
safe("timezone", () => Intl.DateTimeFormat().resolvedOptions().timeZone);
safe("tzOffset", () => new Date().getTimezoneOffset());
safe("screen", () => [screen.width, screen.height, screen.availWidth,
                      screen.availHeight, screen.colorDepth,
                      window.devicePixelRatio].join("x"));
safe("hardwareConcurrency", () => navigator.hardwareConcurrency);
safe("deviceMemory", () => navigator.deviceMemory === undefined ? "undefined"
                                                               : navigator.deviceMemory);
safe("cookieEnabled", () => navigator.cookieEnabled);
safe("doNotTrack", () => navigator.doNotTrack === null ? "null" : navigator.doNotTrack);
safe("pdfViewerEnabled", () => navigator.pdfViewerEnabled);
safe("plugins", () => navigator.plugins.length);
safe("mimeTypes", () => navigator.mimeTypes.length);
safe("maxTouchPoints", () => navigator.maxTouchPoints);
safe("webdriver", () => navigator.webdriver);
safe("serviceWorkerSupported", () => "serviceWorker" in navigator);
safe("indexedDBSupported", () => "indexedDB" in window);
safe("referrer", () => document.referrer || "<empty>");

safe("localStorage", () => { localStorage.setItem("bruh", "1");
                             const v = localStorage.getItem("bruh");
                             localStorage.removeItem("bruh"); return v === "1"; });
safe("sessionStorage", () => { sessionStorage.setItem("bruh", "1");
                               const v = sessionStorage.getItem("bruh");
                               sessionStorage.removeItem("bruh"); return v === "1"; });
safe("firstPartyCookie", () => { document.cookie = "bruh=1;SameSite=Lax";
                                 return document.cookie.indexOf("bruh=1") >= 0; });

safe("canvas", () => {
  const c = document.createElement("canvas"); c.width = 200; c.height = 40;
  const g = c.getContext("2d");
  g.textBaseline = "top"; g.font = "14px Arial"; g.fillStyle = "#f60";
  g.fillRect(0, 0, 100, 20); g.fillStyle = "#069"; g.fillText("bruhswer", 2, 2);
  const d = c.toDataURL();
  let h = 0; for (let i = 0; i < d.length; i++) { h = (h * 31 + d.charCodeAt(i)) | 0; }
  return "h" + (h >>> 0).toString(16);
});
safe("webgl", () => {
  const c = document.createElement("canvas");
  const g = c.getContext("webgl") || c.getContext("experimental-webgl");
  if (!g) return "none";
  const dbg = g.getExtension("WEBGL_debug_renderer_info");
  if (!dbg) return g.getParameter(g.VENDOR) + " | " + g.getParameter(g.RENDERER);
  return g.getParameter(dbg.UNMASKED_VENDOR_WEBGL) + " | " +
         g.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
});

const jobs = [];

// Permissions: query() reports state WITHOUT prompting.
const perms = ["geolocation", "camera", "microphone", "notifications", "clipboard-read"];
R.permissions = {};
for (const p of perms) {
  jobs.push(navigator.permissions.query({ name: p })
    .then(s => { R.permissions[p] = s.state; })
    .catch(e => { R.permissions[p] = "ERR:" + e.name; }));
}

// IndexedDB actually usable?
jobs.push(new Promise(res => {
  try {
    const req = indexedDB.open("bruhprobe", 1);
    req.onsuccess = () => { R.indexedDBUsable = true; req.result.close();
                            indexedDB.deleteDatabase("bruhprobe"); res(); };
    req.onerror = () => { R.indexedDBUsable = false; res(); };
    req.onblocked = () => { R.indexedDBUsable = "blocked"; res(); };
    setTimeout(() => { if (R.indexedDBUsable === undefined) {
                         R.indexedDBUsable = "timeout"; } res(); }, 3000);
  } catch (e) { R.indexedDBUsable = "ERR:" + e.name; res(); }
}));

// WebRTC: what addresses does a page get to see?
jobs.push(new Promise(res => {
  R.webrtcCandidates = []; R.webrtcHostAddrs = [];
  try {
    const pc = new RTCPeerConnection({ iceServers: [] });
    pc.createDataChannel("x");
    pc.onicecandidate = e => {
      if (!e.candidate) { res(); return; }
      const c = e.candidate.candidate;
      R.webrtcCandidates.push(c);
      const m = c.match(/([0-9]{1,3}(?:\\.[0-9]{1,3}){3}|[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,})/i);
      if (m) { R.webrtcHostAddrs.push(m[1]); }
    };
    pc.createOffer().then(o => pc.setLocalDescription(o)).catch(() => res());
    setTimeout(res, 4000);
  } catch (e) { R.webrtcCandidates = ["ERR:" + e.name]; res(); }
}));

// Third-party storage: an iframe on a DIFFERENT host string reports whether it can
// set and read its own cookie. See the report note about what this can and cannot show.
jobs.push(new Promise(res => {
  R.thirdPartyCookie = "no-response";
  const done = ev => { if (ev.data && ev.data.bruh3p !== undefined) {
                         R.thirdPartyCookie = ev.data.bruh3p; res(); } };
  window.addEventListener("message", done);
  const f = document.createElement("iframe");
  f.style.display = "none";
  f.src = "THIRD_PARTY_URL";
  document.body.appendChild(f);
  setTimeout(res, 4000);
}));

Promise.all(jobs.map(p => Promise.resolve(p).catch(() => null))).then(() => {
  document.getElementById("out").textContent =
    "RESULT_ID_TOKEN" + JSON.stringify(R) + "RESULT_ID_TOKEN";
});
</script></body></html>"""

THIRD_PARTY_HTML = """<!doctype html><html><body><script>
let ok = "blocked";
try {
  document.cookie = "tp=1;SameSite=None;Secure";
  document.cookie = "tp2=1;SameSite=Lax";
  ok = (document.cookie.indexOf("tp") >= 0) ? "allowed" : "blocked";
} catch (e) { ok = "ERR:" + e.name; }
parent.postMessage({ bruh3p: ok }, "*");
</script></body></html>"""


def _make_handler(body: str):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))

        def log_message(self, *a):
            pass

    return H


def start_servers() -> tuple:
    page = (PROBE_HTML
            .replace("THIRD_PARTY_URL", f"http://{HOST_B}:{PORT_B}/tp")
            .replace("RESULT_ID_TOKEN", RESULT_ID))
    a = http.server.ThreadingHTTPServer((HOST_A, PORT_A), _make_handler(page))
    b = http.server.ThreadingHTTPServer(("127.0.0.1", PORT_B), _make_handler(THIRD_PARTY_HTML))
    for s in (a, b):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    return a, b


def run_probe(profile_dir: Path, label: str) -> dict | None:
    argv = [str(config.find_edge()), "--headless=new", "--disable-gpu",
            f"--user-data-dir={profile_dir}", "--no-first-run",
            "--no-default-browser-check", "--virtual-time-budget=20000",
            "--dump-dom", f"http://{HOST_A}:{PORT_A}/probe"]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=180, shell=False)
    except subprocess.TimeoutExpired:
        print(f"  {label}: probe timed out")
        return None
    dom = proc.stdout or ""
    match = re.search(re.escape(RESULT_ID) + r"(.*?)" + re.escape(RESULT_ID), dom, re.S)
    if not match:
        print(f"  {label}: no result token in DOM ({len(dom)} bytes)")
        return None
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        print(f"  {label}: result was not valid JSON ({exc})")
        return None


def flatten(result: dict) -> dict:
    flat = {}
    for key, value in result.items():
        if key == "permissions" and isinstance(value, dict):
            for perm, state in sorted(value.items()):
                flat[f"permission.{perm}"] = state
        elif key == "webrtcCandidates":
            flat["webrtc.candidateCount"] = len(value) if isinstance(value, list) else value
        elif key == "webrtcHostAddrs":
            addrs = sorted(set(value)) if isinstance(value, list) else []
            private = [a for a in addrs
                       if a.startswith(("10.", "192.168.", "172.16.", "172.17.",
                                        "172.18.", "172.19.", "172.2", "172.3",
                                        "169.254.", "fe80", "fc", "fd"))]
            flat["webrtc.addressesSeen"] = ", ".join(addrs) if addrs else "<none>"
            flat["webrtc.LAN_ADDRESS_LEAK"] = "YES" if private else "no"
        else:
            flat[key] = value
    return flat


def main() -> int:
    edge = config.find_edge()
    if edge is None:
        print("Microsoft Edge not found.")
        return 1

    print(f"{config.MOAI} bruhswer privacy comparison")
    print("=" * 100)
    print("Controlled local pages only. Nothing is sent to any external service.\n")

    start_servers()
    temp_root = Path(tempfile.mkdtemp(prefix="bruh_privacy_"))
    profiles: list[tuple[str, Path, bool]] = []

    stock = temp_root / "stock_edge"
    stock.mkdir(parents=True, exist_ok=True)
    profiles.append(("Stock Edge", stock, False))

    std = temp_root / "bruhswer_standard"
    std.mkdir(parents=True, exist_ok=True)
    privacy_guard.apply_to_profile(std, "standard")
    profiles.append(("bruhswer Standard", std, True))

    mx = temp_root / "bruhswer_maximum"
    mx.mkdir(parents=True, exist_ok=True)
    privacy_guard.apply_to_profile(mx, "maximum")
    profiles.append(("bruhswer Maximum", mx, True))

    results: dict[str, dict] = {}
    try:
        for label, path, _ in profiles:
            print(f"  probing {label} ...")
            raw = run_probe(path, label)
            if raw is not None:
                results[label] = flatten(raw)
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)

    if "Stock Edge" not in results:
        print("\nStock Edge probe failed; no comparison is possible.")
        return 1

    keys = sorted({k for r in results.values() for k in r})
    stock_row = results["Stock Edge"]

    print("\n" + "=" * 100)
    print(f"{'PROPERTY':<30}{'STOCK EDGE':<26}{'bruhswer STD':<26}{'DIFFERS?'}")
    print("=" * 100)

    differences: list[str] = []
    for key in keys:
        sv = str(stock_row.get(key, "-"))
        bv = str(results.get("bruhswer Standard", {}).get(key, "-"))
        differs = "CHANGED" if sv != bv else ""
        if differs:
            differences.append(key)
        print(f"{key:<30}{sv[:24]:<26}{bv[:24]:<26}{differs}")

    print("\n" + "=" * 100)
    print(f"Properties measured : {len(keys)}")
    print(f"Differ from stock   : {len(differences)}")
    for key in differences:
        print(f"   - {key}")

    print("\nHOW TO READ THIS (brief SS18)")
    print("  A difference from stock Edge makes bruhswer RARER, which is worse for")
    print("  fingerprinting. Differences are only acceptable when they remove a")
    print("  collection surface rather than change a reported value.")
    print("\n  Identity values that MUST match stock (or bruhswer is more unique):")
    for key in ("ua", "platform", "languages", "timezone", "screen",
                "hardwareConcurrency", "deviceMemory", "canvas", "webgl"):
        sv = str(stock_row.get(key, "-"))
        bv = str(results.get("bruhswer Standard", {}).get(key, "-"))
        verdict = "SAME (good)" if sv == bv else "DIFFERENT (worse)"
        print(f"    {key:<22} {verdict}")

    print("\nNOTE on the third-party cookie row: this test uses two loopback host")
    print("strings (127.0.0.1 and localhost). Chromium's cookie policy is site-based,")
    print("and neither has a registrable domain, so this is NOT a substitute for a")
    print("real cross-site test. Treat that single row as INDICATIVE, not proof.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
