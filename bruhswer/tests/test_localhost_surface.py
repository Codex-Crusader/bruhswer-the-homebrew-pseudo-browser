"""Localhost attack-surface regression suite.

    python tests/test_localhost_surface.py

WHAT THIS SUITE IS FOR

Every other network test in bruhswer asks "is the boundary holding?". This one asks a
harder and more uncomfortable question: "what can a webpage still reach on this
machine, and does bruhswer describe that honestly?"

It therefore does NOT force every result into PASS. Stage 4 gate A16 measured that
Windows Firewall does not filter loopback, and no amount of configuration changes that.
A suite that reported "localhost BLOCKED" would be lying, and a lying security test is
worse than no test at all. So results are reported in four categories:

    REACHED          the browser got through, measured
    BLOCKED          the browser was stopped, measured
    NOT ENFORCEABLE  reached, and bruhswer has no mechanism that could stop it
    UNKNOWN          the probe could not establish either way

The pass/fail verdict of this suite rests on three things bruhswer genuinely controls,
NOT on whether loopback is reachable:

  1. bruhswer creates no local endpoint of its own       (section A)
  2. bruhswer refuses the URL schemes that would bypass its controls   (section A)
  3. what bruhswer CLAIMS matches what was just measured (section D)

Section D is the point of the whole file. If a future change made loopback reachable
in a new way, or made a blocked range reachable, the suite fails not because the
platform changed but because bruhswer's UI would then be telling the user something
untrue.

HOW REACHABILITY IS MEASURED

By server-side observation, not by scraping the DOM. Each probe carries a unique token
in its path; the local test servers record every token they actually receive. A request
that arrives is proof of reachability regardless of what CORS then does to the
response - which matters, because CORS restricts READING a reply, not SENDING the
request. That distinction is the whole reason CSRF and DNS-rebinding attacks against
localhost services work.

The attacker page is served from a loopback origin on a different port. Stated plainly:
a real hostile page would be served from the internet. Same-origin policy treats a
different port as a different origin, so the cross-origin behaviour is representative,
but the network path from an internet origin is NOT re-measured here - section C covers
the routed cases separately.

Nothing in this file scans, and nothing touches a service it did not itself create. The
third-party services listening on this machine are INVENTORIED (section E) and reported,
never probed and never modified - brief SS8/SS9 of the hardening pass.

WHAT THIS SUITE ITSELF EXPOSES, WHILE IT RUNS

Being honest about the test as well as the product: to measure whether the host's own
LAN address behaves like loopback, the suite binds one probe service to that address
for the duration of the run. For those few minutes port 18732 is reachable from the
local network, subject to the host firewall's inbound rules. Every other probe service
is bound to a loopback address only, and no probe server is ever bound to a wildcard
address, because that would expose it far more broadly than the measurement requires.
All of them are shut down in a `finally` block.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

import _env  # noqa: E402
from app import config  # noqa: E402
from app.browser import edge, urls  # noqa: E402
from app.controller import controller as ctrl  # noqa: E402
from app.network import network_guard  # noqa: E402

# Ports chosen high and fixed so a failure is reproducible. ORIGIN serves the attacker
# page; TARGET is what the page tries to reach.
ORIGIN_PORT = 18731
TARGET_PORT = 18732

# This suite's own scaffolding, excluded when it audits bruhswer for listeners.
_PROBE_PORTS = {ORIGIN_PORT, TARGET_PORT}

_ERR_CODES = ("ERR_NETWORK_ACCESS_DENIED", "ERR_CONNECTION_REFUSED",
              "ERR_CONNECTION_TIMED_OUT", "ERR_ADDRESS_UNREACHABLE",
              "ERR_CONNECTION_RESET", "ERR_CONNECTION_FAILED",
              "ERR_ADDRESS_INVALID", "ERR_UNSAFE_PORT")

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

_passed: list[str] = []
_failed: list[str] = []
_findings: list[tuple[str, str, str]] = []   # (target, verdict, detail)

# Tokens seen by any of the local servers. One set, shared, thread-safe enough for
# this purpose because sets have atomic add under the GIL.
_hits: set[str] = set()


def check(name: str, ok: bool, detail: str = "") -> None:
    (_passed if ok else _failed).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -  {detail}" if detail else ""))


def record(target: str, verdict: str, detail: str = "") -> None:
    """Report a measurement WITHOUT asserting on it. Section D asserts on the set."""
    _findings.append((target, verdict, detail))
    print(f"  [{verdict:<15}] {target}" + (f"  -  {detail}" if detail else ""))


# --------------------------------------------------------------------- test servers

class _Recorder(http.server.BaseHTTPRequestHandler):
    """Records the token in any request it receives, over HTTP or a WebSocket upgrade."""

    protocol_version = "HTTP/1.1"

    def _token(self) -> str:
        # /probe/<token> - the token is generated by this suite, never by page content.
        parts = self.path.strip("/").split("/")
        return parts[-1] if parts else ""

    def do_GET(self):
        token = self._token()
        if self.headers.get("Upgrade", "").lower() == "websocket":
            self._websocket_accept(token)
            return
        _hits.add(token)
        self._plain(b"ok")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(min(length, 4096))
        _hits.add(self._token())
        self._plain(b"ok")

    def do_OPTIONS(self):
        _hits.add(self._token())
        self._plain(b"")

    def _plain(self, body: bytes):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        # Deliberately permissive: this stands in for a local service that trusts any
        # origin, which is the realistic dangerous case and the one worth measuring.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _websocket_accept(self, token: str):
        """Complete a real RFC6455 handshake so the page's onopen actually fires.

        The token is recorded on HANDSHAKE RECEIPT - that alone proves the socket was
        reachable, independently of whether framing then succeeds.
        """
        _hits.add(token)
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()

    def log_message(self, *args):
        pass


class _Origin(http.server.BaseHTTPRequestHandler):
    """Serves the harmless attacker page, and records the page's completion signal.

    The completion signal has to be recorded HERE rather than on the target servers:
    it is fetched from the page's own origin, so it proves the page finished its work
    regardless of whether any target was reachable. That is precisely what lets the
    suite tell "no request arrived because it was blocked" apart from "no request
    arrived because the page never got that far".
    """

    protocol_version = "HTTP/1.1"
    PAGE = b""

    def do_GET(self):
        if self.path.startswith("/probe/"):
            _hits.add(self.path.strip("/").split("/")[-1])
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(self.PAGE)))
        self.end_headers()
        self.wfile.write(self.PAGE)

    def log_message(self, *args):
        pass


class _QuietServer(http.server.ThreadingHTTPServer):
    """Suppresses the traceback socketserver prints when a client hangs up.

    Closing a WebSocket resets the connection, and the browser abandons no-cors
    requests it cannot read - both are NORMAL here and both make socketserver dump a
    ConnectionResetError traceback to stderr. Dozens of those scrolling past is how a
    genuine failure gets missed, so the noise is suppressed rather than tolerated.
    Nothing else is swallowed: the recorder has already logged the token by then, and
    a connection that never arrived is still measured as BLOCKED.
    """

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError,
                            BrokenPipeError)):
            return
        super().handle_error(request, client_address)


class _V6Server(_QuietServer):
    address_family = socket.AF_INET6


def _serve(server) -> None:
    threading.Thread(target=server.serve_forever, daemon=True).start()


def _try_bind(host: str, port: int, handler, v6: bool = False):
    """Start a recorder on one specific address. Returns None if the OS refuses.

    Bound to ONE address each time. A wildcard bind would expose the probe server to
    the LAN for the duration of the test, which is not a thing a security suite should
    do to the user's machine.
    """
    cls = _V6Server if v6 else _QuietServer
    try:
        server = cls((host, port), handler)
    except OSError:
        return None
    _serve(server)
    return server


# --------------------------------------------------------------------- browser probe

def edge_probe(url: str, udd: Path, marker: str | None = None) -> tuple[str, str]:
    """Navigate the real browser to `url` and classify what happened.

    Uses the same msedge.exe the firewall rule names, so the rule applies identically.
    Exit code is not a signal - Edge returns 0 while rendering an error page - so the
    verdict comes from the DOM and, where relevant, from server-side observation.
    """
    argv = [str(config.find_edge()), "--headless=new", "--disable-gpu",
            f"--user-data-dir={udd}", "--no-first-run",
            "--no-default-browser-check", "--dump-dom", url]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=90, shell=False,
                              creationflags=config.NO_WINDOW)
    except subprocess.TimeoutExpired:
        return "UNKNOWN", "probe timed out"
    dom = proc.stdout or ""
    if marker and marker in _hits:
        return "REACHED", "request observed by the local service"
    for code in _ERR_CODES:
        if code in dom:
            return "BLOCKED", code
    if marker:
        return "BLOCKED", "no request ever arrived"
    if len(dom) > 400:
        return "REACHED", f"content returned ({len(dom)} bytes)"
    return "UNKNOWN", f"dom {len(dom)} bytes, no error code"


def _attack_page(targets: list[tuple[str, str, str]], done_token: str,
                 origin_url: str) -> bytes:
    """Build the harmless attacker page.

    `targets` is (label, origin, token). The page fires one no-cors GET, one no-cors
    POST and one WebSocket at each. no-cors is used deliberately: it is what a hostile
    page would use against a local service, because it sends the request even though
    the reply cannot be read.

    When every probe has settled the page signals completion by fetching `done_token`
    on the ORIGIN server. That signal is what the test waits for.

    NO --virtual-time-budget, deliberately. An earlier version used it so the async
    work would finish before --dump-dom fired, and the result flapped: virtual time
    advances almost instantly, so the page's own setTimeout resolved long before a
    real TCP handshake could complete, and the first WebSocket of the run was
    intermittently recorded as BLOCKED when it had simply not landed yet. A security
    measurement that changes between runs is worse than useless - it teaches you to
    ignore it. Real time and an explicit completion signal remove the race entirely.
    """
    spec = json.dumps([{"o": origin, "t": token} for _label, origin, token in targets])
    return ("""<!doctype html><meta charset="utf-8"><title>probe</title>
<body><div id="d">running</div><script>
const T = """ + spec + """;
const DONE = """ + json.dumps(f"{origin_url}/probe/{done_token}") + """;
function settle(w, ms) {
  return new Promise(r => {
    let done = false;
    const fin = () => { if (!done) { done = true; r(); } };
    w.onopen = fin; w.onerror = fin; w.onclose = fin;
    setTimeout(fin, ms);
  });
}
async function go() {
  for (const x of T) {
    try { await fetch(x.o + "/probe/" + x.t + "-get", {mode:"no-cors",cache:"no-store"}); } catch(e) {}
    try { await fetch(x.o + "/probe/" + x.t + "-post", {method:"POST",mode:"no-cors",
          body:"probe",cache:"no-store"}); } catch(e) {}
    try {
      const w = new WebSocket(x.o.replace(/^http/, "ws") + "/probe/" + x.t + "-ws");
      await settle(w, 4000);
      try { w.close(); } catch(e) {}
    } catch(e) {}
  }
  document.getElementById("d").textContent = "PROBE_COMPLETE";
  try { await fetch(DONE, {mode:"no-cors",cache:"no-store"}); } catch(e) {}
}
go();
</script></body>""").encode()


# --------------------------------------------------------------------------- sections

def section_a_bruhswer_own_surface() -> None:
    """ASSERTED. bruhswer must not add any local attack surface of its own."""
    print("\nA. bruhswer's own local attack surface  (asserted)")

    # 1. No socket owned by this Python process, measured from the OS.
    own_pid = _current_pids()
    listeners = _listeners_for(own_pid)
    check("bruhswer opens no listening socket", not listeners,
          f"pids={sorted(own_pid)} listeners={listeners}" if listeners
          else "no TCP listener owned by bruhswer or its children")

    # 2. No control pipe. The reserved constants were removed; assert they stay gone.
    for name in ("PIPE_NAME", "ALLOWED_IPC_VERBS", "MAX_IPC_MESSAGE_BYTES"):
        check(f"config has no reserved IPC surface ({name})",
              not hasattr(config, name))

    # 3. Schemes that would sidestep the network boundary entirely.
    refused = ("file:///C:/Windows/win.ini", "javascript:alert(1)",
               "data:text/html,<script>1</script>", "vbscript:msgbox",
               "ws://127.0.0.1:1/", "wss://127.0.0.1:1/", "blob:http://x/y",
               "chrome://net-internals", "edge://settings",
               "view-source:http://127.0.0.1/", "ftp://127.0.0.1/",
               r"\\127.0.0.1\c$", r"C:\Windows\win.ini")
    bad = []
    for text in refused:
        try:
            urls.normalise(text)
            bad.append(text)
        except urls.RefusedURL:
            pass
    check("address bar refuses non-http(s) schemes and file paths", not bad,
          f"accepted: {bad}" if bad else f"all {len(refused)} refused")

    # 4. The browser command line cannot be made to open a debugging endpoint.
    opened = []
    for flag in ("--remote-debugging-port=9222", "--remote-debugging-pipe",
                 "--load-extension=C:\\x"):
        try:
            edge.build_command(Path("msedge.exe"), Path("p"), (flag,))
            opened.append(flag)
        except ValueError:
            pass
    check("browser cannot be launched with a debugging endpoint", not opened,
          f"accepted: {opened}" if opened else "all refused by build_command")


def _current_pids() -> set[int]:
    """This process and any child processes, so a helper listener would be caught too."""
    import os
    pids = {os.getpid()}
    script = ("@(Get-CimInstance Win32_Process | Select-Object ProcessId,"
              "ParentProcessId) | ConvertTo-Json -Compress -Depth 3")
    data = _ps_json(script) or []
    parents = {int(p["ProcessId"]): int(p["ParentProcessId"]) for p in data
               if p.get("ProcessId") is not None}
    for _ in range(4):   # a few generations is plenty; bruhswer spawns shallow trees
        for pid, parent in parents.items():
            if parent in pids:
                pids.add(pid)
    return pids


def _listeners_for(pids: set[int]) -> list[str]:
    """Listening sockets owned by bruhswer, EXCLUDING this suite's own probe servers.

    The exclusion is narrow and deliberate. This suite has to stand up local services
    to have anything to measure reachability against, and those run inside the test
    process - so without the exclusion the suite reports itself as a bruhswer listener
    and fails on its own scaffolding.

    Only the two fixed probe ports are excluded, by number. A real listener that
    bruhswer opened on any other port is still caught, which is the property that
    matters. The application source is separately proven listener-free by
    tests/test_security.py::TestNoLocalListener, which reads the code rather than the
    running process, so neither check depends on the other being right.
    """
    script = ("@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
              "Select-Object LocalAddress,LocalPort,OwningProcess) | "
              "ConvertTo-Json -Compress -Depth 3")
    out = []
    for row in _ps_json(script) or []:
        if int(row.get("OwningProcess") or -1) not in pids:
            continue
        if int(row.get("LocalPort") or 0) in _PROBE_PORTS:
            continue
        out.append(f"{row.get('LocalAddress')}:{row.get('LocalPort')}")
    return out


def _ps_json(script: str):
    try:
        proc = subprocess.run(
            [str(config.POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=90, shell=False, creationflags=config.NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return None
    try:
        value = json.loads((proc.stdout or "").strip() or "null")
    except json.JSONDecodeError:
        return None
    if value is None:
        return None
    return value if isinstance(value, list) else [value]


def section_b_loopback_matrix(probe_dir: Path, lan_ip: str | None) -> None:
    """MEASURED, not asserted. What a page can actually reach on this machine."""
    print("\nB. Loopback and host reachability matrix  (measured, not forced)")

    forms = [
        ("localhost by name", f"http://localhost:{TARGET_PORT}/"),
        ("IPv4 loopback 127.0.0.1", f"http://127.0.0.1:{TARGET_PORT}/"),
        ("alternate loopback 127.0.0.2", f"http://127.0.0.2:{TARGET_PORT}/"),
        ("decimal form of 127.0.0.1", f"http://2130706433:{TARGET_PORT}/"),
        ("hex form of 127.0.0.1", f"http://0x7f000001:{TARGET_PORT}/"),
        ("IPv6 loopback [::1]", f"http://[::1]:{TARGET_PORT}/"),
    ]
    if lan_ip:
        forms.append(("host's own LAN IP", f"http://{lan_ip}:{TARGET_PORT}/"))

    for label, url in forms:
        token = secrets.token_hex(6)
        verdict, detail = edge_probe(url.rstrip("/") + f"/probe/{token}", probe_dir,
                                     marker=token)
        # A loopback path that is reachable is NOT a failure - it is the documented
        # platform limitation. It is recorded under the name that says so.
        if verdict == "REACHED":
            verdict = "NOT ENFORCEABLE"
        record(f"top-level navigation -> {label}", verdict, detail)


def section_b2_page_driven(probe_dir: Path, lan_ip: str | None) -> None:
    """The realistic shape: a PAGE reaching local services, not the address bar."""
    print("\nB2. Page-driven access (fetch GET, fetch POST, WebSocket)")

    targets = [("IPv4 loopback", f"http://127.0.0.1:{TARGET_PORT}", secrets.token_hex(6)),
               ("alternate loopback", f"http://127.0.0.2:{TARGET_PORT}",
                secrets.token_hex(6)),
               ("IPv6 loopback", f"http://[::1]:{TARGET_PORT}", secrets.token_hex(6))]
    if lan_ip:
        targets.append(("host's own LAN IP", f"http://{lan_ip}:{TARGET_PORT}",
                        secrets.token_hex(6)))

    origin_url = f"http://127.0.0.1:{ORIGIN_PORT}"
    done_token = secrets.token_hex(6)
    _Origin.PAGE = _attack_page(targets, done_token, origin_url)
    origin = _try_bind("127.0.0.1", ORIGIN_PORT, _Origin)
    if origin is None:
        record("page-driven probe", "UNKNOWN", f"could not bind origin :{ORIGIN_PORT}")
        return

    proc = None
    try:
        # Launched WITHOUT --dump-dom: the browser is left running while the page
        # works, and the test waits on the page's own completion signal arriving at
        # the origin server. Waiting for an observed fact beats sleeping a guessed
        # number of seconds and hoping.
        argv = [str(config.find_edge()), "--headless=new", "--disable-gpu",
                f"--user-data-dir={probe_dir}", "--no-first-run",
                "--no-default-browser-check", origin_url + "/"]
        proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, shell=False,
                                creationflags=config.NO_WINDOW)

        deadline = time.time() + 90
        while time.time() < deadline and done_token not in _hits:
            time.sleep(0.25)
        completed = done_token in _hits

        if not completed:
            record("page-driven probe completion", "UNKNOWN",
                   "the probe page never signalled completion; results below are a "
                   "lower bound, not a measurement")

        for label, _target_url, token in targets:
            for method in ("get", "post", "ws"):
                reached = f"{token}-{method}" in _hits
                if reached:
                    verdict, detail = ("NOT ENFORCEABLE",
                                       "request observed by the local service")
                elif completed:
                    verdict, detail = "BLOCKED", "no request arrived"
                else:
                    # The page did not finish, so absence of a hit proves nothing.
                    verdict, detail = "UNKNOWN", "probe did not complete"
                record(f"page {method.upper():<4} -> {label}", verdict, detail)
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
        origin.shutdown()


def section_c_enforceable_boundary(probe_dir: Path, router: str) -> None:
    """ASSERTED. The part of the boundary that genuinely IS enforceable."""
    print("\nC. Routed network boundary  (asserted - this part IS enforceable)")

    verdict, detail = edge_probe(f"http://{router}/", probe_dir)
    check(f"router {router} is BLOCKED", verdict == "BLOCKED", f"{verdict} {detail}")

    verdict, detail = edge_probe("https://1.1.1.1/", probe_dir)
    check("internet is still REACHED", verdict == "REACHED", f"{verdict} {detail}")


def section_d_claims_match_measurements() -> None:
    """ASSERTED, and this is the point of the suite.

    Whatever section B measured, bruhswer's own UI and policy summary must describe it
    truthfully. A green light nobody verified is the defect class this project treats
    as a vulnerability; so is an "enforced" label over a path that was just reached.
    """
    print("\nD. bruhswer's claims match what was just measured  (asserted)")

    reached = {t for t, v, _ in _findings if v == "NOT ENFORCEABLE"}
    summary = dict(network_guard.policy_summary())

    loopback_reached = any("loopback" in t or "localhost" in t for t in reached)

    # If ANY loopback path got through, every loopback-ish claim must say so.
    for label in ("Localhost (127.0.0.1)", "This PC's own IP", "Development services"):
        state = summary.get(label)
        if loopback_reached:
            check(f"policy summary reports {label!r} as NOT ENFORCEABLE",
                  state == "NOT ENFORCEABLE", f"says {state!r}")
        else:
            # Nothing got through. bruhswer still must not upgrade the claim to
            # "BLOCKED" on the strength of one machine's result.
            check(f"policy summary does not overclaim {label!r}",
                  state in ("NOT ENFORCEABLE", "UNKNOWN"), f"says {state!r}")

    # The routed claims must be the enforceable ones.
    check("policy summary reports the router as BLOCKED",
          summary.get("Router") == "BLOCKED", f"says {summary.get('Router')!r}")
    check("policy summary reports the internet as ALLOWED",
          summary.get("Internet") == "ALLOWED", f"says {summary.get('Internet')!r}")

    # The status row the browser window renders must never be green for localhost.
    rows = {label: (value, kind) for label, value, kind, _ in
            ctrl.fixed_status_rows(None)}
    value, kind = rows.get("LOCALHOST", ("<missing>", "<missing>"))
    check("UI status row for LOCALHOST reads NOT ENFORCEABLE",
          value == "NOT ENFORCEABLE", f"reads {value!r}")
    check("UI status row for LOCALHOST is never coloured as OK", kind != "ok",
          f"colour kind is {kind!r}")

    # And the verifier's own check must be flagged unenforceable rather than passing.
    loopback_checks = [c for c in network_guard.verify(config.find_edge())
                       if c.check_id in ("net.loopback", "net.devservices")]
    check("verifier marks loopback checks as not enforceable",
          bool(loopback_checks) and all(not c.enforceable for c in loopback_checks),
          f"{len(loopback_checks)} loopback checks found")
    check("unenforceable loopback checks never block launch",
          all(not c.blocks_launch for c in loopback_checks))


def section_e_third_party_inventory() -> None:
    """REPORTED ONLY. Identify, never alter (hardening brief SS8/SS9)."""
    print("\nE. Third-party local services  (inventory only - nothing is altered)")

    script = ("@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
              "Select-Object LocalAddress,LocalPort,OwningProcess) | "
              "ConvertTo-Json -Compress -Depth 3")
    rows = [r for r in (_ps_json(script) or [])
            if int(r.get("LocalPort") or 0) not in _PROBE_PORTS]
    own = _current_pids()

    loopback = sorted({int(r["LocalPort"]) for r in rows
                       if str(r.get("LocalAddress")) in ("127.0.0.1", "::1")})
    wildcard = sorted({int(r["LocalPort"]) for r in rows
                       if str(r.get("LocalAddress")) in ("0.0.0.0", "::")})
    ours = [r for r in rows if int(r.get("OwningProcess") or -1) in own]

    print(f"  loopback-only listeners : {len(loopback)} port(s) {loopback}")
    print(f"  wildcard listeners      : {len(wildcard)} port(s) {wildcard}")
    print("  These belong to other applications. bruhswer identifies them and does not")
    print("  modify them: silently reconfiguring a user's software because it happens")
    print("  to listen on loopback is not a thing a browser gets to do.")

    check("none of the listening services belong to bruhswer", not ours,
          f"bruhswer-owned listeners: {ours}" if ours else "confirmed zero")

    known = set(config.DEV_SERVICE_PORTS)
    overlap = sorted(set(loopback) & known)
    print(f"  of those, on ports bruhswer names as development services: {overlap}")


# ------------------------------------------------------------------------------ main

def main() -> int:
    print("bruhswer localhost attack-surface suite")
    print("=" * 74)
    print("Reports REACHED / BLOCKED / NOT ENFORCEABLE / UNKNOWN.")
    print("Loopback reachability is a measured platform limitation, not a test failure.")

    if config.find_edge() is None:
        print("\nMicrosoft Edge not found; cannot measure browser behaviour.")
        return 1

    lan_ip = _env.host_lan_ip()
    router = _env.require_gateway()
    print(f"\nhost LAN IP: {lan_ip or 'not found'}   router: {router}")

    # Section A runs BEFORE any probe server is bound, so its "bruhswer opens no
    # listening socket" result is measured against a process that genuinely has none.
    # Ordering it this way means the result does not rest on the port exclusion in
    # _listeners_for being correct.
    section_a_bruhswer_own_surface()

    servers = [
        _try_bind("127.0.0.1", TARGET_PORT, _Recorder),
        _try_bind("127.0.0.2", TARGET_PORT, _Recorder),
        _try_bind("::1", TARGET_PORT, _Recorder, v6=True),
    ]
    if lan_ip:
        servers.append(_try_bind(lan_ip, TARGET_PORT, _Recorder))
    live = [s for s in servers if s is not None]
    print(f"local probe services bound: {len(live)} of {len(servers)}")

    probe_dir = config.PROFILE_DISPOSABLE_ROOT / "lhprobe"
    probe_dir.mkdir(parents=True, exist_ok=True)

    try:
        section_b_loopback_matrix(probe_dir, lan_ip)
        section_b2_page_driven(probe_dir, lan_ip)
        section_c_enforceable_boundary(probe_dir, router)
        section_d_claims_match_measurements()
        section_e_third_party_inventory()
    finally:
        for server in live:
            server.shutdown()
        shutil.rmtree(probe_dir, ignore_errors=True)

    print("\n" + "=" * 74)
    print("MEASURED REACHABILITY")
    for target, verdict, _detail in _findings:
        print(f"  {verdict:<16} {target}")

    unenforceable = sum(1 for _, v, _ in _findings if v == "NOT ENFORCEABLE")
    print(f"\n{unenforceable} of {len(_findings)} probed paths reached a local service.")
    print("bruhswer cannot block these: Windows Firewall does not filter loopback.")
    print("This is reported as NOT ENFORCEABLE everywhere the user can see it, and")
    print("section D fails if it is ever described as anything else.")

    print("\n" + "=" * 74)
    print(f"PASSED {len(_passed)}   FAILED {len(_failed)}")
    if _failed:
        for name in _failed:
            print(f"  FAILED: {name}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
