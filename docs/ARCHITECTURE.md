# Architecture

**Status: current.** This describes the code that ships in v0.12.1.

Earlier designs (WSL2, Hyper-V, QEMU) were built, measured, and rejected. They live in
[`research/`](research/) as evidence and are not guidance. If you want the story of how
the design got here, read [`PROJECT-HISTORY.md`](PROJECT-HISTORY.md).

---

## The shape of it

bruhswer is a single unelevated Python process that launches Microsoft Edge, hosts
Edge's window inside its own frame, and verifies a fixed set of security properties
before it will let the browser start.

```
                      +---------------------------+
                      |         UI (tkinter)      |
                      |  browser_window.py        |
                      |  panels/  dialogs/        |
                      +-------------+-------------+
                                    |  direct method calls
                                    |  (one process, no IPC)
                      +-------------v-------------+
                      |        Controller         |
                      |  owns the session         |
                      |  lifecycle, closed verbs  |
                      +-------------+-------------+
                                    |
        +--------+--------+---------+--------+---------+---------+
        |        |        |         |        |         |         |
   +----v---+ +--v-----+ +v------+ +v-----+ +v------+ +v--------+
   | browser| |security| |network| |privacy| | host  | |sessions |
   |  edge  | |verifier| | guard | | guard | | guard | |downloads|
   |  embed | | browser|  ...                                    |
   +----+---+ +---+----+ +---+---+ +--+----+ +--+----+ +----+----+
        |         |          |        |         |           |
        +---------+----------+--------+---------+-----------+
                                    |
                      +-------------v-------------+
                      |   sysquery.py             |
                      |   the ONLY place an       |
                      |   external program runs   |
                      +-------------+-------------+
                                    |
                      +-------------v-------------+
                      |   Windows + Microsoft Edge |
                      +---------------------------+
```

**There is no IPC.** The UI and the Controller are objects in the same process and call
each other directly. Nothing is serialised, parsed, authenticated or authorised,
so none of that can be got wrong. This is deliberate: Stage 4 measured that a
compromised browser process can reach any local endpoint and that no firewall rule
stops it, so any control channel bruhswer opened would be reachable by the exact thing
it exists to contain. A test parses the source and fails the build if anything ever
imports `socket`, `http.server` or `asyncio`, calls `listen`, or opens a named pipe.

---

## The layers

### UI - `app/ui/`

Presentation and interaction only. It never re-implements a check, never decides
whether launch is allowed, and never manages a session itself.

| File | Responsibility |
|---|---|
| `browser_window.py` | Layout, menu actions, panel launchers. Assembles the two mixins below into one `BrowserWindow` class |
| `window_shell.py` | Declared, never instantiated. The state and cross-mixin methods `session_lifecycle.py` and `verification_ui.py` both call on `self`, so a genuine typo in either is not lost in hundreds of otherwise-unresolvable references |
| `session_lifecycle.py` | Startup, window hosting (the `SetParent` handshake), teardown - the session lifecycle as the user experiences it |
| `verification_ui.py` | Status lights, regression warnings, the account banner, the panic indicator, and the re-verification worker's lifecycle |
| `verify_worker.py` | A background thread that re-runs every check once a minute for as long as a session is open, so the lights describe the live system rather than a launch-time snapshot. Publishes results through a queue; never touches a Tk object itself |
| `panic_key.py` | Registers the global panic hotkey on its own thread and reports whether it is actually armed |
| `panels/` | One module per panel - security, network, privacy, host, quarantine. Each renders a guard's output; none computes it |
| `dialogs.py` | Modal confirmations, e.g. warning before disposable downloads are destroyed |
| `app_ui.py` | The standalone control panel (`--panel`), usable without a browser |

A status light is green only if a check returned `PASS`. `LOCALHOST` is permanently
amber and reads `NOT ENFORCEABLE`.

### Controller - `app/controller/controller.py`

Owns the session lifecycle and holds no browser-supplied state.

It exposes a **closed set of verbs** - `verify`, `status`, `start`, `stop`, `navigate`,
`new_tab`, `export_request`. There is no `execute`, no `run_shell`, no dispatcher that
maps a string to code. The attack surface is small by construction rather than by
filtering, because filtering is a thing you can get wrong.

### The guards - one concern each

| Module | Question it answers | Notable property |
|---|---|---|
| `browser/edge.py` | Is this the browser we expect, and how do we start it? | Fixed absolute paths, Authenticode checked every launch, argv list never a string, `DANGEROUS_FLAGS` refused rather than filtered |
| `browser/embed.py` | How do we host Edge's window? | Win32 reparenting, DPI awareness, shared input queues |
| `browser/tokens.py` | What are the renderer processes actually running as? | Reads live process tokens, so the sandbox claim is measured not asserted |
| `browser/urls.py` | Is this address-bar text safe to hand over? | Returns an `http(s)` URL or refuses. `file:`, `javascript:`, `data:`, UNC paths and drive letters are excluded by construction |
| `security/verifier.py` | May the browser launch? | **The single decision point.** Fail-closed: a critical check must PASS, and UNKNOWN blocks |
| `security/browser_guard.py` | Is the profile confined and the command line clean? | ACLs applied with `icacls`, then proved with a real read/write probe |
| `network/network_guard.py` | Is the firewall policy actually in place? | Verifies only. Applying needs Administrator and lives in a separate one-shot |
| `privacy/privacy_guard.py` | Did the privacy settings stick? | Writes preferences, then **reads them back**. Chromium reverts some, and that is reported |
| `host/host_guard.py` | What can other devices on this network reach on this PC? | Detects and explains. Never changes the host by itself |
| `sessions/session_manager.py` | Persistent or disposable, and is it really gone? | Deletion is verified, confined to its root, and refuses reparse points |
| `downloads/quarantine.py` | Where do downloads land, and how do they get out? | Filenames rebuilt from scratch; export destination comes only from the user's own folder picker |

### `sysquery.py` - the only external-program boundary

Every PowerShell and `icacls` invocation in the application goes through here.

- `subprocess` is always given an **explicit argument list**. `shell=True` appears
  nowhere, enforced by an AST test.
- The executable is a fixed absolute path from `config.py`, never resolved via `PATH`.
- Every script is a **module-level constant**. The only values ever interpolated are
  bruhswer's own constants or integers it validated.
- Nothing here modifies system state. Read-only queries only.

There is deliberately no generic `run(command)` function, so no caller can ask this
module to execute something arbitrary.

### `config.py` - every constant, no logic

Paths, brand colours, Edge candidate locations, blocked address ranges, browser flags,
the dangerous-flag list. Nothing in it is derived from a URL, a filename, a header, a
downloaded file, or any other browser-controlled input.

#### Why these values are what they are

These are the constants whose value is a finding rather than a preference. The file
itself carries a one-line note; the reasoning lives here.

**The three palettes.** bruhswer is dark by default, but the dark palette's amber and
green do not clear WCAG AA (4.5:1) on black. So `apply_high_contrast()` swaps in a
palette that does when Windows reports high-contrast mode, and `apply_light()` swaps in
a light one when Windows says the user prefers light apps. The light palette *darkens*
the verdict hues rather than reusing them - the dark theme's `#3FB950` green is only
1.9:1 on white. Both switches are one-way and must run before any widget is built,
because each widget reads its colour once at construction. `tests/test_accessibility.py`
computes the ratios rather than trusting any of this.

Anything that snapshots the palette at import time has to be refreshed after a switch.
`chrome.COLOUR` is the one such snapshot, and `chrome.refresh_palette()` updates it in
place because `browser_window` and `verification_ui` alias that dict.

**`POLICY_STATE_COLOUR`.** One map, keyed by `network_guard.PolicyState`'s *value* so
`config` need not import the network layer. There used to be two - one in
`network_panel.py`, one inline in `app_ui.py` - and when `policy_summary()` gained a
fourth state both `KeyError`'d, taking two UIs offline. An unrecognised state renders
`POLICY_STATE_UNKNOWN_COLOUR`, which is red: a broken reporting contract is a louder
problem than any single row's verdict, and amber would quietly normalise it.

**`FILE_ATTRIBUTE_REPARSE_POINT` (0x400).** The single most load-bearing constant in
the delete and export paths. Measured in this project: `Path.is_symlink()` returns
**False** for a directory junction created with `mklink /J`, so the obvious-looking
symlink check is silently inert against the exact thing it appears to defend against.
The file-attribute test is the one that works.

**`VERIFY_INTERVAL_SECONDS = 60`.** A full pass starts 14 helper processes (13
PowerShell + 1 icacls) and takes 5.5s measured - re-measured after HostGuard's queries
were made concurrent, down from 8.31s across 15 processes. That number is what settles
the design: a Tk `after()` callback doing this would freeze the window for five seconds
once a minute for the whole session, so it runs on a worker thread. Sixty seconds is
long enough that the helpers are a rounding error on battery, short enough that a
control which silently stopped applying surfaces while the user is still in the session
it affects.

**`FIT_MAX_ATTEMPTS` / `HOST_MAX_ATTEMPTS`.** The curtain drops when the resize is
*confirmed* landed (`embed.is_fitted`), not on a timer. This replaced fixed
200/900/950ms delays that were a guess at how long Chromium takes. The attempt caps
exist because this is a verification, not a wait: if the window is not the right size
after three rounds, more rounds will not fix it and the curtain must come up anyway
rather than hang.

**`DISPOSABLE_OVERWRITE_MAX_BYTES` = 8 MiB.** A browser profile's cache routinely runs
to gigabytes; overwriting all of it would turn closing a session into a multi-minute
operation, and a user who cancels gets neither the overwrite nor a timely close. The
files that hold identifying material - Cookies, Login Data, History, Web Data, the
Local Storage LevelDB - sit far below the cap. Files above it are skipped **and
counted**, and the count is reported.

**`RULE_PREFIX = "BRUHWSER"`,** deliberately, while the user-facing product name is
lowercase `bruhswer`. These are genuinely different strings (`WSER` vs `SWER`), so
renaming would be a migration, not a case change - and the failure mode is that the app
fails closed on "rule not present" while two perfectly good rules sit on the host under
the old name, stopping the browser launching for a cosmetic rename.

**`BLOCKED_IPV4`.** Measured effective in Stage 4 gate A16: the router became
unreachable (`ERR_NETWORK_ACCESS_DENIED`) while the internet stayed up, because traffic
*routed through* the gateway is not traffic *addressed to* it. `100.64.0.0/10` (CGNAT)
is deliberately excluded - some ISPs and mobile hotspots put the user's own path to the
internet inside it, and brief SS19 says not to block ranges legitimate operation
depends on. `BLOCKED_IPV6` is separate on purpose (SS23): IPv4 rules do not protect
IPv6.

**`DEV_SERVICE_PORTS`.** Not enforceable, and listed only so the UI can be specific
about what stays exposed. Windows Firewall does not filter loopback, so no rule stops
the browser reaching these - measured in gate A16 and confirmed against a live PyCharm
service.

**`BASE_EDGE_FLAGS`.** Two entries are measurements rather than tidiness. Without the
`--disable-features` entry, a fresh profile launched with only `--no-first-run` ended
up on an ad/redirect page ("Redirecting... and 1 more page"); with it, the profile
opens exactly the page that was asked for. `--disable-sync` was added late, after a
windowed launch with a brand-new profile signed itself into the Windows account and
recorded sync consent - a "disposable" profile arriving already carrying the user's
identity and synced favourites, which made the disposable-session claim materially
wrong. Measured twice on a fresh profile: without the flag, `account_info=1`, email
present, `sync_consent=True`; with it, `sync_consent=None`. So it stops the sync. It
does **not** stop the sign-in - the account record is still written, and no
command-line switch prevents that. Only machine-wide Edge policy (`BrowserSignin=0`)
would, and bruhswer refuses to write policy that changes every Edge instance on the PC.
The residual is reported as `NOT ENFORCEABLE` by
`privacy_guard.verify_account_signin()`, never hidden.

`--no-sandbox`, `--disable-web-security`, `--ignore-certificate-errors`,
`--allow-running-insecure-content` and `--disable-site-isolation-trials` are never
used: they would disable the only real process boundary this architecture has (gate
A3). They sit in `DANGEROUS_FLAGS`, which `edge.build_command` refuses to launch with.

**There is no IPC, and that is the design.** An earlier iteration reserved a named pipe
(`\\.\pipe\bruhswer-control`) and a verb allow-list for a channel between the UI and
the controller. It was never built, because it was never needed - both run in the same
Python process, so the UI calls `Controller` methods directly and nothing has to be
serialised, parsed, authenticated or authorised. The reserved constants were deleted
rather than kept "for later": Stage 4 measured that a compromised browser process can
reach `127.0.0.1` and that no firewall rule stops it, so any local control endpoint is
reachable by the exact thing bruhswer exists to contain. A dormant pipe name in config
is an invitation to implement one; a documented refusal is not.
`tests/test_security.py` asserts bruhswer's source opens no listening socket and no
named pipe at all.

### `verdict.py` - the vocabulary

`Check`, `Verdict`, and the rule that `UNKNOWN` is not `PASS`. A check marked
`enforceable=False` renders as `NOT ENFORCEABLE`, never green, and never blocks launch
- because blocking on a platform limitation would just mean the app never starts.

Every `Check` also declares an `EvidenceKind` - `LIVE` ("measured now"), `READ_BACK`
("configuration read back; enforcement not observed"), `HISTORICAL` ("earlier
measurement, not re-run now"), or the weakest, `INFERENCE` ("reasoned, not measured").
"The check passed" and "how bruhswer knows" are different claims, and a check that
forgets to declare its kind gets the weakest one by default rather than the strongest -
a test fails the build if any shipped check is left on that default. Where a `Check`
reports `UNKNOWN`, an `UnknownReason` says which of several different situations that
is - a query that failed, an artefact nobody could read, a property no measurement has
ever established - so "could not measure" and "measured, and it was fine" can never
collapse into the same result the way they once did
(`tests/test_overclaim_regressions.py` pins the specific defects this closed).

---

## What happens at launch

```
1. ensure_dirs()            everything under %LOCALAPPDATA%\BRUHWSER, nowhere else
2. sweep_orphans()          remove disposable profiles and quarantines left by a crash
3. DPI awareness            before any window exists, or Edge renders at the wrong scale
4. Controller.verify()      every guard runs; 31 checks
        |
        +-- any critical check not PASS?  --> BRUH. NO. No browser. No override.
        |
5. session_manager.create() persistent, or a fresh disposable profile
6. browser_guard.harden()   ACLs, then a real write/read probe to prove usability
7. privacy_guard.apply()    preferences written into the profile
8. verify_all() again       including the download directory, now that it is set
9. edge.launch(argv)        explicit argv, shell=False, no dangerous flags
10. embed.host_window()     Edge's window reparented into the frame, input queues joined
11. VerifyWorker.start()    re-verification begins: every check again, once a minute,
                            for as long as the session stays open
```

Steps 4 and 8 are the reason the app exists. Everything else is plumbing around them.
Step 11 exists because they are not the only moment a control can stop holding - a
firewall rule deleted by another admin tool, or an Edge update, does not wait for the
next launch to happen. The status lights describe step 11's latest pass, not step 4's or
step 8's, for as long as a session is open.

---

## The trusted computing base

If you are reviewing this and want to know what actually matters, read these and skip
the rest. A security decision made anywhere else is a bug.

| Module | Why it is in the TCB |
|---|---|
| `security/verifier.py` | The only thing that decides whether the browser may launch |
| `security/browser_guard.py` | Profile confinement, ACLs, command-line inspection |
| `network/network_guard.py` | Firewall policy verification |
| `sysquery.py` | The only place an external program is ever run |
| `browser/edge.py`, `browser/urls.py` | Launch argv construction, URL refusal |
| `sessions/session_manager.py` | Session destruction, reparse-point handling |
| `downloads/quarantine.py` | Quarantine paths and export |
| `config.py`, `verdict.py` | Constants, and the rule that UNKNOWN is not PASS |

**3,255 lines of the application's 8,716.** The remaining 5,461 are UI, window hosting,
orchestration and presentation. They can be wrong without a security property being
wrong, which is the point of keeping the split visible.

Not in the TCB, and deliberately so: everything under `ui/` (it renders verdicts, it
never computes one), `browser/embed.py` (Win32 window reparenting), `host/host_guard.py`
(advisory only, changes nothing by itself), and everything in `/tools` at the repository
root, which is research tooling that does not ship.

---

## Trust boundaries, and which ones are ours

```
hostile page  ->  renderer        Edge's sandbox. AppContainer, UNTRUSTED integrity.
                                  NOT bruhswer's boundary. Measured, not assumed.

renderer      ->  browser process Chromium's boundary. The broker runs on an ordinary
                                  user token and is NOT sandboxed. bruhswer does not
                                  claim to contain it.

browser       ->  bruhswer        OURS. No listener, no IPC, no browser-controlled
                                  value reaching a path, an argv element or a
                                  PowerShell string.

bruhswer      ->  Administrator   OURS. The app is unelevated. Privileged changes live
                                  in tools/*.ps1, run knowingly, with a confirmation
                                  word and a recorded rollback.
```

## What this architecture does not do

It is not a virtual machine and there is no hypervisor. It does not sandbox the browser
process. It cannot filter loopback, because Windows Firewall cannot. It runs as the
user, so it cannot defend against anything else running as the user.

Those are properties of the design, stated here so they are not mistaken for gaps.
See [`LIMITATIONS.md`](LIMITATIONS.md).
