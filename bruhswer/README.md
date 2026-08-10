# 🗿 bruhswer - source layout

> **This is the developer-facing map of the source tree.**
> For what bruhswer is, what it protects, what it does not, how to install it and its
> security model, read the **[root README](../README.md)**.

This file deliberately makes **no security claims and quotes no test counts.**

It used to. It claimed "114 assertions across 6 suites" in one place and "86 assertions
in 5 suites" in another - two numbers, in one file, both wrong by the time anyone read
them. Two documents describing the same security properties will always drift apart,
and the version nobody is watching is the one that ends up lying. So the claims live in
exactly one place each now, and this file points at them.

| What you want to know | Where it actually lives |
|---|---|
| What bruhswer is and does | [root README](../README.md) |
| Current verified state, test counts, limitations | [docs/RELEASE-CANDIDATE.md](../docs/RELEASE-CANDIDATE.md) |
| Threat model | [docs/SECURITY-MODEL.md](../docs/SECURITY-MODEL.md) |
| Architecture | [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) |
| What is stored on disk, and encryption decisions | [docs/DATA-INVENTORY.md](../docs/DATA-INVENTORY.md) |
| Network and privacy measurements | [docs/NETWORK-PRIVACY.md](../docs/NETWORK-PRIVACY.md) · [docs/PRIVACY.md](../docs/PRIVACY.md) |
| Reporting a vulnerability | [SECURITY.md](../SECURITY.md) |
| How the project got here, including rejected designs | [docs/PROJECT-HISTORY.md](../docs/PROJECT-HISTORY.md) |

---

## Running it

```powershell
python bruhswer.py              # the browser
python bruhswer.py --check      # every verification, printed, no UI
python bruhswer.py --hostguard  # host exposure only
python bruhswer.py --panel      # the control panel, without a browser
python bruhswer.py --uninstall  # show and remove what bruhswer left behind
```

Standard library only. No `pip install` step, and there must never be one.

## Running the tests

```powershell
python tests\run_all.py            # every suite, one verdict
python tests\test_security.py      # unit + static analysis only (no browser needed)
```

`run_all.py` reports the counts. Suites needing the firewall policy are reported as
**SKIPPED** rather than passing quietly - a suite that silently does nothing is worse
than one that fails.

## Layout

```
bruhswer.py               entry point and the four text modes
app/
  config.py               every constant. No logic, no derived values, no dynamic input
  verdict.py              Check / Verdict, and the rule that UNKNOWN is not PASS
  sysquery.py             the ONLY place an external program runs. Read-only queries
  logging_setup.py        redacting logger. No telemetry exists anywhere in this tree
  browser/
    edge.py               Edge discovery, signature check, fixed-argv launch
    embed.py              hosting Edge's window inside the frame; DPI; input queues
    tokens.py             reads renderer process tokens, to MEASURE the sandbox
    urls.py               address-bar text -> an http(s) URL, or a refusal
  controller/             session lifecycle. A closed set of verbs; no dispatcher
  security/
    verifier.py           the single place that decides whether launch is allowed
    browser_guard.py      profile ACLs, command line, renderer sandbox measurement
  network/network_guard.py   verifies firewall policy. Never applies it
  host/host_guard.py         what the network can reach on THIS PC. Detects, never changes
  privacy/privacy_guard.py   profile preferences, written then read back
  downloads/quarantine.py    downloads land here; filenames rebuilt from scratch
  sessions/session_manager.py  persistent and disposable profiles, and their destruction
  ui/
    browser_window.py     the browser window
    app_ui.py             the standalone control panel (--panel)
tests/                    run_all.py runs every suite in dependency order
tools/                    the elevated one-shots (PowerShell) and maintenance scripts
```

## Rules for changes

1. **No new dependencies.** Standard library only.
2. **No unverified claim.** If you add a control, add the test. If the platform will
   not let you prove it, it reads `NOT ENFORCEABLE` or `UNKNOWN` - both are acceptable
   answers and neither is a failure.
3. **Nothing may open a listening socket, named pipe or debugging port.** A test parses
   the source and fails the build if that changes.
4. **No browser-supplied value may reach a path, an argv element or a PowerShell
   string.**
