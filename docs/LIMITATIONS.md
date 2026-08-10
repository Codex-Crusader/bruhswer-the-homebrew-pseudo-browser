# Limitations

**These are measured boundaries, not unfinished work.**

Every item here was tested, found to be unachievable within the platform or within the
scope this project allows itself, and is reported in the product rather than hidden.
Several took real effort to establish. Finding out precisely where a guarantee stops is
the work; pretending it does not stop would be the failure.

Each one lists what was tried, what was measured, and what bruhswer says instead.

---

## 1. Localhost cannot be blocked

**Verdict shown: `NOT ENFORCEABLE`**

Windows Firewall does not filter loopback traffic. A malicious page inside bruhswer can
reach anything listening on your own machine: a dev server, a database admin panel, a
local API.

**What was tried.** Program-scoped firewall rules naming `127.0.0.1` and the host's own
LAN address, the same mechanism that successfully blocks the router and the LAN.

**What was measured.** 19 paths, against real local services, observed **server-side**
(a request that arrives proves reachability regardless of what CORS then does to the
response):

| Path | Result |
|---|---|
| `localhost` by name | REACHED |
| `127.0.0.1` | REACHED |
| `127.0.0.2` (alternate loopback) | REACHED |
| `2130706433` (decimal form) | REACHED |
| `0x7f000001` (hex form) | REACHED |
| IPv6 `[::1]` | REACHED |
| The host's own LAN address | REACHED |
| Page-driven `fetch` GET / POST / WebSocket, to each of the above | REACHED |

**19 of 19 reached.** The rules that block the router simply do not apply to traffic
that never leaves the machine.

**What bruhswer does instead.** Reports `NOT ENFORCEABLE` everywhere the user can see
it - the status bar light is permanently amber - and
`tests/test_localhost_surface.py` **fails the build** if the UI or the policy summary
is ever changed to describe it as anything else. That test asserts on what bruhswer
genuinely controls: that it opens no local endpoint of its own, that it refuses the URL
schemes which would bypass its controls, and that its claims match what was just
measured.

---

## 2. A disposable session is fresh, but not anonymous

**Verdict shown: `NOT ENFORCEABLE`**

On a windowed launch, Edge signs a **brand-new profile** into the Windows Microsoft
account by itself, within seconds. The account record - email, full name, account id,
tenant id - is written into the profile, synced favourites appear, and sync consent is
recorded. This happens to disposable sessions too.

**What was measured**, on a fresh profile, twice:

| | account record | sync consent |
|---|---|---|
| bruhswer's flags before the fix | present, with email | recorded |
| plus `--disable-sync` | still present | not recorded |

**What was done.** `--disable-sync` is now passed at every launch. It stops the syncing.
It does not stop the sign-in, and no command-line switch does.

**Why it is not fixed further.** The only mechanism that prevents the sign-in is
machine-wide Edge policy (`BrowserSignin=0`), which would change **every** Edge profile
on the PC, including ordinary browsing outside bruhswer. That is far broader than this
project is permitted to be, for the same reason it refuses to write enterprise policy
anywhere else.

**What bruhswer does instead.** `privacy_guard.verify_account_signin()` reads the
profile at every launch and reports `NOT ENFORCEABLE` whenever an account is present.
It never shows green while you are signed in. The email itself is never logged or
displayed. The remedy is real and documented: sign out inside the session, in Edge's
own **Settings -> Profiles**.

Note this was found by taking a screenshot for the README, not by any test suite.

---

## 3. The browser process is not sandboxed

**Not provided, by design**

Chromium's sandbox contains **renderers**. The browser (broker) process runs on an
ordinary user token.

bruhswer measures the renderer sandbox live - reading actual process tokens for
integrity level and AppContainer membership, because that property turned out to be
build-dependent - but it makes no claim about the broker, which can read anything the
user can.

---

## 4. DNS encryption cannot be confirmed

**Verdict shown: `UNKNOWN`**

A local resolver sits in the path on the development machine, so an external diagnostic
cannot see what the browser actually sent. Confirming it would need packet capture,
which needs a driver this project will not install.

bruhswer reports how many encrypted-DNS templates Windows knows about and which
resolvers have no known encrypted option - then says `UNKNOWN`, rather than inferring
"encrypted" from configuration that may not be honoured.

---

## 5. IPv6 is only partly verified

**Partly verified, stated as such**

IPv6 rules for unique-local (`fc00::/7`) and link-local (`fe80::/10`) are applied and
verified as present. IPv6 loopback `[::1]` was measured and reaches, as expected.

What is **not** established is the full routed IPv6 case, because the test network did
not provide IPv6 connectivity. Absence of IPv6 there is a property of that Wi-Fi, not of
the design. It is not labelled PASS.

---

## 6. No VPN

**Verdict shown: `UNSUPPORTED`**

None is configured and no kill switch has been demonstrated. bruhswer will not imply
one exists.

If one were added, these would still hold and would need saying: the VPN provider
becomes a new party that sees your destination traffic; a VPN does not make you
anonymous; websites still identify you; traffic metadata still exists; and signing in to
any account identifies you completely regardless.

---

## 7. No VM isolation

**Not provided**

This was the original design, and it was abandoned on evidence rather than on effort.

- **WSL2** failed its gates: guest-to-host traffic bypassed guest-scoped firewall rules
  via SNAT, so the network boundary was not enforceable.
- **QEMU/WHPX** was rejected on supply chain at gate B17 - it would have added a new,
  large, unaudited trust root, which is exactly what the project's argument forbids.

Both investigations are preserved in [`research/`](research/) and summarised in
[`PROJECT-HISTORY.md`](PROJECT-HISTORY.md). What replaced them is a smaller, honest
claim: a hardened wrapper that measures what it can enforce.

---

## 8. No defence against a compromised host

**Not provided**

bruhswer runs as an ordinary user process. Anything else running as the same user -
malware, another application, a compromised browser broker - can read what bruhswer can
read. A local Administrator can do anything at all.

This is not a gap that user-mode code can close, which is also why bruhswer adds no
encryption at rest: the key would have to be available to the very token you are trying
to defend against. The full reasoning, including a correction to an earlier overclaim,
is in [`DATA-INVENTORY.md`](DATA-INVENTORY.md) section 4.

---

## 9. No fingerprinting resistance

**Not claimed**

bruhswer turns **off collection surfaces** - permissions, WebRTC local-IP exposure,
payment-method presence, search suggestions. It does **not** spoof User-Agent, screen,
timezone, locale, fonts, canvas, WebGL, CPU count or memory.

The reason is measured, not ideological: a browser reporting four cores, a 1000x1000
screen and a UTC timezone on a Windows laptop is **rarer** than one telling the truth,
and rarity is what fingerprinting feeds on. A comparison of 34 properties against stock
Edge found all 9 identity values identical.

So the claim is: bruhswer adds **no fingerprint entropy**. Not that it makes you hard to
fingerprint.

---

## 10. Release artifacts are unsigned

**Not provided**

There is no code-signing certificate for this project. SmartScreen will warn about an
unrecognised publisher, and that warning is correct.

Self-signing a certificate and describing it as trusted publisher authentication was
explicitly refused - it would be precisely the kind of reassuring-but-false signal this
project exists to avoid. Verify the published SHA-256 instead. Signing is on the
[roadmap](ROADMAP.md).

---

## 11. Time-of-check / time-of-use in deletion

**Accepted risk**

The guards that protect recursive deletion resolve a path, confirm it is inside its
expected root and is not a reparse point, and then delete it. In principle the path
could be swapped between the check and the delete.

Closing that needs handle-based APIs Python does not expose on Windows. An attacker able
to win that race is already running as the user, which section 8 states is not defended
against. Documented in `session_manager._safe_to_delete` rather than left as a silent
assumption.

---

## How to read this page

If you are evaluating bruhswer: this list is the point, not the disclaimer. A security
tool that cannot tell you where its guarantees stop has not finished being engineered.

If you are testing bruhswer: [`SECURITY-TESTING.md`](SECURITY-TESTING.md) has the same
list as an "already known" table, plus the things previously tried that did not work -
so you can skip straight to the parts nobody has looked at yet.
