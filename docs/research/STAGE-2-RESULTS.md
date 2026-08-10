# Stage 2 Results - Empirical Security Verification

**Date:** 2026-08-08
**Host:** Windows 11 Home Single Language, build 10.0.26200, Ryzen 7 7840HS, 15.3 GB RAM
**WSL:** 2.7.3.0, kernel 6.6.114.1-microsoft-standard-WSL2
**Guest:** Debian 13 (trixie), disposable, installed for this test only
**Host LAN:** host `10.0.0.50`, router `10.0.0.1`, subnet `10.0.0.0/24`
**WSL NAT:** guest `172.16.0.2/20`, gateway `172.16.0.1`, DNS `10.255.255.254`

## Summary

```
G1  /dev/dxg isolation       FAIL
G2  WSL interop              PASS (with residual)
G3  IPv4 network isolation   FAIL
G4  IPv6 isolation           UNKNOWN
G5  RDP isolation            UNKNOWN (not reached - stop condition)
G6  Shared utility VM        PASS (shared VM confirmed; MX-1 necessary)
G7  Filesystem isolation     PASS (with residual)
G8  Firewall enforcement     FAIL
```

**Recommendation: REVISE ARCHITECTURE AND REPEAT STAGE 2.** Rationale in §Recommendation.

---

## Baseline: WSL defaults before any hardening

Recorded first, because it establishes what the defaults actually expose.

```
--- /dev/dxg ---
crw-rw-rw- 1 root root 10, 125 Aug  8 17:23 /dev/dxg

--- /proc/mounts (host filesystem) ---
C:\134 /mnt/c 9p rw,noatime,aname=drvfs;path=C:\;uid=0;gid=0;symlinkroot=/mnt/,...

--- read host project sentinel ---
BM_STAGE2_SENTINEL_7f3a9c21_REPO_MUST_NOT_BE_READABLE_FROM_GUEST

--- host user profile listing ---
AppData / Contacts / Cookies / Desktop / Documents / Downloads / Favorites /
NTUSER.DAT / ntuser.dat.LOG1 / ...

--- Windows PATH entries leaked into guest ---
35
```

By default the guest read the project sentinel, listed the entire host user profile, and received a `PATH` disclosing the host username, the project directory, and an inventory of installed software (Python 3.10/3.11/3.13, Node, Git, GitHub CLI, GitHub Desktop, Ollama, LM Studio, npm, NVIDIA, dotnet).

**Consequence:** WSL's out-of-the-box configuration is unusable for this project. Confirms Stage 1 §6 "dangerous defaults."

---

## G1 - `/dev/dxg` isolation - **FAIL**

**Claim:** `[wsl2] guiApplications=false` removes `/dev/dxg`, eliminating surface S3 (GPU paravirtualisation to host `dxgkrnl`).

**Configuration:** `%UserProfile%\.wslconfig` → `guiApplications=false`; WSL VM restarted via `wsl --shutdown`.

**Expected:** `/dev/dxg` absent.

**Observed:** `/dev/dxg` **present**, world read/write, and **openable read-write by an unprivileged user** - the exact privilege level the browser would run at.

```
--- G1: /dev/dxg ---
crw-rw-rw- 1 root root 10, 125 Aug  8 17:25 /dev/dxg
--- find /dev -name "*dxg*" ---
/dev/dxg
--- openability ---
RESULT: root OPENED /dev/dxg rw
RESULT: UNPRIVILEGED user OPENED /dev/dxg rw
--- WSLg env after guiApplications=false ---
WSL2_GUI_APPS_ENABLED=[]  PULSE_SERVER=[]
```

`guiApplications=false` **did** disable WSLg (env vars cleared, `/mnt/wslg` no longer populated), so surface **S5 is eliminated**. It did **not** remove the dxgkrnl device node.

**Verdict: FAIL.**

**Security consequence:** S3 is **residual, not eliminated**. An unprivileged compromised browser process in the guest has a direct ioctl interface to the host's `dxgkrnl` kernel driver. This is a guest→host kernel attack surface with prior CVE history, and it is reachable at exactly the privilege level the threat model assumes an attacker reaches (T3/T4).

**Architecture consequence:** `THREAT-MODEL.md` S3 changed from "Target: eliminated" to "Residual." Any claim that GPU paravirtualisation is removed must not be made. Mitigation would require removing the device node inside the guest (guest-side, therefore defeated by T4) or a backend that does not expose `/dev/dxg`.

---

## G2 - WSL interop - **PASS (with residual)**

**Claim:** `[interop] enabled=false` + `appendWindowsPath=false` prevents guest→host Windows execution while host→guest `wsl.exe` still works.

**Important negative control:** at baseline, before hardening, the `WSLInterop` binfmt handler was *absent* and PE execution already failed. That absence is **incidental** - it is a known interaction with systemd's binfmt unit (Debian ships `[boot] systemd=true`), not a security control. After restart the handler *was* registered. **This project must not rely on it.**

**Observed after hardening:**

```
--- WSL_INTEROP env var ---   WSL_INTEROP=[]                (cleared)
--- Windows PATH entries ---  0                             (cleared)
--- full PATH ---  /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/lib/wsl/lib
--- binfmt handlers ---       register  status  WSLInterop   (handler IS registered)
--- execute staged Windows PE (hostname.exe copied into guest fs) ---
<3>WSL (217 - ) ERROR: UtilAcceptVsock:273: accept4 failed 110
RESULT: guest->host EXEC BLOCKED
--- host->guest control path ---
wsl.exe -d Debian -u root -- ... exit=0     (works)
```

**Verdict: PASS.** The required asymmetry holds: host→guest allowed, guest→host execution blocked. The block is enforced **host-side** - the guest's binfmt handler attempted a vsock connection and the host refused it (errno 110, ETIMEDOUT). Enforcement outside the guest is the correct place.

**Residual - the surface is refused, not removed:**

```
--- /run/WSL interop sockets ---
lrwxrwxrwx 1_interop -> /run/WSL/2_interop
srwxrwxrwx 2_interop
--- connect test ---
RESULT: CONNECTED to /run/WSL/2_interop
RESULT: CONNECTED to /run/WSL/1_interop
```

Guest code can still **connect** to the interop unix sockets. Only the execution relay is refused at the host end.

**Architecture consequence:** `THREAT-MODEL.md` S4 reworded from "eliminated" to "execution refused host-side; interop endpoint still reachable from the guest." The socket remains attack surface against `wslservice.exe` (S6, LocalSystem). Stage 2 did not fuzz that protocol; that is unquantified residual risk.

---

## G3 - IPv4 network isolation - **FAIL**
## G8 - Hyper-V Firewall enforcement - **FAIL**

Reported together because they share one body of evidence.

**Claim:** Host-side Hyper-V Firewall with `DefaultOutboundAction=Block` plus a minimal allowlist gives internet access while preventing the guest reaching host services, localhost, router, and LAN devices.

**Configuration applied** (elevated, `tools/stage2/apply-hyperv-firewall.ps1`, VMCreatorId `{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}`):

```
DefaultInboundAction  : Block
DefaultOutboundAction : Block
LoopbackEnabled       : False
AllowHostPolicyMerge  : False        (also tested as True - no difference)

Deny  (priority 100/101): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
                          169.254.0.0/16, 127.0.0.0/8, fc00::/7, fe80::/10
Allow (priority 1000+) : TCP 80, TCP 443, UDP 443
```

**Pre-firewall baseline (default `DefaultOutboundAction=Allow`):**

```
HOST LAN IP  smb        10.0.0.50    :445   REACHABLE
HOST LAN IP  rpc        10.0.0.50    :135   REACHABLE
ROUTER admin            10.0.0.1      :80    REACHABLE
ROUTER https            10.0.0.1      :443   REACHABLE
INTERNET                1.1.1.1         :443   REACHABLE
```

**Post-firewall, repeated twice, stable:**

```
INTERNET tcp443         1.1.1.1         :443   REACHABLE          (allowed - correct)
INTERNET tcp80          1.1.1.1         :80    REACHABLE          (allowed - correct)
INTERNET tcp22          1.1.1.1         :22    timeout(filtered)  (blocked - correct)
ROUTER 80               10.0.0.1      :80    timeout(filtered)  (blocked - correct)
ROUTER 443              10.0.0.1      :443   timeout(filtered)  (blocked - correct)
HOST LAN 443            10.0.0.50    :443   timeout(filtered)
HOST LAN 3389           10.0.0.50    :3389  timeout(filtered)
NAT GATEWAY             172.16.0.1     :53    timeout(filtered)
169.254 metadata        169.254.169.254 :80    timeout(filtered)

HOST LAN smb 445        10.0.0.50    :445   REACHABLE   <-- FAIL
HOST LAN rpc 135        10.0.0.50    :135   REACHABLE   <-- FAIL
WSL hostfwd             10.255.255.254  :53    REACHABLE   <-- FAIL
```

**What works:** the egress port allowlist is enforced (port 22 blocked). LAN devices including the router are blocked. Host ports with no listener are blocked.

**What fails:** the guest reaches host services on **445 (SMB)** and **135 (RPC)** despite an explicit `Block` rule covering `10.0.0.0/8` and a default outbound action of `Block`. It also reaches `10.255.255.254`, WSL's host-forwarding address, through which DNS flows.

**Mechanism - determined, not assumed.** While the guest held a connection open, the host was inspected:

```
--- HOST view, established connections on port 445 ---
LocalAddress   LocalPort  RemoteAddress   RemotePort  OwningProcess
10.0.0.50   445        10.0.0.50    52256       4

--- established connections from WSL subnet 172.16.x ---
NONE
```

The connection **is real and terminates on the host's kernel SMB server** (`OwningProcess 4` = System). Its `RemoteAddress` is `10.0.0.50` - **the host's own LAN IP**, not the guest's `172.16.0.2`. Guest traffic to the host is source-NAT'd to the host's own address before it reaches the host TCP stack, so guest-scoped Hyper-V Firewall rules never match it, and the host firewall sees what looks like a host-to-host connection.

`LoopbackEnabled=False` did not prevent it. `AllowHostPolicyMerge=False` did not prevent it. The port-based allowlist did not prevent it (445 is not in the allowlist, yet it connects).

Note the ports that fail are precisely the ports where the host has a listener; ports without a listener time out. This is consistent with the SNAT explanation and inconsistent with the deny rules being applied at all on this path.

**Verdict: G3 FAIL, G8 FAIL.**

**Security consequence - stated at exactly the level proven.** What was measured is that the guest **completes a TCP connection** to the host's SMB (445) and RPC (135) listeners, terminating on host PID 4, despite host-side rules that should have blocked it. That alone means **TB-3 is not established** for the guest→host direction, and it alone blocks Stage 3.

**What was NOT established:** whether the guest can actually *speak* SMB or RPC over that connection. The single protocol probe attempted sent deliberately malformed bytes and returned `TimeoutError` with no data, which is inconclusive in both directions. No SMB negotiate, authentication, or share access was demonstrated.

The distinction matters for severity, not for the verdict:

- *Proven:* a TCP-reachable path from an untrusted guest to a historically vulnerable host kernel service that host-side policy was configured to deny.
- *Not proven:* a usable SMB/RPC session, and therefore not NTLM coercion/relay or protocol-level attack. **Do not claim these until tested.**

**First test when Stage 2 repeats:** send a well-formed SMB2 `NEGOTIATE_PROTOCOL` request over that connection and record whether a valid SMB2 response header comes back. That single result decides whether this is "an unexpectedly reachable port" or "a usable protocol path from hostile code to the host kernel."

**Architecture consequence.** The Stage 1 claim that Hyper-V Firewall provides host-side network enforcement for the WSL guest is **disproven for the guest→host direction**. It remains valid for guest→LAN and guest→internet-port-allowlisting. `ARCHITECTURE.md §6` and `SECURITY.md §4` corrected. Guest-side `nftables` is explicitly **not** an acceptable substitute (a T4 attacker removes it), so this cannot be closed inside the guest.

---

## G4 - IPv6 isolation - **UNKNOWN**

**Claim:** IPv6 cannot bypass the IPv4 boundary.

**Observed:**

```
--- guest IPv6 addresses ---
::1/128 scope host
fe80::215:5dff:fe56:366b/64 scope link
--- guest IPv6 routes ---
fe80::/64 dev eth0 proto kernel metric 256
--- connectivity ---
IPv6 loopback ::1              ConnectionRefusedError (nothing listening)
IPv6 public 2606:4700:4700::1111  OSError 101 Network is unreachable
--- host IPv6 ---
Wi-Fi adapter has NO IPv6 address assigned
```

The guest has only link-local IPv6 and no default IPv6 route, because **the host's network has no IPv6 at all**. Public IPv6 was unreachable for environmental reasons, not because a control blocked it.

Additionally, one intended control could not be expressed:

```
GAP: platform REJECTED ::1     -> The parameter is incorrect (Windows error 87)
GAP: platform REJECTED ::1/128 -> The parameter is incorrect (Windows error 87)
```

`New-NetFirewallHyperVRule` accepts `fc00::/7` and `fe80::/10` but rejects both forms of the IPv6 loopback address. (Blocking the guest's own loopback there is close to meaningless anyway - guest loopback traffic never traverses the vNIC.)

**Verdict: UNKNOWN.** The test environment cannot exercise IPv6. Absence of IPv6 connectivity here is a property of this Wi-Fi network, not of the design. On an IPv6-capable network the result could differ, and given the G3 SNAT finding there is specific reason to expect the same bypass to exist over IPv6.

**Architecture consequence:** IPv6 must be explicitly disabled inside the guest as a positive control, and re-tested on an IPv6-capable network before any IPv6 claim is made. No IPv6 claim may be made now.

---

## G5 - RDP display isolation - **UNKNOWN (not reached)**

Not tested. Work stopped at the G3/G8 failure, which is a hard stop condition under the Stage 2 brief §22 ("host-side network enforcement does not work").

Testing G5 first would also have required an inbound host→guest allow rule, and building a display path on top of a network boundary already known to be broken would produce a misleading result.

One relevant observation was recorded incidentally: `DefaultInboundAction=Block` on the WSL VM will block host→guest RDP, so the display path will require an explicit inbound allow rule that does not yet exist.

**That is now a design problem, not just a deferred test.** The needed inbound rule sits on **the same enforcement path that G3/G8 just showed to be unreliable**. Since guest→host traffic bypasses guest-scoped rules via SNAT, it is no longer safe to assume the symmetric case works either: whether a host→guest inbound allow rule can be scoped tightly enough to admit the RDP display path *without* also widening guest exposure is now an **open question** rather than an assumption. It must be answered before the display path is built, and it is a consequence of the G3/G8 failure.

**Verdict: UNKNOWN.**

---

## G6 - Shared utility VM - **PASS (shared VM confirmed)**

**Claim:** All WSL distributions share one utility VM, so MX-1 (mode mutual exclusion) is necessary.

**Method:** exported the test distro, imported it as a second distribution `bm-t2`, ran both, compared kernel instance identity.

```
--- Debian ---                                    --- bm-t2 ---
boot_id=7186b8d8-13b8-42b3-b3a7-69fdfb6b4b25      boot_id=7186b8d8-13b8-42b3-b3a7-69fdfb6b4b25
uptime=352.59                                     uptime=353.91
kernel=6.6.114.1-microsoft-standard-WSL2          kernel=6.6.114.1-microsoft-standard-WSL2
init_pid1=systemd                                 init_pid1=systemd
```

`/proc/sys/kernel/random/boot_id` is regenerated on every kernel boot. **Identical boot_id plus near-identical uptime proves a single kernel instance**, i.e. one shared utility VM.

Namespace separation was also measured - a `sleep` process started in `Debian` was **not** visible from `bm-t2` (`sleep procs visible: 0`), and each distro has its own PID 1.

**Verdict: PASS.** Distributions share one VM and one kernel; they are separated only by Linux namespaces.

**Architecture consequence:** MX-1 is confirmed **necessary** and stays a controller invariant. Separation between Mode A and Mode B is container-grade, not hypervisor-grade, exactly as Stage 1 stated.

---

## G7 - Host filesystem isolation - **PASS (with residual)**

**Claim:** With `[automount] enabled=false` and `mountFsTab=false`, no host filesystem is exposed.

**Observed after hardening:**

```
--- /proc/mounts, host filesystems ---
drivers /usr/lib/wsl/drivers 9p ro,nosuid,nodev,noatime,aname=drivers;fmask=222;dmask=222,...
(no /mnt/c entry)

--- read host project sentinel ---
cat: '/mnt/c/Users/.../browser maker/STAGE2-SENTINEL.txt': No such file or directory
RESULT: SENTINEL UNREADABLE

--- host user profile ---
ls: cannot access '/mnt/c/Users/youruser/': No such file or directory
```

The development-host boundary holds: the project repository, `.git`, `.venv`, PyCharm config, Desktop, Documents, Downloads, host browser profiles and credential stores are **not reachable**. `/mnt/c` remains as an empty directory (a leftover mount point), not a mount.

**Residual - one host filesystem path remains exposed:**

```
--- /usr/lib/wsl/drivers contents ---
1394.inf_amd64_...  3ware.inf_amd64_...  acpi.inf_amd64_... (851 entries)
--- writable? ---
touch: cannot touch '...': Read-only file system
```

A read-only 9p mount exposes **851 Windows driver packages** from the host DriverStore, mounted `ro,nosuid,nodev` with `fmask=222,dmask=222` (no execute, no write). No user data. It is an **information disclosure**: it reveals the host's exact hardware and driver-version inventory, which is useful to an attacker selecting an exploit. It is also live host-backed 9p surface reachable from the guest.

**Verdict: PASS** for the assets the threat model protects, **with a documented residual**.

**Architecture consequence:** `THREAT-MODEL.md` S7 updated - "no host path mounted" is not accurate; the accurate statement is "no host *user data* is mounted; a read-only driver store mount remains."

---

## Privilege model verification - **PASS**

| Requirement | Result |
|---|---|
| Runtime read of Hyper-V Firewall state without elevation | **PASS** - `Get-NetFirewallHyperVRule` / `...VMSetting` succeeded unelevated (16 rules enumerated) |
| Write refused without elevation | **PASS** - `Set-NetFirewallHyperVVMSetting` returned `Access is denied` unelevated |
| Distro install without elevation | **PASS** - `wsl --install -d Debian --no-launch` succeeded unelevated |
| All guest control host→guest via fixed argv | **PASS** - every guest command used `wsl.exe` with fixed arguments; no `shell=True`, no `eval`, no `exec`, no dynamic code generation |
| No generic command execution primitive built | **PASS** - none created |
| Elevation isolated to a separate interactive script | **PASS** - only `tools/stage2/apply-hyperv-firewall.ps1`, run interactively via UAC, with all values fixed in source and no runtime-supplied arguments |

The Stage 1 privilege split (`ARCHITECTURE.md §10`) is **confirmed viable**: fail-closed check #4 is runnable by an unelevated runtime.

---

## Security findings (unexpected results)

1. **`/dev/dxg` survives `guiApplications=false` and is openable by an unprivileged user.** (G1)
2. **The guest reaches the host's SMB and RPC services despite host-side Block rules**, because guest→host traffic is SNAT'd to the host's own IP and never matches guest-scoped rules. (G3/G8) - most serious.
3. **`10.255.255.254` (WSL host-forwarding) is not filterable** by the 10/8 deny rule; DNS flows through it.
4. **Interop unix sockets remain connectable** from the guest even with `interop.enabled=false`; only the exec relay is refused. (G2)
5. **The absence of the binfmt interop handler at baseline was incidental** (systemd interaction), not a control - a trap for anyone testing casually.
6. **`New-NetFirewallHyperVRule` rejects `::1` and `::1/128`** (Windows error 87), so that range is not expressible.
7. **The `Priority` column renders blank** on created Hyper-V rules, so rule precedence is not introspectable; it had to be inferred from behaviour.
8. **`DefaultInboundAction=Block` will block the planned host→guest RDP display path**, which needs an inbound rule not yet designed.
9. **The default `PATH` leak** discloses host username, project path, and installed-software inventory even without any exec capability.

---

## Architecture changes required

| Document | Change |
|---|---|
| `THREAT-MODEL.md` S3 | "Target: eliminated" → **Residual**. `/dev/dxg` is not removable via `guiApplications=false`. |
| `THREAT-MODEL.md` S4 | "eliminated" → **execution refused host-side; interop sockets still reachable**. |
| `THREAT-MODEL.md` S7 | "eliminated (mounts)" → **no host user data mounted; read-only driver-store 9p mount remains**. |
| `THREAT-MODEL.md` S8, TB-3 | Host-side network enforcement **does not hold for guest→host**. TB-3 is not established. |
| `ARCHITECTURE.md §6` | Network design invalidated for the guest→host direction; rewritten to state what is and is not enforceable. |
| `ARCHITECTURE.md §1` | Hyper-V Firewall enforcement row: `[ASSUMPTION]` → `[MEASURED] - partial, fails guest→host`. |
| `SECURITY.md §4` | Weakness 3 upgraded from "unverified" to **measured failure**. |
| `IMPLEMENTATION-PLAN.md` | Stage 3 blocked pending a resolution to the guest→host network gap. |

MX-1 is **unchanged and confirmed necessary** (G6).

---

## Residual risks now measured rather than assumed

1. `/dev/dxg` → host `dxgkrnl` ioctl surface, reachable unprivileged. **Measured.**
2. Guest → host SMB (445) and RPC (135). **Measured, reproducible.**
3. Guest → `10.255.255.254` host-forwarding path. **Measured.**
4. Guest → interop unix sockets → `wslservice.exe` (LocalSystem). Connectable; protocol not fuzzed. **Partly measured.**
5. Read-only exposure of 851 host driver packages. **Measured.**
6. IPv6 behaviour entirely untested. **Unknown.**
7. Hypervisor escape. Unchanged, unmitigated.

---

## Host change audit

Every change made to Windows during Stage 2, and its final state.

| # | Change | Disposition |
|---|---|---|
| 1 | Installed WSL distribution `Debian` (unelevated, `wsl --install -d Debian --no-launch`) | changed → tested → **restored** (`wsl --unregister Debian`) |
| 2 | Imported WSL distribution `bm-t2` from a local export (G6) | changed → tested → **restored** (`wsl --unregister bm-t2`) |
| 3 | Created `%UserProfile%\.wslconfig` (did not exist before; nothing to back up) | changed → tested → **restored** (deleted) |
| 4 | Created `/etc/wsl.conf` inside the test distro | removed with the distro |
| 5 | Hyper-V Firewall VM setting `{40E0AC32-…}`: Outbound `Allow`→`Block`, Loopback `True`→`False`, HostPolicyMerge `True`→`False` | changed → tested → **restored** to `Block/Allow/True/True` |
| 5a | *Provenance note for the restore:* the state file captured at 17:30:34Z held four fields and not `AllowHostPolicyMerge`. Its original value `True` was read in the diagnostic call that ran **after** the apply script succeeded but **before** `-AllowHostPolicyMerge False` was added to that script in a later edit. `True` is therefore the genuine untouched value, not a guess. | verified against transcript |
| 6 | 10 Hyper-V Firewall rules named `BM-Stage2-*` | changed → tested → **restored** (0 remain) |
| 7 | Scratch directory `%LOCALAPPDATA%\bm-stage2` (export tar, VHDX, logs, state file) | changed → tested → **restored** (deleted) |
| 8 | Sentinel file `STAGE2-SENTINEL.txt` in the project directory | changed → tested → **restored** (deleted) |
| 9 | `apt-get install python3-minimal curl iproute2 iputils-ping` **inside the guest** | removed with the distro; no host effect |
| 10 | Two elevated runs of `apply-hyperv-firewall.ps1` + one of `revert-hyperv-firewall.ps1`, each via interactive UAC | consent given per invocation |
| 11 | New repository files: `tools/stage2/apply-hyperv-firewall.ps1`, `tools/stage2/revert-hyperv-firewall.ps1`, `docs/STAGE-2-RESULTS.md`, edits to four Stage 1 docs | **retained deliberately** - these are project deliverables |

**Not changed at any point:** Windows Defender, SmartScreen, Windows Firewall profiles, Secure Boot, VBS, HVCI, ASLR/DEP/CFG, the registry, services, scheduled tasks, startup entries, drivers, certificates, proxy settings, host DNS, host network configuration, and Windows optional features. No third-party hypervisor, kernel driver, or virtualization product was installed. `-ExecutionPolicy Bypass` was used process-scoped only for the two local scripts; no machine execution policy was modified.

**Verified final state (measured after cleanup):**

```
WSL distros:         none
.wslconfig:          absent          scratch dir: absent      sentinel: absent
Hyper-V VM setting:  DefaultInboundAction=Block  DefaultOutboundAction=Allow
                     LoopbackEnabled=True        AllowHostPolicyMerge=True
BM-Stage2 rules:     0
Defender realtime:   True
Firewall profiles:   Domain=True  Private=True  Public=True
Secure Boot: 1       VBS status: 2 (running)     HVCI: 1
```

The host is in its pre-Stage-2 state.

### Test-safety compliance

No real credentials, API keys, SSH keys, password-manager data, personal files, or the real browser profile were used. The only host file placed within reach of the guest was a synthetic sentinel string. The project repository was never mounted into the guest - at baseline the guest could read it via WSL's default `/mnt/c`, which is itself the finding recorded above; after hardening it was verified unreadable. No malware was executed. No LAN scanning or device enumeration was performed; only the predetermined addresses listed in this document were contacted.

## Recommendation

**REVISE ARCHITECTURE AND REPEAT STAGE 2.**

Not "proceed": G3 and G8 fail on the guest→host axis, and TB-3 - a boundary the Stage 1 design declared load-bearing - is not established. The Stage 2 brief is explicit that guest-side firewall rules are not an acceptable substitute, and they would in any case be removed by the T4 attacker the threat model assumes.

Not "STOP - WSL2 unsuitable" either, because the failure is specific and bounded rather than total. WSL2 delivered: filesystem isolation of all host user data (G7), the host→guest / guest→host execution asymmetry (G2), egress port allowlisting, and LAN/router blocking (G3, partially). What it did not deliver is protection of **host-local services** from the guest.

Three candidate directions, to be decided before Stage 2 repeats:

1. **Close the gap on the host** - remove the listeners rather than filter the path, i.e. restrict the host's own SMB/RPC exposure. This is the **only direction available without changing platform or licence**. It is also the one that most needs an explicit decision, because it modifies host configuration **outside the browser's scope**: a §54 stop-condition class change. **It will not be done unprompted.** It also fixes only the network axis; `/dev/dxg` (G1) would remain.
2. **Change the network path** so guest traffic is not SNAT'd to the host identity. Requires a WSL networking mode that may not exist on this SKU - `mirrored` is strictly worse for isolation, so this may have no viable form. Needs investigation before it can be costed.
3. **Change the isolation backend** - Windows Sandbox / Hyper-V on a Pro SKU, or QEMU+WHPX. A backend whose VM has a real, independently filterable vNIC would not exhibit SNAT-to-host-identity, and need not expose `/dev/dxg` at all.

**Technical recommendation: direction 3.** It is the only direction that resolves **both** failing axes - G3/G8 *and* G1 - and it is the direction the Stage 1 backend matrix already ranked highest before the Home SKU forced the WSL2 choice. The licence and cost decision is the user's; the engineering conclusion is not ambiguous.

Direction 1 is a legitimate interim step if the user wants to stay on this SKU, but it should be understood as narrowing one hole rather than establishing TB-3.
