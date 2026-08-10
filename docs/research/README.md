# Research archive

**None of this describes the current implementation.**

These are the investigations that produced bruhswer's design, including the ones that
failed. They are kept because the evidence is the interesting part: three isolation
backends were built and measured before the current architecture was chosen, and two of
them were rejected on data rather than on taste.

For what bruhswer actually is today:

| | |
|---|---|
| [`../ARCHITECTURE.md`](../ARCHITECTURE.md) | current architecture |
| [`../SECURITY-MODEL.md`](../SECURITY-MODEL.md) | current threat model and guarantees |
| [`../LIMITATIONS.md`](../LIMITATIONS.md) | current measured boundaries |
| [`../PROJECT-HISTORY.md`](../PROJECT-HISTORY.md) | the chronology, and why each backend was dropped |

---

## What is in here

### Stage 1 - original design (WSL2 backend)

Written before any implementation existed. Marked "design only" in their own headers.

| Document | Note |
|---|---|
| `THREAT-MODEL.md` | The original threat model. **Superseded** by `../SECURITY-MODEL.md` |
| `ARCHITECTURE.md` | The original architecture. **Superseded** by `../ARCHITECTURE.md` |
| `STAGE-1-SECURITY-DESIGN.md` | The original security entry point. Was `docs/SECURITY.md` until the 0.9.0 publication pass |
| `IMPLEMENTATION-PLAN.md` | The original staged plan |

### Stage 2 - WSL2 measured and rejected

| Document | Note |
|---|---|
| `STAGE-2-RESULTS.md` | The gate results that killed the WSL2 backend. Guest-to-host traffic bypassed guest-scoped firewall rules via SNAT (G3, G8), so the network boundary was not enforceable |

### Stage 2.5 - Hyper-V and QEMU evaluated and rejected

| Document | Note |
|---|---|
| `HYPERV-ARCHITECTURE.md`, `HYPERV-THREAT-MODEL.md`, `HYPERV-VERIFICATION.md` | The Hyper-V replacement design and what was measured |
| `B17-QEMU-PROVENANCE.md` | Supply-chain analysis of the QEMU binaries. The gate that rejected them: adding a large unaudited trust root contradicts the project's central argument. Explicitly **not** a claim that the binaries are malicious |
| `BACKEND-REDESIGN.md`, `BACKEND-THREAT-MODEL.md`, `BACKEND-VERIFICATION.md` | The backend reassessment after both rejections |

### Stage 4 - the measurements the current design rests on

The most load-bearing documents in this folder. Several current guarantees trace
directly back to gates recorded here.

| Document | Note |
|---|---|
| `STAGE-4-VERIFICATION.md` | The gate results. A3 (Edge renderers are AppContainer/UNTRUSTED), A4 (the browser process is an ordinary user token), A16 (program-scoped rules block the router but **not** loopback), A17 (the browser cannot alter its own rules) |
| `STAGE-4-ARCHITECTURE.md`, `STAGE-4-THREAT-MODEL.md` | The design that followed from them |

### Stages 6 and 7 - the implemented product

| Document | Note |
|---|---|
| `STAGE-6-RESULTS.md` | Privacy comparison against stock Edge, and the download-directory defect |
| `STAGE-7-HOSTGUARD-VALIDATION.md` | Host Guard applied, verified, rolled back and re-measured on a real host |

---

## Reading these safely

1. **Check the header.** Every document states its status and date. Several say "design
   only, no implementation".
2. **A rejected design is not a bug.** WSL2 and QEMU were dropped for measured reasons
   recorded in these files.
3. **Machine-specific values are sanitised.** Addresses, hostnames and the network SSID
   were replaced with neutral equivalents before publication. Technical findings were
   left intact.
4. **Where a measurement still stands, it is cited from the current docs.** If the
   current documentation does not reference it, treat it as history.
