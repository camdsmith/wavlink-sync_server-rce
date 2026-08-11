# WAVLINK `sync_server` — Unauthenticated Remote Root Code Execution

Two vulnerabilities in the `sync_server` mesh-sync daemon shipped in WAVLINK WN535M1 / WN535M3 firmware. Both are exploitable over the network with no credentials, no pairing and no user interaction, and both give root.

| | |
|---|---|
| **Vendor** | Wavlink Technology Limited |
| **Product** | WN535M1 / WN535M3 (*Halo Base Pro*) |
| **Affected firmware** | `M35M1_V210223` (confirmed by vendor) |
| **Fixed firmware** | `M35M1_V250922` (per vendor; intermediate versions unverified) |
| **Component** | `/usr/bin/sync_server`, TCP 13136 |
| **CVE IDs** | Requested from MITRE CNA-LR — *pending assignment* |
| **Reported** | 3 August 2026 |
| **Vendor status** | Confirmed and independently reproduced |

## The issue

`sync_server` listens on TCP 13136 whenever mesh mode is enabled — the out-of-box default on the WN535M1 — and accepts file-transfer messages with no authentication of any kind. The filename field in those messages is trusted completely, which yields two separate problems:

- **Arbitrary file write** (CWE-36, CWE-306) — any absolute path can be created or overwritten with attacker-controlled content, as root.
- **OS command injection** (CWE-78, CWE-306) — under one condition the filename reaches a shell, giving arbitrary command execution as root.

Either one alone is enough to fully compromise the device.

## Impact

Complete unauthenticated remote compromise of any affected unit with mesh mode enabled, requiring only network reachability to TCP 13136. A live root shell was confirmed against physical hardware. The vendor has independently reproduced this on their own hardware.

| Finding | CVSS 3.1 | CVSS 4.0 |
|---|---|---|
| Command injection | 9.8 Critical | 9.3 Critical |
| Arbitrary file write | 9.1 Critical | 8.7 High |

> **Note on patching.** The vendor states these models are discontinued and unmaintained, and that `sync_server` is not in their current product lineup. Devices on `M35M1_V210223` **cannot be upgraded directly** to the fixed firmware — it requires a two-step U-Boot Recovery procedure carrying brick risk. In practice, most units in the field will never be patched.

## If you own one of these

- **Set `MeshMode` to `0`.** This stops `sync_server` binding TCP 13136. You lose mesh functionality.
- **Block inbound TCP 13136** at the network boundary.
- **Upgrade to `M35M1_V250922`** if you're willing to attempt the U-Boot recovery procedure. Read the vendor's instructions first.

Don't assume a device is safe because it sits behind the router. These are range extenders and mesh nodes, usually reachable from anything on the LAN — including guest networks and compromised IoT.

## Technical detail and PoC

Full protocol specification, the vulnerable code path, and a working proof of concept will be published here once CVE IDs are assigned.

## Disclosure timeline

| Date | Event |
|---|---|
| **2026-08-03** | Reported to the vendor with full technical detail and PoC. 90-day coordinated disclosure proposed. |
| **2026-08-04** | Vendor acknowledged and opened an internal review. |
| **2026-08-05** | Vendor confirmed `M35M1_V210223` is affected, independently reproduced the PoC on their own hardware, confirmed the issue had not been reported before, and endorsed this CVE request. |
| **2026-08-11** | CVE IDs requested from the MITRE CNA-LR. |

Credit where it's due: Wavlink acknowledged within one working day, reproduced the finding themselves rather than taking my word for it, and actively supported the CVE request. That's a better response than plenty of larger companies manage.

Two things remain open:

- **The precise affected version range is unresolved.** The vendor describes an SDK upgrade in 2021, but the vulnerable firmware is dated February 2021 and the nominated fix is dated September 2025. The status of everything in between is unconfirmed.
- **The affected model list is incomplete.** The `sync_server` binary appears in firmware for other Wavlink devices where the port doesn't listen by default. Those become vulnerable if the service is enabled. They haven't been enumerated.

If you have a Wavlink device with TCP 13136 listening, I'd like to hear about it.

## Credit

Found and reported by Cam Smith.

## Legal

This research was conducted against hardware I own, on an isolated network. It's published so owners of affected devices can identify and mitigate their exposure.

Don't use any of this against equipment you don't own or have written authorisation to test. Doing so is likely a criminal offence in your jurisdiction.
