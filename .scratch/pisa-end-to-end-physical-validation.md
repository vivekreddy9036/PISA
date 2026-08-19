# PISA END-TO-END PHYSICAL VALIDATION

**Result up front, stated plainly: this validation stopped at Phase 1/2 due to a real, correctly-triggered blocker (no root access available to this agent) and a second, independent gate that was never satisfied (no authorized lab network/target was ever specified). No network join, no device discovery, no fingerprinting, no CPE/CVE lookup, no verification, and no exploitation were attempted — physical or otherwise, real or mocked. This report documents exactly what *was* genuinely validated on real hardware, and stops there, rather than fabricating or simulating anything past that point.**

---

## 1. Test Environment

| | Value |
|---|---|
| OS | Parrot Security 7.3 ("echo") |
| Kernel | `7.0.13+parrot7-amd64` |
| Platform | x86_64 physical/dev machine — **not** a Raspberry Pi (`/proc/device-tree/model` absent) |
| Python | 3.13.5 |
| PISA git commit | `2f9c8ee` ("Upgrade and enhancement") |
| Baseline test count | 368 passed, 1 skipped (confirmed re-run, §19) |

## 2. Hardware

| | Value | Source |
|---|---|---|
| Alfa AWUS036ACM (real MT7612U chipset) | `Bus 004 Device 002: ID 0e8d:7612 MediaTek Inc. MT7612U 802.11a/b/g/n/ac Wireless Adapter` | `lsusb` |
| Its interface name | `wlx00c0cab96bf1` | `ip link` / `iw dev` |
| Its PHY | `phy1` | `iw dev` |
| **Its current state at the start of this validation** | **UP, `type managed`, actively connected to SSID `Amrita_CHN2`, channel 36 (5GHz)** | `iw dev` |
| Built-in laptop WiFi | Intel-family (co-located `8087:0026` Intel AX201 Bluetooth on the same bus strongly implies an Intel AX201 WiFi/BT combo) | `lsusb` |
| Its interface name | `wlp0s20f3` | `ip link` / `iw dev` |
| Its PHY | `phy0` | `iw dev` |
| **Its current state at the start of this validation** | **UP, `type managed`, actively connected to SSID `ROOT`, channel 7 (2.4GHz)** | `iw dev` |

**A genuinely notable finding, not assumed going in**: both real interface names (`wlx00c0cab96bf1`, `wlp0s20f3`) are an *exact* match for `config.WIFI_IFACE` and `config.JOIN_IFACE`'s hardcoded defaults in `config.py`. This machine's config was clearly set up for exactly this hardware already — no interface-name override is needed to point PISA at these real adapters.

**Both radios were live, in active use, connected to real networks at the moment this validation began.** Neither SSID had been declared to me as an authorized isolated lab network. `Amrita_CHN2` in particular reads as an institutional/campus network name — I did not treat it as a target, did not attempt to join anything, and did not run any scan against either network's subnet.

## 3. Alfa Driver/Interface

| | Value |
|---|---|
| Driver bound | `mt76x2u` (`/sys/bus/usb/drivers/mt76x2u`) — the correct, expected driver for this chipset |
| Supported interface modes (`iw phy1 info`) | IBSS, **managed**, AP, AP/VLAN, **monitor**, mesh point, P2P-client, P2P-GO |
| Monitor mode support | **Confirmed present in the driver's capability list.** Not yet confirmed *in practice* (§21) — capability ≠ a completed live switch. |
| Built-in radio driver (`wlp0s20f3`) | `iwlwifi` — also lists `monitor` in `iw phy0 info`'s supported modes |
| `rfkill` | Both `phy0` and `phy1` report soft/hard blocked = no — no radio kill switch is engaged |

**Classification: PASS — REAL HARDWARE** for driver binding and monitor-mode *capability* confirmation. This is genuine evidence read directly from the kernel's own driver/capability tables on the real device, not inferred from the adapter's model name alone.

## 4. M0 Real Capture

**BLOCKED.** Not attempted — see §21.

## 5. M1 Real Discovery

**BLOCKED / NOT APPLICABLE.** Not attempted — depends on §4 and on an authorized lab network that was never specified (§21).

## 6. M2 Real Fingerprinting

**NOT APPLICABLE.** No device was discovered to fingerprint.

## 7. Structured Identity

**NOT APPLICABLE.**

## 8. CPE Mapping

**NOT APPLICABLE.** No identity existed to map.

## 9. CVE Correlation

**NOT APPLICABLE.**

## 10. EPSS/KEV/CVSS

**NOT APPLICABLE.**

## 11. Applicability

**NOT APPLICABLE.**

## 12. Verification

**NOT APPLICABLE.**

## 13. Exploitation Gate

**NOT APPLICABLE.** No CVE finding existed to evaluate a gate against. (The gate's *logic* was already proven correct at the software level in Phase 8's route-level tests — re-confirmed passing in §19 of this report — but that is a **PASS — SOFTWARE TEST**, not a physical validation, and is not conflated with one here.)

## 14. Authorized Exploitation

**NOT APPLICABLE.** No exploitation was attempted, considered, or came close to being triggered. No RouterSploit module was invoked against any real target.

## 15. Proof-of-Impact

**NOT APPLICABLE.**

## 16. Evidence/Database

**NOT APPLICABLE for physical evidence.** The real production `pisa.db` was not touched by this validation session — no session, network, or device rows were created as a result of this exercise.

## 17. M5/API/Dashboard

**NOT APPLICABLE.** Not started; there was no real assessment data to display, and starting the Flask app against the real `pisa.db` for a validation that produced no new real data would add no evidence value.

## 18. Negative Controls

**NOT APPLICABLE against real hardware/network in this session.** The six negative-control behaviors this phase asks for (CVE-but-UNKNOWN, NOT_APPLICABLE, AFFECTED-but-NOT_VERIFIED, no-authorization, unsupported CVE, arbitrary module_path) were already exercised and passed as **PASS — SOFTWARE TEST** in Phase 8's route-level integration test suite (`tests/m5/test_routes.py::test_5` through `test_10`), reconfirmed passing in §19 below. They were not re-run against real hardware here because no real hardware pipeline reached the point where they'd apply.

## 19. Full Regression

```
368 passed, 1 skipped, 4 warnings in 3.30s
```

Matches the stated baseline (368 passed, 1 skipped) exactly — zero regressions, zero failures. **Classification: PASS — SOFTWARE TEST.** This is real evidence that the codebase itself is unchanged and healthy; it is not evidence of anything about physical hardware behavior.

## 20. Raspberry Pi Readiness

**Cannot be assessed from this session at all**, for two independent reasons, stated exactly rather than glossed over:
1. This machine is confirmed **not** a Raspberry Pi (§1) — it's a standard x86_64 laptop/desktop running Parrot Security OS.
2. No physical M0-M5 stage was actually exercised here (§4-§17), so there is no real resource-usage data (CPU/RAM/thermal/SQLite-contention/RouterSploit-load) from *this* session to extrapolate from, on any platform.

Per the prior architecture review's own explicit instruction — "do not claim Raspberry Pi readiness merely because the laptop passed" — this report claims **nothing** about Pi readiness. The relevant classifications (SAFE ON PI / NEEDS OPTIMIZATION / HIGH RISK / UNKNOWN — NEED BENCHMARK) from that earlier review stand unchanged and unconfirmed by this session.

## 21. Failures/Blockers

**Blocker 1 (primary, stops everything downstream): root access is required to switch `wlx00c0cab96bf1` into monitor mode, and is not available to this agent non-interactively.**
- `sudo -n true` → `sudo: a password is required`
- `sudo ip link set wlx00c0cab96bf1 down` → `sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper` / `sudo: a password is required` (exit code 1)
- This is the exact, correct behavior of `sudo` when no TTY/askpass mechanism is available to the calling process — I did not attempt `-S` with a guessed password, did not attempt to modify `/etc/sudoers`, and did not attempt any other privilege-escalation workaround. This is reported as a blocker, not silently routed around, per the instruction to stop and document rather than fix quietly.

**Blocker 2 (independent, would still apply even if Blocker 1 were resolved): no authorized lab network was specified.** The task's own Phase 4 requires an explicitly identified, isolated lab SSID/subnet/target before M1 discovery may proceed. Neither `Amrita_CHN2` nor `ROOT` (the two real networks found already connected in §2) were declared authorized targets by the user, and I did not treat either as one by inference from their names or from being already connected. No SSID, password, subnet, gateway, or target IP was ever provided for this session.

**Neither blocker was worked around. Both stop the validation at exactly the point the task's own strict stop conditions require ("STOP immediately if: target is not explicitly authorized; target scope is ambiguous").**

## 22. Recommended Fixes

Not code fixes — this blocker is entirely environmental/operational, not a PISA software defect:
1. Re-run the monitor-mode setup sequence (`sudo nmcli device set wlx00c0cab96bf1 managed no && sudo ip link set wlx00c0cab96bf1 down && sudo iw dev wlx00c0cab96bf1 set type monitor && sudo ip link set wlx00c0cab96bf1 up`) **yourself, interactively**, in a terminal where you can supply your sudo password — or grant this session passwordless sudo for these specific commands if you're comfortable doing so, whichever you prefer.
2. Provide the explicit authorized lab network details (SSID, password, subnet, and ideally the target device's expected IP) before any M1/discovery phase is attempted.
3. Once both are in hand, this same validation plan can resume exactly where it stopped — nothing about Phases 4 onward needs to be redesigned.

## 23. Overall Physical Validation Score

**Software correctness: fully confirmed (368/369, unchanged).**
**Physical hardware presence and driver capability: confirmed real (§2/§3).**
**Actual physical pipeline execution: 0 of 14 remaining stages attempted.**

---

# FINAL DECISION

```
M0: BLOCKED   (root access unavailable to this agent; monitor-mode switch never performed)
M1: BLOCKED   (depends on M0; also independently blocked — no authorized lab network specified)
M2: BLOCKED   (depends on M1)
M3: BLOCKED   (depends on M2 — no identity was ever produced to map to a CPE)
M4: BLOCKED   (depends on M3)
M5: NOT APPLICABLE (no real assessment data existed to display)
```

**COMPLETE PHYSICAL PIPELINE: NO**

**Raspberry Pi deployment blockers**: none newly discovered by this session — this session ran entirely on non-Pi hardware and reached no stage that would have produced Pi-relevant evidence either way. The Pi-readiness questions and classifications from the prior architecture review remain exactly as they were: unconfirmed by real measurement, not contradicted by anything found here.

**Exact next 3 engineering actions:**
1. **You run the monitor-mode switch commands yourself, interactively** (exact commands in §22.1) — this is a one-time, few-second manual step; report back the output of `iw dev wlx00c0cab96bf1 info` afterward (should report `type monitor`) so this validation can resume at Phase 2.
2. **Provide the explicit authorized lab network** (SSID + password + subnet/gateway, and ideally a known target IP) — without this, Phase 4 onward cannot legitimately proceed regardless of Blocker 1's resolution.
3. **Re-invoke this same validation plan once both are in hand** — no changes to the plan, code, or scope are needed; it resumes exactly at Phase 2 with the actual PISA M0 beacon-capture code (`pisa/m0/beacon_capture.py::start_capture`), not a replacement script, exactly as originally specified.
