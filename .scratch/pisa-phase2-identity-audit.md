# PISA — Phase 2 Identity Audit

No code changed to produce this document. Every claim below is anchored to a specific file/line read fresh from the current working tree.

---

## 1. Every M2 probe, exactly what it produces

| Probe | File | Port | Feature(s) returned | `device_type_hint` | What the value actually is |
|---|---|---|---|---|---|
| HTTP | `pisa/m2/http_probe.py` | 80/443/8080/8443 | `http.server` | `None` (never sets a hint) | Raw `Server:` response header, e.g. `"nginx/1.18.0"`, `"uc-httpd 1.0.0"`, `"GoAhead-Webs"` — verbatim, unparsed |
| HTTP | same | same | `http.keyword_match` | one of Camera/NVR/Router/Printer/Smart Home Hub | The *matched keyword itself* (`"camera"`, `"nvr"`, …), not the banner — device-type signal only, no product info |
| MQTT | `pisa/m2/mqtt_probe.py` | 1883 | `mqtt.connack` | `"MQTT Broker"` | CONNACK reason code (`reason_code=0` etc.) — confirms broker presence/anon-access, zero product/vendor info |
| CoAP | `pisa/m2/coap_probe.py` | 5683 (unconditional) | `coap.well_known_core` | `"CoAP Device"` | First 200 chars of the raw `/.well-known/core` CoRE-Link-Format payload — resource paths, not a product identifier |
| RTSP | `pisa/m2/rtsp_probe.py` | 554 | `rtsp.options` | `"IP Camera"` | The RTSP status line (`"RTSP/1.0 200 OK"`) — presence-only signal |
| RTSP | same | same | `rtsp.server` | `None` (never sets a hint) | Raw `Server:` header from the RTSP OPTIONS response, e.g. `"GStreamer RTSP server"` — verbatim, unparsed |

**Key finding**: exactly two feature keys carry text that could plausibly identify *what software/product* is running rather than just *that a protocol is present* — `http.server` and `rtsp.server`. Both currently have `device_type_hint: None`, meaning `fusion.fuse()`'s existing algorithm (which only sums confidence for entries with a hint) **silently ignores them today**. They are still persisted to `fingerprint_signatures` (the persistence loop in `fingerprint_runner.py` writes every feature regardless of hint) — the raw evidence already exists in the database for every past scan; it's just never been read back out for anything.

---

## 2. Current fusion algorithm (unchanged in Phase 2 — documented as baseline)

`pisa/m2/fusion.py::fuse(existing_device_type, probe_results)`:

1. Seed a `{candidate: score}` dict with the *existing* `device_type` (passed in from the device row, which by the time M2 runs already holds the mDNS-derived label from M1 — see §4) at a fixed baseline weight of `0.5`.
2. For every feature with a non-empty `device_type_hint`, add its `confidence` to that hint's running score, capped at `1.0`.
3. Return the highest-scoring `(device_type, confidence)` pair.

Pure function, no I/O, unit-tested without mocks. Confidence is a single scalar per fused result — no per-field breakdown exists today because there's only one field (`device_type`) being fused.

---

## 3. How vendor/product/model/firmware/version are represented *today*

| Field | Currently populated by | When | Where stored |
|---|---|---|---|
| Vendor | `pisa/m0/oui_cve.py::bssid_to_vendor()` — IEEE OUI database lookup on the device's MAC address | Once, at M1 discovery time (`discovery_runner.py::_scan_host`) | `devices.vendor` — plain free-text OUI vendor string, e.g. `"Hangzhou Xiongmai Technology Co.,Ltd"` |
| Product | **Nothing.** No probe, no field, no code path produces a "product" concept anywhere in the repository today. | — | — |
| Model | **Nothing.** Same. | — | — |
| Firmware | **Nothing.** Same. | — | — |
| Version | **Nothing** as a *persisted* field, but `http.server`/`rtsp.server` banner text frequently *contains* a version substring (unparsed, see §1) | — | Only inside the raw `feature_value` string in `fingerprint_signatures`, never extracted |
| Device type | mDNS service-type label (M1, `pisa/m1/mdns_discover.py::_label_for`) as the initial value, then overwritten by M2 fusion combining that mDNS baseline with protocol-probe hints | M1 sets it first (`discovery_runner.py`), M2 fusion (`fingerprint_runner.py`) revises it | `devices.device_type` + `devices.fingerprint_confidence` |
| mDNS friendly name | `pisa/m1/mdns_discover.py::identify_hosts` — the DNS-SD instance name (e.g. `"Vivek's iPhone"`) | Once, at M1 discovery | `devices.mdns_name` |

**A gap found and deliberately not fixed in this phase**: `pisa/m1/nmap_scan.py::_parse_nmap_xml` only extracts `service.get("name")` from Nmap's `-sV` XML output — Nmap's version-detection probe (`-sV`) also populates `product`/`version`/`extrainfo` attributes on the same `<service>` element when it identifies one, and PISA currently discards them. This is a real, available evidence source PISA isn't using — but `nmap_scan.py` is M1, not M2, and touching it isn't in Phase 2's authorized scope (audit-M2-first, don't touch M1). Flagged as a Phase 2.5/8 candidate in §7, not acted on here.

---

## 4. `fingerprint_signatures` schema (existing, unmodified)

```sql
CREATE TABLE fingerprint_signatures (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     INTEGER REFERENCES devices(id),
    protocol      TEXT    NOT NULL,
    feature_key   TEXT    NOT NULL,
    feature_value TEXT,
    confidence    REAL,
    captured_at   TEXT    NOT NULL
);
```

One row per raw probe feature, written unconditionally for every feature every probe returns (`fingerprint_runner.py::run_fingerprint`, the loop right before `update_device_fingerprint`). This already is the "underlying evidence" layer — `(protocol, feature_key, feature_value, confidence)` is exactly the shape needed to answer "why did you believe this," for every feature that goes through a probe.

**One evidence source is not represented here at all**: the OUI vendor lookup. `devices.vendor` is written directly by `discovery_runner.py::_scan_host`, bypassing `insert_fingerprint_signature` entirely — there is no `fingerprint_signatures` row recording "OUI lookup on MAC X produced vendor Y." This is a real gap for full evidence traceability, addressed in §5 without adding a new table (see decision below).

---

## 5. Architectural decision: no new evidence table

Per the instruction to prefer the existing `fingerprint_signatures` model and only introduce a new structure if inspection proves it can't represent the required provenance — **inspection shows it doesn't need to be extended or duplicated**:

- Every probe-derived feature already has a `fingerprint_signatures` row with exactly the fields needed for traceability (source, raw value, confidence, timestamp).
- The one gap (OUI vendor has no corresponding row) doesn't require a schema change to fix at the *reporting* level: Phase 2's fusion function can synthesize an in-memory evidence entry describing "OUI lookup produced this vendor" for the `DeviceIdentity` object it returns, sourced directly from the real `devices.vendor` value already computed — not a new persisted row, not a fabricated one, just an honest description of a computation that already happened. This is documented explicitly as a synthesized (not database-backed) evidence entry, not silently presented as equivalent to a stored `fingerprint_signatures` row.
- Field-level confidence *storage* is out of scope per instruction (Phase 1 deliberately didn't add a per-field confidence column — see the Phase 1 log). The single existing `devices.fingerprint_confidence` column remains the only persisted confidence number. Per-field confidence is representable in the *in-memory* `DeviceIdentity.evidence` list (each evidence entry already carries the confidence of the specific feature it came from) without any schema change — satisfying the "traceability, not mathematical sophistication" instruction without a Phase-8-style redesign.

**Conclusion: no new table. `fingerprint_signatures` is reused as-is, read back (not written to differently) by the new identity-fusion logic.**

---

## 6. Evidence → identity field mapping (only what's actually produced today)

| Evidence source | `feature_key` | Vendor | Product | Model | Firmware | Version | Device Type |
|---|---|---|---|---|---|---|---|
| OUI (MAC lookup) | *(not a fingerprint_signatures row — see §4)* | ✅ (baseline) | ❌ | ❌ | ❌ | ❌ | ❌ |
| HTTP Server header | `http.server` | ❌ | ✅ (parsed) | ❌ | ❌ | ✅ (parsed, when present) | ❌ (hint is None) |
| HTTP keyword match | `http.keyword_match` | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| RTSP OPTIONS status line | `rtsp.options` | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| RTSP Server header | `rtsp.server` | ❌ | ✅ (parsed) | ❌ | ❌ | ✅ (parsed, when present) | ❌ (hint is None) |
| MQTT CONNACK | `mqtt.connack` | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| CoAP well-known/core | `coap.well_known_core` | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| mDNS instance name | *(not a fingerprint_signatures row — M1)* | ❌ | ❌ (personal/free text, see below) | ❌ | ❌ | ❌ | ✅ (already used, unchanged) |
| mDNS service type | *(not a fingerprint_signatures row — M1)* | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (already used, unchanged) |
| Nmap OS guess | `devices.os_guess` (M1, not a fingerprint row) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ (used only for M3 CVE keyword search today, not identity) |

**`model` and `firmware` are NULL for every device, always, under Phase 2** — no current evidence source produces either. This is the correct, honest state given today's probes; it is not a bug in the fusion logic.

**mDNS instance name is deliberately excluded from `identity_product`**, even though it's the closest thing to a "name" PISA has for consumer devices. It's user-assigned personal text (`"Vivek's iPhone"`, `"John's Pixel 7"`), not a structured product identifier — sometimes it happens to contain a model name, but treating it as one would require unreliable free-text parsing of an arbitrary human-chosen string. Left as `devices.mdns_name`, used exactly as it is today (device_type fusion baseline only).

---

## 7. Findings carried forward, not acted on in Phase 2

1. Nmap's `-sV` XML `product`/`version` service attributes are available but discarded by `nmap_scan.py` (M1) — real, available evidence PISA doesn't use. Out of Phase 2 scope (M1 file); flag for a future phase.
2. `identity_model`/`identity_firmware` have no evidence source at all today — will remain NULL until a new probe or the Nmap product/version fix above lands.
3. OUI vendor lookup has no `fingerprint_signatures` row — addressed by synthesizing (not persisting) an evidence entry at fusion time, not by a schema change.

These are documented findings for a later phase to pick up, not gaps this phase is silently leaving broken — every one of them already produces the correct `NULL`/`None` today, which is the right behavior in their absence.
