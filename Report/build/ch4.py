from report_engine import add_chapter, add_division, add_subdivision, add_para, add_bullet, add_table_with_caption, add_figure_with_caption
from refs_data import cite
from docx.enum.text import WD_ALIGN_PARAGRAPH

DIAG = r"C:\Vivek's Workspace\Projects\Project Phase 1\docs\diagrams"


def build(doc, registry):
    CH = 4

    add_chapter(doc, registry, CH, "System Design and Implementation")

    add_division(doc, registry, CH, 1, "System Architecture Overview")
    add_para(doc, (
        "PISA is organized as a single Flask application running six software modules — labelled M0 "
        "through M5 throughout this report, matching the project's own internal naming — on one "
        "machine. No module runs as a separate microservice and no module requires a cloud dependency "
        "for its core function; the only components that call out to the internet are the NVD, "
        "FIRST.org EPSS, and CISA KEV lookups in M3, all of which are triggered on demand rather than "
        "continuously. Figure 4.1 shows the five-layer pipeline this implies: the Hardware Layer "
        "(Raspberry Pi 4 plus an external monitor-mode WiFi adapter) feeds M0's WiFi assessment "
        "engine, whose output flags a target network for the M1-M2 discovery-and-fingerprinting stage, "
        "whose output in turn feeds the M3-M4 threat-intelligence-and-verification engine, with M5 "
        "presenting every stage's results through a single dashboard."
    ))
    add_figure_with_caption(doc, registry, CH, "PISA five-layer system architecture",
                             f"{DIAG}\\PISA_Architecture_Diagram.png", width=6.0)
    add_para(doc, (
        "Data flows strictly downstream in Figure 4.1 — a network must be assessed by M0 before it "
        "can be joined by M1, a device must be discovered by M1 before it can be fingerprinted by M2 "
        "or correlated against CVEs by M3, and M4 will not offer an exploit until M3 has returned an "
        "applicable finding for that specific device. This strict, one-directional dependency is a "
        "deliberate design choice, not an implementation accident: it is what makes the authorization "
        "gate described in Section 4.6 structurally enforceable rather than merely a UI convention, "
        "since a later stage can never run ahead of the evidence an earlier stage actually "
        "established."
    ))

    add_division(doc, registry, CH, 2, "Hardware Architecture")
    add_para(doc, (
        "PISA's hardware target is a Raspberry Pi 4, chosen because it is inexpensive, has sufficient "
        "CPU headroom for the packet-processing and multi-threaded scanning workloads M0 through M3 "
        "require, and — critically — its built-in WiFi adapter (Broadcom BCM43455) can join a network "
        "in managed mode but does not expose monitor mode through its Linux driver. An external "
        "USB adapter is therefore required for M0's passive beacon capture; this project uses the Alfa "
        "AWUS036ACM (MediaTek MT7612U chipset), a dual-band 802.11ac adapter with a native mt76 kernel "
        "driver, chosen specifically because a 2.4 GHz-only adapter would miss the many networks — "
        "most WPA3 deployments among them — that only broadcast on 5 GHz. The Raspberry Pi's own "
        "built-in adapter is then free to serve M1's network-join role (`config.JOIN_IFACE`), giving "
        "the system two independent radios: one permanently in monitor mode for passive capture, one "
        "in managed mode for active device discovery, so that joining a target network never interrupts "
        "the background WiFi assessment. Table 4.1 summarizes the hardware used to develop and validate "
        "the system reported in Chapter 5, alongside peripherals scoped for a later hardware-integration "
        "phase but not yet part of v1."
    ))
    add_table_with_caption(doc, registry, CH, "Hardware specification", [
        ["Component", "Role", "Status in v1"],
        ["Raspberry Pi 4 (4 GB)", "Core compute platform; runs the Flask application and all six modules", "Core — used for validation"],
        ["Alfa AWUS036ACM (MT7612U)", "Dual-band 802.11ac monitor-mode adapter for M0 beacon capture", "Core — used for validation"],
        ["Built-in WiFi (BCM43455)", "Managed-mode radio for M1 network join, independent of the monitor-mode adapter", "Core — used for validation"],
        ["ESP32 development board (firmware/esp32-iot-target)", "Controlled IoT test target running MQTT/HTTP services for M2/M3 validation", "Core — used for validation"],
        ["NEO-6M GPS module + USB-UART adapter", "Geolocation tagging of assessment sessions (warwalking)", "Planned extension — not yet integrated"],
        ["7-inch DSI touchscreen", "Standalone field UI, removing the dependency on a separate laptop/phone browser", "Planned extension — not yet integrated"],
    ], widths=[1.9, 3.0, 1.7])
    add_para(doc, (
        "A deliberate hardware simplification follows from the radio arrangement described above: an "
        "earlier design draft specified a second purchased USB WiFi adapter for the managed-mode join "
        "role, until it was confirmed that the Raspberry Pi's own built-in adapter already covers that "
        "role, removing one line item without any loss of capability. Table 4.2 gives an indicative "
        "cost breakdown for the hardware a new build of PISA requires beyond a Raspberry Pi 4 already "
        "on hand, separating what v1's validation in Chapter 5 actually used from the planned "
        "extensions in Table 4.1."
    ))
    add_table_with_caption(doc, registry, CH, "Indicative hardware cost (components not already owned)", [
        ["Component", "Indicative cost (INR)", "Required for"],
        ["Alfa AWUS036ACM monitor-mode adapter", "~7,000", "Core v1 (M0)"],
        ["ESP32 development board + sensors", "~800", "Core v1 (M2/M3 controlled test target)"],
        ["Powered USB hub (self-powered, 4-port USB 3.0)", "~800", "Core v1 (stable Alfa power delivery)"],
        ["NEO-6M GPS module + USB-to-UART adapter", "~800", "Planned extension (geolocation tagging)"],
        ["7-inch DSI touchscreen", "~6,600", "Planned extension (standalone field UI)"],
    ], widths=[2.7, 1.6, 2.3])
    add_para(doc, (
        "The self-powered USB hub in Table 4.2 is a deliberate, non-obvious inclusion rather than an "
        "incidental accessory: the Alfa adapter draws enough current under active scanning that a "
        "bus-powered hub was found to cause it to drop or behave unstably, so the hub's own power "
        "supply, not just its port count, is the reason it is specified."
    ))

    add_division(doc, registry, CH, 3, "Software Architecture and Technology Stack")
    add_para(doc, (
        "The entire system is written in Python 3.12 for consistency across modules and native "
        "compatibility with Raspberry Pi OS. Table 4.3 lists the libraries actually pinned in the "
        "project's `requirements.txt` and the module each supports, rather than a larger aspirational "
        "list — for example, no machine-learning, Modbus, or PDF-generation library is present, "
        "consistent with those being out of v1 scope as stated in Chapter 1."
    ))
    add_table_with_caption(doc, registry, CH, "Core software dependencies (requirements.txt)", [
        ["Library", "Version pinned", "Used by"],
        ["Flask", "3.0.3", "M5 — dashboard, REST API endpoints"],
        ["Scapy", "2.5.0", "M0 — raw 802.11 beacon capture and parsing"],
        ["python-nmap", "0.7.1", "M1 — Nmap service/OS scan wrapper"],
        ["paho-mqtt", "2.1.0", "M2 — MQTT behavioural probe"],
        ["aiocoap", "0.4.7", "M2 — CoAP behavioural probe"],
        ["requests", "2.31.0", "M0/M3 — NVD, FIRST.org EPSS, CISA KEV HTTP calls; M2 HTTP/RTSP probes"],
        ["boto3", "1.34.131", "AWS SDK — present for the planned M-AWS cloud-reporting stub"],
        ["routersploit", "3.4.7", "M4 — exploit module index and execution backend"],
        ["standard-telnetlib, setuptools<81", "3.13.0 / n/a", "Python 3.13 compatibility shims required by RouterSploit"],
        ["arp-scan, nmap (system binaries)", "n/a", "M1 — shelled out to for ARP host discovery and OS/service scanning"],
    ], widths=[1.9, 1.5, 3.2])
    add_para(doc, (
        "Two dependencies in Table 4.3 were specifically chosen over a more \"natural\" Python-native "
        "alternative after that alternative was tried and measured against real conditions, a pattern "
        "that recurs across this project and is reported honestly rather than smoothed over: M1 shells "
        "out to the system `arp-scan` binary rather than performing a hand-rolled Scapy ARP sweep, "
        "because Scapy's Python-level reply matching could not keep pace with reply volume on a real, "
        "busy campus subnet of roughly eight thousand addresses, surfacing only a handful of hosts "
        "where `arp-scan` completed a full sweep of the same subnet in about thirty seconds; and M1's "
        "device-type labelling uses mDNS rather than reverse DNS, after reverse DNS was confirmed "
        "non-functional against the project's actual target network while mDNS was confirmed to "
        "resolve real device names independently of that network's own DNS infrastructure."
    ))

    add_division(doc, registry, CH, 4, "Module Design")

    add_subdivision(doc, registry, CH, 4, 1, "M0 — WiFi Assessment Layer")
    add_para(doc, (
        "M0 captures 802.11 management frames (type 0, subtype 8 — beacon frames) from the monitor-mode "
        "adapter using raw Scapy sockets, filtering and parsing SSID, BSSID, channel, signal strength, "
        "RSN information element (encryption type and Protected Management Frame capability), beacon "
        "interval, and WPS vendor-specific information element presence, de-duplicating by BSSID and "
        "persisting each result to the `networks` table. From this packet-derived data alone, M0 "
        "computes the WiFi Security Posture Score (WSPS): a 0-100 score built additively from seven "
        "factors, shown in Table 4.4, clamped to the [0, 100] range and mapped to a letter grade."
    ))
    add_table_with_caption(doc, registry, CH, "WSPS scoring factors (pisa/m0/wsps.py)", [
        ["Factor", "Points", "Scoring logic"],
        ["Encryption type", "up to 35", "WPA3 = 35, WPA2 = 25, WPA = 10, Open = 0"],
        ["Channel", "up to 15", "Non-overlapping channel (1/6/11) = 15, other = 5, none = 0"],
        ["Signal strength", "up to 20", "> -50 dBm = 20, > -70 dBm = 12, > -85 dBm = 6, weaker = 0"],
        ["Beacon interval", "up to 12", "Standard 100 TU = 12, non-standard = 5"],
        ["Management Frame Protection (802.11w)", "+15", "PMF capability bit set in RSN IE = +15, else 0"],
        ["WPS status", "-15", "WPS vendor IE present = -15 penalty, absent = 0"],
        ["Hidden SSID", "-10", "Empty SSID in beacon = -10 penalty, else 0"],
    ], widths=[2.1, 0.9, 3.6])
    add_para(doc, (
        "Grades are assigned as A (score ≥ 90) down to F (score < 30). Two factors originally scoped — "
        "pairwise cipher-suite strength (CCMP versus TKIP) and folding router CVE exposure directly "
        "into the score — were deliberately deferred rather than silently dropped. The cipher-suite "
        "factor needs no new capture logic (the RSN information element already parsed for "
        "encryption-type detection carries the AKM suite) and is a natural near-term addition. CVE "
        "exposure, however, was deferred for an architectural reason: folding a live NVD lookup into "
        "`score_network()` would make WSPS scoring depend on network connectivity, breaking the "
        "property that scoring is a pure function of already-captured packet data (Non-Functional "
        "Requirement NFR-2, Table 3.2) — a property the module's own unit tests rely on to run "
        "entirely offline. Vendor CVE exposure is instead surfaced as a separate, on-demand lookup "
        "(FR-3): M0 resolves the access point's manufacturer from its BSSID's OUI against the IEEE OUI "
        "database and, only when the operator explicitly requests it from the dashboard, queries the "
        "live NVD 2.0 API for CVEs associated with that vendor."
    ))
    add_figure_with_caption(doc, registry, CH, "M0 (WiSentinel) internal processing pipeline",
                             f"{DIAG}\\PISA_Module_0_WiSentinel_HighClarity.png", width=6.0)
    add_para(doc, (
        "Figure 4.2 expands the single \"M0 — WiFi\" box of Figure 4.1 into its internal stages: beacon "
        "capture feeds the WSPS scoring engine, WPS detection, and OUI-to-CVE correlation in parallel, "
        "with every stage's output written to a dedicated WiFi evidence store rather than held only in "
        "memory, so that a network's score, its WPS/hidden-SSID findings, and any CVE correlation "
        "already performed for it survive independently of the dashboard session that triggered them. "
        "The PMKID/EAPOL handshake-capture stage shown in the figure is passive by default and "
        "deliberately gated when operated in its active (deauth-based) form, consistent with the "
        "authorization-gate principle introduced in Section 3.6 and implemented concretely for exploit "
        "verification in Section 4.6."
    ))

    add_subdivision(doc, registry, CH, 4, 2, "M1 — Network Discovery")
    add_para(doc, (
        "On operator request, M1 joins a network already scored by M0 using its supplied password, via "
        "`nmcli` on the managed-mode interface, then builds a device inventory of the joined subnet in "
        "two stages: an `arp-scan` sweep for live hosts (IP, MAC, OUI-resolved vendor), followed by a "
        "concurrent Nmap `-sV -O` scan across a thread pool, restricted to common IoT-relevant ports "
        "(1883/MQTT, 5683/CoAP, 502/Modbus, 554/RTSP, plus standard web/management/remote-access ports) "
        "for open ports, service banners, and an OS guess. Each host is additionally queried over mDNS "
        "(`224.0.0.251:5353`) for a self-announced friendly name and service type. Running the Nmap "
        "stage concurrently, rather than one host at a time, was a direct response to a measured "
        "bottleneck: once the `arp-scan` fix described in Section 4.3 started surfacing hundreds of "
        "live hosts on a real subnet instead of a handful, a sequential scan became a multi-hour "
        "operation; a thread pool bounded by `config.NMAP_MAX_WORKERS` brought this back to a "
        "field-practical duration. A single host's scan failure (an Nmap crash, a vendor-lookup error) "
        "is isolated and recorded as a warning-severity alert rather than aborting the hosts already "
        "scanned successfully elsewhere in the pool."
    ))
    add_para(doc, (
        "Each discovered host's open-port set is the handoff point into Module 2: Table 4.5 shows the "
        "routing rule that maps an open port to the protocol probe M2 runs against it, with CoAP probed "
        "unconditionally on every device for the reason given in Section 4.4.3."
    ))
    add_table_with_caption(doc, registry, CH, "M1-to-M2 port-to-protocol routing rule", [
        ["Open port (from M1)", "Protocol probe triggered (M2)"],
        ["1883", "MQTT"],
        ["80, 443, 8080, 8443", "HTTP"],
        ["554", "RTSP"],
        ["5683 (UDP, not in Nmap's TCP results)", "CoAP — probed unconditionally on every device"],
        ["More than one of the above open", "All applicable probes run; results merged by Cross-Protocol Confidence Fusion (Section 4.4.3)"],
    ], widths=[2.9, 3.5])

    add_subdivision(doc, registry, CH, 4, 3, "M2 — Protocol-Aware Behavioural Fingerprinting")
    add_para(doc, (
        "M2 probes each discovered device's open ports against the protocol conventionally associated "
        "with that port (MQTT on 1883, HTTP on 80/443/8080/8443, RTSP on 554), and probes CoAP (5683) "
        "unconditionally on every device regardless of Nmap's port list, since CoAP runs over UDP and "
        "never appears in Nmap's TCP-only open-port results from M1. Each protocol probe fails soft on "
        "any timeout or error — returning an empty result rather than raising — and, where it succeeds, "
        "returns one or more evidence features, each optionally suggesting a candidate device type. The "
        "mDNS-derived type already recorded by M1 is included as one such candidate at a fixed baseline "
        "weight. Panel M1-M2 of Figure 4.3 shows this routing and probing pipeline; panel M4's "
        "\"Cross-Protocol Fusion\" box shows where the per-protocol confidence scores are combined."
    ))
    add_figure_with_caption(doc, registry, CH, "Per-module processing pipelines, M0 through M5",
                             f"{DIAG}\\Module Diagrams.png", width=6.2)
    add_para(doc, (
        "Fusion sums each candidate device-type's confidence across every protocol that proposed it, "
        "capped at 1.0, using a probabilistic complement rule rather than a simple average: two "
        "moderate-confidence signals (for example 0.75 from MQTT and 0.80 from HTTP) combine to 1 − "
        "(1 − 0.75)(1 − 0.80) = 0.95, so agreement across independent protocols raises confidence "
        "faster than either signal alone — the specific mechanism behind Novelty Claim 3 in Section "
        "3.4. The highest-scoring candidate, with its fused confidence, is written back to the device's "
        "record. Devices can be fingerprinted individually or in bulk across a network via a thread "
        "pool (`config.M2_MAX_WORKERS`), for the same reason M1's Nmap stage is pooled: a mandatory "
        "CoAP probe alone costs up to `config.M2_PROBE_TIMEOUT` per device, making a sequential sweep "
        "impractical at realistic device counts."
    ))
    add_para(doc, (
        "Table 4.6 lists representative, concrete behavioural signatures each protocol probe checks "
        "for, to make Claim 3's \"how a device behaves, not just which services it runs\" distinction "
        "(Section 3.4.3) tangible rather than abstract."
    ))
    add_table_with_caption(doc, registry, CH, "Representative behavioural signatures probed per protocol", [
        ["Protocol", "Behavioural signature probed", "Example evidence"],
        ["MQTT", "CONNACK response flags, topic hierarchy on wildcard subscription, retained-message and keepalive handling", "Topic pattern `tele/{hostname}/STATE` is characteristic of Tasmota-flashed devices"],
        ["CoAP", "`/.well-known/core` resource directory content, block-transfer negotiation, observe-notification interval", "Resource path naming conventions specific to a given CoAP stack implementation"],
        ["HTTP", "Server header value, response header ordering, login-page form field names, error-response format", "`/doc/page/login.asp` presence is characteristic of Hikvision camera firmware"],
        ["RTSP", "OPTIONS response headers, DESCRIBE/SDP format, authentication-challenge type (Digest/Basic/None)", "`Server: Dahua` combined with a `/RPC2` JSON-RPC endpoint is characteristic of Dahua cameras"],
    ], widths=[0.9, 3.1, 2.4])

    add_subdivision(doc, registry, CH, 4, 4, "M3 — Vulnerability Intelligence")
    add_para(doc, (
        "M3 correlates each fingerprinted (or, at minimum, OS-guessed) device against the live NVD CVE "
        "API, preferring the device's Nmap OS guess as the search keyword over its vendor alone — "
        "simplified to drop version-specific detail, since NVD's keyword search ANDs every token "
        "together and a literal version string in the query can zero out otherwise-relevant results. A "
        "vendor-only fallback was deliberately not implemented after it was found, in practice, to "
        "return the same decade-old, generically-matched CVEs regardless of the actual device; M3 "
        "returns an explicit \"no data\" result rather than a low-confidence guess in this case, "
        "consistent with the project's broader discipline of never reporting a finding it cannot "
        "actually support with evidence. Every CVE returned is enriched with its FIRST.org EPSS score "
        "(probability of real-world exploitation within 30 days) and its CISA KEV listing status, then "
        "combined into a single 0-100 exploit score:"
    ))
    add_para(doc, "exploit_score = 0.4 × CVSS_normalized + 0.4 × EPSS + 0.2 × KEV_bonus", indent=False,
              align=WD_ALIGN_PARAGRAPH.CENTER)
    add_para(doc, (
        "where CVSS and EPSS are weighted equally, a CISA KEV listing contributes a flat 0.2 bonus, and "
        "a missing CVSS or EPSS value contributes zero to its own term rather than being excluded or "
        "renormalized — a deliberate choice that penalizes incomplete evidence instead of inflating a "
        "score around it. This formula operationalizes Novelty Claim 5 (Section 3.4.5) and is a direct "
        "application of the tri-metric principle established in the EPSS/KEV literature reviewed in "
        "Section 2.5 " + cite("P15", "P16") + ". Beyond scoring, M3 also implements the applicability "
        "engine that determines whether a CVE genuinely applies to a device — evaluating NVD's real "
        "AND/OR/version-range configuration logic against the device's identity, rather than treating "
        "any keyword match as a positive finding — and the live verification stage that must return a "
        "confirmed-vulnerable result before Module 4 will offer exploitation at all, detailed in "
        "Section 4.6."
    ))
    add_para(doc, (
        "To make this formula concrete rather than purely symbolic, consider the real reference finding "
        "reported in Chapter 5: CVE-2017-7577, returned by a live NVD lookup with CVSS = 9.8 and an "
        "EPSS score of 29% retrieved live from FIRST.org. If this CVE were not listed in the CISA KEV "
        "catalogue, its exploit score would be 0.4 × 0.98 + 0.4 × 0.29 + 0.2 × 0 = 0.508, or roughly "
        "51 out of 100; were it additionally KEV-listed, the flat 0.2 bonus would raise the same finding "
        "to 0.708, roughly 71 out of 100 — a single confirmed real-world exploitation record moving a "
        "finding from the middle of the scoring range toward its upper end, independent of CVSS or EPSS "
        "changing at all. This is precisely the behaviour the tri-metric design in Novelty Claim 5 "
        "(Section 3.4.5) is intended to produce: KEV listing acts as a correction for exactly the case the "
        "literature identifies as EPSS's own blind spot " + cite("P17") + " — a CVE whose EPSS score has "
        "not yet caught up with its observed real-world exploitation."
    ))

    add_subdivision(doc, registry, CH, 4, 5, "M4 — Authorized Verification and Gated Exploitation")
    add_para(doc, (
        "M4 is scoped narrowly and deliberately: given a device and a CVE that M3 has already surfaced "
        "and verified live, M4 searches RouterSploit's module index (roughly 358 modules, of which only "
        "around two dozen cite an explicit CVE ID) for a matching exploit module. If a match exists, the "
        "dashboard exposes it only behind three gates in sequence — a named operator field (\"authorized "
        "by\"), an explicit confirmation checkbox, and a mandatory five-second countdown before the "
        "action becomes clickable — matching Non-Functional Requirement NFR-7 (Table 3.5) and the "
        "authorization-gate pattern from the organizational risk-assessment literature "
        + cite("P19") + " discussed in Section 2.6. \"Check only\" (RouterSploit's non-destructive "
        "`check()` method) is the default mode; \"full exploit\" (`run()`) is a separate, explicitly "
        "selected mode. Every attempt — check or run, success or failure — is written as its own row in "
        "the `exploit_results` table with the authorizing operator and both an authorization and an "
        "execution timestamp, as an append-only audit log rather than a cached, overwritable lookup. "
        "The precise state machine enforcing all of this is described in Section 4.6 and is shown in "
        "Chapter 5 to have been tested adversarially rather than merely implemented."
    ))
    add_para(doc, (
        "The module-matching step deserves a closer look, since it is the specific mechanism that "
        "keeps M4 from ever executing an unvetted module. RouterSploit's module index is searched by "
        "CVE identifier, against a curated registry PISA itself maintains rather than RouterSploit's "
        "full, unfiltered module set — a deliberate narrowing, since not every module RouterSploit "
        "ships has been reviewed for safe behaviour against the specific device classes PISA targets. "
        "Coverage against this registry is inherently partial: with only around two dozen of "
        "RouterSploit's roughly 358 modules citing an explicit CVE ID at all, a CVE returning no match "
        "is an expected, honest outcome rather than a gap to be hidden, consistent with the project's "
        "broader discipline, established for M3 in Section 4.4.4, of never manufacturing a positive "
        "result where the evidence does not support one. This registry-based lookup is also what the "
        "adversarial test in row four of Table 5.3 (Chapter 5) specifically exercises: a client request "
        "that supplies its own `module_path` is checked against — and overridden by — this same "
        "server-side registry resolution, rather than being trusted directly."
    ))

    add_subdivision(doc, registry, CH, 4, 6, "M5 — Dashboard and Reporting")
    add_para(doc, (
        "M5 is a Flask application that is simultaneously the operator's control surface and the only "
        "way any other module is actually triggered — none of M0 through M4 run autonomously in the "
        "background in v1; each is invoked on demand from a dashboard action or an equivalent CLI flag "
        "on `run.py`. The dashboard lists past sessions, starts new scans, displays per-session "
        "networks with WSPS grade badges, and — per network or device — exposes the on-demand CVE "
        "lookup, join-and-discover, fingerprint, and exploit-verification actions described above. By "
        "design it binds to `127.0.0.1` and must be explicitly reconfigured (`--host 0.0.0.0` or an "
        "environment variable) to be reachable from another device, since its API carries no "
        "authentication of its own and several of its endpoints accept WiFi passwords, consistent with "
        "the ethics and safety posture set out in Section 3.6."
    ))
    add_figure_with_caption(doc, registry, CH, "M5 interface and reporting engine",
                             f"{DIAG}\\PISA_Module_5_Interface_Reporting_HighClarity.png", width=6.0)
    add_para(doc, (
        "Figure 4.4 shows M5 as the convergence point for every evidence stream produced by M0 through "
        "M4: WiFi evidence, discovery evidence, fingerprint evidence, vulnerability evidence, and "
        "verification evidence are each written independently to the local SQLite database as they are "
        "produced, and the dashboard's web and REST interfaces read from that shared store rather than "
        "from any one module directly. The \"Report Generator (PDF/JSON/CSV)\" and \"Evidence Archive\" "
        "boxes in the figure correspond to the cloud-backed reporting capability scoped in Chapter 1 as "
        "planned future work (`pisa/aws/`); in the current release, session data is exported directly "
        "from the dashboard's existing JSON API rather than through a dedicated report-generation "
        "service."
    ))

    add_division(doc, registry, CH, 5, "Database Design")
    add_para(doc, (
        "All assessment data is persisted locally first, in a single SQLite database, so that the core "
        "pipeline works fully offline except for the on-demand NVD/EPSS/KEV calls in M3; this is also "
        "why cloud sync (AWS) is additive future work rather than a dependency the current system "
        "requires to function. Table 4.7 summarizes the nine tables created on startup. A deliberate "
        "simplicity choice runs through the schema: it uses plain `INTEGER PRIMARY KEY AUTOINCREMENT` "
        "identifiers and no SQL-level `CHECK` constraints, because every constraint that matters is "
        "already enforced in the application's query layer, and SQLite's constraint checking would be "
        "redundant with it."
    ))
    add_table_with_caption(doc, registry, CH, "SQLite schema (pisa/db/models.py)", [
        ["Table", "Purpose", "Populated by"],
        ["sessions", "One row per assessment session; status and timing", "M0"],
        ["networks", "Beacon-derived network records, WSPS score and grade", "M0"],
        ["network_cves", "On-demand OUI-to-vendor CVE lookups per network", "M0"],
        ["devices", "Discovered device records — IP, MAC, vendor, open ports, OS guess, fingerprint", "M1 / M2"],
        ["device_cves", "Device-specific CVE correlation with CVSS/EPSS/KEV/exploit score", "M3"],
        ["exploit_results", "Append-only log of every exploit authorization and outcome", "M4"],
        ["fingerprint_signatures", "Per-protocol evidence features captured during M2 probing", "M2"],
        ["behavioral_drift", "Session-to-session fingerprint delta records", "Reserved — M2 extension"],
        ["alerts", "Unified alert log — scan failures today; broader use as modules extend", "M0-M5"],
    ], widths=[1.7, 3.6, 1.3])

    add_division(doc, registry, CH, 6, "Security and Authorization Gate Design")
    add_para(doc, (
        "The authorization gate described functionally in Sections 3.6 and 4.4.5 is implemented as an "
        "explicit state check in `pisa/m4/routersploit_gate.py`, evaluated before any exploit action is "
        "permitted to run, encoded as a single boolean condition: `applicability == AFFECTED AND "
        "verification == VERIFIED_VULNERABLE AND module is a specifically registered, vetted module AND "
        "an explicit named human authorization is present`. Each term in this condition corresponds to "
        "a distinct module's output — `applicability` from M3's configuration-tree evaluation, "
        "`verification` from M3's live verification test, the module registry from M4's own vetted "
        "list — so that no single module's output, on its own, is ever sufficient to unlock "
        "exploitation. This design directly operationalizes the \"never conflate a CVE match with a "
        "confirmed vulnerability\" principle stated as part of Novelty Claim 4: a keyword-only NVD "
        "match is structurally incapable of reaching the `AFFECTED` state this gate checks for, since "
        "`AFFECTED` is only reached after the applicability engine's AND/OR/version-range evaluation, "
        "not before it. Chapter 5 reports the results of testing this gate adversarially against the "
        "running dashboard, including a client attempting to supply an arbitrary exploit module path "
        "directly."
    ))

    add_division(doc, registry, CH, 7, "Testing Strategy and Continuous Integration")
    add_para(doc, (
        "Every module is covered by its own automated test suite under `tests/`, organized to mirror "
        "the module layout (`tests/m0/` through `tests/m5/`, plus `tests/db/`), run with pytest and "
        "measured with branch coverage via pytest-cov. The suite runs in GitHub Actions on every push "
        "and pull request against the main branch (`.github/workflows/test.yml`), giving the project a "
        "continuous regression safety net from the first module onward rather than a test pass "
        "performed once before a review. Tests that exercise external services — the NVD, EPSS, and "
        "KEV HTTP calls in M3, and RouterSploit's execution path in M4 — mock those calls so that CI "
        "remains fast and deterministic; this is deliberately kept separate from the real-hardware, "
        "real-network, real-API validation runs reported in Chapter 5, which exist specifically to "
        "confirm that what the mocked tests assert is actually true against live systems, not only "
        "internally consistent."
    ))

    add_division(doc, registry, CH, 8, "Deployment and Operation")
    add_para(doc, (
        "Operating PISA requires the monitor-mode adapter to be placed into monitor mode before the "
        "dashboard is started — `nmcli device set <iface> managed no`, followed by bringing the "
        "interface down, setting `iw dev <iface> set type monitor`, and bringing it back up. The "
        "`nmcli ... managed no` step is not cosmetic: without it, NetworkManager silently reclaims the "
        "adapter back to managed mode the moment the link comes up, and a scan then completes with a "
        "`done` status, zero logged errors, and zero captured beacons — the channel-hopping and sniffing "
        "code runs without fault, it is simply listening on a managed-mode socket that never receives a "
        "raw 802.11 frame. This specific failure mode, discovered during development rather than assumed "
        "away, is documented in the project's own operating instructions precisely because it produces "
        "no error message of its own; an operator is told to check that `iw dev <iface> info` still "
        "reports `type monitor` if a scan finishes clean but empty, and to repeat the sequence after "
        "every reboot, since the interface reverts to managed mode on restart."
    ))
    add_para(doc, (
        "The dashboard itself must then be started as root, since `iw`, Scapy's raw-socket beacon "
        "capture, and `arp-scan` all require `CAP_NET_ADMIN`/`CAP_NET_RAW` capabilities; the project "
        "runs the whole application as root rather than isolating only the specific calls that need the "
        "privilege, a deliberate simplicity trade-off for a tool whose field operator is assumed to "
        "already hold physical access to the hardware. Both the full dashboard (`sudo venv/bin/python "
        "run.py`) and a headless CLI path (`run.py --scan --iface <iface> --duration <seconds>`, or "
        "`--join-network`/`--password`/`--join-iface` for M1) are supported, so the system can be "
        "operated identically whether or not a browser is available on the field device — a design "
        "decision that anticipates, without yet implementing, the dedicated touchscreen interface scoped "
        "as future work in Chapter 6."
    ))

    add_division(doc, registry, CH, 9, "Summary of Engineering Design Decisions")
    add_para(doc, (
        "Several of the design choices described across this chapter were not the first approach tried "
        "— each was arrived at after an earlier, more conventional choice was measured against real "
        "conditions and found wanting. Table 4.8 collects these decisions in one place as a single "
        "reference, since they are individually easy to lose track of when read across six separate "
        "module subsections, but collectively they are the clearest evidence that this system's design "
        "was shaped by what was actually observed during development, not only by what was planned "
        "before it started."
    ))
    add_table_with_caption(doc, registry, CH, "Key engineering design decisions and their rationale", [
        ["Decision", "Rationale"],
        ["`arp-scan` (shelled out) instead of a hand-rolled Scapy ARP sweep", "Scapy's reply matching could not keep pace with reply volume on a real, busy subnet (Section 4.3)"],
        ["mDNS instead of reverse DNS for device-type labelling", "Reverse DNS was confirmed non-functional on the actual target network; mDNS was confirmed to work (Section 4.3)"],
        ["Vendor CVE lookup kept separate from WSPS scoring", "Keeps `score_network()` a pure, offline-testable function (NFR-2) rather than dependent on network connectivity (Section 4.4.1)"],
        ["Concurrent, thread-pooled Nmap scanning in M1", "Sequential scanning became a multi-hour bottleneck once `arp-scan` started surfacing hundreds of real hosts (Section 4.4.2)"],
        ["A curated RouterSploit module registry rather than its full module set", "Not every shipped module has been vetted for safe behaviour against PISA's target device classes (Section 4.4.5)"],
        ["Whole-application root privilege rather than per-call privilege isolation", "A simplicity trade-off appropriate for a tool whose operator already holds physical hardware access (Section 4.8)"],
        ["Self-powered USB hub specified for the Alfa adapter", "A bus-powered hub was found to cause the adapter to drop or behave unstably under active scanning (Section 4.2)"],
    ], widths=[2.6, 3.8])
