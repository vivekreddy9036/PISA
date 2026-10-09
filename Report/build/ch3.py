from report_engine import add_chapter, add_division, add_subdivision, add_para, add_bullet, add_table_with_caption
from refs_data import cite


def build(doc, registry):
    CH = 3

    add_chapter(doc, registry, CH, "Problem Statement and Methodology")

    add_division(doc, registry, CH, 1, "Problem Definition")
    add_para(doc, (
        "Chapters 1 and 2 established that IoT security assessment today requires an assessor to "
        "manually operate four or more disconnected tools across two layers — WiFi-network security "
        "and device-level security — with no shared model of \"the target\" carried between them, and "
        "that no published tool or system closes this gap on portable, field-deployable hardware. This "
        "chapter restates that gap as a formal problem statement, derives concrete research questions "
        "and hypotheses from it, states the project's methodology, articulates PISA's five specific "
        "novelty claims against the related work surveyed in Chapter 2, summarizes the functional and "
        "non-functional requirements the system is built against, and sets out the ethical and legal "
        "boundaries the system is designed to operate within."
    ))
    add_para(doc, (
        "Formally: **given a wireless network and the IoT devices reachable on it, no existing "
        "portable system can (a) grade the network's own security posture from passive observation "
        "alone, (b) identify the specific devices on it without a labelled training corpus, (c) "
        "correlate those devices to real, currently-exploited vulnerabilities rather than keyword-"
        "matched ones, and (d) safely and verifiably confirm exploitability before reporting a device "
        "as at risk — all within a single pipeline on commodity edge hardware.** PISA is the system "
        "built to close this gap."
    ))

    add_division(doc, registry, CH, 2, "Research Questions and Hypotheses")
    add_para(doc, (
        "The primary research question this project investigates is whether a portable, "
        "self-contained system can perform end-to-end IoT security assessment — from wireless network "
        "vulnerability scoring through protocol-aware device fingerprinting to CVE-exploit correlation "
        "— without machine learning, on commodity hardware. This is decomposed into three supporting "
        "questions, each paired with a testable hypothesis evaluated in Chapter 5."
    ))
    add_bullet(doc, "**RQ2 (Network layer).** Can passive WiFi beacon-frame analysis alone produce a "
                    "security-posture score that meaningfully predicts a network's exploitability, "
                    "without active packet injection or authentication? — **H1:** the WSPS framework "
                    "will assign security grades that agree with manual expert assessment on the same "
                    "networks.")
    add_bullet(doc, "**RQ3 (Device layer).** Do IoT devices from the same manufacturer and firmware "
                    "generation exhibit sufficiently consistent protocol-behavioural signatures — MQTT "
                    "topic structure, CoAP response-option ordering, HTTP header ordering — to enable "
                    "deterministic, non-ML device identification at accuracy comparable to ML-based "
                    "approaches? — **H2:** protocol-aware behavioural fingerprinting will correctly "
                    "identify device type with accuracy competitive with the ML baselines surveyed in "
                    "Chapter 2.")
    add_bullet(doc, "**RQ4 (Integration).** What accuracy, completeness, and time-to-assessment does "
                    "the integrated two-layer pipeline achieve relative to a manual multi-tool "
                    "workflow (Nmap, Bettercap, RouterSploit, and manual NVD search)? — **H3:** the "
                    "automated CVE-correlation pipeline will surface applicable high-severity CVEs "
                    "faster than an equivalent manual search; **H4:** end-to-end assessment time on the "
                    "integrated pipeline will be substantially lower than the equivalent manual "
                    "workflow.")
    add_para(doc, (
        "Table 3.1 states, for each hypothesis, the specific metric and target this project treats as "
        "evidence for or against it, so that the discussion in Chapter 5 can be read against a stated "
        "bar rather than an implicit one. Several of these evaluations require the physical hardware "
        "acquisition scoped in Chapter 6 and are reported in Chapter 5 only where real evidence toward "
        "them already exists."
    ))
    add_table_with_caption(doc, registry, CH, "Planned evaluation metrics per hypothesis", [
        ["Hypothesis", "Metric", "Target"],
        ["H1 — WSPS validity", "Agreement between WSPS grade and independent manual expert assessment on the same networks", "High agreement across a multi-network sample"],
        ["H2 — Fingerprinting accuracy", "Per-protocol and fused-confidence precision/recall against known device ground truth", "Accuracy competitive with the ML baseline reported in Section 2.4"],
        ["H3 — CVE surfacing completeness", "Time from device identification to a ranked, applicable CVE list; completeness against vendor-advisory ground truth", "All applicable high-severity (CVSS ≥ 7.0) CVEs surfaced within a short, field-practical window"],
        ["H4 — End-to-end timing", "Total assessment time, PISA's integrated pipeline vs. an equivalent manual Nmap + Bettercap + RouterSploit + manual-NVD-search workflow", "Substantial reduction relative to the manual baseline"],
    ], widths=[1.7, 3.1, 1.8])

    add_division(doc, registry, CH, 3, "Development Methodology")
    add_para(doc, (
        "PISA was developed iteratively rather than against a single fixed specification produced "
        "up front. Each module (M0 through M5) was specified in its own section of the project's "
        "Software Requirements Specification, implemented, covered by automated unit and integration "
        "tests, and only then marked **Implemented** in the specification's own requirement-"
        "traceability table — a discipline that was maintained across seven tracked specification "
        "revisions as the system grew from WiFi-only scoring (M0) through network discovery (M1), "
        "protocol fingerprinting (M2), CVE correlation (M3), and gated exploitation (M4). This "
        "iterative, test-driven approach was chosen deliberately over a waterfall design-then-build "
        "process for two reasons specific to a security tool: first, several design assumptions — "
        "such as whether a Scapy-based ARP sweep would scale to a real, busy subnet — could only be "
        "validated against real hardware and real networks, not on paper; second, keeping every "
        "requirement explicitly labelled **Implemented** or **Planned** at all times (rather than "
        "assumed complete) was adopted as a project-wide honesty discipline to prevent the "
        "documentation from silently drifting ahead of the code, a risk this report itself follows by "
        "distinguishing, in Chapters 4 and 5, what has been built and validated from what remains "
        "future work."
    ))
    add_para(doc, (
        "Each module's test suite was written and run continuously via GitHub Actions on every push, "
        "giving the project a regression safety net from the first module onward; by the state "
        "reported in Chapter 5, this had grown to 381 automated tests spanning all six implemented "
        "modules. Validation was further organized into two deliberately distinct evidence tiers, kept "
        "visibly separate throughout development: automated unit/integration tests running against "
        "mocked external services (for fast, deterministic CI runs), and a smaller set of explicit "
        "real-hardware, real-network, real-external-API validation passes, the results of which are "
        "reported honestly in Chapter 5 as what was actually observed, not what the design predicts."
    ))
    add_para(doc, (
        "Table 3.2 traces this iterative growth directly through the Software Requirements "
        "Specification's own revision history, each entry corresponding to one module or capability "
        "reaching the **Implemented** status referenced throughout this report."
    ))
    add_table_with_caption(doc, registry, CH, "Software Requirements Specification revision history", [
        ["Version", "Change"],
        ["1.0", "Initial SRS, aligned to the first implemented slice: M0 (WiFi assessment), the database layer, and M5 (dashboard)"],
        ["1.1", "Added PMKID / EAPOL handshake capture (passive mode) to M0"],
        ["1.2", "M1 (network join + device discovery) implemented; the earlier synthetic demo-data mode removed in favour of live-hardware validation"],
        ["1.3", "M3 device CVE correlation (NVD lookup) implemented"],
        ["1.4", "M1 extended with mDNS-based device identification"],
        ["1.5", "M2 (protocol behavioural fingerprinting) implemented"],
        ["1.6", "M3 extended with EPSS and CISA KEV correlation and the tri-metric exploit score"],
        ["1.7", "M4 (authorized RouterSploit exploit verification) implemented"],
    ], widths=[1.0, 5.6])
    add_para(doc, (
        "Several of these transitions were driven by a measured engineering risk rather than a planning "
        "assumption, and Table 3.3 records the risks that materially changed the implementation as they "
        "were actually encountered, alongside the mitigation adopted — a risk register kept honest by "
        "only including risks that were real enough to have already changed a design decision described "
        "in Chapter 4, rather than a generic, unverified list."
    ))
    add_table_with_caption(doc, registry, CH, "Technical risks encountered and their mitigations", [
        ["Risk", "Where it surfaced", "Mitigation adopted"],
        ["Scapy-based ARP sweep cannot keep pace with reply volume on a large, busy subnet",
         "M1 host discovery (Section 4.3)", "Shelled out to the system `arp-scan` binary instead"],
        ["Sequential Nmap scanning becomes a multi-hour bottleneck once host discovery surfaces hundreds of live hosts",
         "M1 service/OS scan (Section 4.4.2)", "Pooled, concurrent scanning bounded by `config.NMAP_MAX_WORKERS`"],
        ["Reverse DNS does not resolve device names on the actual target network",
         "M1 device labelling (Section 4.3)", "Switched to mDNS-based device identification (SRS v1.4)"],
        ["Folding a live CVE lookup into WSPS scoring would make scoring depend on network connectivity",
         "M0 scoring design (Section 4.4.1)", "CVE correlation kept as a separate, on-demand lookup (FR-3), preserving NFR-2"],
        ["RouterSploit's wordlist loader and shell module fail outright on Python 3.13",
         "M4 dependency setup", "Pinned compatibility shims (`setuptools<81`, `standard-telnetlib`) in requirements.txt"],
    ], widths=[2.6, 1.8, 2.0])

    add_division(doc, registry, CH, 4, "Novelty Claims")
    add_para(doc, (
        "Against the five research gaps identified in Chapter 2 (Section 2.10), PISA makes five "
        "specific novelty claims. Each is stated here against its closest related work; the "
        "corresponding engineering design is described in Chapter 4, and its current validation status "
        "is reported in Chapter 5."
    ))
    add_subdivision(doc, registry, CH, 4, 1, "Claim 1 — WiFi Security Posture Scoring (WSPS)")
    add_para(doc, (
        "A quantitative, letter-graded (A-F) security score computed for a wireless network from "
        "passive beacon-frame analysis alone, with no active association, authentication, or packet "
        "injection. Existing wardriving tools such as Kismet and WiGLE capture comparable raw data but "
        "apply no scoring; no reviewed paper defines a passive-beacon-only posture-scoring framework "
        "closing gap G3 " + cite("P01", "P02", "P03", "P04") + "."
    ))
    add_subdivision(doc, registry, CH, 4, 2, "Claim 2 — OUI-to-CVE Infrastructure Correlation")
    add_para(doc, (
        "Automatic correlation of a WiFi access point's hardware identity, derived from its BSSID's "
        "Organizationally Unique Identifier (OUI), to applicable CVEs from the live NVD database, "
        "computed on-demand rather than from a static offline list. Internet-facing device indexes "
        "such as Shodan perform a comparable correlation at internet scale on internet-facing devices; "
        "no reviewed tool performs it for local, non-internet-facing router hardware from passively "
        "captured beacon data."
    ))
    add_subdivision(doc, registry, CH, 4, 3, "Claim 3 — Non-ML Cross-Protocol Behavioural Fingerprinting")
    add_para(doc, (
        "Device identification from *how* a device behaves within MQTT, CoAP, HTTP, and RTSP — topic "
        "hierarchy, response-option ordering, header ordering, and authentication-challenge format — "
        "fused across protocols when a device answers on more than one, using a probabilistic "
        "complement-fusion rule (combined confidence = 1 − ∏(1 − cᵢ) across each protocol's individual "
        "confidence cᵢ), rather than requiring a labelled training corpus per device class as the "
        "closest ML baseline does " + cite("P07") + ". No reviewed single-protocol fingerprinting work "
        + cite("P08", "P09", "P10") + " proposes a cross-protocol fusion mechanism, closing gaps G4 and "
        "G5."
    ))
    add_subdivision(doc, registry, CH, 4, 4, "Claim 4 — Integrated Two-Layer Pipeline on Portable Hardware")
    add_para(doc, (
        "Chaining WiFi-layer assessment (Claims 1-2) with device-layer fingerprinting and CVE "
        "correlation (Claims 3, 5) in one automated pipeline on Raspberry Pi 4 class hardware, "
        "eliminating the fragmented Nmap-Bettercap-RouterSploit-manual-NVD-search workflow with a "
        "single field-deployable device, closing gap G1 " + cite("P06", "P20") + "."
    ))
    add_subdivision(doc, registry, CH, 4, 5, "Claim 5 — Tri-Metric Exploitability Scoring at the Edge")
    add_para(doc, (
        "Computing device-specific exploitability from all three authoritative signals together — "
        "CVSS v3.1 severity, FIRST.org's EPSS 30-day exploitation-probability score, and CISA KEV "
        "confirmed-exploitation listing — on edge hardware rather than requiring cloud-scale compute, "
        "closing gap G2. No reviewed portable IoT assessment tool combines EPSS with CVSS and KEV at "
        "the point of assessment " + cite("P15", "P16", "P17", "P18") + "; the full combination formula "
        "is given in Chapter 4."
    ))

    add_division(doc, registry, CH, 5, "Requirements Specification")
    add_para(doc, (
        "PISA's Software Requirements Specification (conforming to the IEEE 830-1998 structure) defines "
        "twelve functional requirements and seven non-functional requirements against the system's v1 "
        "scope. Table 3.4 and Table 3.5 summarize both, each tagged by its current implementation "
        "status; the file(s) implementing each requirement are given in Chapter 4 alongside the module "
        "they belong to."
    ))
    add_table_with_caption(doc, registry, CH, "Functional requirements summary (v1)", [
        ["ID", "Requirement", "Module", "Status"],
        ["FR-1", "WiFi beacon frame capture (BSSID, SSID, channel, signal, encryption, PMF, WPS)", "M0", "Implemented"],
        ["FR-2", "WiFi Security Posture Score (WSPS), 0-100 and A-F grade", "M0", "Implemented"],
        ["FR-3", "OUI-to-vendor resolution and on-demand vendor-to-CVE (NVD) lookup", "M0", "Implemented"],
        ["FR-4", "Scan session creation, status tracking, and persistence", "M0 / DB", "Implemented"],
        ["FR-6", "Web dashboard — session list, scan trigger, results, CVE lookup", "M5", "Implemented"],
        ["FR-7", "Network join + device discovery (ARP sweep, Nmap -sV -O, mDNS ID)", "M1", "Implemented"],
        ["FR-8", "Protocol behavioural fingerprinting (MQTT/CoAP/HTTP/RTSP) with fusion", "M2", "Implemented"],
        ["FR-9", "Device CVE correlation, enriched with EPSS + CISA KEV + exploit score", "M0 / M3", "Implemented"],
        ["FR-10", "Authorized exploit verification via RouterSploit, with audit logging", "M4", "Implemented"],
        ["FR-12", "PMKID / EAPOL handshake capture (passive mode)", "M0", "Implemented, passive only"],
        ["FR-11", "Cloud reporting — AWS sync and automated PDF generation", "AWS", "Planned"],
    ], widths=[0.7, 3.4, 0.9, 1.5])
    add_table_with_caption(doc, registry, CH, "Non-functional requirements summary (v1)", [
        ["ID", "Requirement", "Status"],
        ["NFR-1", "A scan shall not block the dashboard from serving other requests", "Implemented"],
        ["NFR-2", "WSPS scoring shall be a pure function of packet data, testable offline", "Implemented"],
        ["NFR-3", "A failed capture shall mark the session errored, not crash the server", "Implemented"],
        ["NFR-4", "The dashboard shall render with no external CDN/internet-hosted asset", "Implemented"],
        ["NFR-5", "All SQLite writes shall enforce foreign-key constraints", "Implemented"],
        ["NFR-6", "The automated test suite shall run in CI on every push/PR", "Implemented"],
        ["NFR-7", "Exploit verification shall require logged, explicit operator authorization", "Implemented"],
    ], widths=[0.9, 4.6, 1.0])
    add_para(doc, (
        "As Table 3.4 shows, every v1 functional requirement except cloud reporting (FR-11) is "
        "implemented; FR-5 (an early synthetic demo-data mode) was deliberately removed in v1.2 once "
        "live-hardware operation was considered the project's standard of evidence, a decision "
        "explained further in Chapter 4."
    ))

    add_division(doc, registry, CH, 6, "Ethics, Legal Constraints, and Safety")
    add_para(doc, (
        "PISA is designed exclusively for authorized security assessment, and this constraint shapes "
        "its architecture rather than being an afterthought layered on top of it. Under India's "
        "Information Technology Act, 2000, unauthorized access to a computer system is a civil offence "
        "under Section 43 and, where accompanied by dishonest intent, a criminal offence under Section "
        "66; PISA's design assumes use exclusively by a network's owner or an operator with explicit, "
        "documented authorization to test it, consistent with the authorization-gate methodology "
        "established in the organizational IoT risk-assessment literature " + cite("P19") + " and "
        "discussed in Section 2.6."
    ))
    add_para(doc, (
        "Three design principles follow directly from this constraint and recur throughout the "
        "module designs in Chapter 4. First, the system never auto-exploits: Module 4's authorization "
        "gate structurally requires a named operator, an explicit confirmation, and a mandatory delay "
        "before any exploit action becomes available, regardless of how confident the system is in a "
        "finding. Second, every scan, join, fingerprint probe, and exploit attempt is written to an "
        "append-only audit log, not merely displayed and discarded, so that a record of what was done, "
        "by whom, and when exists independently of the dashboard session. Third, the dashboard binds to "
        "the local loopback interface by default rather than being exposed on the network — since its "
        "API has no authentication layer of its own and several of its endpoints accept WiFi passwords "
        "and trigger real network actions, exposing it by default would itself be a safety regression; "
        "an operator must explicitly opt in to exposing it, and is told exactly why in the system's own "
        "documentation."
    ))
    add_para(doc, (
        "A fourth principle governs how captured data itself is treated: WiFi passwords supplied for "
        "M1's network-join action exist only for the duration of the join operation and are not "
        "persisted in the session database alongside the rest of a network's record, and the passive "
        "PMKID/EAPOL material M0 can capture (Section 4.4.1) is stored as the hash material itself "
        "rather than in any plaintext-recoverable form, consistent with the principle that an "
        "assessment tool's own evidence store should not become a second attack surface. This principle "
        "is stated here as a binding design constraint that the implementation in Chapter 4 is held to, "
        "rather than as a claim about a specific encryption-at-rest mechanism not yet built in v1."
    ))
    add_para(doc, (
        "These constraints are revisited concretely in Chapter 4, where the specific state machine "
        "enforcing them in Module 4 is described, and in Chapter 5, where the gate is shown to have "
        "been tested adversarially — not merely asserted to exist."
    ))
