from report_engine import add_chapter, add_division, add_subdivision, add_para, add_bullet, add_table_with_caption
from refs_data import cite


def build(doc, registry):
    CH = 1

    add_chapter(doc, registry, CH, "Introduction")

    add_division(doc, registry, CH, 1, "Background and Motivation")
    add_para(doc, (
        "The number of Internet of Things (IoT) devices deployed across homes, enterprises, and "
        "industrial environments has grown far faster than the security practices needed to manage "
        "them. Smart plugs, IP cameras, home routers, and sensor hubs are routinely shipped with "
        "default credentials, outdated firmware, and application-layer protocols such as MQTT and "
        "CoAP that were never designed with an adversarial network in mind. The United States "
        "Cybersecurity and Infrastructure Security Agency (CISA) maintains a Known Exploited "
        "Vulnerabilities (KEV) catalogue that, as of this project's survey of the literature, lists "
        "hundreds of router and IoT-device CVEs confirmed to be under active exploitation in the "
        "wild, yet no widely available tool allows a field assessor to determine, in minutes and on "
        "portable hardware, whether a specific environment is exposed to any of them."
    ))
    add_para(doc, (
        "This gap is not for lack of individual tools. Wardriving utilities such as Kismet and WiGLE "
        "log raw WiFi beacon data without any security scoring; network scanners such as Nmap "
        "enumerate open ports and services without correlating them to known vulnerabilities; "
        "vulnerability databases such as the National Vulnerability Database (NVD) and exploitation "
        "frameworks such as RouterSploit exist in complete isolation from one another. An assessor "
        "wishing to answer the simple question \"is this network, and the devices on it, safe\" today "
        "has to manually stitch together four or more separate tools, each with its own mental model "
        "of what a \"target\" is, and no shared chain of evidence connecting a discovered weakness to "
        "a verified, exploitable finding. This fragmentation is itself a documented research gap: a "
        "2024 systematic review of more than forty IoT security audit tools concluded that no existing "
        "tool integrates wireless-network-layer assessment with device-layer vulnerability correlation "
        "in a single, portable pipeline " + cite("P20") + "."
    ))
    add_para(doc, (
        "PISA (Portable IoT Security Assessment Platform) is the system developed in response to this "
        "gap. It is designed to run on commodity, field-deployable hardware (a Raspberry Pi 4 together "
        "with an external monitor-mode WiFi adapter) and to carry an assessor through a single, "
        "evidence-preserving pipeline: passively score the security posture of a wireless network from "
        "its beacon frames alone, correlate the access point's hardware vendor against known CVEs, "
        "join the network on request to enumerate and fingerprint the IoT devices living on it, "
        "correlate those devices' CVEs using NVD, FIRST.org's Exploit Prediction Scoring System (EPSS) "
        "and the CISA KEV catalogue, and — only under explicit, logged operator authorization — verify "
        "specific vulnerabilities against those devices before any exploitation is even offered. Every "
        "stage of this pipeline is architecturally in the spirit of standalone penetration-testing "
        "hardware (in the manner of Hak5-style gadgets) rather than a laptop-bound application, and the "
        "whole assessment is presented through a single browser dashboard."
    ))

    add_division(doc, registry, CH, 2, "Problem Statement")
    add_para(doc, (
        "The IoT attack surface has two layers that existing tooling treats in complete isolation. "
        "The first is the **network access layer**: the WiFi network an IoT device connects to is "
        "itself frequently misconfigured, running deprecated encryption, leaving Wi-Fi Protected Setup "
        "(WPS) enabled, or running access-point firmware with publicly known, actively exploited CVEs. "
        "Even WPA3, the current state of the art, has been shown to carry exploitable side-channel and "
        "downgrade weaknesses in its Dragonfly handshake " + cite("P01") + ", and systematic analysis "
        "of pre-authentication WiFi behaviour has confirmed that management frames such as beacons "
        "leak substantial security-relevant information before a device ever associates with a network "
        + cite("P04") + ". No portable tool autonomously assesses this layer and expresses the result "
        "as a single, actionable security grade."
    ))
    add_para(doc, (
        "The second is the **device layer**: once inside a network, IoT devices communicate using "
        "application-layer protocols — MQTT, CoAP, HTTP, RTSP — that carry behavioural signatures "
        "specific to their manufacturer and firmware generation. Existing approaches to identifying "
        "these devices either depend on machine learning and large labelled traffic corpora "
        + cite("P07") + ", or stop at confirming which service ports are open without analysing how a "
        "device behaves within its own protocol. Compounding this, large-scale measurement of MQTT "
        "broker deployments has found that the large majority run with no authentication configured at "
        "all " + cite("P12") + ", and CoAP's plaintext, connectionless design exposes a comparable "
        "resource-discovery surface " + cite("P14") + ". Translating \"this device is a Hikvision "
        "camera\" into \"this device is affected by CVE-2021-36260\" is itself non-trivial: a device "
        "fingerprint has to be mapped to a precise Common Platform Enumeration (CPE) string, correlated "
        "against NVD, and ranked by real-world exploitability rather than severity alone, since EPSS "
        "scores are frequently low or unavailable for CVEs at the moment they first appear in the CISA "
        "KEV catalogue " + cite("P16") + " — meaning no single scoring metric is sufficient on its own."
    ))
    add_para(doc, (
        "No existing tool, product, or published work performs an end-to-end, automated assessment "
        "spanning both layers — from passive wireless posture scoring through device fingerprinting, "
        "precise CVE correlation, and safe exploit verification — on portable, field-deployable "
        "hardware. This leaves security practitioners, and academic researchers studying IoT security "
        "at scale, without an efficient methodology for comprehensive environment auditing that does "
        "not depend on a laptop, an internet-scale cloud service, or a trained machine-learning model. "
        "Table 1.1 summarizes the specific capability gaps this project addresses and is examined in "
        "full, against named prior tools and published work, in Chapter 2."
    ))
    add_table_with_caption(doc, registry, CH, "Capability gaps addressed by this project", [
        ["Gap", "Existing practice", "Consequence"],
        ["No unified WiFi + device pipeline",
         "Nmap, Bettercap, RouterSploit, manual NVD search used as four disconnected tools",
         "No shared evidence model from discovery to exploitation"],
        ["No passive WiFi posture scoring",
         "Wardriving tools (Kismet, WiGLE) log raw beacon data only",
         "No actionable A-F grade an assessor can report"],
        ["No non-ML cross-protocol fingerprinting",
         "ML-based classifiers require labelled training data per device class",
         "Cannot identify unseen or custom industrial/IoT devices"],
        ["No contextual exploitability ranking",
         "CVSS severity alone is used to prioritize findings",
         "Low-severity, actively-exploited CVEs (per CISA KEV) are missed"],
        ["No gated, auditable exploitation step",
         "Manual exploit selection with no enforced authorization state machine",
         "No defensible, logged chain of authorization before any live exploit attempt"],
    ], widths=[1.7, 2.3, 2.3])
    add_para(doc, (
        "Each row in Table 1.1 is a gap in current practice, not a gap in any single tool's feature "
        "list — meaning it cannot be closed by adding a feature to Nmap or to RouterSploit individually, "
        "since the missing element is the connective evidence chain between them, not a missing "
        "capability within either. This framing matters for how PISA's contribution should be read "
        "throughout this report: Chapter 4 does not claim to out-perform Nmap at scanning or "
        "RouterSploit at exploitation — both are reused directly as execution backends, as detailed in "
        "Section 4.3 — but to be the first system that connects what they each already do into one "
        "pipeline that never loses track of which stage actually established which piece of evidence."
    ))

    add_division(doc, registry, CH, 3, "Objectives of the Project")
    add_para(doc, (
        "The primary objective of this project is to design, implement, and evaluate a portable, "
        "self-contained IoT security assessment platform on Raspberry Pi 4 class hardware that "
        "performs automated, two-layer security assessment: wireless-network vulnerability scoring "
        "and access-point CVE correlation on one hand, and IoT device protocol-aware behavioural "
        "fingerprinting with CVE correlation and gated exploit verification on the other."
    ))
    add_para(doc, "This primary objective is decomposed into the following secondary objectives.", indent=True)
    add_bullet(doc, "**O1.** Develop a WiFi Security Posture Scoring (WSPS) framework that derives a "
                    "quantitative, letter-graded (A-F) security score for a network from passive beacon "
                    "frame analysis alone, without active association, authentication, or packet "
                    "injection.")
    add_bullet(doc, "**O2.** Implement protocol-aware behavioural fingerprinting for IoT devices across "
                    "MQTT, CoAP, HTTP, and RTSP that identifies device type and, where evidence "
                    "supports it, manufacturer and model, without using machine learning or a labelled "
                    "training corpus.")
    add_bullet(doc, "**O3.** Build an automated device-fingerprint-to-CVE correlation pipeline against "
                    "the live NVD CVE API, enriched with FIRST.org's EPSS exploitation-probability "
                    "score and the CISA KEV catalogue, combined into a single contextual exploitability "
                    "metric.")
    add_bullet(doc, "**O4.** Implement a safe, explicitly authorized exploit-verification stage that "
                    "structurally prevents a device from being reported as exploitable unless it has "
                    "first been found applicable by the CVE engine and then live-verified, with every "
                    "authorization and outcome recorded in an append-only audit log.")
    add_bullet(doc, "**O5.** Validate the complete pipeline against real hardware, real live networks, "
                    "and real external threat-intelligence APIs (NVD, FIRST.org EPSS, CISA KEV) rather "
                    "than synthetic or simulated data, and report results exactly as observed.")

    add_division(doc, registry, CH, 4, "Scope of the Project")
    add_subdivision(doc, registry, CH, 4, 1, "In Scope for the Current Phase")
    add_para(doc, (
        "The current release (v1) of PISA, which this report documents, implements six software "
        "modules, referred to throughout this report as M0 through M5, described in full in Chapter 4. "
        "In summary, the system in its present form: captures 802.11 beacon frames passively and "
        "computes a WSPS grade per network (M0); resolves an access point's vendor from its BSSID and "
        "performs an on-demand NVD CVE lookup against that vendor (M0); joins a scored network with an "
        "operator-supplied password and discovers live devices on it using an ARP sweep and an Nmap "
        "service/OS scan, identified further via mDNS (M1); fingerprints each discovered device's "
        "MQTT, CoAP, HTTP, and RTSP behaviour and fuses the per-protocol evidence into a single "
        "device-type and confidence (M2); correlates each device against NVD, enriches every returned "
        "CVE with its EPSS score and CISA KEV status, and computes a combined exploit score (M3); and, "
        "only under an operator's explicit, logged authorization, verifies specific CVEs against a "
        "device through RouterSploit and performs a gated exploitation attempt (M4). All of the above "
        "is presented and triggered through a single local Flask dashboard (M5)."
    ))
    add_subdivision(doc, registry, CH, 4, 2, "Out of Scope for the Current Phase")
    add_para(doc, (
        "Cloud-backed reporting and long-term storage (synchronization of session data to AWS "
        "DynamoDB/S3 and automated PDF report generation via AWS Lambda) is architecturally scoped "
        "but intentionally not implemented in v1; the `pisa/aws/` package exists as a stub only, and "
        "is treated as future work in Chapter 6. Likewise, GPS-tagged \"warwalking\", a dedicated "
        "touchscreen interface, continuous background monitoring mode, and any machine-learning- or "
        "blockchain-based component are explicitly out of scope — the last two by a project-level "
        "constraint to keep every classification and scoring decision deterministic and auditable, "
        "which is itself revisited as a design principle in Chapter 3."
    ))

    add_division(doc, registry, CH, 5, "Project Constraints")
    add_para(doc, (
        "This project was undertaken under a fixed set of technology and domain constraints set for "
        "the Bachelor of Technology final-year project track it belongs to. Table 1.2 states each "
        "constraint and how PISA's design, described fully in Chapter 4, satisfies it; these "
        "constraints directly shaped several of the scope decisions explained in Section 1.4 — most "
        "visibly, the decision to keep every classification and scoring decision in Chapters 4 and 5 "
        "deterministic and rule-traceable rather than learned."
    ))
    add_table_with_caption(doc, registry, CH, "Project constraints and how PISA satisfies them", [
        ["Constraint", "How PISA satisfies it"],
        ["Cloud platform (AWS or Azure)", "AWS integration (DynamoDB, S3, Lambda) is architected in Chapter 4 and scoped as the project's next major extension in Chapter 6; boto3 is already a pinned dependency"],
        ["CI/CD and DevOps practice", "GitHub Actions runs the full automated test suite on every push/PR (Section 4.7)"],
        ["Raspberry Pi 4 and peripheral hardware", "RPi 4 plus an external monitor-mode WiFi adapter is the system's core target platform (Section 4.2)"],
        ["IoT security / hardware security domain", "The project's entire scope, from Chapter 1 onward"],
        ["No machine learning or deep learning as a core mechanism", "Every classification and scoring decision (WSPS, device fingerprinting, CVE applicability) is additive, rule-based, and individually traceable (Chapter 4)"],
        ["No blockchain component", "Not used anywhere in the system"],
        ["No dataset-based offline analysis", "All assessment is performed against live, active capture and live external APIs, never a static/offline dataset (Chapter 5)"],
    ], widths=[2.6, 3.8])

    add_division(doc, registry, CH, 6, "Significance of the Study")
    add_para(doc, (
        "This project is significant along two distinct axes. Practically, it addresses a concrete, "
        "named shortfall in current security-assessment practice: the manual, multi-tool workflow "
        "described in Section 1.2 is not merely inconvenient, it structurally loses the evidence chain "
        "between discovery and exploitation, meaning an assessor using Nmap, Bettercap, and RouterSploit "
        "separately has no systematic guarantee against conflating \"this CVE's keyword matched this "
        "device's banner\" with \"this device is actually vulnerable\" — a distinction Chapter 4 shows "
        "PISA enforces structurally rather than by operator discipline alone. A field assessor, a "
        "small organization without a dedicated security team, or a student studying IoT security "
        "stands to benefit directly from a single, portable tool that preserves this distinction "
        "automatically."
    ))
    add_para(doc, (
        "Academically, the project contributes a specific, falsifiable set of claims — the five novelty "
        "claims formalized in Chapter 3 — each positioned against named prior work rather than asserted "
        "in isolation, and each paired with a result reported honestly in Chapter 5 as validated, "
        "partially validated, or not yet validated. This discipline is itself part of the contribution: "
        "a project report that only ever reports successes is weaker evidence of engineering competence "
        "than one that states, in the same document, what has been proven and what remains open, which "
        "is the standard this report holds itself to throughout."
    ))

    add_division(doc, registry, CH, 7, "Organization of the Report")
    add_para(doc, (
        "The remainder of this report is organized as follows. Chapter 2 surveys the published "
        "literature underpinning each layer of PISA's design and positions the project against named "
        "prior tools and research systems. Chapter 3 formalizes the problem statement into concrete "
        "research questions and hypotheses, states the project's novelty claims, and summarizes the "
        "functional and non-functional requirements and the ethical/legal constraints the system is "
        "designed under. Chapter 4 describes the system architecture, hardware, technology stack, and "
        "the design of each of the six software modules in detail. Chapter 5 reports the results "
        "obtained to date, including real-hardware validation, an automated test-suite summary, and "
        "adversarial testing of the authorization gate, and discusses these results against the "
        "related work identified in Chapter 2. Chapter 6 concludes the report and sets out the scope "
        "of work remaining before the final project review."
    ))
    add_para(doc, (
        "A reader interested specifically in what has been built and proven, rather than in the full "
        "research framing, can read Chapters 4 and 5 directly; a reader interested in how this project "
        "positions itself against existing tools and published work can start from Chapter 2. The "
        "chapters are nonetheless written to be read in order, since each later chapter's claims are "
        "stated against terms — the novelty claims of Chapter 3, the module names and figures of "
        "Chapter 4 — introduced in the chapter before it."
    ))
