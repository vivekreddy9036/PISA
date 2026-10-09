from report_engine import add_chapter, add_division, add_subdivision, add_para, add_bullet, add_table_with_caption
from refs_data import cite


def build(doc, registry):
    CH = 2

    add_chapter(doc, registry, CH, "Literature Review")

    add_division(doc, registry, CH, 1, "Introduction")
    add_para(doc, (
        "This chapter surveys the twenty peer-reviewed and pre-print sources that ground PISA's "
        "design, organized by the layer of the system each informs: WiFi-level security assessment "
        "(Section 2.2), network and device discovery in enterprise/IoT contexts (Section 2.3), "
        "protocol-aware device fingerprinting (Section 2.4), CVE correlation and exploit scoring "
        "(Section 2.5), authorized exploit validation (Section 2.6), and the state of unified IoT "
        "audit tooling as a whole (Section 2.7). Section 2.8 then compares PISA directly against named "
        "prior tools, platforms, and research systems, and Section 2.10 draws the chapter together into "
        "the specific research gaps this project addresses."
    ))

    add_division(doc, registry, CH, 2, "WiFi Security Assessment and Beacon-Level Analysis")
    add_para(doc, (
        "Vanhoef and Ronen's analysis of WPA3's Dragonfly handshake, known as Dragonblood, showed that "
        "even the current generation of WiFi encryption carries exploitable timing and cache "
        "side-channels that permit offline password recovery, and that downgrade attacks can force a "
        "WPA3-capable network back to the weaker WPA2 handshake " + cite("P01") + ". This result is "
        "significant for PISA because it establishes that a network's advertised encryption capability "
        "in its beacon frame is not, by itself, a reliable indicator of security — a station that has "
        "silently been downgraded is a materially different risk than one that was never configured "
        "for WPA3 at all, which is why PISA's WiFi Security Posture Score (WSPS, detailed in Chapter 4) "
        "treats protocol downgrade as a distinct, trackable signal rather than folding it into a single "
        "static encryption-type score. Vanhoef's subsequent, broader study of IEEE 802.11 frame "
        "aggregation and fragmentation handling identified twelve design-level flaws affecting every "
        "WiFi device shipped since 1997, independent of which encryption protocol is in use "
        + cite("P02") + ", reinforcing that passive, protocol-level observation of a network carries "
        "genuine security information well beyond a simple \"is it encrypted\" check. Schepers et al. "
        "extended this line of work by showing that an access point's transmit-queue behaviour during "
        "power-save mode can be manipulated to bypass WPA2 and WPA3 encryption outright "
        + cite("P03") + ", and Gvozdenovic et al. conducted a systematic study of the pre-authentication "
        "phase of WiFi connection establishment specifically, concluding that management frames — "
        "beacons among them — leak substantial, exploitable information before a client ever "
        "associates with the network " + cite("P04") + "."
    ))
    add_para(doc, (
        "Taken together, these four studies form the direct justification for PISA's Module 0 design "
        "decision: that a WiFi network's security posture can and should be assessed from beacon "
        "frames alone, before any active association, authentication, or packet injection is "
        "attempted. None of the four, however, propose an aggregate scoring methodology — each "
        "documents a specific class of vulnerability rather than a mechanism for turning passively "
        "observed signals into a single, field-actionable grade. That synthesis step is PISA's own "
        "contribution, discussed in Chapter 3."
    ))
    add_para(doc, (
        "Each of these four studies maps onto a specific, traceable factor in the WSPS formula "
        "described fully in Section 4.4.1, rather than informing the design only in general terms. "
        "Vanhoef and Ronen's Dragonfly side-channel result " + cite("P01") + " is the direct motivation "
        "for treating encryption type as the single highest-weighted factor in the formula, since it is "
        "the factor that most directly reflects which handshake class — and therefore which known "
        "weaknesses — a network is exposed to. Vanhoef's frame-aggregation study " + cite("P02") + ", "
        "which affects WiFi devices independent of encryption generation, supports scoring signal and "
        "channel characteristics as independent factors rather than folding everything into the "
        "encryption score alone, since a frame-level vulnerability is not mitigated by stronger "
        "encryption. Schepers et al.'s transmit-queue manipulation result " + cite("P03") + " and "
        "Gvozdenovic et al.'s pre-authentication leakage study " + cite("P04") + " jointly motivate "
        "treating Management Frame Protection (802.11w) support and WPS exposure as explicit, separately "
        "weighted factors rather than secondary detail, since both studies identify pre-association "
        "management-frame behaviour, not post-association traffic, as the exploitable surface — exactly "
        "the surface WSPS is scoped to observe."
    ))

    add_division(doc, registry, CH, 3, "Network Discovery and the Enterprise IoT Attack Surface")
    add_para(doc, (
        "Nguyen et al. proposed DIoT, a federated, self-learning system that detects compromised IoT "
        "devices from network-level traffic anomalies across many deployments without centralizing raw "
        "traffic " + cite("P05") + ". DIoT is architecturally significant as a privacy-preserving "
        "detection design, but it requires continuous network visibility, a federated training "
        "infrastructure, and cloud connectivity that a field-portable, point-in-time assessment tool "
        "such as PISA does not assume. Churcher et al.'s survey of the enterprise IoT (E-IoT) attack "
        "surface " + cite("P06") + " is used in this project primarily as evidence rather than as a "
        "design template: it confirms, across a wide range of deployed protocols and device classes, "
        "that device discovery, protocol enumeration, and vulnerability correlation remain disconnected "
        "activities in current security practice — precisely the fragmentation problem described in "
        "Chapter 1."
    ))

    add_division(doc, registry, CH, 4, "Protocol-Aware IoT Device Fingerprinting")
    add_subdivision(doc, registry, CH, 4, 1, "Traffic-Flow and Machine-Learning Approaches")
    add_para(doc, (
        "Sivanathan et al. demonstrated that multi-class IoT device identification from flow-level "
        "traffic features can exceed 97% accuracy across 28 device types " + cite("P07") + ", "
        "establishing the practical accuracy ceiling that any non-machine-learning alternative, "
        "including PISA's, is implicitly measured against. The cost of that accuracy is a dependency "
        "on a labelled training corpus per device class, which does not generalize to a device model "
        "the system has never seen before — a limitation this project's protocol-behavioural approach "
        "is specifically designed to avoid. Habibi Lashkari et al. showed that lightweight, optimized "
        "\"digital footprint\" feature sets can identify devices under the kind of resource constraints "
        "a Raspberry Pi 4 operates under " + cite("P09") + ", which directly supports the feasibility "
        "of running fingerprinting logic on the same commodity hardware PISA targets, independent of "
        "whether that logic is ML-based or rule-based."
    ))
    add_subdivision(doc, registry, CH, 4, 2, "Deterministic and Protocol-Specific Fingerprinting")
    add_para(doc, (
        "Dong et al. addressed devices that speak proprietary, undocumented protocols using key-block "
        "pattern matching rather than a learned classifier " + cite("P08") + ", demonstrating that "
        "deterministic, non-ML fingerprinting is viable in principle, though their technique is "
        "evaluated on a single protocol family rather than the multi-protocol surface (MQTT, CoAP, "
        "HTTP, RTSP) PISA targets. Ren et al.'s large-scale empirical study of more than fifteen "
        "thousand consumer IoT traffic flows across MQTT, HTTP, and CoAP " + cite("P10") + " provides "
        "ground-truth behavioural diversity data that corroborates the premise behind PISA's Module 2: "
        "that distinct protocols carry distinguishable, manufacturer-specific behavioural signatures "
        "worth probing independently and then fusing."
    ))
    add_para(doc, (
        "Three further sources ground PISA's protocol-specific probe design directly. Soni and Singh's "
        "systematic vulnerability assessment of the MQTT protocol " + cite("P11") + " catalogues "
        "authentication bypass, topic enumeration, and plaintext credential exposure as recurring "
        "weaknesses, informing exactly which MQTT behaviours PISA's probe checks for. Palmieri et al.'s "
        "empirical evaluation of MQTT broker deployments found that 83% ran with no authentication "
        "configured by default " + cite("P12") + " — a statistic this project cites directly in its "
        "problem framing — and Hasan et al. catalogued known MQTT exploit patterns to motivate runtime "
        "detection rather than static auditing alone " + cite("P13") + ". On the CoAP side, Amsuess et "
        "al.'s security analysis of CoAP and DNS-over-CoAP name resolution " + cite("P14") + " "
        "identifies the plaintext, connectionless `/.well-known/core` resource-discovery surface that "
        "PISA's CoAP probe specifically exercises."
    ))
    add_para(doc, (
        "None of P07 through P14 combine MQTT, CoAP, HTTP, and RTSP probing in a single deterministic "
        "engine, and none propose a method for fusing confidence across protocols when a device "
        "responds on more than one of them simultaneously, which is the specific contribution PISA "
        "makes at this layer, described fully in Chapter 4."
    ))
    add_para(doc, (
        "As with the WiFi-layer literature in Section 2.2, each protocol-specific source maps onto a "
        "named, concrete probe in Module 2 rather than informing the design only in general terms. "
        "Soni and Singh's catalogue of MQTT weaknesses " + cite("P11") + " — authentication bypass, "
        "topic enumeration, plaintext credentials — is the direct source for what the MQTT probe checks "
        "on connection (CONNACK flags, keepalive negotiation) and on wildcard subscription (topic "
        "hierarchy exposure); Palmieri et al.'s no-authentication prevalence statistic " + cite("P11") +
        " justifies checking authentication state as a first-class signal rather than an incidental "
        "one. Amsuess et al.'s CoAP security analysis " + cite("P14") + " is the direct source for "
        "probing CoAP's `/.well-known/core` resource directory and block-transfer negotiation "
        "behaviour, rather than only checking whether port 5683 is open. For HTTP and RTSP, no single "
        "reviewed paper specifies a probe design as directly as the MQTT and CoAP literature does; this "
        "is reflected honestly in Chapter 4, where the HTTP and RTSP probes are instead grounded in "
        "named, vendor-specific behavioural patterns (such as Hikvision's `/doc/page/login.asp` endpoint "
        "and Dahua's `/RPC2` JSON-RPC interface) rather than a single academic source, since protocol-"
        "behavioural fingerprinting for these two protocols specifically is closer to an engineering "
        "gap than a published one."
    ))

    add_division(doc, registry, CH, 5, "CVE Correlation and Exploit Scoring")
    add_para(doc, (
        "Jacobs et al. introduced the Exploit Prediction Scoring System (EPSS), the first open, "
        "data-driven framework for predicting the probability that a given CVE will be exploited "
        "within the following thirty days, reporting an area-under-curve of 0.838 and updated daily "
        "by FIRST.org " + cite("P15") + ". EPSS is a direct, load-bearing input to PISA's exploit "
        "scoring: it is the one of the three metrics PISA combines that reflects near-term, empirically "
        "observed attacker behaviour rather than a static severity rating. Subramaniam et al.'s "
        "longitudinal analysis found that EPSS scores are frequently low or entirely unavailable at "
        "the moment a CVE first enters the CISA KEV catalogue of confirmed, actively exploited "
        "vulnerabilities " + cite("P17") + " — a result that is, on its face, a limitation of EPSS, but "
        "which this project reads instead as direct evidence that no single metric (CVSS, EPSS, or KEV "
        "listing alone) is sufficient for prioritization, which is precisely why PISA computes all "
        "three and combines them rather than relying on any one in isolation."
    ))
    add_para(doc, (
        "Radoglou-Grammatikis et al. compared CVSS, EPSS, the Common Weakness Scoring System, and "
        "IoT-specific scoring frameworks, and found that none of the existing frameworks is designed "
        "for real-time, portable assessment " + cite("P17") + ", while Anand et al. demonstrated the "
        "technical feasibility of graph-based IoT risk scoring against live NVD feeds, though their "
        "design assumes cloud-scale compute rather than an edge device " + cite("P18") + ". PISA "
        "adapts the real-time-feed principle from the latter while deliberately keeping the scoring "
        "computation itself light enough to run on a Raspberry Pi 4 without a cloud dependency."
    ))

    add_division(doc, registry, CH, 6, "Exploit Validation and Authorization")
    add_para(doc, (
        "Heiding et al. deployed a practical IoT risk assessment framework, SAFER, across three "
        "multinational organizations and, in doing so, established an authorization-gate methodology "
        "as both a legal and an operational necessity before any exploit verification step is allowed "
        "to run " + cite("P19") + ". This is the single most directly adopted piece of prior work in "
        "PISA's design: Module 4's mandatory named-operator confirmation and five-second countdown "
        "before any RouterSploit action becomes clickable (detailed in Chapter 4) is a direct, "
        "software-enforced implementation of the authorization-gate pattern Heiding et al. describe at "
        "an organizational-process level."
    ))

    add_division(doc, registry, CH, 7, "Unified IoT Security Audit Tooling")
    add_para(doc, (
        "Varga et al. conducted the most comprehensive recent review of IoT security audit tooling "
        "available at the time of this survey, examining more than forty tools and proposing a layered "
        "(network, protocol, application) reference architecture " + cite("P20") + ". Critically for "
        "this project's motivation, their review explicitly concludes that no existing tool integrates "
        "wireless-network-layer assessment with device-layer CVE correlation within a single, portable "
        "system — the most direct piece of published evidence supporting PISA's central novelty claim, "
        "and the paper this project's problem statement in Chapter 1 cites most heavily."
    ))

    add_division(doc, registry, CH, 8, "Comparative Analysis of Existing Tools and Platforms")
    add_para(doc, (
        "Beyond the academic literature surveyed above, a number of widely used practitioner tools "
        "occupy parts of the same problem space PISA addresses. Table 2.1 positions PISA against the "
        "closest of these by the specific capability each does or does not provide, extending the "
        "capability-gap framing introduced in Table 1.1 with named, concrete alternatives."
    ))
    add_para(doc, (
        "The tools in Table 2.1 fall into three broad categories, and PISA's relationship to each "
        "differs. The first category — Pwnagotchi, Kismet, WiGLE — captures WiFi-layer data passively, "
        "the same capture discipline Module 0 uses, but stops at logging or crowdsourced mapping rather "
        "than computing an actionable security score; PISA's contribution relative to this category is "
        "specifically the WSPS scoring layer described in Section 4.4.1, not the capture technique "
        "itself, which is methodologically similar. The second category — WiFi Pineapple, Bettercap, "
        "RouterSploit — performs active, operator-driven assessment or exploitation, closer to what "
        "PISA's later modules do, but each requires an operator to already know which device or network "
        "to target and supplies no automated discovery-to-CVE pipeline of its own; PISA's Module 4 "
        "deliberately reuses RouterSploit as an execution backend rather than re-implementing exploit "
        "modules, so this is a relationship of composition, not displacement. The third category — "
        "Nmap and Shodan — performs discovery and indexing at, respectively, local-network and "
        "internet scale, and both are used or referenced within PISA's own pipeline (Nmap directly, as "
        "Module 1's scan engine; Shodan as the closest conceptual analogue to Module 0's OUI-to-CVE "
        "correlation, performed instead on local, non-internet-facing router hardware)."
    ))
    add_table_with_caption(doc, registry, CH, "PISA compared against existing tools and platforms", [
        ["Tool / Platform", "What it does", "What it does not do, relative to PISA"],
        ["Pwnagotchi", "Passive PMKID capture and wardriving on Raspberry Pi Zero hardware",
         "No CVE correlation, no security scoring, no device-layer assessment, not integrated with a cloud or reporting layer"],
        ["Kismet", "Passive WiFi (and other RF) logging across many protocols",
         "Logs raw observational data only; no posture scoring, no CVE correlation, no device fingerprinting"],
        ["WiGLE", "Crowdsourced mapping of SSIDs and encryption types",
         "Cloud-only aggregation; no per-session security scoring, no CVE correlation, no device layer"],
        ["WiFi Pineapple (Hak5)", "Commercial active WiFi auditing hardware platform",
         "Proprietary hardware, no CVE correlation pipeline, not built for academic reproducibility"],
        ["Bettercap", "General-purpose network attack and MITM toolkit",
         "Manual, operator-driven operation; no CVE pipeline, no device fingerprinting, not a portable standalone unit"],
        ["RouterSploit", "IoT/router exploitation framework with a large module index",
         "No discovery stage, no fingerprinting, no automatic CVE lookup; PISA uses RouterSploit as its Module 4 execution backend rather than competing with it"],
        ["Nmap (+ NSE scripts)", "Network/port/service scanning and OS fingerprinting",
         "No protocol-behavioural analysis beyond banner grabbing, no CVE pipeline; PISA uses Nmap as its Module 1 discovery backend"],
        ["Shodan", "Internet-scale indexing of internet-facing devices",
         "Cloud-only, passive, no local/offline assessment, no exploit-verification pipeline"],
    ], widths=[1.6, 2.3, 2.4])
    add_para(doc, (
        "A recurring pattern in Table 2.1 is that PISA does not seek to replace Nmap or RouterSploit — "
        "both remain best-in-class at their specific function and are used internally as PISA's "
        "Module 1 and Module 4 execution backends respectively, as detailed in Chapter 4. PISA's "
        "contribution is the pipeline connecting discovery, fingerprinting, CVE correlation, and gated "
        "verification into one evidence-preserving chain, a role none of the tools in Table 2.1 "
        "individually fill."
    ))

    add_division(doc, registry, CH, 9, "Consolidated View of the Reviewed Literature")
    add_para(doc, (
        "Table 2.2 consolidates all twenty sources discussed in Sections 2.2 through 2.7 into a single "
        "reference, cross-indexed against the PISA module each most directly informs and the reference "
        "number it carries in this report's bibliography, to make the mapping between the literature "
        "review and the system design in Chapter 4 explicit and easy to verify."
    ))
    add_table_with_caption(doc, registry, CH, "Consolidated summary of the twenty reviewed sources", [
        ["Ref.", "First author", "Year", "Venue", "PISA module informed"],
        ["[19]", "Vanhoef & Ronen", "2020", "IEEE S&P", "M0 — WPA3 downgrade awareness"],
        ["[18]", "Vanhoef", "2021", "USENIX Security", "M0 — frame-level WiFi vulnerability"],
        ["[14]", "Schepers et al.", "2023", "USENIX Security", "M0 — beacon/queue anomaly basis"],
        ["[5]", "Gvozdenovic et al.", "2022", "IEEE CNS", "M0 — pre-authentication WiFi vulnerability"],
        ["[10]", "Nguyen et al.", "2023", "IEEE IoT Journal", "M1 — compromised-device detection context"],
        ["[3]", "Churcher et al.", "2021", "IEEE Access", "M1 — enterprise IoT attack-surface evidence"],
        ["[15]", "Sivanathan et al.", "2020", "arXiv", "M2 — ML fingerprinting accuracy ceiling"],
        ["[4]", "Dong et al.", "2023", "Elsevier Computer Networks", "M2 — deterministic, non-ML fingerprinting feasibility"],
        ["[6]", "Habibi Lashkari et al.", "2022", "arXiv", "M2 — lightweight, edge-feasible fingerprinting"],
        ["[13]", "Ren et al.", "2024", "arXiv", "M2 — cross-protocol behavioural ground truth"],
        ["[16]", "Soni & Singh", "2021", "IEEE ICCCA", "M2 — MQTT probe design basis"],
        ["[11]", "Palmieri et al.", "2021", "ACM WiNTECH", "M2 — MQTT no-auth prevalence statistic"],
        ["[7]", "Hasan et al.", "2022", "MDPI Sensors", "M2 — MQTT exploit-pattern catalogue"],
        ["[1]", "Amsuess et al.", "2023", "ACM SIGCOMM", "M2 — CoAP resource-discovery probe design"],
        ["[9]", "Jacobs et al.", "2021", "ACM DTRAP", "M3 — EPSS exploit-prediction scoring"],
        ["[17]", "Subramaniam et al.", "2024", "arXiv", "M3 — tri-metric scoring justification"],
        ["[12]", "Radoglou-Grammatikis et al.", "2023", "MDPI Electronics", "M3 — scoring-framework landscape"],
        ["[2]", "Anand et al.", "2023", "Elsevier Computer Networks", "M3 — real-time NVD feed feasibility"],
        ["[8]", "Heiding et al.", "2020", "arXiv", "M4 — authorization-gate methodology"],
        ["[20]", "Varga et al.", "2024", "Springer IJIS", "All — central unified-tool-gap evidence"],
    ], widths=[0.6, 2.0, 0.6, 1.7, 2.5])

    add_division(doc, registry, CH, 10, "Summary of Research Gaps")
    add_para(doc, (
        "The twenty sources reviewed in this chapter collectively confirm five distinct research gaps "
        "that this project addresses directly:"
    ))
    add_bullet(doc, "**G1 — No unified WiFi-and-device assessment tool.** Established most directly by "
                    "the layered-architecture review " + cite("P20") + " and the enterprise IoT attack-"
                    "surface survey " + cite("P06") + ".")
    add_bullet(doc, "**G2 — No real-time, EPSS/KEV-integrated exploitability scoring on edge hardware.** "
                    "Established by " + cite("P15", "P16", "P17", "P18") + ".")
    add_bullet(doc, "**G3 — No passive, beacon-only WiFi posture grading framework.** Established by "
                    "the WiFi-layer vulnerability studies " + cite("P01", "P02", "P03", "P04") + ".")
    add_bullet(doc, "**G4 — No non-machine-learning, cross-protocol device fingerprinting technique.** "
                    "Established by " + cite("P07", "P08", "P09", "P10") + ".")
    add_bullet(doc, "**G5 — No cross-protocol confidence-fusion mechanism when a device is identifiable "
                    "on more than one protocol at once.** Established by the single-protocol scope of "
                    + cite("P11", "P12", "P13", "P14") + ".")
    add_para(doc, (
        "Chapter 3 formalizes these five gaps into the specific novelty claims and research questions "
        "this project sets out to answer, and Chapter 4 describes, module by module, how PISA's "
        "architecture answers each of them."
    ))
