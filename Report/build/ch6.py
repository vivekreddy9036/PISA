from report_engine import add_chapter, add_division, add_subdivision, add_para, add_bullet, add_table_with_caption


def build(doc, registry):
    CH = 6

    add_chapter(doc, registry, CH, "Conclusion and Scope for Future Work")

    add_division(doc, registry, CH, 1, "Conclusion")
    add_para(doc, (
        "This report has described PISA, a portable IoT security assessment platform that chains "
        "passive WiFi posture scoring, device discovery, non-machine-learning protocol fingerprinting, "
        "tri-metric CVE correlation, and gated exploit verification into a single pipeline on commodity, "
        "field-deployable hardware. Chapter 1 established that no existing tool closes the specific gap "
        "between network-layer and device-layer IoT security assessment; Chapter 2 grounded that claim "
        "in twenty peer-reviewed and pre-print sources and positioned PISA against nine named prior "
        "tools and platforms; Chapter 3 formalized the problem into research questions, five specific "
        "novelty claims, and a requirements specification; Chapter 4 described the resulting six-module "
        "architecture in full; and Chapter 5 reported, honestly and with limitations stated proactively, "
        "what has actually been validated against real hardware, real networks, and real external APIs "
        "as of this review."
    ))
    add_para(doc, (
        "Every module proposed at the start of this phase — M0 through M5 — is implemented, covered by "
        "an automated test suite of 381 tests, and has been exercised at least once against real, "
        "non-synthetic conditions rather than only against mocked data. The one component explicitly out "
        "of scope, cloud reporting, remains an intentional, clearly labelled stub rather than an "
        "unfinished claim. What remains before the system can be considered complete is real-world "
        "scale — acquiring and testing against a genuinely vulnerable physical device, and deploying the "
        "full pipeline onto its target Raspberry Pi form factor — rather than any open architectural "
        "question."
    ))
    add_para(doc, (
        "The discipline this report has tried to hold itself to throughout — stating what is "
        "implemented against what is planned (Chapter 3), what is real against what is simulated-for-"
        "demonstration (Chapter 4), and what is validated against what remains to be measured "
        "(Chapter 5) — is not incidental to the project's engineering quality; it is argued here to be "
        "part of it. A system whose own documentation cannot be trusted to state its limitations "
        "accurately is a weaker foundation for a security tool specifically, where an assessor "
        "downstream will act on PISA's output as if it were ground truth. The five novelty claims in "
        "Chapter 3 are offered in that spirit: as specific, checkable commitments against named prior "
        "work, not as a general assertion of originality."
    ))

    add_division(doc, registry, CH, 2, "Summary of Contributions")
    add_bullet(doc, "A WiFi Security Posture Scoring (WSPS) framework that grades a network from "
                    "passive beacon analysis alone, validated against four real campus networks.")
    add_bullet(doc, "A non-machine-learning, cross-protocol device fingerprinting engine (MQTT, CoAP, "
                    "HTTP, RTSP) with a probabilistic confidence-fusion rule, validated at confidence "
                    "1.0 against a real IP camera target.")
    add_bullet(doc, "A tri-metric (CVSS + EPSS + CISA KEV) exploit-scoring formula computed on edge "
                    "hardware, validated in both directions — an honest non-match and a real, correctly "
                    "scored reference CVE — against live NVD, FIRST.org, and CISA data.")
    add_bullet(doc, "A deterministic applicability engine that evaluates real NVD configuration logic "
                    "rather than treating a keyword match as a finding, structurally preventing a "
                    "later pipeline stage from overclaiming what an earlier one established.")
    add_bullet(doc, "A software-enforced, adversarially-tested authorization gate for exploit "
                    "verification, shown in Chapter 5 to correctly block every unauthorized or "
                    "under-evidenced exploitation attempt tried against the live running system.")

    add_division(doc, registry, CH, 3, "Roadmap to the Final Review")
    add_para(doc, (
        "The work remaining before the final project review is organized into five phases, summarized "
        "in Table 6.1. These follow directly from the limitations stated proactively in Section 5.6 "
        "rather than introducing new scope at this stage."
    ))
    add_table_with_caption(doc, registry, CH, "Roadmap to the final review", [
        ["Phase", "Goal"],
        ["A", "Acquire the identified physical vulnerable IoT target hardware"],
        ["B", "Run the complete, real, positive M1-M4 chain on real hardware — real CPE match, real AFFECTED verdict, real VERIFIED_VULNERABLE result, real authorized exploitation"],
        ["C", "Deploy the full pipeline onto a Raspberry Pi 4 in its target field form factor"],
        ["D", "Expand the verified-exploit registry beyond its current entries, each vetted with the same rigour as the existing ones"],
        ["E", "Final report and full end-to-end demonstration rehearsal"],
    ], widths=[0.8, 5.8])

    add_division(doc, registry, CH, 4, "Future Work Beyond the Final Review")
    add_para(doc, (
        "Several extensions were deliberately scoped out of v1 to keep the current phase's claims "
        "fully verifiable against real evidence, and remain candidates for future work rather than "
        "abandoned ideas."
    ))
    add_bullet(doc, "**Cloud reporting (AWS).** Synchronizing session data to DynamoDB and S3 and "
                    "generating automated PDF reports via Lambda, as scoped in Chapter 4, remains the "
                    "most immediately actionable extension, since the local SQLite schema already "
                    "carries the data such a sync would need.")
    add_bullet(doc, "**Continuous monitoring mode.** Running M0 indefinitely in the background and "
                    "alerting on new devices, WSPS score degradation, or newly published CVEs matching "
                    "an already-fingerprinted device, converting PISA from a point-in-time audit tool "
                    "into a longitudinal monitor.")
    add_bullet(doc, "**Behavioral drift detection.** The `behavioral_drift` table (Table 4.4) is already "
                    "reserved in the schema; populating it by comparing a device's fingerprint across "
                    "sessions would flag firmware updates or possible device impersonation.")
    add_bullet(doc, "**GPS-tagged assessment and a dedicated touchscreen interface,** removing the "
                    "current dependency on a separate laptop or phone browser for field operation, as "
                    "scoped in Table 4.1.")
    add_bullet(doc, "**Formal evaluation against Hypotheses H1-H4** (Section 3.2), measured against the "
                    "metrics already defined in Table 3.1 — an expert-agreement study for WSPS, a "
                    "multi-device fingerprinting accuracy study, and a timed comparison against a manual "
                    "multi-tool workflow — once the physical hardware acquisition in Phase A above is "
                    "complete.")
    add_bullet(doc, "**Modbus behavioural fingerprinting,** extending Module 2's protocol coverage to "
                    "industrial/OT devices (PLCs, SCADA endpoints) by the same deterministic, non-ML "
                    "probing approach used for MQTT, CoAP, HTTP, and RTSP.")
    add_bullet(doc, "**A multi-device fleet mode,** where several PISA units report findings to one "
                    "shared signature database without centralizing raw traffic — extending the single-"
                    "device assessment reported in this document toward the kind of privacy-preserving, "
                    "federated architecture reviewed in Section 2.3.")
