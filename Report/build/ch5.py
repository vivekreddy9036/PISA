from report_engine import add_chapter, add_division, add_subdivision, add_para, add_bullet, add_table_with_caption
from refs_data import cite


def build(doc, registry):
    CH = 5

    add_chapter(doc, registry, CH, "Results and Discussion")

    add_division(doc, registry, CH, 1, "Implementation Status Summary")
    add_para(doc, (
        "This chapter reports results exactly as observed at the current review point, following the "
        "same discipline set out in Chapter 3: a result is reported as real only where it was obtained "
        "against live hardware, a live network, or a live external API, and is explicitly labelled "
        "where it is not. Table 5.1 summarizes the implementation status of every module introduced in "
        "Chapter 4 as a starting point for the detailed results that follow."
    ))
    add_table_with_caption(doc, registry, CH, "Module implementation status at the current review", [
        ["Module", "Status", "Evidence tier"],
        ["M0 — WiFi assessment (beacon capture, WSPS, OUI-CVE)", "Implemented", "Real hardware"],
        ["M1 — Network discovery (join, ARP sweep, Nmap, mDNS)", "Implemented", "Real network"],
        ["M2 — Protocol behavioural fingerprinting", "Implemented", "Real, controlled target"],
        ["M3 — CVE correlation (NVD + EPSS + CISA KEV + applicability)", "Implemented", "Real external APIs"],
        ["M4 — Authorized verification and gated exploitation", "Implemented (software)", "Gate proven live; physical exploit target pending"],
        ["M5 — Dashboard / API", "Implemented", "Real routes, live + demo mode"],
        ["AWS cloud reporting (pisa/aws/)", "Planned", "Not started — intentional v1 stub"],
    ], widths=[3.0, 1.8, 1.8])
    add_para(doc, (
        "Every module proposed and scoped in Chapters 3 and 4 is implemented except cloud reporting, "
        "which remains an intentional stub unchanged since the project's initial scoping, as stated in "
        "Chapter 1. The remainder of this chapter substantiates each \"Implemented\" row with the "
        "specific evidence obtained for it."
    ))

    add_division(doc, registry, CH, 2, "Real Hardware Validation Results")
    add_subdivision(doc, registry, CH, 2, 1, "M0 — WiFi Assessment")
    add_para(doc, (
        "M0 was run against real 802.11 beacon traffic using the Alfa AWUS036ACM in genuine monitor "
        "mode. In the session reported here, four real campus networks were captured; all four were "
        "WPA2-secured, with real, measured RSSI values, and the WSPS framework (Section 4.4.1) scored "
        "the strongest of them at Grade D (score 54) — a real, non-synthetic result rather than a "
        "constructed example, and a useful one precisely because it is not a best-case result: it shows "
        "the scoring formula correctly penalizing a network that is encrypted but otherwise weakly "
        "configured, rather than only ever producing high grades on networks already known to be well "
        "configured."
    ))
    add_subdivision(doc, registry, CH, 2, 2, "M1 — Network Discovery")
    add_para(doc, (
        "M1 was run against a single real, explicitly authorized target on a live network. The target's "
        "real MAC address was resolved via ARP even though the device had ICMP blocked, and a real "
        "Nmap scan completed against it running as root. The scan's result was an honest negative — no "
        "open IoT-relevant ports — because the authorized target available for this session was a "
        "general-purpose laptop rather than an IoT device. This negative result is reported here "
        "deliberately: a system that only ever reports positive findings during development is weaker "
        "evidence than one that is shown, on a real target, to correctly report nothing when there is "
        "nothing to find."
    ))
    add_subdivision(doc, registry, CH, 2, 3, "M2 — Protocol Fingerprinting")
    add_para(doc, (
        "M2 was run against a real, controlled local IoT-service target exposing live HTTP and RTSP "
        "behaviour. All four protocol probes (HTTP, MQTT, CoAP, RTSP) ran as real network probes rather "
        "than against mocked responses, feeding the additive-confidence fusion algorithm described in "
        "Section 4.4.3. The result was `device_type = \"IP Camera\"` at a fused confidence of 1.0, with "
        "structured identity fields (product, version) extracted directly from real response banners — "
        "a result traceable, feature by feature, to a named rule in the fusion engine rather than to an "
        "opaque model score."
    ))
    add_subdivision(doc, registry, CH, 2, 4, "M3 — Vulnerability Intelligence")
    add_para(doc, (
        "M3 was validated in both directions that matter for a system whose central discipline is never "
        "fabricating a match. Against a synthetic banner with no corresponding entry in the live NVD CPE "
        "Dictionary, M3 correctly returned `NO_CPE_DATA` rather than forcing a low-confidence guess. "
        "Against a real reference vulnerability, CVE-2017-7577, M3 returned a real `AFFECTED` verdict "
        "from a genuine CPE match, with a real CVSS score of 9.8 and a real EPSS score of 29% retrieved "
        "live from FIRST.org — both the positive and the negative result were obtained from live NVD, "
        "EPSS, and KEV calls, not from cached or mocked data."
    ))
    add_subdivision(doc, registry, CH, 2, 5, "M4 — Verification and Gated Exploitation")
    add_para(doc, (
        "M4's software path — the authorization gate described in Section 4.6 — was tested adversarially "
        "against the real, running dashboard via live HTTP requests, with results reported in Section "
        "5.4. What has not yet been obtained is a positive result against a genuinely vulnerable "
        "physical device: every real M3 result collected so far is an honest non-match or a reference "
        "CVE rather than a device acquired specifically for this purpose. This is stated as a known "
        "limitation in Section 5.6 rather than implied to be complete."
    ))
    add_subdivision(doc, registry, CH, 2, 6, "M5 — Dashboard / API")
    add_para(doc, (
        "Every route backing the stages above was verified end-to-end over live HTTP against the "
        "running dashboard, in both its real-assessment mode and a dedicated demo mode. The demo mode "
        "exists specifically to present pipeline states not yet reached on real hardware — `AFFECTED`, "
        "`VERIFIED_VULNERABLE`, `EXPLOIT_SUCCESSFUL` — for review purposes, without ever presenting "
        "simulated data as real: a persistent on-screen banner reads \"DEMO MODE — SIMULATED / REPLAY "
        "DATA\", demo sessions are stored in a structurally separate database file never mixed with real "
        "assessment data, every state shown is produced by the real `applicability.py`, `verification.py`, "
        "and `exploitation.py` functions driven by real, previously captured CVE data rather than by a "
        "separate mock code path, and simulated exploitation results are labelled "
        "\"[DEMO — SIMULATED, NOT A REAL EXPLOIT]\" in the persisted text itself, not only in the "
        "surrounding UI chrome."
    ))

    add_division(doc, registry, CH, 3, "Automated Test Suite Summary")
    add_para(doc, (
        "At the point reported in this chapter, the project's automated test suite comprised 381 tests "
        "across twenty-eight test files spanning every implemented module (`tests/m0/` through "
        "`tests/m5/`, plus `tests/db/`), all passing, run continuously in GitHub Actions on every push "
        "as described in Section 4.7. Table 5.2 breaks this count down by module, collected directly "
        "from the live test suite rather than carried forward from an earlier status report."
    ))
    add_table_with_caption(doc, registry, CH, "Automated test count by module (live pytest --collect-only)", [
        ["Module", "Test count"],
        ["db — SQLite schema and query layer", "43"],
        ["M0 — WiFi assessment (beacon capture, WSPS, OUI-CVE)", "39"],
        ["M1 — network discovery", "30"],
        ["M2 — protocol fingerprinting", "41"],
        ["M3 — CVE correlation, applicability, verification", "168"],
        ["M4 — authorization gate", "18"],
        ["M5 — dashboard / API routes", "42"],
        ["Total", "381"],
    ], widths=[4.6, 1.8])
    add_para(doc, (
        "M3's share of the suite (168 of 381 tests, 44%) reflects where the project's engineering "
        "effort has been concentrated: it is the module responsible for never letting a CVE keyword "
        "match be reported as a confirmed vulnerability (Section 4.4.4), and the applicability and "
        "verification logic that enforces this is tested far more exhaustively than any other single "
        "module, consistent with it being the load-bearing component behind both Novelty Claim 4 "
        "(Section 3.4.4) and the adversarial gate results in Section 5.4. This count is reported as a "
        "scale indicator rather than a correctness proof on its own: a mocked unit test confirms "
        "internal consistency, not that the mocked behaviour matches a real external system, which is "
        "precisely why Section 5.2's real-hardware results are kept visibly distinct from, rather than "
        "substituted for, this count."
    ))

    add_division(doc, registry, CH, 4, "Security Gate — Adversarial Testing Results")
    add_para(doc, (
        "Because Module 4's authorization gate (Section 4.6) is the one component of PISA that carries "
        "direct ethical and legal weight, it was tested adversarially rather than only unit-tested in "
        "isolation: each row in Table 5.3 is a real HTTP request issued against the real, running "
        "dashboard, not a call directly into the gate function in a test harness."
    ))
    add_table_with_caption(doc, registry, CH, "Adversarial gate testing results (live HTTP against the running dashboard)", [
        ["Condition exercised", "Result"],
        ["Exploit attempted on a NOT_APPLICABLE finding",
         "HTTP 403, gate_state = BLOCKED_APPLICABILITY, zero exploit_results rows created"],
        ["Exploit attempted on an AFFECTED but NOT_VERIFIED finding",
         "HTTP 403, gate_state = BLOCKED_VERIFICATION"],
        ["Authorization fields missing, even on a fully eligible finding",
         "HTTP 400, request blocked before any network action was taken"],
        ["Client supplies an arbitrary / attacker-chosen module_path",
         "Value silently ignored; the real, registry-resolved module executes instead, never the client's"],
        ["A genuine RouterSploit execution timeout occurs",
         "Persisted as its own TIMEOUT status; never collapsed into a generic failure result"],
    ], widths=[3.0, 3.6])
    add_para(doc, (
        "The fourth row in Table 5.3 is the most security-significant of the five: it confirms that the "
        "gate's module-selection logic is not merely validated client-side but is re-derived "
        "server-side from the already-verified CVE, so that a request crafted to specify a different, "
        "unvetted module path cannot cause that module to run. This directly substantiates the design "
        "claim made in Section 4.6 — that no single module's output is independently sufficient to "
        "unlock exploitation — against a live adversarial input rather than only against the code as "
        "written."
    ))

    add_division(doc, registry, CH, 5, "Discussion")
    add_para(doc, (
        "Returning to the research questions posed in Section 3.2: RQ2 (can passive beacon analysis "
        "alone produce a meaningful posture score) is supported by the M0 result in Section 5.2.1, "
        "where WSPS correctly distinguished a weakly configured, though encrypted, real network from a "
        "hypothetical stronger one, without any active probing — though a single real session is not "
        "yet sufficient evidence to confirm Hypothesis H1's stronger claim of expert-level agreement, "
        "which remains for the evaluation planned ahead of the final review (Chapter 6). RQ3 (can "
        "non-ML, protocol-behavioural signatures identify a device at usable accuracy) is directly "
        "supported by the M2 result in Section 5.2.3: a confidence of 1.0 on a real IP camera obtained "
        "through deterministic, rule-traceable fusion rather than a learned classifier — consistent "
        "with, though not yet a controlled comparison against, the ML accuracy baseline reported in the "
        "literature " + cite("P07") + ". RQ4 (integration accuracy and completeness) is partially "
        "addressed: M3's both-directions result in Section 5.2.4 demonstrates the pipeline can produce "
        "a correct real CVE match without ever fabricating one, directly supporting the \"no single "
        "metric is sufficient on its own\" argument from Section 2.5 " + cite("P16") + ", but the timed "
        "comparison against a manual multi-tool workflow implied by Hypothesis H4 has not yet been "
        "run and is scoped into the roadmap in Chapter 6."
    ))
    add_para(doc, (
        "Table 5.4 summarizes this hypothesis-by-hypothesis status explicitly, against the metrics "
        "and targets already defined in Table 3.1, so that \"supported,\" \"partially supported,\" and "
        "\"not yet evaluated\" are read as this report defines them rather than informally."
    ))
    add_table_with_caption(doc, registry, CH, "Hypothesis validation status at the current review", [
        ["Hypothesis", "Status", "Basis"],
        ["H1 — WSPS grades agree with expert assessment", "Not yet formally evaluated",
         "A real WSPS grade (D, score 54) was produced correctly (Section 5.2.1); the multi-network expert-agreement study itself is scoped for Chapter 6"],
        ["H2 — Fingerprinting accuracy competitive with ML baselines", "Partially supported",
         "A real, single-device result (confidence 1.0, Section 5.2.3) is consistent with H2; a multi-device accuracy study is scoped for Chapter 6"],
        ["H3 — Applicable high-severity CVEs surfaced quickly", "Partially supported",
         "M3 returned a correct real match and a correct real non-match (Section 5.2.4); timed completeness at scale is scoped for Chapter 6"],
        ["H4 — End-to-end time substantially below manual workflow", "Not yet evaluated",
         "Requires the timed comparison against a manual multi-tool baseline, scoped for Chapter 6"],
    ], widths=[2.2, 1.6, 2.6])
    add_para(doc, (
        "Measured against the novelty claims in Section 3.4, Claim 4's strongest substantiation to date "
        "is the adversarial gate-testing result in Section 5.4: the project's central claim is not "
        "merely that PISA chains more stages than prior tools, but that it never lets a later stage "
        "overclaim what an earlier one actually established, and Table 5.3's module-substitution test "
        "is direct, live evidence of exactly that property holding under an adversarial input, not only "
        "under the inputs the system's own developers chose to test with."
    ))
    add_para(doc, (
        "Taken together, Sections 5.1 through 5.4 support a specific, bounded claim: that the pipeline "
        "proposed in Chapter 4 works correctly on real inputs, in both its positive and negative cases, "
        "and that its single most safety-critical control — the exploitation authorization gate — holds "
        "under adversarial live testing, not only under the conditions its own developers anticipated. "
        "They do not yet support the broader, statistical claims embedded in Hypotheses H1-H4, and "
        "Table 5.4 states that distinction explicitly rather than letting the two kinds of evidence "
        "blur together."
    ))

    add_division(doc, registry, CH, 6, "Known Limitations")
    add_para(doc, "The following limitations are stated proactively rather than discovered by a reviewer, consistent with the reporting discipline set out in Chapter 3.", indent=True)
    add_bullet(doc, "**No physically vulnerable IoT device has been tested end-to-end yet.** Every real "
                    "M3 result obtained so far (Section 5.2.4) is an honest non-match or a reference CVE "
                    "rather than a live device acquired specifically for this purpose. A target hardware "
                    "family with demonstrated real NVD CPE-match potential has been identified and "
                    "scoped but not yet acquired; acquiring and running the complete positive M1-through-"
                    "M4 chain against it is the single highest-priority item in the roadmap (Chapter 6).")
    add_bullet(doc, "**M1's discovery has no built-in target-range restriction.** This is a genuine, "
                    "acknowledged architecture note treated as an authorization-scope question during "
                    "development rather than an oversight glossed over in this report: nothing in M1 "
                    "today prevents a discovery sweep from extending beyond the specific range an "
                    "operator was authorized to assess, which is addressed procedurally today (the "
                    "ethics framework in Section 3.6) rather than architecturally.")
    add_bullet(doc, "**RouterSploit's execution timeout is thread-bound, not process-isolated.** A "
                    "documented limitation of running RouterSploit modules inside CPython threads rather "
                    "than separate processes; acceptable for a supervised, operator-present assessment "
                    "of the kind M4 is designed for, but a constraint worth stating rather than "
                    "assuming away.")
    add_bullet(doc, "**Cloud reporting remains an intentional stub.** Unchanged since the project's "
                    "initial scope (Chapter 1); `pisa/aws/` exists as a package with no Lambda, "
                    "DynamoDB, or S3 wiring implemented, and is treated entirely as future work in "
                    "Chapter 6 rather than partially claimed here.")

    add_division(doc, registry, CH, 7, "Illustrative End-to-End Session Walkthrough")
    add_para(doc, (
        "To make the results reported in Sections 5.1 through 5.4 concrete as a single pipeline rather "
        "than six isolated results, this section traces one assessment session end to end, using only "
        "the real findings already reported above — no new claim is introduced here, only their "
        "sequence. An operator starts a scan on the monitor-mode interface; M0 captures real beacon "
        "traffic and grades the strongest of four real captured networks at WSPS Grade D (score 54, "
        "Section 5.2.1). The operator supplies that network's password and triggers M1's join-and-"
        "discover action; an ARP sweep and a pooled Nmap scan enumerate the live hosts on the joined "
        "subnet (Section 5.2.2). For a device exposing HTTP and RTSP services, the operator triggers "
        "M2's fingerprint action; the four protocol probes return `device_type = \"IP Camera\"` at a "
        "fused confidence of 1.0 (Section 5.2.3). The operator then triggers M3's CVE-lookup action; "
        "for a device matching the reference finding used throughout this report, M3 returns CVE-2017-"
        "7577 with an `AFFECTED` applicability verdict, CVSS 9.8, and a live EPSS score of 29% "
        "(Section 5.2.4), from which Section 4.4.4's worked example computes an exploit score of "
        "roughly 51 (or 71, if KEV-listed) out of 100. Only at this point does Module 4's authorization "
        "gate become relevant: Table 5.3 shows that this finding would be blocked from exploitation "
        "until M3 additionally returns `VERIFIED_VULNERABLE` from a live verification test, and that "
        "even then, exploitation requires a named operator, an explicit confirmation, and a five-second "
        "delay before it can proceed at all. Every stage above is recorded in the dashboard and "
        "persisted to the local database (Section 4.5) independently of whether the operator continues "
        "to the next one, so the session's evidence trail survives even if, as in the real validation "
        "run reported in Section 5.2.5, the physical exploitation step itself has not yet been reached."
    ))

    add_division(doc, registry, CH, 8, "Threats to Validity")
    add_para(doc, (
        "Two threats to the validity of the results in this chapter are stated explicitly rather than "
        "left implicit. First, **single-session evidence**: several of the real-hardware results "
        "reported in Section 5.2 (the WSPS grade on four campus networks, the fingerprinting confidence "
        "on one IP camera) are drawn from individual assessment sessions rather than a repeated, "
        "multi-session sample; they demonstrate that the pipeline produces correct results on real "
        "inputs, which is a necessary condition for the hypotheses in Section 3.2, but they do not yet "
        "constitute the statistical evidence — expert-agreement scores, accuracy across many device "
        "instances — those hypotheses ultimately require, and which Table 3.1's planned metrics are "
        "designed to collect. Second, **target availability**: the negative M1 result and the absence "
        "of a positive M4 exploitation result (Sections 5.2.2 and 5.2.5) both trace to the same "
        "underlying constraint, that the specific devices authorized for testing during this phase did "
        "not include a confirmed-vulnerable IoT target; this is a constraint on what could be validated, "
        "not a result suggesting the pipeline itself is incomplete, and is addressed directly by Phase A "
        "of the roadmap in Chapter 6. Neither threat is treated as resolved by this report — both are "
        "carried forward explicitly into Chapter 6 rather than left as an implicit caveat."
    ))
