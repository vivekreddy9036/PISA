# Literature Survey Notes — PISA (Based on Core 20 Papers Only)

---

## 1. WiFi Security Assessment (P01, P02, P03, P04)

Vanhoef & Ronen [P01] demonstrated that WPA3's Dragonfly handshake leaks information through timing and cache side-channels, enabling offline password recovery — confirming that even "modern" WiFi standards carry exploitable weaknesses. This was followed by Vanhoef [P02] exposing 12 design-level flaws in IEEE 802.11 frame handling that affect every WiFi device since 1997, regardless of protocol version. Schepers et al. [P03] further showed that transmit queue manipulation can bypass WPA2/WPA3 encryption entirely. Gvozdenovic et al. [P04] conducted systematic analysis of pre-authentication WiFi vulnerabilities, establishing that beacon frames leak significant security-relevant information passively.

**PISA Gap:** None of these works provide a unified, portable, field-deployable tool that passively scores WiFi security posture. WSPS fills this gap.

---

## 2. Network Discovery & IoT Context (P05, P06)

Nguyen et al. [P05] proposed DIoT, a self-learning federated system for detecting compromised IoT devices using network-level traffic anomalies — but requires labeled training data and cloud connectivity. Churcher et al. [P06] surveyed the enterprise IoT attack surface, confirming that device discovery, protocol enumeration, and vulnerability correlation remain disconnected activities in current practice.

**PISA Gap:** No discovery tool combines ARP sweep + OS fingerprinting + service enumeration with real-time CVE correlation on portable hardware.

---

## 3. Protocol-Aware IoT Fingerprinting (P07–P14)

Sivanathan et al. [P07] achieved 97%+ accuracy in IoT device classification using ML over network flow features — but requires a pre-labeled training corpus, making it impractical for unseen or custom industrial devices. Dong et al. [P08] addressed proprietary-protocol IoT devices using key-block pattern matching, approaching non-ML fingerprinting but limited to single protocols. Habibi et al. [P09] showed that optimized lightweight digital footprints can identify devices on constrained hardware — directly applicable to RPi 4 deployment.

Ren et al. [P10] mapped large-scale consumer IoT traffic across MQTT, HTTP, and CoAP, providing ground-truth behavioral profiles for protocol-level identification. Soni & Singh [P11] formally assessed MQTT vulnerabilities — authentication bypass, topic enumeration, plaintext credentials — providing the basis for PISA's MQTT probe. Palmieri et al. [P12] empirically confirmed that 83% of MQTT brokers run with no authentication in default configurations. Hasan et al. [P13] catalogued MQTT attack patterns, demonstrating the need for runtime detection. Amsuess et al. [P14] analyzed CoAP's security exposure, particularly the plaintext UDP resource discovery surface.

**PISA Gap:** No prior work combines MQTT + CoAP + HTTP + RTSP fingerprinting in a single deterministic, non-ML engine with cross-protocol confidence fusion. [P07–P14] each address at most one protocol.

---

## 4. CVE Correlation & Exploit Scoring (P15–P18)

Jacobs et al. [P15] introduced EPSS — the first data-driven framework for predicting exploit probability within 30 days (AUC = 0.838), updated daily. This is a landmark contribution that PISA's ExploitScore directly incorporates. Subramaniam et al. [P16] demonstrated that EPSS scores are often low or unavailable when CVEs first enter CISA KEV, proving that no single metric is sufficient — validating PISA's tri-metric approach (CVSS + EPSS + KEV). Radoglou et al. [P17] compared existing IoT vulnerability quantification frameworks and confirmed none integrates EPSS or KEV for real-time portable scoring. Anand et al. [P18] proposed graph-based IoT risk scoring using live NVD feeds, demonstrating real-time CVE correlation feasibility but requiring cloud compute.

**PISA Gap:** ExploitScore = α·CVSS + β·EPSS + γ·KEV computed locally on RPi 4 in real time — no prior work does this.

---

## 5. Exploit Validation & Authorization (P19)

Heiding et al. [P19] deployed a practical IoT risk assessment framework across 3 multinational organizations, establishing the authorization gate pattern before exploit execution as a legal and operational necessity. PISA's 5-second manual confirmation gate in Module 4 is directly informed by this methodology.

---

## 6. Unified IoT Audit Tool Gap (P20)

Varga et al. [P20] conducted the most comprehensive recent review of 40+ IoT security audit tools, proposing a layered architecture but concluding that no existing tool integrates WiFi-layer assessment with device-layer CVE correlation in a single portable system. This is the most direct evidence for PISA's primary novelty claim.

---

## KEY ARGUMENT (for Literature Survey slide)

> All 20 papers from 2020–2024 collectively confirm five distinct research gaps that PISA addresses:
> - G1 (P20, P06): No unified WiFi + device assessment tool
> - G2 (P15, P16, P17, P18): No real-time EPSS/KEV-integrated exploit scoring
> - G3 (P01, P02, P03, P04): No passive WiFi posture grading framework
> - G4 (P07, P08, P09, P10): No non-ML cross-protocol fingerprinting
> - G5 (P07–P14): No cross-protocol confidence fusion engine
