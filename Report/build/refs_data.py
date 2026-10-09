# Master reference list — alphabetical by first author surname, numbered
# [1]-[20] to match in-text citations used across all chapters.
# Source: docs/papers/PAPERS_INDEX.md ("Core 20 Reference Papers").

REFERENCES = [
    dict(n=1, pcode="P14", text='T. Amsuess, C. Amsuss, T. Fossati, and M. Tiloca, "Securing Name Resolution in IoT: DNS over CoAP," *ACM Transactions on Internet of Things*, vol. 1, no. 2, Article 9, 2023, doi: 10.1145/3609423.'),
    dict(n=2, pcode="P18", text='M. Anand, M. Joshi, and N. Chirculescu, "A New Method for Vulnerability and Risk Assessment of IoT," *Computer Networks* (Elsevier), vol. 236, Article 109788, 2023, doi: 10.1016/j.comnet.2023.109788.'),
    dict(n=3, pcode="P06", text='A. Churcher, R. Ullah, J. Ahmad, S. ur Rehman, et al., "Survey on Enterprise IoT Systems (E-IoT): A Security Perspective," *IEEE Access*, vol. 9, pp. 62289-62317, 2021, doi: 10.1109/ACCESS.2021.3073730.'),
    dict(n=4, pcode="P08", text='X. Dong, J. Zheng, Z. Li, and Y. Chen, "Toward IoT Device Fingerprinting from Proprietary Protocol Traffic," *Computer Networks* (Elsevier), vol. 224, Article 109612, 2023, doi: 10.1016/j.comnet.2023.109612.'),
    dict(n=5, pcode="P04", text='E. Gvozdenovic, J. Bridwell, J. Weston, and D. Raje, "Systematically Analyzing Vulnerabilities in Wi-Fi Connection Establishment," in *Proc. IEEE Conf. on Communications and Network Security (CNS)*, 2022.'),
    dict(n=6, pcode="P09", text='S. Habibi Lashkari, A. Zino, and A. Tavallaee, "Device Identification Using Optimized Digital Footprints," *arXiv preprint* arXiv:2212.04354, 2022.'),
    dict(n=7, pcode="P13", text='M. Hasan, M. Islam, M. Zarif, and M. Hashem, "Preventing MQTT Vulnerabilities Using IoT-Enabled Intrusion Detection," *Sensors* (MDPI), vol. 22, no. 2, Article 567, 2022, doi: 10.3390/s22020567.'),
    dict(n=8, pcode="P19", text='G. Heiding, B. Lundell, and U. Lindqvist, "SAFER: IoT Device Risk Assessment Framework in a Multinational Organization," *arXiv preprint* arXiv:2007.14724, 2020.'),
    dict(n=9, pcode="P15", text='J. Jacobs, S. Romanosky, B. Edwards, M. Roytman, and I. Adjerid, "Exploit Prediction Scoring System (EPSS)," *ACM Digital Threats: Research and Practice*, vol. 2, no. 3, Article 16, 2021, doi: 10.1145/3436242.'),
    dict(n=10, pcode="P05", text='T. D. Nguyen, S. Marchal, M. Miettinen, H. Fereidooni, N. Asokan, and A.-R. Sadeghi, "DIoT: A Self-Learning System for Detecting Compromised IoT Devices," *IEEE Internet of Things Journal*, vol. 10, no. 5, pp. 3851-3863, 2023, doi: 10.1109/JIOT.2022.3199104.'),
    dict(n=11, pcode="P12", text='M. Palmieri, M. Cebe, C. Ozmen-Ertekin, et al., "Experimental Evaluation of MQTT Authentication and Authorization in IoT," in *Proc. ACM WiNTECH Workshop (co-located with ACM MobiCom)*, 2021, doi: 10.1145/3477086.3480838.'),
    dict(n=12, pcode="P17", text='P. Radoglou-Grammatikis, P. Sarigiannidis, G. Efstathopoulos, P. Karypidis, and A. Sarigiannidis, "Analysis of Consumer IoT Device Vulnerability Quantification Frameworks," *Electronics* (MDPI), vol. 12, no. 5, Article 1176, 2023, doi: 10.3390/electronics12051176.'),
    dict(n=13, pcode="P10", text='J. Ren, D. J. Dubois, D. Choffnes, A. Mandalari, R. Kolcun, and H. Haddadi, "Analyzing Consumer IoT Traffic: Security and Privacy Perspectives," *arXiv preprint* arXiv:2403.16149, 2024.'),
    dict(n=14, pcode="P03", text='D. Schepers, A. Ranganathan, and M. Vanhoef, "Framing Frames: Bypassing Wi-Fi Encryption via Transmit Queue Manipulation," in *Proc. 32nd USENIX Security Symposium*, 2023.'),
    dict(n=15, pcode="P07", text='A. Sivanathan, H. H. Gharakheili, and V. Sivaraman, "IoT Behavioral Monitoring via Network Traffic Analysis," *arXiv preprint* arXiv:2001.10632, 2020.'),
    dict(n=16, pcode="P11", text='M. Soni and A. Singh, "Vulnerability Assessment of MQTT Protocol in Internet of Things (IoT)," in *Proc. IEEE Int. Conf. on Computing, Communication and Automation (ICCCA)*, 2021, doi: 10.1109/ICCCA52192.2021.9478156.'),
    dict(n=17, pcode="P16", text='A. Subramaniam, S. Krishnan, and R. Vitale, "Efficacy of EPSS in High-Severity CVEs Found in CISA KEV," *arXiv preprint* arXiv:2411.02618, 2024.'),
    dict(n=18, pcode="P02", text='M. Vanhoef, "Fragment and Forge: Breaking Wi-Fi Through Frame Aggregation and Fragmentation," in *Proc. 30th USENIX Security Symposium*, 2021.'),
    dict(n=19, pcode="P01", text='M. Vanhoef and E. Ronen, "Dragonblood: Analyzing the Dragonfly Handshake of WPA3 and EAP-pwd," in *Proc. IEEE Symposium on Security and Privacy (S&P)*, 2020, pp. 517-533, doi: 10.1109/SP40000.2020.00071.'),
    dict(n=20, pcode="P20", text='J. Varga, A. Kovacs, and P. Szabo, "IoT Device Security Audit Tools: Comprehensive Analysis and Layered Architecture," *International Journal of Information Security* (Springer), 2024, doi: 10.1007/s10207-024-00930-z.'),
]

BY_PCODE = {r["pcode"]: r["n"] for r in REFERENCES}


def cite(*pcodes):
    """cite('P01','P02') -> '[19], [18]' sorted ascending -> '[18], [19]'"""
    nums = sorted(BY_PCODE[p] for p in pcodes)
    return ", ".join(f"[{n}]" for n in nums)
