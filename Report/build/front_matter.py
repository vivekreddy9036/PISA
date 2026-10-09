# -*- coding: utf-8 -*-
"""
Front matter: Title page, Bonafide Certificate, Declaration, Abstract,
Acknowledgement, Table of Contents, List of Tables, List of Figures,
List of Symbols/Abbreviations/Nomenclature.

Built AFTER the chapters (so the registry is fully populated for TOC/LOT/LOF),
then physically moved to the start of the document by report_engine.finalize_layout().
"""
from docx.shared import Pt, Cm, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from report_engine import (
    add_para, add_table, page_ref_placeholder, _set_run_font, WD_LINE_SPACING,
)

STUDENT_NAME = "VIVEK REDDY"
REG_NO = "CH.SC.U4CYS23034"
SUPERVISOR_NAME = "Dr. Jinka Aravind"
SUPERVISOR_DESIG = "Assistant Professor, Department of Computer Science and Engineering"
HOD_NAME = "Dr. S. Udhaya Kumar"
HOD_DESIG = "Program Chair, Department of Computer Science and Engineering (Cyber Security)"
TITLE = "PISA: PORTABLE IoT SECURITY ASSESSMENT PLATFORM"
SUBTITLE = "An End-to-End System for Wireless Network Posture Scoring, IoT Device Fingerprinting, and Authorized Vulnerability Verification"
DEGREE = "BACHELOR OF TECHNOLOGY"
BRANCH = "IN COMPUTER SCIENCE AND ENGINEERING (CYBER SECURITY)"
MONTH_YEAR = "November 2026"


def _centered(doc, text, size=12, bold=False, italic=False, space_after=6, space_before=0, upper=False):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(space_after)
    p.paragraph_format.space_before = Pt(space_before)
    p.paragraph_format.line_spacing_rule = WD_LINE_SPACING.ONE_POINT_FIVE
    r = p.add_run(text.upper() if upper else text)
    _set_run_font(r)
    r.bold = bold
    r.italic = italic
    r.font.size = Pt(size)
    return p


def _title_page(doc):
    _centered(doc, TITLE, size=18, bold=True, space_after=4, space_before=20)
    _centered(doc, SUBTITLE, size=13, italic=True, space_after=24)
    _centered(doc, "A PROJECT REPORT", size=14, bold=True, space_after=24)
    _centered(doc, "Submitted by", size=12, italic=True, space_after=10)
    _centered(doc, STUDENT_NAME, size=14, bold=True, space_after=2)
    _centered(doc, f"({REG_NO})", size=12, space_after=20)
    _centered(doc, "in partial fulfillment for the award of the degree of", size=12, italic=True, space_after=16)
    _centered(doc, DEGREE, size=14, bold=True, space_after=2)
    _centered(doc, BRANCH, size=14, bold=True, space_after=24)
    _centered(doc, "Supervisor", size=12, italic=True, space_after=6)
    _centered(doc, SUPERVISOR_NAME, size=14, bold=True, space_after=24)
    _centered(doc, "Submitted to", size=12, italic=True, space_after=20)
    _centered(doc, "AMRITA SCHOOL OF COMPUTING", size=16, bold=True, space_after=2)
    _centered(doc, "AMRITA VISHWA VIDYAPEETHAM", size=16, bold=True, space_after=2)
    _centered(doc, "CHENNAI – 601103", size=16, bold=True, space_after=24)
    _centered(doc, MONTH_YEAR, size=14, bold=True, space_after=0)


def _bonafide_page(doc):
    _centered(doc, "AMRITA SCHOOL OF COMPUTING, CHENNAI", size=14, bold=True, space_after=4)
    _centered(doc, "BONAFIDE CERTIFICATE", size=16, bold=True, space_after=20, space_before=10)
    add_para(doc, (
        f'Certified that this project report "{TITLE}" is the bonafide work of '
        f'"{STUDENT_NAME} ({REG_NO})" who carried out the project work under my supervision.'
    ), indent=True, space_after=30)

    tbl = doc.add_table(rows=4, cols=2)
    tbl.autofit = True
    cells = [
        ("<<Signature of Head of the Department>>", "<<Signature of Supervisor>>"),
        (HOD_NAME, SUPERVISOR_NAME),
        (HOD_DESIG, SUPERVISOR_DESIG),
        ("Amrita School of Computing, Amrita Vishwa Vidyapeetham, Chennai – 601103",
         "Amrita School of Computing, Amrita Vishwa Vidyapeetham, Chennai – 601103"),
    ]
    for ri, (a, b) in enumerate(cells):
        for ci, val in enumerate((a, b)):
            cell = tbl.cell(ri, ci)
            cell.text = ""
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            r = p.add_run(val)
            _set_run_font(r)
            r.font.size = Pt(11)
            if ri == 1:
                r.bold = True
    for row in tbl.rows:
        for cell in row.cells:
            for b in cell._tc.iter():
                pass
    doc.add_paragraph().paragraph_format.space_after = Pt(30)
    tbl2 = doc.add_table(rows=1, cols=2)
    for ci, label in enumerate(("INTERNAL EXAMINER", "EXTERNAL EXAMINER")):
        cell = tbl2.cell(0, ci)
        cell.text = ""
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(label)
        _set_run_font(r)
        r.bold = True
        r.font.size = Pt(12)


def _declaration_page(doc):
    _centered(doc, "AMRITA SCHOOL OF COMPUTING, CHENNAI", size=14, bold=True, space_after=4)
    _centered(doc, "DECLARATION BY THE CANDIDATE", size=16, bold=True, space_after=20, space_before=10)
    add_para(doc, (
        f'I declare that the report entitled "{TITLE}" submitted by me for the degree of '
        f'Bachelor of Technology in Computer Science and Engineering (Cyber Security) is the record '
        f'of the project work carried out by me under the guidance of "{SUPERVISOR_NAME}" '
        f'({SUPERVISOR_DESIG}), and that this work has not formed the basis for the award of any '
        f'degree, diploma, associateship, fellowship, or similar title in this or any other '
        f'University or other similar institution of higher learning.'
    ), indent=True, space_after=40)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    r = p.add_run(f"<<Signature of Student>>\n{STUDENT_NAME}\nReg. No. {REG_NO}")
    _set_run_font(r)
    r.font.size = Pt(12)


def _abstract_page(doc):
    _centered(doc, "ABSTRACT", size=16, bold=True, space_after=16, space_before=10)
    add_para(doc, (
        "The proliferation of Internet of Things (IoT) devices has created an attack surface with two "
        "layers that existing security tooling treats in complete isolation: the wireless network a "
        "device connects through, and the device itself. No published tool scores a network's security "
        "posture from passive observation alone, identifies the IoT devices on it without a "
        "machine-learning model, correlates those devices against real, currently-exploited "
        "vulnerabilities, and safely verifies exploitability — all within a single pipeline on "
        "portable, field-deployable hardware. This report presents PISA (Portable IoT Security "
        "Assessment Platform), a system built to close that gap on Raspberry Pi 4 class hardware. PISA "
        "is organized as six modules: M0 computes a WiFi Security Posture Score (WSPS, A–F) from "
        "passive 802.11 beacon analysis and correlates an access point's vendor against known CVEs; M1 "
        "joins a scored network and discovers its devices via ARP sweep, Nmap, and mDNS; M2 fingerprints "
        "each device's MQTT, CoAP, HTTP, and RTSP behaviour and fuses per-protocol confidence using a "
        "probabilistic complement rule; M3 correlates devices against the live National Vulnerability "
        "Database, enriches results with FIRST.org's Exploit Prediction Scoring System (EPSS) and the "
        "CISA Known Exploited Vulnerabilities catalogue, and evaluates real NVD configuration logic "
        "before ever reporting a device as affected; and M4 verifies and, only under explicit, "
        "logged operator authorization, exploits a confirmed vulnerability through RouterSploit, gated "
        "by a named-operator confirmation and a mandatory countdown. All six modules are implemented, "
        "covered by 381 automated tests, and have each been validated against real hardware, real "
        "networks, and real external APIs: four real campus networks scored by WSPS, a real IP camera "
        "fingerprinted at full confidence, a real reference CVE (CVSS 9.8, EPSS 29%) correctly matched "
        "and an honest non-match correctly refused, and the authorization gate shown, through adversarial "
        "live testing, to block every unauthorized or under-evidenced exploitation attempt tried against "
        "it. The report positions PISA against twenty peer-reviewed sources and nine named prior tools, "
        "states five specific novelty claims, and reports results and limitations honestly as a basis "
        "for the work remaining before the final project review."
    ), indent=True, space_after=16)
    p = doc.add_paragraph()
    p.paragraph_format.line_spacing_rule = WD_LINE_SPACING.ONE_POINT_FIVE
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r1 = p.add_run("Keywords: ")
    _set_run_font(r1)
    r1.bold = True
    r1.font.size = Pt(12)
    r2 = p.add_run(
        "IoT Security, WiFi Security Posture Scoring, Protocol Behavioural Fingerprinting, "
        "Vulnerability Correlation, EPSS, CISA KEV, Authorized Exploitation, Penetration Testing, "
        "Edge Security, Raspberry Pi."
    )
    _set_run_font(r2)
    r2.font.size = Pt(12)


def _acknowledgement_page(doc):
    _centered(doc, "ACKNOWLEDGEMENT", size=16, bold=True, space_after=16, space_before=10)
    add_para(doc, (
        "This project would not have been possible without the contribution of many people. It gives "
        "me immense pleasure to express my profound gratitude to our honourable Chancellor, "
        "**Sri Mata Amritanandamayi Devi**, for her blessings and for being a source of inspiration. I "
        "extend my sincere thanks to Administrative Director, **Sampoojya Swami Vinyamritananda Puri**, "
        "of Amrita Vishwa Vidyapeetham, Chennai, for his guidance and support. I am deeply indebted to "
        "our Director, **I B Manikantan**, of Amrita School of Computing, for providing all the "
        "facilities and extended support that enabled me to gain valuable education and learning "
        "experience."
    ))
    add_para(doc, (
        "I extend my special thanks to **Dr. V Jayakumar**, Principal of Amrita School of Computing, "
        "for the support provided in the successful completion of this project. I am also grateful to "
        "**Dr. S Baghavathi Priya**, Chairperson, Department of Computer Science and Engineering, and "
        f"**{HOD_NAME}**, {HOD_DESIG}, for their continued encouragement throughout this work."
    ))
    add_para(doc, (
        f"I am sincerely thankful to my supervisor, **{SUPERVISOR_NAME}**, {SUPERVISOR_DESIG}, for his "
        "valuable guidance, constructive feedback, and constant support at every stage of this project, "
        "from the initial problem scoping through to the real-hardware validation reported in this "
        "report. Finally, I thank my family and friends for their encouragement and support throughout "
        "this project."
    ))
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    p.paragraph_format.space_before = Pt(20)
    r = p.add_run(STUDENT_NAME)
    _set_run_font(r)
    r.bold = True
    r.font.size = Pt(12)


def _toc_pages(doc, registry):
    _centered(doc, "TABLE OF CONTENTS", size=16, bold=True, space_after=16, space_before=10)
    rows = [["Chapter No.", "Title", "Page No."]]
    for e in registry.toc:
        indent = "    " * (e['level'] - 1)
        rows.append([e['number'] if e['level'] == 1 else "", f"{indent}{e['title']}", ""])
    tbl = add_table(doc, rows, header=True, widths=[0.9, 4.6, 1.0], font_size=11)
    for ri, e in enumerate(registry.toc, start=1):
        page_ref_placeholder(tbl.cell(ri, 2), e['bookmark'])


def _lot_page(doc, registry):
    _centered(doc, "LIST OF TABLES", size=16, bold=True, space_after=16, space_before=10)
    rows = [["Table No.", "Title", "Page No."]]
    for e in registry.tables:
        rows.append([e['number'], e['title'], ""])
    tbl = add_table(doc, rows, header=True, widths=[0.9, 4.6, 1.0], font_size=11)
    for ri, e in enumerate(registry.tables, start=1):
        page_ref_placeholder(tbl.cell(ri, 2), e['bookmark'])


def _lof_page(doc, registry):
    _centered(doc, "LIST OF FIGURES", size=16, bold=True, space_after=16, space_before=10)
    rows = [["Figure No.", "Title", "Page No."]]
    for e in registry.figures:
        rows.append([e['number'], e['title'], ""])
    tbl = add_table(doc, rows, header=True, widths=[0.9, 4.6, 1.0], font_size=11)
    for ri, e in enumerate(registry.figures, start=1):
        page_ref_placeholder(tbl.cell(ri, 2), e['bookmark'])


SYMBOLS = [
    ("IoT", "Internet of Things"),
    ("WSPS", "WiFi Security Posture Score"),
    ("OUI", "Organizationally Unique Identifier"),
    ("BSSID", "Basic Service Set Identifier"),
    ("SSID", "Service Set Identifier"),
    ("PMF", "Protected Management Frames (IEEE 802.11w)"),
    ("WPS", "WiFi Protected Setup"),
    ("RSSI", "Received Signal Strength Indicator"),
    ("CVE", "Common Vulnerabilities and Exposures"),
    ("CVSS", "Common Vulnerability Scoring System"),
    ("CPE", "Common Platform Enumeration"),
    ("NVD", "National Vulnerability Database"),
    ("EPSS", "Exploit Prediction Scoring System"),
    ("KEV", "Known Exploited Vulnerabilities (CISA catalogue)"),
    ("MQTT", "Message Queuing Telemetry Transport"),
    ("CoAP", "Constrained Application Protocol"),
    ("RTSP", "Real Time Streaming Protocol"),
    ("HTTP", "Hypertext Transfer Protocol"),
    ("ARP", "Address Resolution Protocol"),
    ("mDNS", "Multicast Domain Name System"),
    ("API", "Application Programming Interface"),
    ("SRS", "Software Requirements Specification"),
    ("FR / NFR", "Functional Requirement / Non-Functional Requirement"),
    ("CI/CD", "Continuous Integration / Continuous Deployment"),
    ("AWS", "Amazon Web Services"),
]


def _los_page(doc):
    _centered(doc, "LIST OF SYMBOLS, ABBREVIATIONS AND NOMENCLATURE", size=15, bold=True, space_after=16, space_before=10)
    rows = [[t, m] for t, m in SYMBOLS]
    add_table(doc, [["Abbreviation", "Expansion"]] + rows, header=True, widths=[1.6, 4.8], font_size=11)


def build(doc, registry):
    _title_page(doc)
    doc.add_page_break()
    _bonafide_page(doc)
    doc.add_page_break()
    _declaration_page(doc)
    doc.add_page_break()
    _abstract_page(doc)
    doc.add_page_break()
    _acknowledgement_page(doc)
    doc.add_page_break()
    _toc_pages(doc, registry)
    doc.add_page_break()
    _lot_page(doc, registry)
    doc.add_page_break()
    _lof_page(doc, registry)
    doc.add_page_break()
    _los_page(doc)
