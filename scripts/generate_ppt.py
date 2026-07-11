from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Inches, Pt
from pptx.enum.dml import MSO_THEME_COLOR
import copy

# ─── COLOUR PALETTE ────────────────────────────────────────────────────────────
BG_DARK       = RGBColor(0x09, 0x0D, 0x1A)   # near-black navy
BG_CARD       = RGBColor(0x12, 0x18, 0x2E)   # card background
ACCENT_CYAN   = RGBColor(0x00, 0xD4, 0xFF)   # primary accent
ACCENT_GREEN  = RGBColor(0x00, 0xFF, 0x88)   # secondary accent
ACCENT_RED    = RGBColor(0xFF, 0x4D, 0x4D)   # danger/critical
ACCENT_ORANGE = RGBColor(0xFF, 0xA5, 0x00)   # warning
WHITE         = RGBColor(0xFF, 0xFF, 0xFF)
GRAY_LIGHT    = RGBColor(0xB0, 0xB8, 0xC8)
GRAY_MED      = RGBColor(0x60, 0x6A, 0x80)
YELLOW        = RGBColor(0xFF, 0xE0, 0x66)

SLIDE_W = Inches(13.33)
SLIDE_H = Inches(7.5)

prs = Presentation()
prs.slide_width  = SLIDE_W
prs.slide_height = SLIDE_H

BLANK_LAYOUT = prs.slide_layouts[6]   # completely blank

# ─── HELPERS ───────────────────────────────────────────────────────────────────

def add_bg(slide, color=BG_DARK):
    bg = slide.shapes.add_shape(1, 0, 0, SLIDE_W, SLIDE_H)
    bg.fill.solid()
    bg.fill.fore_color.rgb = color
    bg.line.fill.background()
    return bg

def add_rect(slide, l, t, w, h, color, radius=False):
    shape = slide.shapes.add_shape(1, l, t, w, h)
    shape.fill.solid()
    shape.fill.fore_color.rgb = color
    shape.line.fill.background()
    return shape

def add_textbox(slide, text, l, t, w, h,
                font_size=18, bold=False, color=WHITE,
                align=PP_ALIGN.LEFT, italic=False, wrap=True):
    txBox = slide.shapes.add_textbox(l, t, w, h)
    tf = txBox.text_frame
    tf.word_wrap = wrap
    p = tf.paragraphs[0]
    p.alignment = align
    run = p.add_run()
    run.text = text
    run.font.size  = Pt(font_size)
    run.font.bold  = bold
    run.font.color.rgb = color
    run.font.italic = italic
    return txBox

def add_para(tf, text, font_size=16, bold=False, color=WHITE,
             align=PP_ALIGN.LEFT, space_before=0, italic=False):
    p = tf.add_paragraph()
    p.alignment = align
    p.space_before = Pt(space_before)
    run = p.add_run()
    run.text = text
    run.font.size  = Pt(font_size)
    run.font.bold  = bold
    run.font.color.rgb = color
    run.font.italic = italic
    return p

def slide_header(slide, title, subtitle=None, tag=None):
    """Standard header bar at top of slide."""
    # accent bar
    add_rect(slide, 0, 0, SLIDE_W, Inches(0.07), ACCENT_CYAN)
    # title
    add_textbox(slide, title, Inches(0.45), Inches(0.12),
                Inches(9), Inches(0.6), font_size=28, bold=True,
                color=WHITE, align=PP_ALIGN.LEFT)
    if subtitle:
        add_textbox(slide, subtitle, Inches(0.45), Inches(0.65),
                    Inches(9), Inches(0.35), font_size=14,
                    color=ACCENT_CYAN, align=PP_ALIGN.LEFT)
    if tag:
        add_textbox(slide, tag, Inches(10.8), Inches(0.18),
                    Inches(2.2), Inches(0.4), font_size=11,
                    color=GRAY_MED, align=PP_ALIGN.RIGHT)
    # divider line
    line = slide.shapes.add_shape(1, Inches(0.45), Inches(0.95),
                                  Inches(12.43), Inches(0.025))
    line.fill.solid(); line.fill.fore_color.rgb = GRAY_MED
    line.line.fill.background()

def pill(slide, text, l, t, w, h, bg=ACCENT_CYAN, fg=BG_DARK, font_size=11, bold=True):
    add_rect(slide, l, t, w, h, bg)
    add_textbox(slide, text, l, t, w, h,
                font_size=font_size, bold=bold, color=fg,
                align=PP_ALIGN.CENTER)

def card(slide, l, t, w, h, accent_color=ACCENT_CYAN, title=None, body_lines=None, title_size=13, body_size=11):
    add_rect(slide, l, t, w, h, BG_CARD)
    # left accent stripe
    add_rect(slide, l, t, Inches(0.06), h, accent_color)
    if title:
        add_textbox(slide, title, l+Inches(0.12), t+Inches(0.08),
                    w-Inches(0.18), Inches(0.32), font_size=title_size,
                    bold=True, color=accent_color)
    if body_lines:
        tb = slide.shapes.add_textbox(l+Inches(0.12), t+Inches(0.38),
                                       w-Inches(0.2), h-Inches(0.48))
        tb.text_frame.word_wrap = True
        for i, line in enumerate(body_lines):
            if i == 0:
                p = tb.text_frame.paragraphs[0]
            else:
                p = tb.text_frame.add_paragraph()
            p.space_before = Pt(2)
            run = p.add_run()
            run.text = line
            run.font.size = Pt(body_size)
            run.font.color.rgb = GRAY_LIGHT

def footer(slide, text="PISA — Portable IoT Security Assessment Platform  |  FYP 2026"):
    add_rect(slide, 0, SLIDE_H - Inches(0.3), SLIDE_W, Inches(0.3), RGBColor(0x06, 0x0A, 0x14))
    add_textbox(slide, text, Inches(0.4), SLIDE_H - Inches(0.28),
                Inches(12.5), Inches(0.26), font_size=9, color=GRAY_MED, align=PP_ALIGN.CENTER)

# ──────────────────────────────────────────────────────────────────────────────
# SLIDE 1  —  TITLE
# ──────────────────────────────────────────────────────────────────────────────
s = prs.slides.add_slide(BLANK_LAYOUT)
add_bg(s)

# background grid pattern (horizontal faint lines)
for i in range(20):
    line = s.shapes.add_shape(1, 0, Inches(i*0.4), SLIDE_W, Inches(0.01))
    line.fill.solid(); line.fill.fore_color.rgb = RGBColor(0x14,0x1C,0x30)
    line.line.fill.background()

# top accent bar
add_rect(s, 0, 0, SLIDE_W, Inches(0.1), ACCENT_CYAN)

# left vertical accent bar
add_rect(s, 0, 0, Inches(0.1), SLIDE_H, ACCENT_CYAN)

# PISA large acronym block
add_rect(s, Inches(0.7), Inches(1.1), Inches(3.0), Inches(1.8), BG_CARD)
add_rect(s, Inches(0.7), Inches(1.1), Inches(0.12), Inches(1.8), ACCENT_CYAN)
add_textbox(s, "PISA", Inches(0.9), Inches(1.15), Inches(2.6), Inches(1.0),
            font_size=72, bold=True, color=ACCENT_CYAN, align=PP_ALIGN.LEFT)
add_textbox(s, "v 1.0  |  FYP Phase 1", Inches(0.9), Inches(2.05), Inches(2.6), Inches(0.4),
            font_size=11, color=GRAY_MED, align=PP_ALIGN.LEFT)

# Full title
add_textbox(s, "Portable IoT Security Assessment Platform",
            Inches(0.7), Inches(3.1), Inches(11.0), Inches(0.8),
            font_size=36, bold=True, color=WHITE, align=PP_ALIGN.LEFT)

add_textbox(s,
            "Automated End-to-End Security Assessment — from Wireless Network Vulnerability Scoring\nto IoT Device Protocol Fingerprinting, CVE Correlation & Exploit Delivery on Commodity Hardware",
            Inches(0.7), Inches(3.95), Inches(11.0), Inches(0.9),
            font_size=16, bold=False, color=GRAY_LIGHT, align=PP_ALIGN.LEFT)

# divider
add_rect(s, Inches(0.7), Inches(4.95), Inches(11.0), Inches(0.04), ACCENT_CYAN)

# bottom info strip
pill(s, "IEEE IoT Journal Target", Inches(0.7), Inches(5.1), Inches(2.4), Inches(0.38),
     bg=RGBColor(0x00,0x3A,0x52), fg=ACCENT_CYAN, font_size=11)
pill(s, "Raspberry Pi 4 + AWS", Inches(3.25), Inches(5.1), Inches(2.2), Inches(0.38),
     bg=RGBColor(0x00,0x3A,0x26), fg=ACCENT_GREEN, font_size=11)
pill(s, "Python 3.12 | Flask | Terraform", Inches(5.6), Inches(5.1), Inches(3.0), Inches(0.38),
     bg=RGBColor(0x3A,0x28,0x00), fg=ACCENT_ORANGE, font_size=11)
pill(s, "No ML/DL | Authorized Use Only", Inches(8.75), Inches(5.1), Inches(3.0), Inches(0.38),
     bg=RGBColor(0x3A,0x00,0x00), fg=ACCENT_RED, font_size=11)

add_textbox(s, "Vivek Reddy  |  20CYS495  |  Amrita School of Engineering  |  June 2026",
            Inches(0.7), Inches(5.7), Inches(11.0), Inches(0.4),
            font_size=13, color=GRAY_LIGHT, align=PP_ALIGN.LEFT)

# ──────────────────────────────────────────────────────────────────────────────
# SLIDE 2  —  AGENDA
# ──────────────────────────────────────────────────────────────────────────────
s = prs.slides.add_slide(BLANK_LAYOUT)
add_bg(s)
slide_header(s, "Agenda", tag="20CYS495")
footer(s)

items = [
    ("01", "Motivation",          "Why IoT security is a critical unsolved problem today"),
    ("02", "Problem Statement",   "Two-layer assessment gap — no unified portable tool exists"),
    ("03", "Literature Search",   "Systematic review methodology — databases & keywords"),
    ("04", "Literature Survey",   "Analysis of 12 existing tools & 7 research papers"),
    ("05", "Research Gaps",       "What the existing work misses and why PISA fills it"),
    ("06", "Objectives",          "Primary goal, 5 secondary objectives, 4 research questions"),
    ("07", "System Architecture", "Two-layer pipeline — WiSentinel → Fingerprinting → CVE → Exploit"),
    ("08", "References",          "Key academic papers and standards cited"),
]

cols = 2
rows = 4
W = Inches(5.9)
H = Inches(0.72)
GAP_X = Inches(0.25)
GAP_Y = Inches(0.12)
START_X = Inches(0.45)
START_Y = Inches(1.15)

for i, (num, title, desc) in enumerate(items):
    col = i % cols
    row = i // cols
    lx = START_X + col * (W + GAP_X)
    ty = START_Y + row * (H + GAP_Y)
    add_rect(s, lx, ty, W, H, BG_CARD)
    add_rect(s, lx, ty, Inches(0.55), H, ACCENT_CYAN)
    add_textbox(s, num, lx, ty, Inches(0.55), H,
                font_size=20, bold=True, color=BG_DARK, align=PP_ALIGN.CENTER)
    add_textbox(s, title, lx+Inches(0.62), ty+Inches(0.06), W-Inches(0.7), Inches(0.32),
                font_size=15, bold=True, color=WHITE)
    add_textbox(s, desc, lx+Inches(0.62), ty+Inches(0.36), W-Inches(0.7), Inches(0.3),
                font_size=10, color=GRAY_LIGHT)

# ──────────────────────────────────────────────────────────────────────────────
# SLIDE 3  —  MOTIVATION (Part 1: Numbers)
# ──────────────────────────────────────────────────────────────────────────────
s = prs.slides.add_slide(BLANK_LAYOUT)
add_bg(s)
slide_header(s, "Motivation", subtitle="The IoT Security Crisis — By the Numbers", tag="01 / 08")
footer(s)

stats = [
    ("18.8 B+", "IoT devices deployed globally in 2024\n(Statista 2024)", ACCENT_CYAN),
    ("29 B+",   "Projected devices by 2030\n(IoT Analytics)", ACCENT_GREEN),
    ("57%",     "IoT devices vulnerable to medium\nor high severity attacks (Palo Alto 2020)", ACCENT_ORANGE),
    ("98%",     "IoT traffic is unencrypted\n(Unit 42 Threat Report 2020)", ACCENT_RED),
    ("300+",    "IoT CVEs in CISA KEV catalog\nactively exploited in the wild", YELLOW),
    ("500 M+",  "Hikvision + Dahua cameras deployed\nglobally — both with KEV-listed RCE CVEs", ACCENT_RED),
]

cols = 3
W = Inches(3.9)
H = Inches(1.35)
GAP_X = Inches(0.22)
GAP_Y = Inches(0.2)
START_X = Inches(0.45)
START_Y = Inches(1.18)

for i, (num, label, color) in enumerate(stats):
    col = i % cols
    row = i // cols
    lx = START_X + col * (W + GAP_X)
    ty = START_Y + row * (H + GAP_Y)
    add_rect(s, lx, ty, W, H, BG_CARD)
    add_rect(s, lx, ty, W, Inches(0.055), color)
    add_textbox(s, num, lx+Inches(0.12), ty+Inches(0.07), W-Inches(0.18), Inches(0.58),
                font_size=34, bold=True, color=color, align=PP_ALIGN.LEFT)
    add_textbox(s, label, lx+Inches(0.12), ty+Inches(0.65), W-Inches(0.18), Inches(0.62),
                font_size=11, color=GRAY_LIGHT, align=PP_ALIGN.LEFT)

# ──────────────────────────────────────────────────────────────────────────────
# SLIDE 4  —  MOTIVATION (Part 2: Attack Surface)
# ──────────────────────────────────────────────────────────────────────────────
s = prs.slides.add_slide(BLANK_LAYOUT)
add_bg(s)
slide_header(s, "Motivation", subtitle="Why IoT Security Assessment Is Critically Unsolved", tag="01 / 08")
footer(s)

bullets = [
    ("⚠  Fragmented Tooling",
     "Security practitioners juggle Nmap, Bettercap, RouterSploit, Shodan, and manual CVE lookups. "
     "No single tool covers both the WiFi network layer and the IoT device layer together.",
     ACCENT_ORANGE),
    ("⚠  No Portable Solution",
     "All existing comprehensive tools (OpenVAS, Nessus, Tenable.io) require laptops, internet, "
     "and significant configuration. Nothing runs autonomously on a $50 RPi 4 in the field.",
     ACCENT_ORANGE),
    ("⚠  WiFi Security Is Blind Spot",
     "Router firmware contains some of the most exploited CVEs in KEV. Yet no tool passively scores "
     "WiFi network security posture and correlates it to router hardware CVEs in real time.",
     ACCENT_RED),
    ("⚠  Protocol Behavior Ignored",
     "IoT devices expose identity through HOW they use MQTT, CoAP, RTSP, and HTTP — not just which "
     "ports are open. Existing tools stop at port scanning; PISA goes into protocol state machines.",
     ACCENT_CYAN),
    ("⚠  CVE Prioritization Is Broken",
     "Tools use CVSS score alone to rank CVEs — a metric that ignores whether the vulnerability "
     "is being actively exploited. EPSS + CISA KEV changes this. No portable tool uses all three.",
     ACCENT_GREEN),
]

START_Y = Inches(1.18)
H = Inches(0.98)
GAP = Inches(0.1)
W = Inches(12.4)

for i, (title, body, color) in enumerate(bullets):
    ty = START_Y + i * (H + GAP)
    add_rect(s, Inches(0.45), ty, W, H, BG_CARD)
    add_rect(s, Inches(0.45), ty, Inches(0.07), H, color)
    add_textbox(s, title, Inches(0.6), ty+Inches(0.07), Inches(4.0), Inches(0.35),
                font_size=13, bold=True, color=color)
    add_textbox(s, body, Inches(0.6), ty+Inches(0.42), Inches(11.7), Inches(0.5),
                font_size=11, color=GRAY_LIGHT)

# ──────────────────────────────────────────────────────────────────────────────
# SLIDE 5  —  PROBLEM STATEMENT (Layer Diagram)
# ──────────────────────────────────────────────────────────────────────────────
s = prs.slides.add_slide(BLANK_LAYOUT)
add_bg(s)
slide_header(s, "Problem Statement", subtitle="The Two-Layer IoT Attack Surface", tag="02 / 08")
footer(s)

# Layer 1 box
add_rect(s, Inches(0.45), Inches(1.15), Inches(5.7), Inches(2.6), BG_CARD)
add_rect(s, Inches(0.45), Inches(1.15), Inches(5.7), Inches(0.06), ACCENT_CYAN)
pill(s, "LAYER 1 — WiFi Network", Inches(0.55), Inches(1.22), Inches(2.6), Inches(0.3),
     bg=ACCENT_CYAN, fg=BG_DARK, font_size=11)
l1_points = [
    "• Weak encryption: WEP / WPA2-TKIP still widespread",
    "• WPS enabled — PIN brute-force in hours",
    "• No Management Frame Protection (deauth floods)",
    "• Router firmware CVEs — many KEV-listed, unpatched",
    "• PMKID/EAPOL handshake crackable offline",
    "• Default SSIDs reveal manufacturer & model",
]
tb = s.shapes.add_textbox(Inches(0.58), Inches(1.6), Inches(5.5), Inches(1.95))
tb.text_frame.word_wrap = True
for i, pt in enumerate(l1_points):
    p = tb.text_frame.paragraphs[0] if i == 0 else tb.text_frame.add_paragraph()
    p.space_before = Pt(2)
    r = p.add_run(); r.text = pt
    r.font.size = Pt(11); r.font.color.rgb = GRAY_LIGHT

# Arrow between layers
add_rect(s, Inches(6.35), Inches(2.1), Inches(0.6), Inches(0.08), ACCENT_ORANGE)
add_textbox(s, "┈┈┈►", Inches(6.3), Inches(1.95), Inches(0.7), Inches(0.3),
            font_size=20, bold=True, color=ACCENT_ORANGE, align=PP_ALIGN.CENTER)
add_textbox(s, "joined\nnetwork", Inches(6.15), Inches(2.25), Inches(1.0), Inches(0.4),
            font_size=9, color=GRAY_MED, align=PP_ALIGN.CENTER)

# Layer 2 box
add_rect(s, Inches(7.18), Inches(1.15), Inches(5.7), Inches(2.6), BG_CARD)
add_rect(s, Inches(7.18), Inches(1.15), Inches(5.7), Inches(0.06), ACCENT_GREEN)
pill(s, "LAYER 2 — IoT Devices", Inches(7.28), Inches(1.22), Inches(2.5), Inches(0.3),
     bg=ACCENT_GREEN, fg=BG_DARK, font_size=11)
l2_points = [
    "• IP cameras — unauthenticated RTSP, default creds",
    "• MQTT brokers — open, no TLS, topic injection",
    "• CoAP sensors — no DTLS, resource enumeration",
    "• HTTP devices — open admin panels, default login",
    "• Outdated firmware — hundreds of known CVEs",
    "• Industrial (Modbus) — no auth, open register access",
]
tb2 = s.shapes.add_textbox(Inches(7.3), Inches(1.6), Inches(5.5), Inches(1.95))
tb2.text_frame.word_wrap = True
for i, pt in enumerate(l2_points):
    p = tb2.text_frame.paragraphs[0] if i == 0 else tb2.text_frame.add_paragraph()
    p.space_before = Pt(2)
    r = p.add_run(); r.text = pt
    r.font.size = Pt(11); r.font.color.rgb = GRAY_LIGHT

# Gap statement
add_rect(s, Inches(0.45), Inches(4.0), Inches(12.43), Inches(1.1), RGBColor(0x1A,0x0A,0x00))
add_rect(s, Inches(0.45), Inches(4.0), Inches(0.09), Inches(1.1), ACCENT_RED)
add_textbox(s, "THE GAP", Inches(0.62), Inches(4.06), Inches(2), Inches(0.3),
            font_size=13, bold=True, color=ACCENT_RED)
add_textbox(s,
    "No existing tool, product, or published research performs end-to-end, automated IoT security "
    "assessment spanning both layers — from passive WiFi network vulnerability scoring through IoT device "
    "protocol fingerprinting, CVE correlation, and exploit delivery — on portable commodity hardware. "
    "This leaves security practitioners without an efficient, field-deployable methodology for comprehensive IoT auditing.",
    Inches(0.62), Inches(4.36), Inches(12.1), Inches(0.65),
    font_size=11.5, color=GRAY_LIGHT)

# Impact strip
add_rect(s, Inches(0.45), Inches(5.22), Inches(12.43), Inches(0.38), RGBColor(0x20,0x05,0x05))
add_textbox(s,
    "IMPACT: CISA KEV lists 300+ actively exploited IoT CVEs — yet no portable unified tool exists to assess whether a given environment is exposed.",
    Inches(0.6), Inches(5.24), Inches(12.1), Inches(0.32),
    font_size=11, bold=True, color=ACCENT_RED)

# ──────────────────────────────────────────────────────────────────────────────
# SLIDE 6  —  PROBLEM STATEMENT — Existing Tools Fail
# ──────────────────────────────────────────────────────────────────────────────
s = prs.slides.add_slide(BLANK_LAYOUT)
add_bg(s)
slide_header(s, "Problem Statement", subtitle="Why Existing Tools Are Insufficient", tag="02 / 08")
footer(s)

# Table header
headers = ["Tool", "WiFi Layer", "Device Layer", "Portable HW", "CVE Correlation", "Automated"]
col_widths = [Inches(2.4), Inches(1.5), Inches(1.8), Inches(1.6), Inches(2.3), Inches(1.6)]
col_starts = [Inches(0.45)]
for w in col_widths[:-1]:
    col_starts.append(col_starts[-1] + w + Inches(0.02))

ROW_H = Inches(0.42)
START_Y = Inches(1.15)

# header row
for j, (hdr, lx, cw) in enumerate(zip(headers, col_starts, col_widths)):
    add_rect(s, lx, START_Y, cw, ROW_H, ACCENT_CYAN)
    add_textbox(s, hdr, lx+Inches(0.06), START_Y, cw-Inches(0.08), ROW_H,
                font_size=12, bold=True, color=BG_DARK, align=PP_ALIGN.CENTER)

rows_data = [
    ["Nmap + NSE",        "✗",  "Port scan only", "✗",  "Manual lookup",  "✗"],
    ["Bettercap",         "✗",  "No fingerprint", "✗",  "✗",              "✗"],
    ["RouterSploit",      "✗",  "Exploits only",  "✗",  "✗",              "✗"],
    ["Kismet / WiGLE",    "Raw data only", "✗",   "Partial","✗",          "✗"],
    ["OpenVAS / Nessus",  "✗",  "Agent-based",    "✗",  "CVSS only",      "Partial"],
    ["Shodan",            "✗",  "Internet only",  "✗",  "CVSS only",      "✗"],
    ["PISA (Proposed) ★", "✔ WSPS A-F", "✔ MQTT/CoAP/RTSP", "✔ RPi 4", "✔ CVSS+EPSS+KEV", "✔ Full pipeline"],
]

for i, row in enumerate(rows_data):
    ty = START_Y + (i+1) * (ROW_H + Inches(0.02))
    is_pisa = i == len(rows_data) - 1
    row_bg = RGBColor(0x00,0x25,0x15) if is_pisa else BG_CARD
    for j, (cell, lx, cw) in enumerate(zip(row, col_starts, col_widths)):
        add_rect(s, lx, ty, cw, ROW_H, row_bg)
        if is_pisa:
            fc = ACCENT_GREEN
        elif cell in ("✗", "✗ "):
            fc = ACCENT_RED
        elif cell.startswith("✔"):
            fc = ACCENT_GREEN
        elif cell == "Partial":
            fc = ACCENT_ORANGE
        else:
            fc = WHITE if j == 0 else GRAY_LIGHT
        fsize = 12 if is_pisa else 11
        add_textbox(s, cell, lx+Inches(0.05), ty, cw-Inches(0.08), ROW_H,
                    font_size=fsize, bold=is_pisa, color=fc, align=PP_ALIGN.CENTER)

# ──────────────────────────────────────────────────────────────────────────────
# SLIDE 7  —  LITERATURE SEARCH (Methodology)
# ──────────────────────────────────────────────────────────────────────────────
s = prs.slides.add_slide(BLANK_LAYOUT)
add_bg(s)
slide_header(s, "Literature Search", subtitle="Systematic Review Methodology", tag="03 / 08")
footer(s)

# Databases
dbs = ["IEEE Xplore", "ACM Digital Library", "Google Scholar", "arXiv.org",
       "USENIX Security", "ScienceDirect", "SpringerLink", "Semantic Scholar"]
add_textbox(s, "Databases Searched", Inches(0.45), Inches(1.18), Inches(5.8), Inches(0.35),
            font_size=14, bold=True, color=ACCENT_CYAN)
for i, db in enumerate(dbs):
    col = i % 2; row = i // 2
    lx = Inches(0.45) + col * Inches(2.9)
    ty = Inches(1.56) + row * Inches(0.38)
    add_rect(s, lx, ty, Inches(2.7), Inches(0.32), BG_CARD)
    add_textbox(s, "● " + db, lx+Inches(0.1), ty, Inches(2.5), Inches(0.32),
                font_size=11.5, color=GRAY_LIGHT)

# Keywords
add_textbox(s, "Search Keywords & Queries", Inches(6.4), Inches(1.18), Inches(6.5), Inches(0.35),
            font_size=14, bold=True, color=ACCENT_CYAN)
keywords = [
    '"IoT security assessment" + "fingerprinting"',
    '"WiFi security scoring" + "beacon frame"',
    '"MQTT fingerprinting" NOT "machine learning"',
    '"CoAP behavioral analysis"',
    '"CVSS EPSS CISA KEV" + "prioritization"',
    '"OUI CVE correlation" + "IoT"',
    '"portable IoT pentest" OR "edge security"',
    '"protocol-aware fingerprinting" + "non-ML"',
]
for i, kw in enumerate(keywords):
    ty = Inches(1.56) + i * Inches(0.38)
    add_rect(s, Inches(6.4), ty, Inches(6.5), Inches(0.32), BG_CARD)
    add_rect(s, Inches(6.4), ty, Inches(0.04), Inches(0.32), ACCENT_GREEN)
    add_textbox(s, kw, Inches(6.5), ty, Inches(6.3), Inches(0.32),
                font_size=10.5, color=GRAY_LIGHT, italic=True)

# Stats bar
stats2 = [
    ("60+",  "Papers Reviewed"),
    ("19",   "UAV/Drone Security Papers\n(for comparison)"),
    ("12",   "Directly Related Tools\nIncluded in Survey"),
    ("7",    "Closest Academic Papers\nCited in Related Work"),
    ("2024–2026", "Prioritized\nPublication Years"),
]
ty = Inches(4.8)
W2 = Inches(2.35)
GAP2 = Inches(0.12)
lx = Inches(0.45)
for num, lbl in stats2:
    add_rect(s, lx, ty, W2, Inches(0.9), BG_CARD)
    add_rect(s, lx, ty, W2, Inches(0.05), ACCENT_ORANGE)
    add_textbox(s, num, lx+Inches(0.1), ty+Inches(0.08), W2-Inches(0.15), Inches(0.42),
                font_size=26, bold=True, color=ACCENT_ORANGE)
    add_textbox(s, lbl, lx+Inches(0.1), ty+Inches(0.48), W2-Inches(0.15), Inches(0.38),
                font_size=10, color=GRAY_LIGHT)
    lx += W2 + GAP2

# ──────────────────────────────────────────────────────────────────────────────
# SLIDE 8  —  LITERATURE SURVEY — Tools
# ──────────────────────────────────────────────────────────────────────────────
s = prs.slides.add_slide(BLANK_LAYOUT)
add_bg(s)
slide_header(s, "Literature Survey", subtitle="Existing Tools — Coverage Analysis", tag="04 / 08")
footer(s)

tools = [
    ("Pwnagotchi (2019)",
     "Passive PMKID/EAPOL capture on RPi Zero W. Warwalking focused.",
     "No CVE correlation, no security scoring, no device layer, not academic."),
    ("Kismet (2002–present)",
     "Passive multi-protocol WiFi/BT logging. Comprehensive raw capture.",
     "Raw data only — no security scoring, no device fingerprinting, no CVE."),
    ("WiFi Pineapple / Hak5",
     "Commercial active WiFi auditing. Rogue AP, MITM, credential capture.",
     "Proprietary ~$100 hardware, no CVE correlation, no IoT device layer, not academic."),
    ("Bettercap (2018–present)",
     "Active network attack toolkit — ARP spoof, MQTT, BLE sniffing.",
     "Manual operation, no CVE pipeline, no fingerprinting, not standalone portable."),
    ("RouterSploit (2016–present)",
     "IoT-focused exploit framework — 100+ router/camera exploit modules.",
     "No device discovery, no fingerprinting, no CVE auto-lookup, not portable."),
    ("Shodan (2009–present)",
     "Internet-facing device indexing — CVE correlation from internet scans.",
     "Cloud-only, passive, no local network assessment, no exploit delivery."),
    ("IoT Sentinel (2017)",
     "ML-based IoT device classification from network traffic patterns.",
     "Requires ML + large training dataset, no CVE/exploit pipeline, not portable."),
    ("SAFER / CERN (2022)",
     "Fingerprinting + CVE assessment on institutional network infrastructure.",
     "Requires enterprise infrastructure, no WiFi layer, no EPSS, not portable HW."),
    ("IoTective / Aston (2025)",
     "Automated smart home pentest across WiFi, BLE, and Zigbee.",
     "No CVE correlation, no behavioral fingerprinting, no cloud backend."),
    ("From Flows to Functions — UNSW (Dec 2025)",
     "Non-ML IoT fingerprinting by tracking which services are present over time.",
     "Only checks WHICH services run — not HOW devices behave within protocols. No RTSP, no fusion, no CVE."),
]

for i, (name, what, diff) in enumerate(tools):
    col = i % 2; row = i // 2
    lx = Inches(0.45) + col * Inches(6.35)
    ty = Inches(1.15) + row * Inches(1.05)
    W3 = Inches(6.1)
    H3 = Inches(0.98)
    add_rect(s, lx, ty, W3, H3, BG_CARD)
    add_rect(s, lx, ty, Inches(0.07), H3, ACCENT_CYAN)
    add_textbox(s, name, lx+Inches(0.14), ty+Inches(0.06), W3-Inches(0.2), Inches(0.28),
                font_size=12, bold=True, color=ACCENT_CYAN)
    add_textbox(s, "What: " + what, lx+Inches(0.14), ty+Inches(0.35), W3-Inches(0.2), Inches(0.25),
                font_size=9.5, color=GRAY_LIGHT)
    add_textbox(s, "Gap: " + diff, lx+Inches(0.14), ty+Inches(0.58), W3-Inches(0.2), Inches(0.35),
                font_size=9.5, color=ACCENT_ORANGE)

# ──────────────────────────────────────────────────────────────────────────────
# SLIDE 9  —  LITERATURE SURVEY — Academic Papers
# ──────────────────────────────────────────────────────────────────────────────
s = prs.slides.add_slide(BLANK_LAYOUT)
add_bg(s)
slide_header(s, "Literature Survey", subtitle="Key Academic Papers", tag="04 / 08")
footer(s)

papers = [
    ("[1] Miettinen et al. — IoT Sentinel (2017), IEEE ICDCS",
     "ML-based IoT device type identification from traffic features at connection setup.",
     "PISA: No ML needed; behavioral protocol analysis achieves comparable accuracy."),
    ("[2] Marchal et al. — AuDI (2019), IEEE TIFS",
     "Unsupervised anomaly detection for IoT devices using network traffic statistics.",
     "PISA: Addresses device identification, not anomaly detection; adds CVE/exploit pipeline."),
    ("[3] Bremler-Barr et al. — SAFER (2022), ACM CoNEXT",
     "Fingerprinting + CVE correlation on enterprise IoT using Nmap + CPE matching.",
     "PISA: Adds WiFi layer, EPSS scoring, portable hardware, behavioral protocol analysis."),
    ("[4] Bai et al. — DeviceRadar (2024), IEEE DSC",
     "Non-ML packet-level IoT fingerprinting on ISP infrastructure switches.",
     "PISA: Edge hardware, WiFi layer, CVE pipeline, protocol behavioral analysis."),
    ("[5] First.org — EPSS Framework (2021, updated 2023)",
     "Exploit Prediction Scoring System — daily probability of CVE exploitation.",
     "PISA: First portable IoT tool to integrate EPSS alongside CVSS + CISA KEV."),
    ("[6] CISA — KEV Catalog (2021–present)",
     "Official catalog of CVEs confirmed actively exploited in the wild.",
     "PISA: Uses KEV as 2× multiplier in ExploitScore — prioritizes real-world threats."),
    ("[7] Perdisci et al. — IoT-Finder (2020), IEEE EuroSP",
     "Passive IoT device detection via DNS traffic patterns from ISP vantage point.",
     "PISA: Active protocol behavioral probing — not passive DNS — enables CVE/exploit chain."),
]

for i, (ref, what, pisa) in enumerate(papers):
    ty = Inches(1.15) + i * Inches(0.76)
    add_rect(s, Inches(0.45), ty, Inches(12.43), Inches(0.7), BG_CARD)
    add_rect(s, Inches(0.45), ty, Inches(0.07), Inches(0.7), ACCENT_GREEN)
    add_textbox(s, ref, Inches(0.6), ty+Inches(0.04), Inches(12.1), Inches(0.24),
                font_size=11, bold=True, color=ACCENT_GREEN)
    add_textbox(s, "▸ " + what, Inches(0.6), ty+Inches(0.28), Inches(6.5), Inches(0.35),
                font_size=9.5, color=GRAY_LIGHT)
    add_textbox(s, "PISA: " + pisa, Inches(7.2), ty+Inches(0.28), Inches(5.5), Inches(0.35),
                font_size=9.5, color=ACCENT_CYAN, italic=True)

# ──────────────────────────────────────────────────────────────────────────────
# SLIDE 10  —  RESEARCH GAPS
# ──────────────────────────────────────────────────────────────────────────────
s = prs.slides.add_slide(BLANK_LAYOUT)
add_bg(s)
slide_header(s, "Research Gaps", subtitle="What the Existing Literature Misses", tag="05 / 08")
footer(s)

gaps = [
    ("GAP 1", "No Portable, Self-Contained Assessment Tool",
     "All comprehensive IoT security tools require laptops, server infrastructure, or cloud connectivity. "
     "No published system delivers end-to-end IoT assessment on commodity RPi 4 hardware.",
     ACCENT_RED),
    ("GAP 2", "WiFi Network Layer Never Integrated With Device Layer",
     "Every existing tool treats the WiFi/router layer and the IoT device layer as completely separate concerns. "
     "The router is the gateway to all IoT devices — yet no tool assesses both in one pipeline.",
     ACCENT_ORANGE),
    ("GAP 3", "Protocol Behavioral Fingerprinting Requires ML or Misses Intra-Protocol Behavior",
     "Non-ML approaches (DeviceRadar, Flows-to-Functions) only check WHICH services run, not HOW devices "
     "behave within those protocols. ML approaches need training data not available for new devices.",
     ACCENT_CYAN),
    ("GAP 4", "CVE Prioritization Uses CVSS Alone — EPSS Never Used on Portable IoT Hardware",
     "EPSS (Exploit Prediction Scoring System) is validated as superior to CVSS alone for prioritizing "
     "exploitable CVEs. No portable IoT tool uses EPSS. CISA KEV is also ignored in existing tools.",
     ACCENT_GREEN),
    ("GAP 5", "No Longitudinal IoT Monitoring — All Tools Are Point-in-Time",
     "Security changes over time: firmware updates, new CVEs, new devices joining networks. "
     "No existing tool tracks behavioral drift across sessions to detect compromise or degradation.",
     YELLOW),
]

for i, (tag, title, body, color) in enumerate(gaps):
    col = i % 1
    ty = Inches(1.15) + i * Inches(1.02)
    add_rect(s, Inches(0.45), ty, Inches(12.43), Inches(0.95), BG_CARD)
    add_rect(s, Inches(0.45), ty, Inches(0.08), Inches(0.95), color)
    pill(s, tag, Inches(0.6), ty+Inches(0.1), Inches(0.95), Inches(0.28),
         bg=color, fg=BG_DARK, font_size=10, bold=True)
    add_textbox(s, title, Inches(1.65), ty+Inches(0.07), Inches(10.9), Inches(0.3),
                font_size=13, bold=True, color=color)
    add_textbox(s, body, Inches(0.6), ty+Inches(0.45), Inches(12.1), Inches(0.45),
                font_size=10.5, color=GRAY_LIGHT)

# ──────────────────────────────────────────────────────────────────────────────
# SLIDE 11  —  OBJECTIVES
# ──────────────────────────────────────────────────────────────────────────────
s = prs.slides.add_slide(BLANK_LAYOUT)
add_bg(s)
slide_header(s, "Research Objectives", subtitle="Primary Objective + 5 Secondary Objectives", tag="06 / 08")
footer(s)

# Primary
add_rect(s, Inches(0.45), Inches(1.15), Inches(12.43), Inches(1.1), RGBColor(0x00,0x1A,0x2E))
add_rect(s, Inches(0.45), Inches(1.15), Inches(0.1), Inches(1.1), ACCENT_CYAN)
pill(s, "PRIMARY OBJECTIVE", Inches(0.65), Inches(1.22), Inches(2.2), Inches(0.28),
     bg=ACCENT_CYAN, fg=BG_DARK, font_size=10)
add_textbox(s,
    "Design, implement, and evaluate a portable, self-contained IoT security assessment platform on Raspberry Pi 4 "
    "that performs automated two-layer security assessment: (1) WiFi network vulnerability scoring and router CVE "
    "correlation, and (2) IoT device protocol-aware behavioral fingerprinting with CVE correlation and exploit recommendation.",
    Inches(0.65), Inches(1.52), Inches(12.0), Inches(0.65),
    font_size=12, color=WHITE)

# Secondary
sec_objs = [
    ("O1", "WSPS Framework",
     "Develop WiFi Security Posture Scoring — quantitative A–F grade per network from passive beacon frames alone. No active exploitation, no authentication required.",
     ACCENT_CYAN),
    ("O2", "Protocol-Aware Fingerprinting",
     "Implement behavioral fingerprinting across MQTT, CoAP, HTTP, and RTSP protocols — identifying device type, manufacturer, and firmware generation without ML.",
     ACCENT_GREEN),
    ("O3", "OUI-to-CVE + Tri-Metric Scoring",
     "Build automated OUI→CVE and fingerprint→CVE correlation using NVD, EPSS, and CISA KEV. Compute ExploitScore = CVSS × EPSS × KEV multiplier × Access factor.",
     ACCENT_ORANGE),
    ("O4", "End-to-End Pipeline Demo",
     "Demonstrate the complete Fingerprint → CVE → Exploit pipeline on ≥10 distinct IoT device types in a controlled lab within a 15-minute target assessment window.",
     YELLOW),
    ("O5", "Accuracy & Performance Validation",
     "Validate ≥85% fingerprinting accuracy, ≥90% WSPS agreement with expert, CISA KEV CVEs surfaced in <60s, full 10-device assessment in <8 minutes.",
     ACCENT_GREEN),
]

for i, (tag, title, body, color) in enumerate(sec_objs):
    col = i % 2 if i < 4 else 0
    row = i // 2 if i < 4 else 2
    if i == 4:
        lx = Inches(0.45); W4 = Inches(12.43)
    else:
        lx = Inches(0.45) + col * Inches(6.35)
        W4 = Inches(6.1)
    ty = Inches(2.45) + row * Inches(0.95)
    H4 = Inches(0.88)
    add_rect(s, lx, ty, W4, H4, BG_CARD)
    add_rect(s, lx, ty, Inches(0.08), H4, color)
    pill(s, tag, lx+Inches(0.16), ty+Inches(0.07), Inches(0.55), Inches(0.26),
         bg=color, fg=BG_DARK, font_size=10, bold=True)
    add_textbox(s, title, lx+Inches(0.85), ty+Inches(0.06), W4-Inches(0.95), Inches(0.3),
                font_size=12, bold=True, color=color)
    add_textbox(s, body, lx+Inches(0.16), ty+Inches(0.4), W4-Inches(0.25), Inches(0.42),
                font_size=10, color=GRAY_LIGHT)

# ──────────────────────────────────────────────────────────────────────────────
# SLIDE 12  —  OBJECTIVES — Research Questions & Hypotheses
# ──────────────────────────────────────────────────────────────────────────────
s = prs.slides.add_slide(BLANK_LAYOUT)
add_bg(s)
slide_header(s, "Research Questions & Hypotheses", subtitle="Testable Claims Driving PISA's Evaluation", tag="06 / 08")
footer(s)

rqs = [
    ("RQ1", "PRIMARY",
     "Can a portable, self-contained system perform end-to-end IoT security assessment — from WiFi vulnerability scoring to device fingerprinting and CVE-exploit correlation — without ML, on commodity hardware?",
     ACCENT_CYAN),
    ("RQ2", "NETWORK LAYER",
     "Can passive WiFi beacon frame analysis alone produce a reliable security posture score that accurately predicts network exploitability without active packet injection?",
     ACCENT_GREEN),
    ("RQ3", "DEVICE LAYER",
     "Do IoT devices of the same manufacturer/firmware exhibit sufficiently consistent protocol behavioral signatures (MQTT topics, CoAP timing, HTTP headers) for deterministic identification at ≥85% accuracy?",
     ACCENT_ORANGE),
    ("RQ4", "INTEGRATION",
     "What is the accuracy, completeness, and time-to-assessment of the integrated two-layer pipeline vs manual multi-tool assessment (Nmap + Bettercap + RouterSploit + NVD search)?",
     YELLOW),
]

hypotheses = [
    ("H1", "WSPS ≥90% Cohen's κ agreement with expert manual assessment"),
    ("H2", "Protocol fingerprinting ≥85% accuracy across tested devices"),
    ("H3", "All CVSS≥7.0 CVEs surfaced within 60 seconds of device identification"),
    ("H4", "End-to-end assessment time ≤20% of equivalent manual multi-tool workflow"),
]

for i, (tag, label, body, color) in enumerate(rqs):
    ty = Inches(1.15) + i * Inches(0.96)
    add_rect(s, Inches(0.45), ty, Inches(8.5), Inches(0.88), BG_CARD)
    add_rect(s, Inches(0.45), ty, Inches(0.08), Inches(0.88), color)
    add_textbox(s, f"{tag}  [{label}]", Inches(0.62), ty+Inches(0.07), Inches(8.1), Inches(0.28),
                font_size=12, bold=True, color=color)
    add_textbox(s, body, Inches(0.62), ty+Inches(0.4), Inches(8.1), Inches(0.44),
                font_size=10.5, color=GRAY_LIGHT)

add_textbox(s, "Hypotheses", Inches(9.2), Inches(1.15), Inches(3.8), Inches(0.35),
            font_size=14, bold=True, color=ACCENT_CYAN)
for i, (tag, body) in enumerate(hypotheses):
    ty = Inches(1.55) + i * Inches(0.9)
    add_rect(s, Inches(9.2), ty, Inches(3.8), Inches(0.82), BG_CARD)
    add_rect(s, Inches(9.2), ty, Inches(0.08), Inches(0.82), ACCENT_CYAN)
    add_textbox(s, tag, Inches(9.35), ty+Inches(0.07), Inches(0.4), Inches(0.28),
                font_size=12, bold=True, color=ACCENT_CYAN)
    add_textbox(s, body, Inches(9.82), ty+Inches(0.07), Inches(3.1), Inches(0.68),
                font_size=10, color=GRAY_LIGHT)

# ──────────────────────────────────────────────────────────────────────────────
# SLIDE 13  —  SYSTEM ARCHITECTURE OVERVIEW
# ──────────────────────────────────────────────────────────────────────────────
s = prs.slides.add_slide(BLANK_LAYOUT)
add_bg(s)
slide_header(s, "System Architecture", subtitle="Two-Layer Automated Assessment Pipeline", tag="07 / 08")
footer(s)

# Pipeline boxes
modules = [
    ("M0", "WiSentinel\nWiFi Assessment", "Beacon capture\nWSPS A–F scoring\nOUI → CVE\nHandshake capture", ACCENT_CYAN),
    ("M1", "Network\nDiscovery",           "ARP sweep\nNmap service scan\nDevice inventory\nPriority ranking",  ACCENT_GREEN),
    ("M2", "Protocol\nFingerprinting",     "MQTT • CoAP\nRTSP • HTTP\nCross-protocol fusion\nDrift detection",  ACCENT_ORANGE),
    ("M3", "CVE Correlation\nEngine",       "NVD v2.0 API\nEPSS • CISA KEV\nTri-Metric scoring\nKEV alerting",  YELLOW),
    ("M4", "Exploit\nPipeline",            "RouterSploit\nAuthorization gate\n5-sec confirm\nResult logging",   ACCENT_RED),
]

BOX_W = Inches(2.15)
BOX_H = Inches(2.4)
GAP_X = Inches(0.25)
START_X = Inches(0.48)
START_Y = Inches(1.2)

for i, (tag, title, body, color) in enumerate(modules):
    lx = START_X + i * (BOX_W + GAP_X)
    add_rect(s, lx, START_Y, BOX_W, BOX_H, BG_CARD)
    add_rect(s, lx, START_Y, BOX_W, Inches(0.06), color)
    # module tag circle
    add_rect(s, lx + Inches(0.08), START_Y + Inches(0.12), Inches(0.48), Inches(0.48), color)
    add_textbox(s, tag, lx + Inches(0.08), START_Y + Inches(0.12),
                Inches(0.48), Inches(0.48), font_size=13, bold=True, color=BG_DARK, align=PP_ALIGN.CENTER)
    add_textbox(s, title, lx + Inches(0.62), START_Y + Inches(0.12),
                BOX_W - Inches(0.72), Inches(0.52), font_size=12, bold=True, color=color)

    tb = s.shapes.add_textbox(lx + Inches(0.08), START_Y + Inches(0.72),
                               BOX_W - Inches(0.14), Inches(1.55))
    tb.text_frame.word_wrap = True
    for j, line in enumerate(body.split("\n")):
        p = tb.text_frame.paragraphs[0] if j == 0 else tb.text_frame.add_paragraph()
        p.space_before = Pt(3)
        r = p.add_run(); r.text = "► " + line
        r.font.size = Pt(10.5); r.font.color.rgb = GRAY_LIGHT

    # Arrow
    if i < len(modules) - 1:
        ax = lx + BOX_W + Inches(0.04)
        add_textbox(s, "▶", ax, START_Y + BOX_H/2 - Inches(0.2), Inches(0.2), Inches(0.3),
                    font_size=16, bold=True, color=color, align=PP_ALIGN.CENTER)

# AWS Cloud + Flask
add_rect(s, Inches(0.45), Inches(3.78), Inches(7.2), Inches(0.8), BG_CARD)
add_rect(s, Inches(0.45), Inches(3.78), Inches(0.08), Inches(0.8), ACCENT_CYAN)
add_textbox(s, "☁  AWS Cloud: DynamoDB · Lambda · S3 · EC2 Spot · SNS · API Gateway · Terraform IaC",
            Inches(0.62), Inches(3.85), Inches(6.9), Inches(0.6),
            font_size=11, bold=True, color=ACCENT_CYAN)

add_rect(s, Inches(7.85), Inches(3.78), Inches(5.03), Inches(0.8), BG_CARD)
add_rect(s, Inches(7.85), Inches(3.78), Inches(0.08), Inches(0.8), ACCENT_GREEN)
add_textbox(s, "M5 — Flask Touchscreen UI  +  SQLite  +  PDF Reports (Lambda)  +  GitHub Actions CI/CD",
            Inches(8.02), Inches(3.85), Inches(4.7), Inches(0.6),
            font_size=11, bold=True, color=ACCENT_GREEN)

# Hardware strip
HW_items = [
    ("RPi 4 (4GB)", ACCENT_CYAN),
    ("Alfa AWUS036ACM\n802.11ac Monitor Mode", ACCENT_GREEN),
    ("RPi 7\"\nTouchscreen", ACCENT_ORANGE),
    ("NEO-6M\nGPS Module", YELLOW),
    ("Python 3.12\nFlask 3.0", ACCENT_CYAN),
    ("RouterSploit\nHashcat · Scapy", ACCENT_RED),
]
HW_W = Inches(1.95)
HW_H = Inches(0.7)
HW_GAP = Inches(0.18)
HW_START = Inches(0.45)
HW_Y = Inches(4.72)
for i, (name, color) in enumerate(HW_items):
    lx = HW_START + i * (HW_W + HW_GAP)
    add_rect(s, lx, HW_Y, HW_W, HW_H, BG_CARD)
    add_rect(s, lx, HW_Y, HW_W, Inches(0.04), color)
    add_textbox(s, name, lx+Inches(0.06), HW_Y+Inches(0.06), HW_W-Inches(0.1), HW_H-Inches(0.1),
                font_size=10, color=color, align=PP_ALIGN.CENTER)

# ──────────────────────────────────────────────────────────────────────────────
# SLIDE 14  —  ARCHITECTURE — Module Detail + Novelty Claims
# ──────────────────────────────────────────────────────────────────────────────
s = prs.slides.add_slide(BLANK_LAYOUT)
add_bg(s)
slide_header(s, "System Architecture", subtitle="5 Novelty Claims & WSPS Scoring Formula", tag="07 / 08")
footer(s)

claims = [
    ("N1", "WSPS Framework",
     "First passive beacon-only WiFi A–F security scoring. 8-factor weighted formula — encryption, WPS, MFP, PMKID, cipher, CVE exposure, SSID, temporal stability.",
     ACCENT_CYAN),
    ("N2", "OUI-to-CVE Correlation",
     "First system to map WiFi BSSID OUI → router manufacturer → real-time NVD + CISA KEV CVE lookup on portable edge hardware.",
     ACCENT_GREEN),
    ("N3", "Protocol Behavioral Fingerprinting",
     "MQTT/CoAP/HTTP/RTSP behavioral state machine analysis. Cross-Protocol Confidence Fusion: combined = 1 − ∏(1−cᵢ). Non-ML, deterministic.",
     ACCENT_ORANGE),
    ("N4", "Two-Layer Integrated Pipeline",
     "First system chaining WiFi layer + device layer + behavioral drift detection in single pipeline on RPi 4. Parallel priority-queue scheduling.",
     YELLOW),
    ("N5", "Tri-Metric CVE Scoring",
     "ExploitScore = CVSS_norm × (1 + 1.5×EPSS) × KEV_multiplier × Access_factor. First portable IoT tool to use EPSS on edge hardware.",
     ACCENT_RED),
]

for i, (tag, title, body, color) in enumerate(claims):
    col = i % 2 if i < 4 else 0
    row = i // 2 if i < 4 else 2
    if i == 4:
        lx = Inches(0.45); W5 = Inches(12.43)
    else:
        lx = Inches(0.45) + col * Inches(6.35)
        W5 = Inches(6.1)
    ty = Inches(1.15) + row * Inches(1.02)
    H5 = Inches(0.95)
    add_rect(s, lx, ty, W5, H5, BG_CARD)
    add_rect(s, lx, ty, Inches(0.08), H5, color)
    pill(s, tag, lx+Inches(0.16), ty+Inches(0.1), Inches(0.55), Inches(0.28),
         bg=color, fg=BG_DARK, font_size=10, bold=True)
    add_textbox(s, title, lx+Inches(0.85), ty+Inches(0.08), W5-Inches(0.95), Inches(0.3),
                font_size=13, bold=True, color=color)
    add_textbox(s, body, lx+Inches(0.16), ty+Inches(0.44), W5-Inches(0.25), Inches(0.45),
                font_size=10.5, color=GRAY_LIGHT)

# WSPS formula box
add_rect(s, Inches(0.45), Inches(4.38), Inches(12.43), Inches(0.88), RGBColor(0x00,0x12,0x22))
add_rect(s, Inches(0.45), Inches(4.38), Inches(0.08), Inches(0.88), ACCENT_CYAN)
add_textbox(s, "WSPS Formula:",
            Inches(0.62), Inches(4.42), Inches(1.8), Inches(0.28),
            font_size=11, bold=True, color=ACCENT_CYAN)
add_textbox(s,
    "WSPS = 0.25·E + 0.20·W + 0.15·M + 0.12·P + 0.10·C + 0.10·V + 0.05·S + 0.03·T",
    Inches(0.62), Inches(4.7), Inches(8.5), Inches(0.48),
    font_size=12, bold=True, color=WHITE, italic=True)
add_textbox(s,
    "E=Encryption  W=WPS  M=MFP  P=PMKID  C=Cipher  V=CVE Exposure  S=SSID  T=Temporal",
    Inches(9.3), Inches(4.42), Inches(3.5), Inches(0.7),
    font_size=9.5, color=GRAY_LIGHT)

grade_colors = [ACCENT_GREEN, ACCENT_GREEN, ACCENT_ORANGE, ACCENT_ORANGE, ACCENT_RED]
grades = [("A", "90–100"), ("B", "75–89"), ("C", "60–74"), ("D", "45–59"), ("F", "<45")]
for i, ((g, r), gc) in enumerate(zip(grades, grade_colors)):
    lx = Inches(0.62) + i * Inches(1.5)
    ty = Inches(5.35)
    add_rect(s, lx, ty, Inches(1.3), Inches(0.5), BG_CARD)
    add_textbox(s, f"Grade {g}: {r}", lx+Inches(0.06), ty+Inches(0.06),
                Inches(1.2), Inches(0.38), font_size=11, bold=True, color=gc, align=PP_ALIGN.CENTER)

# ──────────────────────────────────────────────────────────────────────────────
# SLIDE 15  —  VULNERABILITIES BY IoT CATEGORY (Prof's Q&A slide)
# ──────────────────────────────────────────────────────────────────────────────
s = prs.slides.add_slide(BLANK_LAYOUT)
add_bg(s)
slide_header(s, "Vulnerability Coverage by IoT Device Category",
             subtitle="What PISA Finds and How It Finds It", tag="Q&A")
footer(s)

cats = [
    ("IP Cameras\n(RTSP/HTTP)",
     ["Default/no credentials on stream", "Unauthenticated RTSP feed", "Hikvision/Dahua KEV-listed CVEs", "No TLS on video stream"],
     ["RTSP DESCRIBE probe", "HTTP banner + /doc/page/login.asp", "CVE lookup via OUI", "RouterSploit exploit module"],
     ACCENT_RED),
    ("Smart Hubs\n(MQTT)",
     ["Open broker — no auth", "No TLS — plaintext topics", "Topic enumeration & injection", "Default HTTP admin creds"],
     ["MQTT anonymous connect", "Wildcard '#' subscribe", "Packet capture on 1883", "HTTP panel fingerprint"],
     ACCENT_CYAN),
    ("Sensors\n(CoAP/Modbus)",
     ["Unauthenticated CoAP endpoints", "No DTLS — unencrypted data", "Open Modbus registers", "Replay attack possible"],
     ["CoAP GET /.well-known/core", "UDP capture on port 5683", "pymodbus register read", "Resource enumeration"],
     ACCENT_GREEN),
    ("Routers/APs\n(WiFi 802.11)",
     ["Weak WPA2/WEP encryption", "WPS PIN attack vector", "No MFP — deauth flood", "Firmware CVEs via OUI"],
     ["Passive beacon RSN IE parse", "PMKID capture + Hashcat", "Deauth flood detection", "OUI → NVD CVE lookup"],
     ACCENT_ORANGE),
    ("HTTP Devices\n(Smart TV/NAS)",
     ["Open admin ports 80/443/8080", "Default credentials", "Outdated firmware CVEs", "No HTTPS on management"],
     ["Nmap TCP scan IoT ports", "HTTP banner grab", "Server: header → version", "Tri-Metric CVE scoring"],
     YELLOW),
]

COL_W = Inches(2.35)
COL_H = Inches(4.55)
COL_GAP = Inches(0.2)
COL_START = Inches(0.45)
COL_Y = Inches(1.18)

for i, (name, vulns, techs, color) in enumerate(cats):
    lx = COL_START + i * (COL_W + COL_GAP)
    add_rect(s, lx, COL_Y, COL_W, COL_H, BG_CARD)
    add_rect(s, lx, COL_Y, COL_W, Inches(0.06), color)
    add_textbox(s, name, lx+Inches(0.08), COL_Y+Inches(0.1), COL_W-Inches(0.12), Inches(0.5),
                font_size=12, bold=True, color=color, align=PP_ALIGN.CENTER)
    # vulns
    add_textbox(s, "VULNERABILITIES", lx+Inches(0.08), COL_Y+Inches(0.62), COL_W-Inches(0.1), Inches(0.22),
                font_size=9, bold=True, color=ACCENT_RED)
    tb = s.shapes.add_textbox(lx+Inches(0.08), COL_Y+Inches(0.84), COL_W-Inches(0.1), Inches(1.6))
    tb.text_frame.word_wrap = True
    for j, v in enumerate(vulns):
        p = tb.text_frame.paragraphs[0] if j == 0 else tb.text_frame.add_paragraph()
        p.space_before = Pt(2)
        r = p.add_run(); r.text = "• " + v; r.font.size = Pt(9.5); r.font.color.rgb = GRAY_LIGHT
    # techniques
    add_textbox(s, "TECHNIQUES", lx+Inches(0.08), COL_Y+Inches(2.52), COL_W-Inches(0.1), Inches(0.22),
                font_size=9, bold=True, color=ACCENT_GREEN)
    tb2 = s.shapes.add_textbox(lx+Inches(0.08), COL_Y+Inches(2.74), COL_W-Inches(0.1), Inches(1.65))
    tb2.text_frame.word_wrap = True
    for j, t in enumerate(techs):
        p = tb2.text_frame.paragraphs[0] if j == 0 else tb2.text_frame.add_paragraph()
        p.space_before = Pt(2)
        r = p.add_run(); r.text = "▶ " + t; r.font.size = Pt(9.5); r.font.color.rgb = GRAY_LIGHT

# ──────────────────────────────────────────────────────────────────────────────
# SLIDE 16  —  HOW PISA DIFFERS FROM EXISTING SYSTEMS (Prof's Q&A slide 2)
# ──────────────────────────────────────────────────────────────────────────────
s = prs.slides.add_slide(BLANK_LAYOUT)
add_bg(s)
slide_header(s, "How PISA Differs from Existing Systems",
             subtitle="Unique Contributions vs Current State of the Art", tag="Q&A")
footer(s)

diffs = [
    ("Single Portable Device vs Fragmented Toolset",
     "Existing: You need Nmap + Bettercap + RouterSploit + manual NVD lookup + Kismet — all running separately on a laptop. PISA: one RPi 4 device runs the entire pipeline from WiFi scanning to exploit recommendation autonomously.",
     ACCENT_CYAN, "vs Multi-tool manual\nworkflow (45+ mins)"),
    ("Both Network and Device Layers — First Time Together",
     "No existing tool, academic or commercial, integrates WiFi network vulnerability assessment (Layer 1) with IoT device fingerprinting and exploitation (Layer 2) in a single pipeline. PISA does this first.",
     ACCENT_GREEN, "vs Layer-isolated\ntools only"),
    ("WSPS — First Passive Beacon-Only Security Score",
     "Kismet/WiGLE capture raw data but score nothing. PISA's WSPS derives a quantitative A–F grade from beacon frames alone — no network join, no packet injection, no authentication needed.",
     ACCENT_ORANGE, "vs Raw data capture\nonly (Kismet)"),
    ("Protocol Behavioral Analysis vs Port Scanning",
     "Nmap tells you port 1883 is open. PISA connects via MQTT and analyzes topic hierarchy, CONNACK flags, QoS behavior, retained messages — to identify the exact device model. Same for CoAP, HTTP, RTSP.",
     YELLOW, "vs Nmap port list\nonly"),
    ("CVSS + EPSS + KEV vs CVSS Alone",
     "Every existing tool ranks CVEs by CVSS score alone. PISA uses Exploit Prediction Scoring System (EPSS, FIRST.org) + CISA KEV catalog to compute ExploitScore — prioritizing CVEs actually being exploited right now.",
     ACCENT_RED, "vs CVSS-only\nprioritization"),
]

for i, (title, body, color, vs) in enumerate(diffs):
    col = i % 2 if i < 4 else 0
    row = i // 2 if i < 4 else 2
    if i == 4:
        lx = Inches(0.45); W6 = Inches(12.43)
    else:
        lx = Inches(0.45) + col * Inches(6.35)
        W6 = Inches(6.1)
    ty = Inches(1.15) + row * Inches(1.02)
    H6 = Inches(0.95)
    add_rect(s, lx, ty, W6, H6, BG_CARD)
    add_rect(s, lx, ty, Inches(0.08), H6, color)
    add_textbox(s, title, lx+Inches(0.16), ty+Inches(0.06), W6-Inches(2.4), Inches(0.3),
                font_size=12, bold=True, color=color)
    add_textbox(s, vs, lx+W6-Inches(2.1), ty+Inches(0.06), Inches(2.0), Inches(0.34),
                font_size=9, color=ACCENT_RED, align=PP_ALIGN.RIGHT, italic=True)
    add_textbox(s, body, lx+Inches(0.16), ty+Inches(0.42), W6-Inches(0.25), Inches(0.48),
                font_size=10.5, color=GRAY_LIGHT)

# ──────────────────────────────────────────────────────────────────────────────
# SLIDE 17  —  REFERENCES
# ──────────────────────────────────────────────────────────────────────────────
s = prs.slides.add_slide(BLANK_LAYOUT)
add_bg(s)
slide_header(s, "References", subtitle="Key Academic Papers, Tools & Standards Cited", tag="08 / 08")
footer(s)

refs = [
    "[1]  M. Miettinen et al., \"IoT Sentinel: Automated Device-Type Identification for Security Enforcement in IoT,\" IEEE ICDCS, 2017.",
    "[2]  S. Marchal et al., \"AuDI: Toward Autonomous IoT Device-Type Identification Using Periodic Communication,\" IEEE TIFS, 2019.",
    "[3]  D. Bremler-Barr et al., \"SAFER: Security Audit Framework for Enterprise IoT,\" ACM CoNEXT, 2022.",
    "[4]  Y. Bai et al., \"DeviceRadar: Packet-Level IoT Device Identification on ISP Infrastructure,\" IEEE DSC, 2024.",
    "[5]  J. Jacobs et al., \"Exploit Prediction Scoring System (EPSS),\" FIRST.org, updated 2023.",
    "[6]  CISA, \"Known Exploited Vulnerabilities Catalog,\" U.S. Cybersecurity & Infrastructure Security Agency, 2021–present.",
    "[7]  R. Perdisci et al., \"IoT-Finder: Efficient Large-Scale Identification of IoT Devices via Passive DNS Traffic Analysis,\" IEEE EuroSP, 2020.",
    "[8]  NIST, \"NVD — National Vulnerability Database, NVD API v2.0,\" nvd.nist.gov, 2024.",
    "[9]  IEEE Std 802.11-2020, \"IEEE Standard for Information Technology — Wireless LAN MAC and PHY Specifications.\"",
    "[10] OASIS MQTT TC, \"MQTT Version 5.0,\" OASIS Standard, 2019.",
    "[11] Z. Shelby et al., \"The Constrained Application Protocol (CoAP),\" RFC 7252, IETF, 2014.",
    "[12] RouterSploit Framework, \"Exploitation Framework for Embedded Devices,\" github.com/threat9/routersploit.",
]

col1 = refs[:6]
col2 = refs[6:]

for i, ref in enumerate(col1):
    ty = Inches(1.18) + i * Inches(0.52)
    add_rect(s, Inches(0.45), ty, Inches(6.15), Inches(0.46), BG_CARD)
    add_rect(s, Inches(0.45), ty, Inches(0.05), Inches(0.46), ACCENT_CYAN)
    add_textbox(s, ref, Inches(0.58), ty+Inches(0.03), Inches(6.0), Inches(0.4),
                font_size=9.5, color=GRAY_LIGHT)

for i, ref in enumerate(col2):
    ty = Inches(1.18) + i * Inches(0.52)
    add_rect(s, Inches(6.78), ty, Inches(6.1), Inches(0.46), BG_CARD)
    add_rect(s, Inches(6.78), ty, Inches(0.05), Inches(0.46), ACCENT_GREEN)
    add_textbox(s, ref, Inches(6.9), ty+Inches(0.03), Inches(5.95), Inches(0.4),
                font_size=9.5, color=GRAY_LIGHT)

# note strip
add_rect(s, Inches(0.45), Inches(4.6), Inches(12.43), Inches(0.5), RGBColor(0x00,0x15,0x1F))
add_textbox(s,
    "Full bibliography of 60 research papers is maintained in /PISA Research Papers/ organized by module. "
    "19 additional UAV/Drone security papers in /Research Papers/ for comparative context.",
    Inches(0.6), Inches(4.65), Inches(12.1), Inches(0.38),
    font_size=10.5, color=GRAY_MED, italic=True)

# ──────────────────────────────────────────────────────────────────────────────
# SLIDE 18  —  THANK YOU / QUESTIONS
# ──────────────────────────────────────────────────────────────────────────────
s = prs.slides.add_slide(BLANK_LAYOUT)
add_bg(s)

for i in range(20):
    line = s.shapes.add_shape(1, 0, Inches(i*0.4), SLIDE_W, Inches(0.01))
    line.fill.solid(); line.fill.fore_color.rgb = RGBColor(0x14,0x1C,0x30)
    line.line.fill.background()

add_rect(s, 0, 0, SLIDE_W, Inches(0.1), ACCENT_CYAN)
add_rect(s, 0, 0, Inches(0.1), SLIDE_H, ACCENT_CYAN)

add_textbox(s, "Thank You", Inches(0.7), Inches(1.5), Inches(11.0), Inches(1.2),
            font_size=64, bold=True, color=WHITE, align=PP_ALIGN.CENTER)

add_rect(s, Inches(2.5), Inches(2.8), Inches(8.3), Inches(0.06), ACCENT_CYAN)

add_textbox(s, "PISA — Portable IoT Security Assessment Platform",
            Inches(0.7), Inches(3.05), Inches(11.0), Inches(0.5),
            font_size=22, bold=True, color=ACCENT_CYAN, align=PP_ALIGN.CENTER)

add_textbox(s, "Questions? Let's discuss any aspect of the system design, novelty claims, or implementation approach.",
            Inches(1.0), Inches(3.65), Inches(11.0), Inches(0.5),
            font_size=14, color=GRAY_LIGHT, align=PP_ALIGN.CENTER)

pills_bottom = [
    ("Vivek Reddy", ACCENT_CYAN),
    ("20CYS495 — FYP Phase 1", ACCENT_GREEN),
    ("Amrita School of Engineering", ACCENT_ORANGE),
    ("June 2026", YELLOW),
]
W7 = Inches(2.6)
GAP7 = Inches(0.2)
START7 = (SLIDE_W - (len(pills_bottom) * W7 + (len(pills_bottom)-1) * GAP7)) / 2
for i, (text, color) in enumerate(pills_bottom):
    lx = START7 + i * (W7 + GAP7)
    add_rect(s, lx, Inches(4.5), W7, Inches(0.5), BG_CARD)
    add_rect(s, lx, Inches(4.5), W7, Inches(0.05), color)
    add_textbox(s, text, lx+Inches(0.05), Inches(4.5), W7-Inches(0.08), Inches(0.5),
                font_size=13, bold=True, color=color, align=PP_ALIGN.CENTER)

# ──────────────────────────────────────────────────────────────────────────────
OUT = r"C:\Vivek's Workspace\Projects\Project Phase 1\PISA_Phase1_Review.pptx"
prs.save(OUT)
print(f"Saved: {OUT}")
print(f"Total slides: {len(prs.slides)}")
