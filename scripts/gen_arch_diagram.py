import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe

# ── Canvas ──────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(20, 11))
ax.set_xlim(0, 20)
ax.set_ylim(0, 11)
ax.axis('off')
fig.patch.set_facecolor('white')

# ── Palette ─────────────────────────────────────────────────────────────────
C_HDR   = '#1B3D6F'   # deep IEEE blue  – lane headers
C_SUB   = '#F5F8FC'   # near-white      – box fills
C_BDR   = '#8A9BB5'   # muted slate     – box borders
C_LANE  = '#EDF2F9'   # very light blue – lane body fill
C_TXT   = '#0D1B2A'   # near-black      – body text
C_HTXT  = '#FFFFFF'   # white           – header text
C_ARR   = '#3A5A8C'   # medium blue     – arrows
C_FTBG  = '#EDF2F9'   # footnote fill
C_FTBD  = '#8A9BB5'   # footnote border

# ── Layout constants ─────────────────────────────────────────────────────────
TITLE_Y   = 10.45
TOP       = 9.85
BOT       = 1.30
HDR_H     = 0.72
LANE_GAP  = 0.18
LW        = 0.8        # border linewidth

lane_defs = [
    # (x_start, width, header_text, items)
    (0.15, 2.90, "Hardware Layer",
     ["RPi 4 (4 GB)", "Alfa AWUS036ACM\n(MT7612U)", "NEO-6M GPS", "7″ DSI Touchscreen"]),

    (3.23, 3.60, "M0 · WiSentinel",
     ["Passive Beacon Capture", "WSPS Scorer  (A – F)", "OUI → CVE Correlation", "Handshake Capture"]),

    (7.01, 3.60, "M1–M2 · Discovery &\nFingerprinting",
     ["ARP Sweep + Nmap", "MQTT / CoAP /\nHTTP / RTSP Probers", "Cross-Protocol Fusion\n1 − ∏(1 − cᵢ)"]),

    (10.79, 3.60, "M3–M4 · Threat Engine",
     ["NVD v2.0 + EPSS + KEV", "Tri-Metric ExploitScore", "Priority Queue\nScheduler", "RouterSploit\nPipeline"]),

    (14.57, 5.28, "M5 · Reporting Layer",
     ["Flask UI  (SQLite, 9 tables)", "AWS S3 + Lambda PDF", "DynamoDB (6 tables)"]),
]

# ── Helper: wrap long header text ───────────────────────────────────────────
def draw_lane(ax, lx, lw, header, items):
    lane_h = TOP - BOT

    # Body fill
    body = mpatches.Rectangle((lx, BOT), lw, lane_h - HDR_H,
                               linewidth=LW, edgecolor=C_BDR, facecolor=C_LANE)
    ax.add_patch(body)

    # Header fill
    hdr = mpatches.Rectangle((lx, TOP - HDR_H), lw, HDR_H,
                              linewidth=LW, edgecolor=C_BDR, facecolor=C_HDR)
    ax.add_patch(hdr)

    # Full outer border on top of everything
    outer = mpatches.Rectangle((lx, BOT), lw, lane_h,
                                linewidth=LW, edgecolor=C_BDR, facecolor='none')
    ax.add_patch(outer)

    # Header text
    ax.text(lx + lw / 2, TOP - HDR_H / 2, header,
            ha='center', va='center', fontsize=9.5, fontweight='bold',
            color=C_HTXT, fontfamily='DejaVu Sans', linespacing=1.3,
            multialignment='center')

    # Item boxes
    body_h   = lane_h - HDR_H
    n        = len(items)
    slot_h   = body_h / n
    box_h    = slot_h * 0.60
    box_padx = 0.16
    box_w    = lw - 2 * box_padx

    for i, label in enumerate(items):
        by = BOT + (n - 1 - i) * slot_h + (slot_h - box_h) / 2
        bx = lx + box_padx
        box = mpatches.FancyBboxPatch(
            (bx, by), box_w, box_h,
            boxstyle="round,pad=0.04",
            linewidth=0.7, edgecolor=C_BDR, facecolor=C_SUB)
        ax.add_patch(box)
        ax.text(bx + box_w / 2, by + box_h / 2, label,
                ha='center', va='center', fontsize=8.2,
                color=C_TXT, fontfamily='DejaVu Sans', linespacing=1.25,
                multialignment='center')

# ── Draw lanes ───────────────────────────────────────────────────────────────
for lx, lw, hdr, items in lane_defs:
    draw_lane(ax, lx, lw, hdr, items)

# ── Arrows between lanes ─────────────────────────────────────────────────────
arrow_y = (TOP + BOT) / 2 - 0.1
for i in range(len(lane_defs) - 1):
    lx, lw, *_ = lane_defs[i]
    nx, *_     = lane_defs[i + 1]
    x0 = lx + lw
    x1 = nx
    ax.annotate(
        '', xy=(x1, arrow_y), xytext=(x0, arrow_y),
        arrowprops=dict(
            arrowstyle='->', color=C_ARR, lw=1.5,
            mutation_scale=14,
            connectionstyle='arc3,rad=0'))

# ── Title ────────────────────────────────────────────────────────────────────
ax.text(10, TITLE_Y, 'PISA System Architecture',
        ha='center', va='center', fontsize=16, fontweight='bold',
        color=C_TXT, fontfamily='DejaVu Sans',
        path_effects=[pe.withStroke(linewidth=0, foreground='white')])

# ── Authorization footnote bar ───────────────────────────────────────────────
fn_y = 0.12
fn_h = 0.82
fn_bar = mpatches.Rectangle((0.15, fn_y), 19.70, fn_h,
                              linewidth=0.7, edgecolor=C_FTBD, facecolor=C_FTBG)
ax.add_patch(fn_bar)
ax.text(10, fn_y + fn_h / 2,
        'Authorized Use Gate   |   India IT Act 2000 Compliant   |   5-Second Confirmation Window',
        ha='center', va='center', fontsize=8.8,
        color='#3A4A6A', fontfamily='DejaVu Sans', fontstyle='italic')

# ── Figure caption (below bar) ───────────────────────────────────────────────
fig.text(0.012, 0.005,
         'Fig. 1.  PISA five-layer pipeline: M0 performs passive WiFi intelligence; '
         'M1–M2 execute network discovery and protocol fingerprinting;\n'
         'M3–M4 provide threat intelligence and exploit automation; '
         'M5 handles cloud reporting and dashboard.',
         ha='left', va='bottom', fontsize=7.5, color='#3A3A3A',
         fontfamily='DejaVu Sans', fontstyle='italic', linespacing=1.4)

# ── Save ─────────────────────────────────────────────────────────────────────
out = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "docs", "diagrams",
    "PISA_Architecture_Diagram.png",
)
out = os.path.abspath(out)
plt.savefig(out, dpi=220, bbox_inches='tight', facecolor='white', pad_inches=0.15)
print(f"Saved: {out}")
