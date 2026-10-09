"""
Reusable python-docx engine implementing the Amrita School of Computing
Project-Report formatting rules (see Report/Guidlines_Images):

  - A4 page, 1" margins all sides
  - Chapter heading : TNR 14pt, bold, ALL CAPS, centred
  - Division heading : TNR 12pt, bold, ALL CAPS, left
  - Sub-division heading : TNR 12pt, bold, Capitalize Each Word, left
  - Running text : TNR 12pt, sentence case, justify, 1.5 line spacing,
                    first line indented 1 cm
  - Table caption ABOVE the table, centred, "Table <chapter>.<n>: Title"
  - Figure caption BELOW the figure, centred, "Figure <chapter>.<n>: Title"
  - Front matter numbered lower-roman (i, ii, iii ...); chapters restart at
    Arabic 1
  - All figures/tables centred
"""
import os
from docx import Document
from docx.shared import Pt, Mm, Cm, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.section import WD_SECTION
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

FONT = "Times New Roman"


# --------------------------------------------------------------------------
# low-level oxml helpers
# --------------------------------------------------------------------------

def _set_run_font(run, name=FONT):
    run.font.name = name
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn('w:rFonts'))
    if rfonts is None:
        rfonts = OxmlElement('w:rFonts')
        rpr.append(rfonts)
    for attr in ('w:ascii', 'w:hAnsi', 'w:eastAsia', 'w:cs'):
        rfonts.set(qn(attr), name)


def add_bookmark(paragraph, name, bm_id):
    start = OxmlElement('w:bookmarkStart')
    start.set(qn('w:id'), str(bm_id))
    start.set(qn('w:name'), name)
    end = OxmlElement('w:bookmarkEnd')
    end.set(qn('w:id'), str(bm_id))
    paragraph._p.insert(0, start)
    paragraph._p.append(end)


def insert_field(paragraph, field_code, result_text="1", bold=False):
    """Insert a real Word field (e.g. ' PAGE ') with a cached result."""
    run = paragraph.add_run()
    _set_run_font(run)
    run.bold = bold
    fld_begin = OxmlElement('w:fldChar')
    fld_begin.set(qn('w:fldCharType'), 'begin')
    run._r.append(fld_begin)

    run2 = paragraph.add_run()
    _set_run_font(run2)
    run2.bold = bold
    instr = OxmlElement('w:instrText')
    instr.set(qn('xml:space'), 'preserve')
    instr.text = f' {field_code} '
    run2._r.append(instr)

    run3 = paragraph.add_run()
    _set_run_font(run3)
    run3.bold = bold
    sep = OxmlElement('w:fldChar')
    sep.set(qn('w:fldCharType'), 'separate')
    run3._r.append(sep)

    run4 = paragraph.add_run(result_text)
    _set_run_font(run4)
    run4.bold = bold

    run5 = paragraph.add_run()
    _set_run_font(run5)
    run5.bold = bold
    end = OxmlElement('w:fldChar')
    end.set(qn('w:fldCharType'), 'end')
    run5._r.append(end)


def set_page_number_format(section, fmt, start=None):
    sect_pr = section._sectPr
    pg_num_type = sect_pr.find(qn('w:pgNumType'))
    if pg_num_type is None:
        pg_num_type = OxmlElement('w:pgNumType')
        sect_pr.append(pg_num_type)
    pg_num_type.set(qn('w:fmt'), fmt)
    if start is not None:
        pg_num_type.set(qn('w:start'), str(start))


def add_centered_page_number_footer(section):
    footer = section.footer
    footer.is_linked_to_previous = False
    p = footer.paragraphs[0] if footer.paragraphs else footer.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    for r in list(p.runs):
        r.text = ""
    insert_field(p, 'PAGE', '1')


# --------------------------------------------------------------------------
# Registry — accumulates TOC / List-of-Tables / List-of-Figures entries
# --------------------------------------------------------------------------

class Registry:
    def __init__(self):
        self.toc = []      # dict(level, number, title, bookmark)
        self.tables = []   # dict(number, title, bookmark)
        self.figures = []  # dict(number, title, bookmark)
        self._bm_id = 1000
        self._chapter_table_seq = {}
        self._chapter_figure_seq = {}

    def next_bm_id(self):
        self._bm_id += 1
        return self._bm_id

    def next_table_number(self, chapter):
        n = self._chapter_table_seq.get(chapter, 0) + 1
        self._chapter_table_seq[chapter] = n
        return f"{chapter}.{n}"

    def next_figure_number(self, chapter):
        n = self._chapter_figure_seq.get(chapter, 0) + 1
        self._chapter_figure_seq[chapter] = n
        return f"{chapter}.{n}"


# --------------------------------------------------------------------------
# Document setup
# --------------------------------------------------------------------------

def new_document():
    doc = Document()
    section = doc.sections[0]
    section.page_width = Mm(210)
    section.page_height = Mm(297)
    section.top_margin = Inches(1)
    section.bottom_margin = Inches(1)
    section.left_margin = Inches(1)
    section.right_margin = Inches(1)

    normal = doc.styles['Normal']
    normal.font.name = FONT
    normal.font.size = Pt(12)
    rpr = normal.element.get_or_add_rPr()
    rfonts = rpr.find(qn('w:rFonts'))
    if rfonts is None:
        rfonts = OxmlElement('w:rFonts')
        rpr.append(rfonts)
    for attr in ('w:ascii', 'w:hAnsi', 'w:eastAsia', 'w:cs'):
        rfonts.set(qn(attr), FONT)
    normal.paragraph_format.space_after = Pt(0)

    return doc, section


# --------------------------------------------------------------------------
# Heading / paragraph builders
# --------------------------------------------------------------------------

def add_chapter(doc, registry, number, title, page_break_before=True):
    p = doc.add_paragraph()
    if page_break_before:
        p.paragraph_format.page_break_before = True
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(6)
    r1 = p.add_run(f"CHAPTER {number}")
    _set_run_font(r1)
    r1.bold = True
    r1.font.size = Pt(14)
    r1.add_break()
    r2 = p.add_run(title.upper())
    _set_run_font(r2)
    r2.bold = True
    r2.font.size = Pt(14)
    p.paragraph_format.line_spacing_rule = WD_LINE_SPACING.ONE_POINT_FIVE

    bm = f"BK_CH{number}"
    add_bookmark(p, bm, registry.next_bm_id())
    registry.toc.append(dict(level=1, number=str(number), title=title.upper(), bookmark=bm))
    return p


def add_major_heading(doc, registry, title, bookmark):
    """REFERENCES / APPENDICES — same visual weight as a chapter heading but
    with no 'CHAPTER N' prefix and no chapter number of its own."""
    p = doc.add_paragraph()
    p.paragraph_format.page_break_before = True
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(14)
    r = p.add_run(title.upper())
    _set_run_font(r)
    r.bold = True
    r.font.size = Pt(14)
    add_bookmark(p, bookmark, registry.next_bm_id())
    registry.toc.append(dict(level=1, number="", title=title.upper(), bookmark=bookmark))
    return p


def add_appendix_heading(doc, registry, letter, title):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p.paragraph_format.space_before = Pt(14)
    p.paragraph_format.space_after = Pt(6)
    r = p.add_run(f"APPENDIX {letter} — {title.upper()}")
    _set_run_font(r)
    r.bold = True
    r.font.size = Pt(12)
    bm = f"BK_APPX_{letter}"
    add_bookmark(p, bm, registry.next_bm_id())
    registry.toc.append(dict(level=2, number=f"App. {letter}", title=title.upper(), bookmark=bm))
    return p


def add_division(doc, registry, chapter, div, title):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p.paragraph_format.space_before = Pt(14)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.keep_with_next = True
    number = f"{chapter}.{div}"
    r = p.add_run(f"{number} {title.upper()}")
    _set_run_font(r)
    r.bold = True
    r.font.size = Pt(12)

    bm = f"BK_DIV{chapter}_{div}"
    add_bookmark(p, bm, registry.next_bm_id())
    registry.toc.append(dict(level=2, number=number, title=title.upper(), bookmark=bm))
    return p


def add_subdivision(doc, registry, chapter, div, sub, title):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p.paragraph_format.space_before = Pt(10)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.keep_with_next = True
    number = f"{chapter}.{div}.{sub}"
    r = p.add_run(f"{number} {title}")
    _set_run_font(r)
    r.bold = True
    r.font.size = Pt(12)

    bm = f"BK_SUB{chapter}_{div}_{sub}"
    add_bookmark(p, bm, registry.next_bm_id())
    registry.toc.append(dict(level=3, number=number, title=title, bookmark=bm))
    return p


def add_para(doc, text, indent=True, space_after=8, align=None):
    p = doc.add_paragraph()
    p.paragraph_format.line_spacing_rule = WD_LINE_SPACING.ONE_POINT_FIVE
    p.paragraph_format.space_after = Pt(space_after)
    p.alignment = align if align is not None else WD_ALIGN_PARAGRAPH.JUSTIFY
    if indent:
        p.paragraph_format.first_line_indent = Cm(1)
    _add_runs_with_inline_bold(p, text)
    return p


def _add_runs_with_inline_bold(paragraph, text):
    """Very small helper: supports **bold** and *italic* inline markers."""
    import re
    tokens = re.split(r'(\*\*[^*]+\*\*|\*[^*]+\*)', text)
    for tok in tokens:
        if not tok:
            continue
        if tok.startswith('**') and tok.endswith('**'):
            run = paragraph.add_run(tok[2:-2])
            run.bold = True
        elif tok.startswith('*') and tok.endswith('*'):
            run = paragraph.add_run(tok[1:-1])
            run.italic = True
        else:
            run = paragraph.add_run(tok)
        _set_run_font(run)
        run.font.size = Pt(12)


def add_bullet(doc, text, level=0):
    p = doc.add_paragraph(style='List Bullet')
    p.paragraph_format.line_spacing_rule = WD_LINE_SPACING.ONE_POINT_FIVE
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.left_indent = Cm(1 + 0.6 * level)
    for r in list(p.runs):
        p._p.remove(r._r)
    _add_runs_with_inline_bold(p, text)
    return p


# --------------------------------------------------------------------------
# Tables & figures (centred; caption above table / below figure)
# --------------------------------------------------------------------------

def _style_cell_text(cell, text, bold=False, size=12, align=WD_ALIGN_PARAGRAPH.LEFT):
    cell.text = ""
    p = cell.paragraphs[0]
    p.alignment = align
    p.paragraph_format.space_after = Pt(2)
    r = p.add_run(str(text))
    _set_run_font(r)
    r.bold = bold
    r.font.size = Pt(size)


def add_table_caption(doc, registry, chapter, title, bookmark_prefix="BK_TBL"):
    number = registry.next_table_number(chapter)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(10)
    p.paragraph_format.space_after = Pt(4)
    r = p.add_run(f"Table {number}: {title}")
    _set_run_font(r)
    r.bold = True
    r.font.size = Pt(12)
    bm = f"{bookmark_prefix}{number.replace('.', '_')}"
    add_bookmark(p, bm, registry.next_bm_id())
    registry.tables.append(dict(number=number, title=title, bookmark=bm))
    return number


def add_table(doc, rows, header=True, widths=None, font_size=11):
    n_rows = len(rows)
    n_cols = len(rows[0])
    table = doc.add_table(rows=n_rows, cols=n_cols)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.style = 'Table Grid'
    for ri, row in enumerate(rows):
        for ci, val in enumerate(row):
            cell = table.cell(ri, ci)
            is_header = header and ri == 0
            _style_cell_text(
                cell, val, bold=is_header, size=font_size,
                align=WD_ALIGN_PARAGRAPH.CENTER if is_header else WD_ALIGN_PARAGRAPH.LEFT,
            )
    if widths:
        for ci, w in enumerate(widths):
            for ri in range(n_rows):
                table.cell(ri, ci).width = Inches(w)
    # centre the table block itself
    tbl_pr = table._tbl.tblPr
    jc = OxmlElement('w:jc')
    jc.set(qn('w:val'), 'center')
    tbl_pr.append(jc)
    return table


def add_table_with_caption(doc, registry, chapter, title, rows, widths=None, font_size=11):
    number = add_table_caption(doc, registry, chapter, title)
    add_table(doc, rows, widths=widths, font_size=font_size)
    spacer = doc.add_paragraph()
    spacer.paragraph_format.space_after = Pt(8)
    return number


def add_figure_with_caption(doc, registry, chapter, title, image_path, width=5.8):
    number = registry.next_figure_number(chapter)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(10)
    if os.path.exists(image_path):
        run = p.add_run()
        run.add_picture(image_path, width=Inches(width))
    else:
        run = p.add_run(f"[missing image: {image_path}]")
        _set_run_font(run)

    cap = doc.add_paragraph()
    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cap.paragraph_format.space_after = Pt(10)
    r = cap.add_run(f"Figure {number}: {title}")
    _set_run_font(r)
    r.bold = True
    r.font.size = Pt(12)
    bm = f"BK_FIG{number.replace('.', '_')}"
    add_bookmark(cap, bm, registry.next_bm_id())
    registry.figures.append(dict(number=number, title=title, bookmark=bm))
    return number


def add_reference(doc, number, text):
    p = doc.add_paragraph()
    p.paragraph_format.line_spacing_rule = WD_LINE_SPACING.ONE_POINT_FIVE
    p.paragraph_format.space_after = Pt(8)
    p.paragraph_format.left_indent = Cm(1.0)
    p.paragraph_format.first_line_indent = Cm(-1.0)
    r = p.add_run(f"[{number}] ")
    _set_run_font(r)
    _add_runs_with_inline_bold(p, text)
    return p


def page_ref_placeholder(cell, bookmark_name, align=WD_ALIGN_PARAGRAPH.CENTER, size=12):
    """Write a {{BOOKMARK}} sentinel into a table cell, resolved to a real
    page number later by apply_page_numbers() once Word has paginated the
    document for real."""
    cell.text = ""
    p = cell.paragraphs[0]
    p.alignment = align
    r = p.add_run(f"{{{{{bookmark_name}}}}}")
    _set_run_font(r)
    r.font.size = Pt(size)


def apply_page_numbers(docx_path, pages, out_path):
    """Pass-2: reopen a built docx and replace every {{BK_...}} sentinel run
    with the real page number resolved via Word COM (resolve_pages.py)."""
    import re
    doc = Document(docx_path)
    pattern = re.compile(r'^\{\{(BK_[A-Za-z0-9_]+)\}\}$')

    def _walk_tables(tables):
        for t in tables:
            for row in t.rows:
                for cell in row.cells:
                    for p in cell.paragraphs:
                        for r in p.runs:
                            m = pattern.match(r.text.strip())
                            if m:
                                name = m.group(1)
                                r.text = str(pages.get(name, '?'))
                    for nested in cell.tables:
                        _walk_tables([nested])

    _walk_tables(doc.tables)
    doc.save(out_path)
    return out_path


def add_new_section(doc, page_break=True):
    """Start a new section on a new page (used for the roman->arabic split)."""
    new_sec = doc.add_section(WD_SECTION.NEW_PAGE if page_break else WD_SECTION.CONTINUOUS)
    return new_sec


# --------------------------------------------------------------------------
# Front-matter-first assembly
#
# Content is authored in build order (chapters -> front matter, because the
# front matter's TOC/List-of-Tables/List-of-Figures/List-of-Symbols need the
# registry populated by the chapters first). These two helpers then (a) move
# the front-matter block to the physical start of the document, and (b)
# split the single implicit section into two: section 1 = front matter,
# numbered lower-roman; section 2 = chapters onward, numbered decimal
# restarting at 1 — exactly matching the specimens (Title=i ... TOC=vi,
# Chapter 1 Introduction=1).
# --------------------------------------------------------------------------

def mark_front_matter_start(doc):
    """Call once, right after chapters/refs/appendices are fully built and
    BEFORE front-matter content is added. Returns an index to pass to
    reorder_front_matter_first()."""
    return len(doc.element.body) - 1  # position just before the trailing sectPr


def reorder_front_matter_first(doc, front_matter_start_index):
    body = doc.element.body
    children = list(body)
    sect_pr = children[-1]
    chapter_elements = children[0:front_matter_start_index]
    front_matter_elements = children[front_matter_start_index:-1]
    for el in children[:-1]:
        body.remove(el)
    for el in front_matter_elements:
        sect_pr.addprevious(el)
    for el in chapter_elements:
        sect_pr.addprevious(el)


def split_front_matter_section(doc, boundary_paragraph):
    """Insert a section break at the end of `boundary_paragraph` (the last
    paragraph of the front matter block), turning it into section 1
    (front matter) with the document's existing trailing sectPr becoming
    section 2 (chapters). Returns (front_matter_sectPr, body_sectPr)."""
    import copy
    body = doc.element.body
    trailing_sect_pr = body.find(qn('w:sectPr'))
    front_sect_pr = copy.deepcopy(trailing_sect_pr)
    # strip any leftover pgNumType/footer refs so we set them fresh below
    for tag in ('w:pgNumType',):
        el = front_sect_pr.find(qn(tag))
        if el is not None:
            front_sect_pr.remove(el)
    pPr = boundary_paragraph._p.get_or_add_pPr()
    pPr.append(front_sect_pr)
    return front_sect_pr, trailing_sect_pr


def finalize_layout(doc, front_matter_start_index, boundary_paragraph):
    """Full pipeline: reorder front matter to the start, split into two
    sections, number them (i, ii, iii ... / 1, 2, 3 ...), and add centred
    page-number footers to both. Returns (front_section, body_section)."""
    reorder_front_matter_first(doc, front_matter_start_index)
    front_sect_pr, _ = split_front_matter_section(doc, boundary_paragraph)

    # re-read sections now that the xml has two sectPr elements
    front_section = doc.sections[0]
    body_section = doc.sections[1]

    set_page_number_format(front_section, 'lowerRoman', start=1)
    set_page_number_format(body_section, 'decimal', start=1)

    for s in (front_section, body_section):
        add_centered_page_number_footer(s)

    return front_section, body_section
