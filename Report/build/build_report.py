import sys, os, json, subprocess
sys.path.insert(0, os.path.dirname(__file__))

from report_engine import (
    new_document, Registry, mark_front_matter_start, finalize_layout, apply_page_numbers,
)
import ch1, ch2, ch3, ch4, ch5, ch6, refs_appendix, front_matter

OUT_DIR = os.path.dirname(__file__)
PASS1 = os.path.join(OUT_DIR, "PISA_Report_pass1.docx")
PAGES_JSON = os.path.join(OUT_DIR, "pages.json")
FINAL = os.path.join(OUT_DIR, "..", "PISA_Project_Phase1_Report.docx")


def main():
    doc, section = new_document()
    registry = Registry()

    for m in (ch1, ch2, ch3, ch4, ch5, ch6, refs_appendix):
        m.build(doc, registry)

    fm_start = mark_front_matter_start(doc)
    front_matter.build(doc, registry)
    boundary = doc.add_paragraph()

    finalize_layout(doc, fm_start, boundary)

    doc.save(PASS1)
    print("pass1 saved:", PASS1)
    print("toc entries:", len(registry.toc), "tables:", len(registry.tables), "figures:", len(registry.figures))

    # resolve real page numbers via Word COM
    subprocess.run([sys.executable, os.path.join(OUT_DIR, "resolve_pages.py"), PASS1, PAGES_JSON], check=True)
    with open(PAGES_JSON) as f:
        data = json.load(f)

    apply_page_numbers(PASS1, data["pages"], FINAL)
    print("final saved:", os.path.abspath(FINAL))
    print("total pages:", data["total_pages"])


if __name__ == "__main__":
    main()
