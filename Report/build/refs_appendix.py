from report_engine import add_major_heading, add_para, add_reference, add_appendix_heading, add_bullet
from refs_data import REFERENCES


def build(doc, registry):
    add_major_heading(doc, registry, "References", "BK_REFERENCES")
    add_para(doc, (
        "The following references are listed in alphabetical order of the first author's surname, "
        "as required by the project report format guidelines. In-text citations throughout this "
        "report refer to these numbers in square brackets."
    ), indent=False)
    for r in REFERENCES:
        add_reference(doc, r["n"], r["text"])

    add_major_heading(doc, registry, "Appendices", "BK_APPENDICES")

    add_appendix_heading(doc, registry, "A", "Plagiarism Report")
    add_para(doc, (
        "A similarity/plagiarism report for this project report, generated through the college's "
        "approved plagiarism-detection tool, is to be inserted at this appendix prior to final "
        "submission, in accordance with the School's plagiarism policy stated in the project report "
        "preparation guidelines."
    ))

    add_appendix_heading(doc, registry, "B", "Repository and Documentation Index")
    add_para(doc, (
        "The complete source code, automated test suite, and underlying project documentation this "
        "report is based on are maintained in the project's version-controlled repository. Table "
        "references, figures, and all status claims made in Chapters 4 and 5 trace to the following "
        "source documents within it:"
    ), indent=False)
    add_bullet(doc, "`README.md` — current module implementation status and operating instructions")
    add_bullet(doc, "`docs/PISA_SRS.md` — formal Software Requirements Specification (IEEE 830-1998)")
    add_bullet(doc, "`docs/FYP_PROJECT_DOCUMENTATION.md` — full research motivation, novelty claims, and system design")
    add_bullet(doc, "`docs/PISA_Review1_Report.md` — real-hardware validation results reported in Chapter 5")
    add_bullet(doc, "`docs/papers/PAPERS_INDEX.md` and `docs/papers/LITERATURE_SURVEY_NOTES.md` — the twenty-paper literature base reviewed in Chapter 2")
    add_bullet(doc, "`docs/diagrams/` — source architecture and module diagrams reproduced as Figures 4.1 and 4.2")
    add_bullet(doc, "`tests/` — the 381-test automated suite summarized in Section 5.3")
