"""
Open a .docx in MS Word via COM, force full repagination, resolve the page
number of every named bookmark, and (optionally) write the result out as a
JSON sidecar. Also returns total page count.

Usage: python resolve_pages.py <path-to-docx> [out.json]
"""
import sys, json, os
import win32com.client as win32

WD_ACTIVE_END_PAGE_NUMBER = 1  # wdActiveEndAdjustedPageNumber — respects section restart/format
WD_NUMBER_OF_PAGES = 2  # wdStatisticPages for ComputeStatistics


def resolve(docx_path):
    docx_path = os.path.abspath(docx_path)
    word = win32.gencache.EnsureDispatch('Word.Application')
    word.Visible = False
    word.DisplayAlerts = 0
    try:
        doc = word.Documents.Open(docx_path)
        try:
            doc.Repaginate()
        except Exception:
            pass
        doc.Fields.Update()

        pages = {}
        for bm in doc.Bookmarks:
            name = bm.Name
            try:
                page_no = bm.Range.Information(WD_ACTIVE_END_PAGE_NUMBER)
            except Exception:
                page_no = None
            pages[name] = page_no

        total_pages = doc.ComputeStatistics(WD_NUMBER_OF_PAGES)
        doc.Close(SaveChanges=0)
        return pages, total_pages
    finally:
        word.Quit()


if __name__ == '__main__':
    path = sys.argv[1]
    pages, total = resolve(path)
    print("TOTAL PAGES:", total)
    for k, v in pages.items():
        print(f"{k:20s} -> {v}")
    if len(sys.argv) > 2:
        with open(sys.argv[2], 'w') as f:
            json.dump({"pages": pages, "total_pages": total}, f, indent=2)
