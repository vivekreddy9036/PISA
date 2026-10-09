import os, sys
import win32com.client as win32

WD_EXPORT_FORMAT_PDF = 17

src = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "PISA_Project_Phase1_Report.docx"))
dst = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "PISA_Project_Phase1_Report.pdf"))

word = win32.gencache.EnsureDispatch('Word.Application')
word.Visible = False
word.DisplayAlerts = 0
doc = word.Documents.Open(src)
doc.ExportAsFixedFormat(OutputFileName=dst, ExportFormat=WD_EXPORT_FORMAT_PDF)
doc.Close(SaveChanges=0)
word.Quit()
print("exported:", dst)
