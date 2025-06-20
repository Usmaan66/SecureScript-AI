from fpdf import FPDF

with open("test_gemini_report.txt", "r", encoding="utf-8") as f:
    lines = f.readlines()

pdf = FPDF()
pdf.add_page()
pdf.set_font("Arial", size=11)

for line in lines:
    # FPDF only supports latin-1, so replace non-latin chars
    pdf.multi_cell(0, 8, line.encode('latin-1', 'replace').decode('latin-1').rstrip())

pdf.output("test_gemini_report.pdf")
print("PDF report generated: test_gemini_report.pdf")
