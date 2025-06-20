from fpdf import FPDF

pdf = FPDF()
pdf.add_page()
pdf.set_font("Courier", size=10)

with open("test.js", "r", encoding="utf-8") as f:
    for line in f:
        # FPDF only supports latin-1, so replace non-latin chars
        pdf.cell(0, 8, line.encode('latin-1', 'replace').decode('latin-1').rstrip(), ln=1)

pdf.output("test_js_code.pdf")
