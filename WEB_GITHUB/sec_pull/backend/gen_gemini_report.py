from gemini_utils import gemini_vulnerability_report
import datetime

with open("test.js", "r", encoding="utf-8") as f:
    code = f.read()

result = gemini_vulnerability_report(code)

report_text = result.get("gemini_report", str(result))

with open("test_gemini_report.txt", "w", encoding="utf-8") as out:
    out.write(report_text)

print("Report written to test_gemini_report.txt")
