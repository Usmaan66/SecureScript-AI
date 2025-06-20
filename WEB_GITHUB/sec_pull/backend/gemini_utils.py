import requests
import datetime

GEMINI_API_KEY = "AIzaSyBCyziLzDy4RivfkJ3wyyrlIIjbOj-Mtdc"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=" + GEMINI_API_KEY

def ai_security_analysis(code):
    if "<script>" in code:
        return {"ai_warning": "Potential XSS detected by AI."}
    return {"ai_warning": "No major vulnerabilities detected by AI."}

def scan_url_with_gemini(url):
    try:
        resp = requests.get(url, timeout=5)
        code = resp.text
    except Exception as e:
        return {"error": f"Failed to fetch URL: {e}"}
    result = gemini_vulnerability_report(code)
    result["snippet"] = code[:200]
    return result

def gemini_vulnerability_report(code):
    prompt = f"""
You are a security code reviewer. Analyze the following code for vulnerabilities.\n\nFor each vulnerability, provide:\n- Type of vulnerability\n- Severity (low/medium/high/critical)\n- Code snippet or line number (if possible)\n- Description\n- Suggested fix\n\nFormat the report as a clear, itemized list.\n\nCODE:\n{code}\n"""
    headers = {"Content-Type": "application/json"}
    data = {
        "contents": [{"parts": [{"text": prompt}]}]
    }
    try:
        r = requests.post(GEMINI_API_URL, json=data, headers=headers, timeout=40)
        r.raise_for_status()
        resp = r.json()
        report = resp.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "No response")
        return {"gemini_report": report}
    except Exception as e:
        return {"error": f"Gemini API error: {e}"}
