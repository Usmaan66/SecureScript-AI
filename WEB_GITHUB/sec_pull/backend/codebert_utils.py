def analyze_code_with_codebert(code):
    # Dummy CodeBERT analysis
    if "SELECT * FROM users WHERE name = '" in code:
        return {"summary": "Potential SQL injection found by CodeBERT."}
    return {"summary": "No major vulnerabilities detected by CodeBERT."}
