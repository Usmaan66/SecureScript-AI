def get_vulnerability_metrics(code):
    metrics = {"risk": "High" if "SELECT * FROM users WHERE name = '" in code else "Low"}
    return metrics
