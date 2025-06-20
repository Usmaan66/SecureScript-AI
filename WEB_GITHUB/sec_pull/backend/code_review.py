# Save as api_server.py in your backend folder
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import requests
import re
from urllib.parse import urlparse
import html
import logging
from starlette.status import HTTP_429_TOO_MANY_REQUESTS
import time
from collections import defaultdict
from fastapi.responses import StreamingResponse
from fpdf import FPDF
import io

# Set up proper logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("code_review.log"), logging.StreamHandler()]
)
logger = logging.getLogger("api_server")

# Rate limiting implementation
class RateLimiter:
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.requests = defaultdict(list)
    
    def is_rate_limited(self, client_ip: str) -> bool:
        current_time = time.time()
        # Remove requests older than 1 minute
        self.requests[client_ip] = [req_time for req_time in self.requests[client_ip] 
                                  if current_time - req_time < 60]
        # Check if client exceeded rate limit
        if len(self.requests[client_ip]) >= self.requests_per_minute:
            return True
        
        # Add current request timestamp
        self.requests[client_ip].append(current_time)
        return False

rate_limiter = RateLimiter()

def get_client_ip(request: Request):
    # Get client IP for rate limiting
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0]
    return request.client.host

app = FastAPI()

# CORS - Allow all origins for testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with specific origins in production
    allow_credentials=True,
    allow_methods=["*"],  # Only allow necessary methods in production
    allow_headers=["*"],
)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = get_client_ip(request)
    
    # Check rate limit
    if rate_limiter.is_rate_limited(client_ip):
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        return HTTPException(
            status_code=HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )
    
    # Process the request
    response = await call_next(request)
    return response

@app.post("/predict")
async def predict(request: Request):
    client_ip = get_client_ip(request)
    logger.info(f"Predict request from IP: {client_ip}")
    
    data = await request.json()
    code = data.get("code", "")
    
    # Input validation
    if not code:
        return {"error": "No code provided"}
    
    if len(code) > 100000:  # Limit code size to prevent DoS
        return {"error": "Code exceeds maximum allowed length"}
    
    # Call your code review/model logic here and return results!
    vulnerabilities = []
    fix = None
    
    # Example vulnerability check
    if "execute(" in code and "%" in code:
        vulnerabilities.append("Possible SQL Injection detected.")
        fix = code.replace("%s", "?")
    
    # Additional checks for code security
    if "eval(" in code:
        vulnerabilities.append("Use of eval() detected (potentially unsafe).")
    
    if "os.system(" in code or "subprocess" in code:
        vulnerabilities.append("Command execution detected (potential RCE risk).")
    
    if "__import__(" in code:
        vulnerabilities.append("Dynamic import detected (potential security risk).")
    
    if "open(" in code and ("w" in code or "a" in code):
        vulnerabilities.append("File write operation detected (potential file system risk).")
    
    # Simple check for potential XSS vulnerabilities
    if ("<script>" in code.lower() and "http" in code.lower()) or "document.write" in code.lower():
        vulnerabilities.append("Potential XSS vulnerability detected.")
    
    # Check for hardcoded credentials
    if re.search(r"password\s*=|api_key\s*=|secret\s*=", code, re.IGNORECASE):
        vulnerabilities.append("Potential hardcoded credentials detected.")
    
    # Check for SQL query string building without parameterization
    if re.search(r"SELECT.*WHERE.*\+", code) or re.search(r"INSERT.*VALUES.*\+", code):
        vulnerabilities.append("SQL query built with string concatenation (SQL injection risk).")
    
    # Log the results
    if vulnerabilities:
        logger.warning(f"Vulnerabilities found in code submission from {client_ip}: {vulnerabilities}")
    
    return {"vulnerabilities": vulnerabilities, "fix": fix}

@app.post("/scan_url")
async def scan_url(request: Request):
    client_ip = get_client_ip(request)
    
    data = await request.json()
    url = data.get("url", "")
    
    if not url:
        return {"error": "No URL provided."}
    
    # Validate URL
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return {"error": "Invalid URL format"}
        
        # Block internal/private networks
        if parsed.hostname in ('localhost', '127.0.0.1') or \
           parsed.hostname.startswith('192.168.') or \
           parsed.hostname.startswith('10.') or \
           parsed.hostname.startswith('172.'):
            return {"error": "Access to internal networks not allowed"}
        
    except Exception:
        return {"error": "Invalid URL format"}
    
    logger.info(f"URL scan request for {url} from IP: {client_ip}")
    
    try:
        # Set up timeouts and limits for the request
        session = requests.Session()
        session.max_redirects = 5  # Limit redirects to prevent redirect loops
        
        headers = {
            'User-Agent': 'SecurityScanner/1.0',  # Identify your scanner
            'Accept': 'text/html,application/xhtml+xml',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        
        resp = session.get(
            url, 
            timeout=10,
            headers=headers,
            verify=True,  # Force SSL verification
            stream=True  # Stream response to limit memory usage
        )
        
        # Limit content size to prevent memory issues
        content_size_limit = 5 * 1024 * 1024  # 5 MB
        content = ""
        bytes_read = 0
        
        for chunk in resp.iter_content(chunk_size=8192, decode_unicode=True):
            if chunk:
                content += chunk
                bytes_read += len(chunk)
                if bytes_read > content_size_limit:
                    raise Exception("Response too large, aborting scan")
        
        # Perform security checks
        vulnerabilities = []
        
        # Check for inline <script> tags
        if "<script>" in content:
            vulnerabilities.append("Inline <script> tag found (possible XSS risk).")
        
        # Check for use of eval()
        if "eval(" in content:
            vulnerabilities.append("Possible use of eval() in client-side JS (dangerous).")
        
        # Check for forms without CSRF token
        forms = re.findall(r'<form.*?>', content, re.IGNORECASE)
        for form in forms:
            if 'csrf' not in form.lower():
                vulnerabilities.append("Form without CSRF token detected.")
        
        # Check for input fields of type password without autocomplete=off
        password_inputs = re.findall(r'<input[^>]*type=["\']password["\'][^>]*>', content, re.IGNORECASE)
        for inp in password_inputs:
            if 'autocomplete="off"' not in inp.lower():
                vulnerabilities.append("Password input without autocomplete=off.")
        
        # Check for http links (mixed content)
        if 'http://' in content and not url.startswith('http://'):
            vulnerabilities.append("Page contains insecure http:// links (mixed content).")
        
        # Check for suspicious JavaScript event handlers
        if re.search(r'onerror\s*=|onload\s*=', content, re.IGNORECASE):
            vulnerabilities.append("Suspicious JS event handlers (onerror/onload) detected.")
        
        # Check for server disclosure in headers
        server_header = resp.headers.get('Server')
        if server_header:
            vulnerabilities.append(f"Server header disclosed: {server_header}")
        
        # Additional checks for Content-Security-Policy
        if 'Content-Security-Policy' not in resp.headers:
            vulnerabilities.append("No Content-Security-Policy header detected.")
        
        # Check for X-Frame-Options header
        if 'X-Frame-Options' not in resp.headers:
            vulnerabilities.append("No X-Frame-Options header detected (clickjacking risk).")
        
        # Check for Strict-Transport-Security header on HTTPS sites
        if url.startswith('https://') and 'Strict-Transport-Security' not in resp.headers:
            vulnerabilities.append("No Strict-Transport-Security header on HTTPS site.")

        # Check for potential CORS misconfigurations
        access_control_allow_origin = resp.headers.get('Access-Control-Allow-Origin')
        if access_control_allow_origin == '*':
            vulnerabilities.append("Wildcard CORS policy detected (Access-Control-Allow-Origin: *).")
            
        # Check for potentially sensitive information in HTML comments
        if re.search(r'<!--.*password.*-->', content, re.IGNORECASE) or \
           re.search(r'<!--.*api[_\s]?key.*-->', content, re.IGNORECASE) or \
           re.search(r'<!--.*secret.*-->', content, re.IGNORECASE):
            vulnerabilities.append("Potential sensitive information in HTML comments.")
            
        # Check for vulnerable JS libraries
        # This is a simple check - in production you'd want a more comprehensive database
        if 'jquery-1.' in content or 'jquery-2.0' in content:
            vulnerabilities.append("Outdated jQuery version detected (potentially vulnerable).")
            
        # Log results
        if vulnerabilities:
            logger.warning(f"Vulnerabilities found for URL {url} scanned from {client_ip}: {vulnerabilities}")
        
        return {
            "url": url, 
            "vulnerabilities": vulnerabilities, 
            "report": "Scan completed.",
            "status_code": resp.status_code
        }
    
    except requests.exceptions.SSLError:
        logger.error(f"SSL verification failed for URL {url} from {client_ip}")
        return {"error": "SSL verification failed. The site might have an invalid certificate."}
    
    except requests.exceptions.Timeout:
        logger.error(f"Timeout occurred when scanning URL {url} from {client_ip}")
        return {"error": "Request timed out. The site might be slow or unavailable."}
    
    except requests.exceptions.ConnectionError:
        logger.error(f"Connection error for URL {url} from {client_ip}")
        return {"error": "Failed to establish a connection to the target."}
    
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error scanning URL {url} from {client_ip}: {error_msg}")
        # Sanitize error messages to prevent information disclosure
        safe_error = html.escape(error_msg)
        return {"error": f"Error processing URL: {safe_error}"}

# New API endpoint for testing with Gemini integration
@app.post("/gemini_analyze")
async def gemini_analyze(request: Request):
    client_ip = get_client_ip(request)
    logger.info(f"Gemini analysis request from IP: {client_ip}")
    
    data = await request.json()
    code = data.get("code", "")
    
    if not code:
        return {"error": "No code provided"}
    
    if len(code) > 100000:
        return {"error": "Code exceeds maximum allowed length"}
    
    # Here you would integrate with Gemini API
    # This is a placeholder - replace with actual Gemini API integration
    
    # Mock response for now
    return {
        "analysis": "Gemini analysis would appear here. Replace this with your actual Gemini API integration.",
        "vulnerabilities": [
            "This is a placeholder. Connect to Gemini API for real analysis."
        ],
        "recommendations": [
            "Implement proper Gemini API integration",
            "Pass the code to Gemini for analysis",
            "Process and return the Gemini response"
        ]
    }

# New endpoint for comprehensive scanning that combines multiple analysis methods
@app.post("/comprehensive_scan")
async def comprehensive_scan(request: Request):
    client_ip = get_client_ip(request)
    logger.info(f"Comprehensive scan request from IP: {client_ip}")
    
    data = await request.json()
    code = data.get("code", "")
    gemini_enabled = data.get("use_gemini", True)  # Default to using Gemini
    
    if not code:
        return {"error": "No code provided"}
    
    # Basic analysis (reusing existing logic)
    vulnerabilities = []
    fix = None
    
    # Example vulnerability check
    if "execute(" in code and "%" in code:
        vulnerabilities.append("Possible SQL Injection detected.")
        fix = code.replace("%s", "?")
    
    # Add more checks from the predict endpoint
    if "eval(" in code:
        vulnerabilities.append("Use of eval() detected (potentially unsafe).")
    
    if "os.system(" in code or "subprocess" in code:
        vulnerabilities.append("Command execution detected (potential RCE risk).")
    
    # Perform Gemini analysis if enabled
    gemini_results = None
    if gemini_enabled:
        # Here you would make the actual call to the Gemini API
        # This is a placeholder
        gemini_results = {
            "analysis": "Placeholder for Gemini analysis",
            "vulnerabilities": ["Placeholder vulnerability from Gemini"],
            "recommendations": ["Placeholder recommendation from Gemini"]
        }
    
    # Combine the results
    return {
        "basic_analysis": {
            "vulnerabilities": vulnerabilities,
            "fix": fix
        },
        "gemini_analysis": gemini_results,
        "severity": "medium" if vulnerabilities else "low",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

@app.post("/scan_and_report")
async def scan_and_report(request: Request):
    data = await request.json()
    code = data.get("code", "")
    url = data.get("url", "")
    if not code and url:
        from .gemini_utils import scan_url_with_gemini
        result = scan_url_with_gemini(url)
        code = result.get("snippet", "")
        gemini_report = result.get("gemini_report", str(result))
    else:
        from .gemini_utils import gemini_vulnerability_report
        result = gemini_vulnerability_report(code)
        gemini_report = result.get("gemini_report", str(result))

    # Generate PDF in-memory
    from fpdf import FPDF
    import io
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=11)
    pdf.cell(0, 10, "Gemini Vulnerability Report", ln=1, align='C')
    pdf.ln(5)
    pdf.multi_cell(0, 8, gemini_report.encode('latin-1', 'replace').decode('latin-1'))
    pdf_stream = io.BytesIO()
    pdf.output(pdf_stream)
    pdf_stream.seek(0)

    from fastapi.responses import StreamingResponse
    return StreamingResponse(pdf_stream, media_type="application/pdf", headers={
        "Content-Disposition": "attachment; filename=gemini_vulnerability_report.pdf"
    })

if __name__ == "__main__":
    uvicorn.run("code_review:app", host="0.0.0.0", port=5000, reload=True)