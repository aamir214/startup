import uuid
import requests
import time

def run_stored_xss_scan(base_url, endpoints, session, discovered_urls=None, max_forms=10):
    """
    Stored XSS Scanner:
    1. Generate unique payload
    2. Inject into POST forms
    3. Re-visit discovered URLs
    4. Search for payload to detect stored XSS
    """
    print(f"\n[STORED-XSS] Starting scan on {base_url}")
    
    payload_id = str(uuid.uuid4())
    # Using a unique tag to easily identify if it's rendered as HTML or escaped
    payload = f"<xss-test>{payload_id}</xss-test>"
    
    findings = []
    post_endpoints = [e for e in endpoints if e.get("method") == "POST"]
    
    # Limit number of forms to avoid spamming
    post_endpoints = post_endpoints[:max_forms]
    
    # Phase 2: Injection Logic
    print(f"[STORED-XSS] Injecting payload into {len(post_endpoints)} POST forms...")
    for endpoint in post_endpoints:
        data = {}
        for param in endpoint.get("params", []):
            name = param.get("name")
            input_type = param.get("type", "text")
            
            # Inject only into text/textarea
            if input_type in ["text", "textarea"]:
                data[name] = payload
            else:
                data[name] = param.get("value", "")
        
        try:
            url = endpoint.get("url")
            print(f"[STORED-XSS] Testing form at: {url}")
            # Use the provided session (authenticated if login was used)
            response = session.post(url, data=data, timeout=10)
            if response.status_code >= 400:
                print(f"[STORED-XSS] Warning: Received status {response.status_code}")
        except Exception as e:
            print(f"[STORED-XSS] Error injecting into {endpoint.get('url')}: {e}")

    # Small delay to ensure DB persistence
    time.sleep(1)

    # Phase 3: Retrieval Phase
    # Re-crawl or revisit discovered URLs
    urls_to_check = discovered_urls if discovered_urls else [base_url]
    
    print(f"[STORED-XSS] Re-visiting {len(urls_to_check)} URLs to detect storage...")
    for url in urls_to_check:
        try:
            print(f"[STORED-XSS] Checking: {url}")
            r = session.get(url, timeout=10)
            
            # Phase 4: Escaping Check
            # If the raw payload is in the text, it means it wasn't escaped
            if payload in r.text:
                print(f"[STORED-XSS] POTENTIAL VULNERABILITY FOUND AT: {url}")
                findings.append({
                    "url": url,
                    "confidence": "High",
                    "reason": "Payload rendered unescaped in response",
                    "payload": payload
                })
            elif payload_id in r.text:
                # Payload ID found but maybe escaped or modified
                print(f"[STORED-XSS] Possible vulnerability (escaped) at: {url}")
                findings.append({
                    "url": url,
                    "confidence": "Low",
                    "reason": "Payload ID found but might be escaped",
                    "payload": payload
                })
        except Exception as e:
            print(f"[STORED-XSS] Error checking {url}: {e}")
            continue

    print(f"[STORED-XSS] Scan complete. Found {len(findings)} issues.")
    return findings
