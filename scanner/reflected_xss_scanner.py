import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

def run_reflected_xss_scan(base_url, endpoints, session):
    """
    Reflected XSS Scanner:
    1. Identify GET endpoints with parameters
    2. Inject XSS payloads into each parameter
    3. Check if payload is reflected in the response without escaping
    """
    print(f"\n[REFLECTED-XSS] Starting scan on {base_url}")
    
    # Common XSS payloads
    payloads = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>"
    ]
    
    findings = []
    # Identify unique GET URLs with parameters
    get_endpoints = [e for e in endpoints if e.get("method") == "GET" and e.get("params")]
    
    for endpoint in get_endpoints:
        target_url = endpoint.get("url")
        params = endpoint.get("params", [])
        
        for param in params:
            param_name = param.get("name")
            for payload in payloads:
                # Construct test URL
                query_params = {p.get("name"): p.get("value", "test") for p in params}
                query_params[param_name] = payload
                
                test_url = f"{target_url.split('?')[0]}?{urlencode(query_params)}"
                
                try:
                    print(f"[REFLECTED-XSS] Testing parameter '{param_name}' at: {test_url}")
                    response = session.get(test_url, timeout=10)
                    
                    if payload in response.text:
                        print(f"[REFLECTED-XSS] VULNERABILITY FOUND AT: {test_url}")
                        findings.append({
                            "url": test_url,
                            "endpoint": target_url.split('?')[0],
                            "parameter": param_name,
                            "payload": payload,
                            "confidence": "High",
                            "vulnerability_type": "Reflected XSS",
                            "impact": "Reflected XSS allows attackers to execute malicious scripts in the victim's browser by tricking them into clicking a specially crafted link.",
                            "reason": f"Payload '{payload}' was reflected in the response page."
                        })
                        break # Move to next parameter after finding one vuln
                except Exception as e:
                    print(f"[REFLECTED-XSS] Error testing {test_url}: {e}")
                    
    print(f"[REFLECTED-XSS] Scan complete. Found {len(findings)} issues.")
    return findings
