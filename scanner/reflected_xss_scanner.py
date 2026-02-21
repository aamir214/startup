import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

def run_reflected_xss_scan(base_url, endpoints, session):
    """
    Reflected XSS Scanner:
    1. Identify GET endpoints with parameters
    2. Inject XSS payloads into each parameter
    3. Check if payload is reflected in the response without escaping
    """
    # Scan markers removed to reduce spam
    
    # Common XSS payloads
    payloads = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "';alert(1)//",
        '<svg/onload=alert(1)>'
    ]
    
    # Hidden parameters to fuzz on every endpoint
    hidden_params = ['msg', 'debug', 'name', 'id', 'query', 'search']
    
    findings = []
    
    # Iterate over all endpoints, not just GET with existing params
    for endpoint in endpoints:
        # Only process GET requests for reflected XSS
        if endpoint.get("method") != "GET":
            continue

        target_url_base = endpoint.get("url").split('?')[0]
        
        # Initialize query_params with existing parameters
        # Convert list of dicts [{'name': 'p1', 'value': 'v1'}] to dict {'p1': 'v1'}
        existing_params_list = endpoint.get("params", [])
        query_params_dict = {p.get("name"): p.get("value", "test") for p in existing_params_list}
        
        # Add hidden params for testing if they don't already exist
        for hp in hidden_params:
            if hp not in query_params_dict:
                query_params_dict[hp] = "" # Add with an empty value to be fuzzed
        
        # If no parameters to test (neither original nor hidden), skip this endpoint
        if not query_params_dict:
            continue
            
        # Iterate over each parameter (original and hidden) to inject payloads
        for param_name_to_fuzz in query_params_dict:
            for payload in payloads:
                # Create a copy of the current parameters to modify for the test
                current_test_params = query_params_dict.copy()
                current_test_params[param_name_to_fuzz] = payload
                
                # Construct test URL
                test_url = f"{target_url_base}?{urlencode(current_test_params)}"
                try:
                    response = session.get(test_url, timeout=10)
                    
                    if payload in response.text:
                        # Scan markers removed
                        findings.append({
                            "url": test_url,
                            "endpoint": target_url_base,
                            "parameter": param_name_to_fuzz,
                            "payload": payload,
                            "confidence": "High",
                            "vulnerability_type": "Reflected XSS",
                            "impact": "Reflected XSS allows attackers to execute malicious scripts in the victim's browser by tricking them into clicking a specially crafted link.",
                            "reason": f"Payload '{payload}' was reflected in the response page."
                        })
                        break # Move to next parameter after finding one vuln
                except Exception:
                    pass
                    
    if findings:
        print(f"[+] Reflected XSS: Found {len(findings)} issues")
    return findings
