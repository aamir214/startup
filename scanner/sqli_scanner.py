import requests
from urllib.parse import urlencode

def run_sqli_scan(base_url, endpoints, session):
    """
    SQL Injection Scanner (Basic):
    1. Identify GET/POST endpoints with parameters
    2. Inject single quotes and other SQL syntax
    3. Look for database error messages in response
    """
    print(f"\n[SQLI] Starting scan on {base_url}")
    
    payloads = ["'", "''", "\"", "safe' OR '1'='1", "') OR ('1'='1"]
    
    error_keywords = [
        "sql academic", "syntax error", "sqlite3.OperationalError", 
        "mysql_fetch_array", "unclosed quotation mark", "PostgreSQL query failed"
    ]
    
    findings = []
    
    # Check GET parameters
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
                    print(f"[SQLI] Testing parameter '{param_name}' at: {test_url}")
                    response = session.get(test_url, timeout=10)
                    
                    if any(keyword.lower() in response.text.lower() for keyword in error_keywords):
                        print(f"[SQLI] VULNERABILITY FOUND AT: {test_url}")
                        findings.append({
                            "url": test_url,
                            "endpoint": target_url.split('?')[0],
                            "parameter": param_name,
                            "payload": payload,
                            "confidence": "High",
                            "vulnerability_type": "SQL Injection",
                            "impact": "SQL Injection allows an attacker to interfere with the queries that an application makes to its database, potentially allowing them to view, modify or delete data.",
                            "reason": "Database error message found in response."
                        })
                        break
                except Exception as e:
                    print(f"[SQLI] Error testing {test_url}: {e}")
                    
    print(f"[SQLI] Scan complete. Found {len(findings)} issues.")
    return findings
