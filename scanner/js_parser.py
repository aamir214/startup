import re
import requests
from urllib.parse import urljoin, urlparse

def extract_api_endpoints_from_js(js_urls, base_url, session=None):
    """
    Extract potential API endpoints from JS files using regex.
    """
    if session is None:
        session = requests.Session()
    
    api_endpoints = []
    # Regex for common API patterns like /api/v1/..., /rest/..., etc.
    # Also looks for common methods like .get(", .post(", fetch(" etc.
    patterns = [
        r'["\'](/api/[\w\-/]*)["\']',
        r'["\'](/rest/[\w\-/]*)["\']',
        r'["\'](/v[0-9]/[\w\-/]*)["\']',
        r'\.get\(["\']([\w\-/]*)["\']',
        r'\.post\(["\']([\w\-/]*)["\']',
        r'fetch\(["\']([\w\-/]*)["\']',
    ]
    
    print(f"\n[JS-PARSER] Analyzing {len(js_urls)} JS files...")
    
    for js_url in js_urls:
        try:
            print(f"[JS-PARSER] Downloading: {js_url}")
            r = session.get(js_url, timeout=10)
            if r.status_code == 200:
                content = r.text
                
                for pattern in patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        path = match.group(1)
                        if path:
                            # Construct full URL
                            full_url = urljoin(base_url, path)
                            
                            # Basic validation: ensure it's still on the same domain
                            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                                # Determine likely method
                                method = "GET"
                                if ".post(" in match.group(0):
                                    method = "POST"
                                
                                endpoint = {
                                    "url": full_url,
                                    "method": method,
                                    "params": [], # We don't know params from simple regex
                                    "source": "js_parser"
                                }
                                api_endpoints.append(endpoint)
            else:
                print(f"[JS-PARSER] Skipping {js_url} (Status {r.status_code})")
        except Exception as e:
            print(f"[JS-PARSER] Error parsing {js_url}: {e}")
            continue
            
    # Deduplicate
    seen = set()
    unique_endpoints = []
    for ep in api_endpoints:
        key = f"{ep['method']}|{ep['url']}"
        if key not in seen:
            seen.add(key)
            unique_endpoints.append(ep)
            
    print(f"[JS-PARSER] Found {len(unique_endpoints)} potential API endpoints.")
    return unique_endpoints
