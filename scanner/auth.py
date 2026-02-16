import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from .utils import check_url_exists

def login_and_get_cookies(login_url, username, password):
    """
    Perform a session-based login and return the cookies.
    Automatically detects forms, hidden fields, and submission types (Form vs JSON).
    """
    session = requests.Session()
    # Professional Headers to look like a real browser
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    })

    print(f"[auth] Checking reachability: {login_url}")
    if not check_url_exists(login_url):
        print(f"[auth] URL {login_url} unreachable.")
        return None

    try:
        # Step 1: Initial Investigation of the Login Page
        print(f"[auth] Analyzing login page: {login_url}")
        res = session.get(login_url, timeout=15, verify=False)
        soup = BeautifulSoup(res.text, "html.parser")
        
        # Step 2: Handle modern SPAs (Special case for Juice Shop and similar REST APIs)
        # If no form is found but it's a known JSON-heavy target, try standard REST endpoint
        is_juice_shop = "juice-shop" in login_url.lower() or "herokuapp.com" in login_url.lower()
        
        forms = soup.find_all("form")
        if not forms and is_juice_shop:
            print("[auth] No HTML form found, but site looks like a modern API. Trying JSON login.")
            # Standard Juice Shop REST login endpoint
            api_url = urljoin(login_url, "/rest/user/login")
            payload = {"email": username, "password": password}
            res = session.post(api_url, json=payload, timeout=15)
        
        elif not forms:
            print("[auth] No traditional form found. Attempting basic POST fallback.")
            payload = {"username": username, "password": password}
            res = session.post(login_url, data=payload, timeout=15)
            
        else:
            # Step 3: Professional Form Extraction
            form = forms[0] # Assume the first form is the login form
            action = form.get("action")
            method = (form.get("method") or "POST").upper()
            target_url = urljoin(login_url, action) if action else login_url
            
            payload = {}
            username_field = None
            password_field = None
            
            # Extract inputs, including hidden ones (CSRF tokens)
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name") or inp.get("id")
                if not name:
                    continue
                
                input_type = inp.get("type", "text").lower()
                current_val = inp.get("value", "")
                
                # Identify fields by type or name heuristics
                if input_type == "password":
                    password_field = name
                    payload[name] = password
                elif any(kw in name.lower() for kw in ["user", "email", "login", "account"]):
                    if not username_field:
                        username_field = name
                        payload[name] = username
                else:
                    # Keep existing values for hidden/CSRF/fixed inputs
                    payload[name] = current_val

            print(f"[auth] Detected Form: {method} {target_url}")
            print(f"[auth] Fields found: {list(payload.keys())}")
            
            if method == "POST":
                # Check for signs that the server expects JSON
                if "application/json" in (res.headers.get("Content-Type", "")) or is_juice_shop:
                    res = session.post(target_url, json=payload, timeout=15)
                else:
                    res = session.post(target_url, data=payload, timeout=15)
            else:
                res = session.get(target_url, params=payload, timeout=15)

        # Step 4: Verify Success
        # Check if we got any session-like cookies OR if the URL changed (redirect)
        captured_cookies = session.cookies.get_dict()
        if captured_cookies:
            print(f"[auth] Success! Captured {len(captured_cookies)} cookies.")
            return captured_cookies
        else:
            print(f"[auth] Login request finished (Status {res.status_code}), but no cookies were captured.")
            if res.status_code < 400 and is_juice_shop:
                # Juice Shop might use tokens in response body instead of just cookies
                print("[auth] Potential Token-based auth detected in response.")

    except Exception as e:
        print(f"[auth] Login error: {e}")
    
    return None
