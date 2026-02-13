import requests

def login_and_get_cookies(login_url, username, password):
    """
    Perform a session-based login and return the cookies.
    """
    session = requests.Session()
    payload = {
        "username": username,
        "password": password
    }
    
    try:
        print(f"[auth] Attempting login at {login_url} for {username}")
        # We use a post request for login
        response = session.post(login_url, data=payload, timeout=15)
        
        if response.status_code == 200:
            cookies = session.cookies.get_dict()
            if cookies:
                print(f"[auth] Successfully captured {len(cookies)} cookies")
                return cookies
            else:
                print("[auth] Login successful but no cookies captured")
        else:
            print(f"[auth] Login failed with status code: {response.status_code}")
    except Exception as e:
        print(f"[auth] Login error: {e}")
    
    return None
