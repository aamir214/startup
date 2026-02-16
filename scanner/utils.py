import requests
import urllib3

# Suppress insecure request warnings for self-signed certs (common in internal apps)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_url_exists(url, timeout=30):
    """
    Check if a URL is reachable.
    Tries HEAD first, falls back to GET if HEAD fails or is not supported.
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    }
    
    try:
        # Step 1: Try HEAD request (faster, doesn't download body)
        response = requests.head(url, timeout=timeout, allow_redirects=True, verify=False, headers=headers)
        
        # Some servers don't like HEAD, or return 405/404 erroneously
        if response.status_code < 400:
            return True
            
        # Step 2: Fallback to GET if HEAD was problematic
        print(f"[utils] HEAD request to {url} returned {response.status_code}, trying GET...")
        response = requests.get(url, timeout=timeout, allow_redirects=True, verify=False, headers=headers)
        
        # If it's a 503, it might be Heroku sleeping. Let's be lenient.
        if response.status_code == 503:
            print(f"[utils] Warning: Target returned 503 (Service Unavailable). It might be sleeping or overloaded.")
            return True
            
        return response.status_code < 400
        
    except requests.exceptions.Timeout:
        print(f"[utils] Timeout checking {url} after {timeout}s.")
        return False
    except requests.exceptions.RequestException as e:
        print(f"[utils] URL check failed for {url}: {e}")
        return False
    except Exception as e:
        print(f"[utils] Unexpected error checking URL {url}: {e}")
        return False
