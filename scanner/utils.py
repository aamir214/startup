import requests
import urllib3

# Suppress insecure request warnings for self-signed certs (common in internal apps)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_url_exists(url, timeout=10):
    """
    Check if a URL is reachable.
    Tries HEAD first, falls back to GET if HEAD fails or is not supported.
    """
    try:
        # Step 1: Try HEAD request (faster, doesn't download body)
        response = requests.head(url, timeout=timeout, allow_redirects=True, verify=False)
        
        # Some servers don't like HEAD, or return 405/404 erroneously
        if response.status_code < 400:
            return True
            
        # Step 2: Fallback to GET if HEAD was problematic
        print(f"[utils] HEAD request to {url} returned {response.status_code}, trying GET...")
        response = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
        return response.status_code < 400
        
    except requests.exceptions.RequestException as e:
        print(f"[utils] URL check failed for {url}: {e}")
        return False
    except Exception as e:
        print(f"[utils] Unexpected error checking URL {url}: {e}")
        return False
