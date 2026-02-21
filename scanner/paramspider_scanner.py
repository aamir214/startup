"""
ParamSpider Scanner — GET parameter mining from web archives.
Runs paramspider as a subprocess and returns URLs with parameters.
"""

import subprocess
import shutil
import os
import glob
from urllib.parse import urlparse, parse_qs
from .utils import check_url_exists


def run_paramspider(target_url, timeout=90):
    """
    Run paramspider against a target domain to find URLs with GET parameters.

    Args:
        target_url: The full URL (domain will be extracted)
        timeout: Max seconds to wait (default 90)

    Returns:
        list[dict]: Normalized endpoint dicts with method, params, source
    """
    # Extract domain from URL
    parsed = urlparse(target_url)
    domain = parsed.hostname
    if not domain:
        print(f"[!] ParamSpider: Could not extract domain from {target_url}")
        return []

    # Localhost Check - ParamSpider is for web archives, not local testing
    if domain in ["localhost", "127.0.0.1"]:
        print(f"[*] ParamSpider: Skipping for local target {domain} (historical data not applicable)")
        return []

    # URL Existence Check
    if not check_url_exists(target_url):
        print(f"[!] ParamSpider: Target {target_url} is unreachable. Skipping.")
        return []

    # Find paramspider
    paramspider_path = shutil.which("paramspider")
    if not paramspider_path:
        # Check in .venv/bin/
        venv_bin = os.path.join(os.getcwd(), ".venv", "bin", "paramspider")
        if os.path.exists(venv_bin):
            paramspider_path = venv_bin
        # Check in .venv/bin/paramspider (if running from root)
        elif os.path.exists(".venv/bin/paramspider"):
             paramspider_path = ".venv/bin/paramspider"
        else:
            raise FileNotFoundError(
                "paramspider not found. Install with: pip install paramspider"
            )

    cmd = [
        paramspider_path,
        "-d", domain,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"[!] ParamSpider: Timed out after {timeout}s for {domain}")
        return []
    except Exception as e:
        print(f"[!] ParamSpider: Error: {e}")
        return []

    # ParamSpider saves output to results/<domain>.txt
    output_file = os.path.join("results", f"{domain}.txt")

    # Also check in the current working directory
    if not os.path.exists(output_file):
        # Try to find it with glob
        possible_files = glob.glob(f"results/*{domain}*")
        if possible_files:
            output_file = possible_files[0]
        else:
            print(f"[!] ParamSpider: No archived data found for {domain}")
            return []

    endpoints = []

    try:
        with open(output_file, "r") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[!] ParamSpider: Error reading output: {e}")
        return []

    for line in lines:
        url = line.strip()
        if not url or not url.startswith("http"):
            continue

        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        params = []
        for param_name, param_values in query_params.items():
            value = param_values[0] if param_values else "FUZZ"
            params.append({
                "name": param_name,
                "type": "query",
                "value": value,
            })

        if params:  # Only include URLs that actually have parameters
            # Reconstruct clean URL (without query string)
            clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

            endpoints.append({
                "url": clean_url,
                "method": "GET",
                "params": params,
                "source": "paramspider",
            })

    if endpoints:
        print(f"[+] ParamSpider: Found {len(endpoints)} parameterized URLs")

    # Cleanup output file
    try:
        os.remove(output_file)
    except:
        pass

    return endpoints
