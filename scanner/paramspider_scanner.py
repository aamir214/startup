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
        print(f"[paramspider] Could not extract domain from {target_url}")
        return []

    # URL Existence Check
    print(f"[paramspider] Checking if {target_url} is reachable...")
    if not check_url_exists(target_url):
        print(f"[paramspider] Target {target_url} is unreachable. Skipping scan.")
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
        print(f"[paramspider] Timed out after {timeout}s for {domain}")
        return []
    except Exception as e:
        print(f"[paramspider] Error: {e}")
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
            print(f"[paramspider] No output file found for {domain}")
            if result.stdout:
                print(f"[paramspider] stdout: {result.stdout[:500]}")
            return []

    endpoints = []

    try:
        with open(output_file, "r") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[paramspider] Error reading output: {e}")
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

    print(f"[paramspider] Found {len(endpoints)} parameterized URLs for {domain}")

    # Cleanup output file
    try:
        os.remove(output_file)
    except:
        pass

    return endpoints
