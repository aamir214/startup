"""
Katana Scanner — Endpoint discovery using ProjectDiscovery's Katana.
Runs katana as a subprocess and returns discovered URLs.
"""

import subprocess
import shutil
import os
from urllib.parse import urlparse
from .utils import check_url_exists


def run_katana(target_url, depth=3, timeout=120, cookies=None, headless=True):
    """
    Run katana against a target URL to discover endpoints.

    Args:
        target_url: The URL to crawl (e.g. https://example.com/path)
        depth: Crawl depth (default 3)
        timeout: Max seconds to wait for katana (default 120)
        cookies: Optional dictionary of cookies
        headless: Whether to use headless mode (default False)

    Returns:
        list[str]: List of discovered URLs
    """
    # Find katana binary
    katana_path = shutil.which("katana")
    if not katana_path:
        # Check in .venv/bin/
        venv_bin = os.path.join(os.getcwd(), ".venv", "bin", "katana")
        if os.path.exists(venv_bin):
            katana_path = venv_bin
        # Check in current directory
        elif os.path.exists("katana"):
            katana_path = "./katana"
        # Try common Go bin path on Windows
        elif os.path.exists(os.path.join(os.path.expanduser("~"), "go", "bin", "katana.exe")):
            katana_path = os.path.join(os.path.expanduser("~"), "go", "bin", "katana.exe")
        else:
            raise FileNotFoundError(
                "katana not found. Install with: go install github.com/projectdiscovery/katana/cmd/katana@latest"
            )

    # URL Existence Check
    if not check_url_exists(target_url):
        print(f"[!] Katana: Target {target_url} is unreachable. Skipping.")
        return []

    cmd = [
        katana_path,
        "-u", target_url,
        "-d", str(depth),
        "-jc",           # JavaScript crawling
        "-no-color",      # Clean output
        "-silent",        # Keep output clean for parsing
    ]

    if headless:
        cmd.append("-headless")

    # Smart Scoping: If the URL has a path and it's not a local target, keep within it
    parsed = urlparse(target_url)
    is_local = parsed.hostname in ["localhost", "127.0.0.1"]
    
    if parsed.path and parsed.path != "/" and not is_local:
        scope_regex = f"^{parsed.scheme}://(www\\.)?{parsed.netloc}{parsed.path}"
        cmd.extend(["-cs", scope_regex])
    elif is_local:
        # For localhost, always scope to the whole "domain"
        scope_regex = f"^{parsed.scheme}://(www\\.)?{parsed.netloc}"
        cmd.extend(["-cs", scope_regex])

    if cookies:
        cookie_string = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        cmd.extend(["-H", f"Cookie: {cookie_string}"])

    stdout = ""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout = result.stdout or ""
        if result.returncode != 0:
            print(f"[!] Katana: Command failed with code {result.returncode}")
            if result.stderr:
                print(f"[!] Katana: STDERR: {result.stderr.strip()}")

    except subprocess.TimeoutExpired as e:
        print(f"[!] Katana: Timed out after {timeout}s")
        if e.stdout:
            stdout = e.stdout if isinstance(e.stdout, str) else e.stdout.decode()
    except Exception:
        # Silently fail for individual pages to avoid spamming the log
        return [] # Changed from `return endpoints` to `return []` as `endpoints` is not defined here.

    urls = []
    if stdout:
        for line in stdout.strip().splitlines():
            line = line.strip()
            if line and line.startswith("http"):
                urls.append(line)

    # Deduplicate while preserving order
    seen = set()
    unique_urls = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)

    return unique_urls
