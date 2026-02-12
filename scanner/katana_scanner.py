"""
Katana Scanner — Endpoint discovery using ProjectDiscovery's Katana.
Runs katana as a subprocess and returns discovered URLs.
"""

import subprocess
import shutil
import os


def run_katana(target_url, depth=3, timeout=120):
    """
    Run katana against a target URL to discover endpoints.

    Args:
        target_url: The URL to crawl (e.g. https://example.com)
        depth: Crawl depth (default 3)
        timeout: Max seconds to wait for katana (default 120)

    Returns:
        list[str]: List of discovered URLs
    """
    # Find katana binary
    katana_path = shutil.which("katana")
    if not katana_path:
        # Try common Go bin path on Windows
        go_bin = os.path.join(os.path.expanduser("~"), "go", "bin", "katana.exe")
        if os.path.exists(go_bin):
            katana_path = go_bin
        else:
            raise FileNotFoundError(
                "katana not found. Install with: go install github.com/projectdiscovery/katana/cmd/katana@latest"
            )

    cmd = [
        katana_path,
        "-u", target_url,
        "-d", str(depth),
        "-jc",           # JavaScript crawling
        "-silent",        # Only output URLs
        "-no-color",      # Clean output
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"[katana] Timed out after {timeout}s for {target_url}")
        return []
    except Exception as e:
        print(f"[katana] Error: {e}")
        return []

    urls = []
    for line in result.stdout.strip().splitlines():
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

    print(f"[katana] Discovered {len(unique_urls)} URLs for {target_url}")
    return unique_urls
