"""
Normalizer — Merge and deduplicate endpoints from all scanners
into a unified JSON format for downstream XSS/LFI testing.
"""

import hashlib
import json


def _endpoint_hash(endpoint):
    """Create a unique hash for an endpoint based on url + method + param names."""
    param_names = sorted([p["name"] for p in endpoint.get("params", [])])
    key = f"{endpoint['url']}|{endpoint['method']}|{','.join(param_names)}"
    return hashlib.md5(key.encode()).hexdigest()


def normalize(target, katana_urls, paramspider_endpoints, form_endpoints):
    """
    Merge all scanner outputs into a unified, deduplicated JSON format.

    Args:
        target: Original target URL
        katana_urls: List of URLs discovered by Katana (for reference)
        paramspider_endpoints: Normalized endpoints from ParamSpider
        form_endpoints: Normalized endpoints from BeautifulSoup

    Returns:
        dict: Unified scan result
    """
    all_endpoints = []
    seen_hashes = set()

    # Add Katana URLs as potential GET endpoints
    for url in katana_urls:
        # Ignore static assets for vulnerability scanning
        if any(url.endswith(ext) for ext in [".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2"]):
            continue
            
        # Strip query string for hashing purposes (as we add empty params list)
        clean_url = url.split('?')[0]
        ep = {
            "url": clean_url,
            "method": "GET",
            "params": [],
            "source": "katana"
        }
        h = _endpoint_hash(ep)
        if h not in seen_hashes:
            seen_hashes.add(h)
            all_endpoints.append(ep)

    # Add ParamSpider endpoints
    for ep in paramspider_endpoints:
        h = _endpoint_hash(ep)
        if h not in seen_hashes:
            seen_hashes.add(h)
            all_endpoints.append(ep)

    # Add BeautifulSoup form endpoints
    for ep in form_endpoints:
        h = _endpoint_hash(ep)
        if h not in seen_hashes:
            seen_hashes.add(h)
            all_endpoints.append(ep)

    # Summary counts
    get_count = sum(1 for ep in all_endpoints if ep["method"] == "GET")
    post_count = sum(1 for ep in all_endpoints if ep["method"] == "POST")
    total_params = sum(len(ep["params"]) for ep in all_endpoints)

    result = {
        "target": target,
        "summary": {
            "urls_discovered": len(katana_urls),
            "total_endpoints": len(all_endpoints),
            "get_endpoints": get_count,
            "post_endpoints": post_count,
            "total_params": total_params,
            "sources": {
                "katana": len(katana_urls),
                "paramspider": sum(1 for ep in all_endpoints if ep["source"] == "paramspider"),
                "beautifulsoup": sum(1 for ep in all_endpoints if ep["source"] == "beautifulsoup"),
            }
        },
        "discovered_urls": katana_urls,
        "endpoints": all_endpoints,
    }

    print(f"[normalizer] Final: {len(all_endpoints)} unique endpoints "
          f"({get_count} GET, {post_count} POST) with {total_params} params")

    return result
