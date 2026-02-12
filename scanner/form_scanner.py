"""
Form Scanner — Extract forms and inputs from web pages using BeautifulSoup.
Fetches pages discovered by Katana and extracts form data.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed


def _scan_single_page(url):
    """
    Fetch a single page and extract all forms and their inputs.

    Returns:
        list[dict]: Normalized endpoint dicts for each form found
    """
    endpoints = []

    try:
        response = requests.get(url, timeout=10, verify=False)
        response.raise_for_status()
    except Exception as e:
        print(f"[form_scanner] Error fetching {url}: {e}")
        return endpoints

    soup = BeautifulSoup(response.text, "html.parser")

    # --- Extract FORMS ---
    for form in soup.find_all("form"):
        form_action = form.get("action")
        form_method = (form.get("method") or "GET").upper()
        action_url = urljoin(url, form_action) if form_action else url

        params = []

        # Inputs
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name:
                continue
            input_type = inp.get("type", "text").lower()

            # Skip submit/hidden/button inputs for injection
            if input_type in ("submit", "button", "image", "reset"):
                continue

            params.append({
                "name": name,
                "type": input_type,
                "value": inp.get("value", ""),
            })

        # Textareas
        for ta in form.find_all("textarea"):
            name = ta.get("name")
            if not name:
                continue
            params.append({
                "name": name,
                "type": "textarea",
                "value": ta.string or "",
            })

        # Selects
        for sel in form.find_all("select"):
            name = sel.get("name")
            if not name:
                continue
            # Get the first option value as default
            first_option = sel.find("option")
            value = first_option.get("value", "") if first_option else ""
            params.append({
                "name": name,
                "type": "select",
                "value": value,
            })

        if params:
            endpoints.append({
                "url": action_url,
                "method": form_method,
                "params": params,
                "source": "beautifulsoup",
            })

    # --- Extract standalone inputs (outside forms, common in SPAs) ---
    # Find inputs that are NOT inside a <form> tag
    all_inputs = soup.find_all("input")
    for inp in all_inputs:
        # Skip if inside a form
        if inp.find_parent("form"):
            continue

        name = inp.get("name")
        if not name:
            continue

        input_type = inp.get("type", "text").lower()
        if input_type in ("submit", "button", "image", "reset", "hidden"):
            continue

        endpoints.append({
            "url": url,
            "method": "GET",  # Standalone inputs typically used with JS/GET
            "params": [{
                "name": name,
                "type": input_type,
                "value": inp.get("value", ""),
            }],
            "source": "beautifulsoup",
        })

    return endpoints


def run_form_scanner(urls, max_workers=10):
    """
    Scan multiple URLs for forms and inputs using BeautifulSoup.

    Args:
        urls: List of URLs to scan (typically from Katana output)
        max_workers: Max concurrent requests (default 10)

    Returns:
        list[dict]: Normalized endpoint dicts
    """
    if not urls:
        return []

    all_endpoints = []

    # Use ThreadPoolExecutor for concurrent fetching
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(_scan_single_page, url): url
            for url in urls
        }

        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                endpoints = future.result()
                all_endpoints.extend(endpoints)
            except Exception as e:
                print(f"[form_scanner] Error processing {url}: {e}")

    print(f"[form_scanner] Found {len(all_endpoints)} form endpoints across {len(urls)} pages")
    return all_endpoints
