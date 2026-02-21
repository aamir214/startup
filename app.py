from flask import Flask, render_template, request, jsonify
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import traceback

# Scanner modules
from scanner.katana_scanner import run_katana
from scanner.paramspider_scanner import run_paramspider
from scanner.form_scanner import run_form_scanner
from scanner.normalizer import normalize
from scanner.auth import login_and_get_cookies
from scanner.utils import check_url_exists
from scanner.stored_xss_scanner import run_stored_xss_scan
from scanner.reflected_xss_scanner import run_reflected_xss_scan
from scanner.lfi_scanner import run_lfi_scan
from scanner.sqli_scanner import run_sqli_scan
from scanner.js_parser import extract_api_endpoints_from_js
import requests

app = Flask(__name__)

# Email configuration
SENDER_EMAIL = os.environ.get('SENDER_EMAIL', 'your-email@gmail.com')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD', 'your-app-password')
RECIPIENT_EMAIL = 'mohamed.aamir.khan.123@gmail.com'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit-form', methods=['POST'])
def submit_form():
    try:
        data = request.json
        
        # Build email content
        email_body = f"""
        <h2>New Vulnerability Fix Request</h2>
        <p><strong>Company Name:</strong> {data.get('company_name', 'N/A')}</p>
        <p><strong>Website / Application URL:</strong> {data.get('website_url', 'N/A')}</p>
        <p><strong>Selected Vulnerability:</strong> {data.get('vulnerability', 'N/A')}</p>
        <p><strong>Affected Endpoint:</strong> {data.get('endpoint', 'N/A')}</p>
        <p><strong>Tech Stack:</strong> {data.get('tech_stack', 'N/A')}</p>
        <p><strong>Contact Email:</strong> {data.get('contact_email', 'N/A')}</p>
        <p><strong>WhatsApp Number:</strong> {data.get('whatsapp_number', 'N/A')}</p>
        """
        
        # Send email
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'New Vulnerability Fix Request'
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECIPIENT_EMAIL
        
        msg.attach(MIMEText(email_body, 'html'))
        
        # Connect to Gmail SMTP
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECIPIENT_EMAIL, msg.as_string())
        server.quit()
        
        return jsonify({'success': True, 'message': 'Form submitted successfully!'})
    
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'success': False, 'message': f'Error sending email: {str(e)}'}), 500

@app.route('/request-fix')
def request_fix():
    return render_template('request_fix.html')

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target_url = data.get("url")
    username = data.get("username")
    password = data.get("password")

    if not target_url or not target_url.startswith("http"):
        return jsonify({"error": "Invalid URL format"}), 400

    # Early URL existence check
    if not check_url_exists(target_url):
        print(f"[!] Target URL is unreachable: {target_url}")
        return jsonify({
            "error": "Target URL is unreachable",
            "target": target_url,
            "success": False
        }), 404

    errors = []
    katana_urls = []
    paramspider_endpoints = []
    form_endpoints = []
    cookies = None

    auth_discovered_links = []
    # Step 0: Authentication (if requested)
    if username and password:
        print(f"[*] Performing login for user: {username}")
        auth_result = login_and_get_cookies(target_url, username, password)
        if auth_result:
            cookies = auth_result.get("cookies")
            auth_discovered_links = auth_result.get("discovered_links", [])
            # If login redirected us (e.g., to /dashboard), use that as an extra discovery seed
            final_url = auth_result.get("final_url")
            if final_url and final_url != target_url:
                print(f"[+] Auth successful, landed at: {final_url}")
                target_url = final_url
            else:
                print(f"[+] Auth successful, captured session cookies")
        else:
            print(f"[!] Auth failed, proceeding without authentication")

    # Step 1: Katana — Endpoint Discovery
    print(f"\n[*] Starting scan for: {target_url}")

    try:
        print("[*] Running Katana for endpoint discovery...")
        katana_urls = run_katana(target_url, cookies=cookies)
        # Merge manually discovered links from auth landing page
        if auth_discovered_links:
            katana_urls = list(set(katana_urls + auth_discovered_links))
        print(f"[+] Discovery: Found {len(katana_urls)} URLs total")
    except Exception as e:
        errors.append({"tool": "katana", "error": str(e)})
        print(f"[!] Katana error: {e}")

    # Step 2: ParamSpider
    try:
        paramspider_endpoints = run_paramspider(target_url)
    except Exception as e:
        errors.append({"tool": "paramspider", "error": str(e)})
        print(f"[!] ParamSpider error: {e}")

    # Step 3: BeautifulSoup — Form Extraction
    try:
        urls_to_scan = katana_urls if katana_urls else [target_url]
        print(f"[*] Running form scanner on {len(urls_to_scan)} URLs...")
        form_endpoints = run_form_scanner(urls_to_scan, cookies=cookies)
        print(f"[+] Form Scanner: Found {len(form_endpoints)} forms")
    except Exception as e:
        errors.append({"tool": "beautifulsoup", "error": str(e)})
        print(f"[!] Form scanner error: {e}")

    # Step 3.5: JS Parsing
    js_endpoints = []
    try:
        js_urls = [u for u in katana_urls if u.endswith(".js")]
        if js_urls:
            print(f"[*] Running JS parser on {len(js_urls)} files...")
            parsing_session = requests.Session()
            if cookies:
                parsing_session.cookies.update(cookies)
            js_endpoints = extract_api_endpoints_from_js(js_urls, target_url, session=parsing_session)
            print(f"[+] JS Parser: Found {len(js_endpoints)} endpoints")
    except Exception as e:
        errors.append({"tool": "js_parser", "error": str(e)})
        print(f"[!] JS parser error: {e}")

    # Step 4: Normalize
    result = normalize(target_url, katana_urls, paramspider_endpoints, form_endpoints + js_endpoints)

    # Step 5: Vulnerability Scanning
    print("[*] Running vulnerability scans...")
    try:
        session = requests.Session()
        if cookies:
            session.cookies.update(cookies)
        
        # 5.1 Stored XSS
        stored_findings = run_stored_xss_scan(
            target_url,
            result["endpoints"],
            session,
            discovered_urls=result["discovered_urls"]
        )
        
        # 5.2 Reflected XSS
        reflected_findings = run_reflected_xss_scan(target_url, result["endpoints"], session)
        
        # 5.3 LFI
        lfi_findings = run_lfi_scan(target_url, result["endpoints"], session)
        
        # 5.4 SQLi
        sqli_findings = run_sqli_scan(target_url, result["endpoints"], session)
        
        # Merge all vulnerabilities
        all_vulnerabilities = stored_findings + reflected_findings + lfi_findings + sqli_findings
        result["vulnerabilities"] = all_vulnerabilities
        result["stored_xss"] = stored_findings # Keep for backward compat if needed
    except Exception as e:
        errors.append({"tool": "vulnerability_scanner", "error": str(e)})
        print(f"[STEP 5] Vulnerability scanner error: {e}")
        traceback.print_exc()

    print(f"[+] Scan complete: {len(all_vulnerabilities)} vulnerabilities found")

    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True, port=5000)

