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

    if not target_url or not target_url.startswith("http"):
        return jsonify({"error": "Invalid URL"}), 400

    errors = []
    katana_urls = []
    paramspider_endpoints = []
    form_endpoints = []

    # Step 1: Katana — Endpoint Discovery
    print(f"\n{'='*50}")
    print(f"[SCAN] Starting scan for: {target_url}")
    print(f"{'='*50}")

    try:
        print("\n[STEP 1] Running Katana for endpoint discovery...")
        katana_urls = run_katana(target_url)
    except FileNotFoundError as e:
        errors.append({"tool": "katana", "error": str(e)})
        print(f"[STEP 1] Katana not found: {e}")
    except Exception as e:
        errors.append({"tool": "katana", "error": str(e)})
        print(f"[STEP 1] Katana error: {e}")
        traceback.print_exc()

    # Step 2: ParamSpider — GET Parameter Mining
    try:
        print("\n[STEP 2] Running ParamSpider for GET parameters...")
        paramspider_endpoints = run_paramspider(target_url)
    except FileNotFoundError as e:
        errors.append({"tool": "paramspider", "error": str(e)})
        print(f"[STEP 2] ParamSpider not found: {e}")
    except Exception as e:
        errors.append({"tool": "paramspider", "error": str(e)})
        print(f"[STEP 2] ParamSpider error: {e}")
        traceback.print_exc()

    # Step 3: BeautifulSoup — Form Extraction
    try:
        # Use Katana URLs if available, otherwise just scan the target
        urls_to_scan = katana_urls if katana_urls else [target_url]
        print(f"\n[STEP 3] Running form scanner on {len(urls_to_scan)} URLs...")
        form_endpoints = run_form_scanner(urls_to_scan)
    except Exception as e:
        errors.append({"tool": "beautifulsoup", "error": str(e)})
        print(f"[STEP 3] Form scanner error: {e}")
        traceback.print_exc()

    # Step 4: Normalize
    print("\n[STEP 4] Normalizing results...")
    result = normalize(target_url, katana_urls, paramspider_endpoints, form_endpoints)

    # Attach errors if any tools failed
    if errors:
        result["errors"] = errors

    print(f"\n{'='*50}")
    print(f"[SCAN] Complete for: {target_url}")
    print(f"{'='*50}\n")

    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True, port=5000)

