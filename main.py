from flask import Flask, render_template, request, send_file
import google.generativeai as genai
import os
import PyPDF2
import whois
import io
import requests
import socket
from bs4 import BeautifulSoup

app = Flask(__name__)

# Set up the Google API Key
os.environ["GOOGLE_API_KEY"] = "your_google-api"
genai.configure(api_key=os.environ["GOOGLE_API_KEY"])

# UPGRADED TO LATEST STABLE MODEL
model = genai.GenerativeModel("gemini-2.5-flash")

# --- HELPER FUNCTIONS ---

def get_hosting_details(url):
    """Fetches technical evidence: IP, Registrar, and Name Servers"""
    try:
        domain = url.split("//")[-1].split("/")[0]
        # Get IP Address
        ip_address = socket.gethostbyname(domain)
        # Get WHOIS details
        w = whois.whois(domain)
        
        return {
            "ip": ip_address,
            "registrar": w.registrar if w.registrar else "Unknown Registrar",
            "name_servers": ", ".join(w.name_servers) if w.name_servers else "N/A",
            "org": w.org or "Privacy Protected"
        }
    except:
        return {"ip": "Not Found", "registrar": "Unknown", "name_servers": "N/A", "org": "N/A"}

def analyze_document_content(text):
    if not text.strip(): return "No text extracted."
    prompt = f"Analyze for scams. Provide Risk Level and explanation: \n\n {text[:3000]}"
    try:
        return model.generate_content(prompt).text
    except Exception as e:
        return f"Error: {str(e)}"

def url_detection(url):
    prompt = f"Classify this URL as 'Benign', 'Phishing', or 'Malware'. Reply with one word: {url}"
    try:
        return model.generate_content(prompt).text.strip().lower()
    except:
        return "unknown"

def screen_site_content(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, timeout=3, headers=headers)
        soup = BeautifulSoup(response.content, "html.parser")
        prompt = f"Is this a brand impersonation scam? {soup.get_text()[:1000]}"
        return model.generate_content(prompt).text.strip()
    except:
        return "Site unreachable. High phishing probability."

# --- ROUTES ---

@app.route('/')
def index():
    return render_template("index.html")

@app.route("/scam/", methods=['POST'])
def detect_scam():
    file = request.files.get('file')
    if not file: return render_template("index.html", message="No file.")
    
    try:
        if file.filename.endswith(".pdf"):
            reader = PyPDF2.PdfReader(file)
            text = " ".join([p.extract_text() for p in reader.pages if p.extract_text()])
        else:
            text = file.read().decode("utf-8")
        return render_template('index.html', message=analyze_document_content(text))
    except Exception as e:
        return render_template('index.html', message=f"Error: {str(e)}")

@app.route('/predict', methods=['POST'])
def predict_url():
    url = request.form.get('url', '').strip()
    if not url.startswith(('http://', 'https://')): url = 'http://' + url
    status = url_detection(url)
    return render_template("index.html", message=f"URL: {url}\nResult: {status.upper()}")

@app.route('/brand-scan', methods=['POST'])
def brand_protection():
    brand_query = request.form.get('brand_name', '').strip()
    brand = brand_query.lower().replace(" ", "")
    fake_sites = [f"http://{brand}-support.com", f"http://{brand.replace('o', '0')}-login.net"]
    
    results = []
    for site in fake_sites:
        results.append({"url": site, "status": url_detection(site), "proof": screen_site_content(site)})
    return render_template("index.html", brand_results=results, target_brand=brand_query)

@app.route('/generate-report', methods=['POST'])
def generate_report():
    url = request.form.get('url')
    brand = request.form.get('brand')
    proof = request.form.get('proof')
    
    # FETCH TECHNICAL PROOF
    tech = get_hosting_details(url)
    
    # IMPROVED LEGAL PROMPT
    prompt = f"""
    Write a formal Notice of Intellectual Property Infringement for {url} impersonating {brand}.
    
    Technical Evidence to include:
    - IP Address: {tech['ip']}
    - Domain Registrar: {tech['registrar']}
    - Name Servers: {tech['name_servers']}
    - Visual Proof: {proof}
    
    Ensure the report includes a formal signature line and a statement under penalty of perjury.
    """
    
    try:
        report_text = model.generate_content(prompt).text
    except Exception as e:
        report_text = f"Error generating report: {str(e)}"
    
    # CORRECT FILE STREAM HANDLING
    buffer = io.BytesIO()
    buffer.write(report_text.encode('utf-8'))
    buffer.seek(0)
    
    return send_file(
        buffer, 
        as_attachment=True, 
        download_name=f"LEGAL_NOTICE_{brand}.txt", 
        mimetype='text/plain'
    )

if __name__ =="__main__":
    app.run(debug=True)