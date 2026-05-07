import whois
from datetime import datetime

def check_domain_age(url):
    """Checks domain age. New domains are considered high risk."""
    try:
        domain = whois.whois(url)
        creation_date = domain.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        age_days = (datetime.now() - creation_date).days
        return f"Domain age is {age_days} days. (Recent registration is a high-risk indicator)."
    except:
        return "WHOIS data unreachable. Domain status: Suspicious."

import os
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

def check_virustotal_reputation(url):
    """Checks the URL reputation using VirusTotal API, if the key is provided."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    if not api_key or api_key.strip() == "":
        return "Threat Intel API (VirusTotal): [SKIPPED] No API Key provided in .env."

    try:
        domain = urlparse(url).netloc
        if not domain:
            domain = url
            
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        
        # We query the domain report
        vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(vt_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            if malicious > 0 or suspicious > 0:
                return f"Threat Intel API (VirusTotal): DANGER! Domain flagged by {malicious} security vendors as malicious and {suspicious} as suspicious."
            else:
                return "Threat Intel API (VirusTotal): SECURE. Domain is not flagged by any security vendors."
        elif response.status_code == 404:
            return "Threat Intel API (VirusTotal): Clean/Unknown. No malicious records found for this domain."
        else:
            return f"Threat Intel API (VirusTotal): API Error {response.status_code}."
            
    except Exception as e:
        return f"Threat Intel API (VirusTotal): Query failed ({str(e)})."

import base64
from io import BytesIO
try:
    from PyPDF2 import PdfReader
except ImportError:
    PdfReader = None

def unshorten_url(url: str) -> str:
    """Attempts to resolve shortened URLs (like bit.ly) to their destination."""
    try:
        r = requests.head(url, allow_redirects=True, timeout=5)
        return r.url
    except:
        return url

def extract_text_from_pdf(base64_data: str) -> str:
    """Extracts raw text from a base64 encoded PDF file."""
    if not PdfReader:
        return "[PDF ERROR: PyPDF2 is not installed on the system]"
        
    try:
        # Strip potential data URI headers
        if "base64," in base64_data:
            base64_data = base64_data.split("base64,")[1]
            
        pdf_bytes = base64.b64decode(base64_data)
        reader = PdfReader(BytesIO(pdf_bytes))
        
        extracted_text = []
        # Only read up to first 5 pages to prevent prompt injection overflow
        max_pages = min(5, len(reader.pages))
        for i in range(max_pages):
            page_text = reader.pages[i].extract_text()
            if page_text:
                extracted_text.append(page_text)
                
        full_text = "\n".join(extracted_text)
        if not full_text.strip():
            return "[PDF contains no readable text or is image-based]"
            
        return full_text
    except Exception as e:
        return f"[PDF Parsing Error: {str(e)}]"