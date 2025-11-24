from flask import Flask, render_template, request
import google.generativeai as genai
import os
import PyPDF2
from dotenv import load_dotenv
import requests # New Import for API Calls
import json # New Import for API Calls

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# --- CRITICAL FIX: Get the API Keys from the environment ---
# Gemini API Key for content analysis
GEMINI_API_KEY = os.environ.get("GOOGLE_API_KEY")
# Safe Browsing API Key for high-accuracy URL detection
SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

if not GEMINI_API_KEY:
    # We must have the Gemini key for content analysis
    raise ValueError("GOOGLE_API_KEY not found. Please ensure it is set in your .env file.")

# Set up the Google API Key and configure genai
genai.configure(api_key=GEMINI_API_KEY)

# Initialize the Gemini model
model = genai.GenerativeModel("gemini-2.5-flash")

# functions
def predict_fake_or_real_email_content(text):
    prompt = f"""
    You are an expert in identifying scam messages in text, email etc. Analyze the given text and classify it as:

    - **Real/Legitimate** (Authentic, safe message)
    - **Scam/Fake** (Phishing, fraud, or suspicious message)

    **for the following Text:**
    {text}

    **Return a clear message indicating whether this content is real or a scam. 
    If it is a scam, mention why it seems fraudulent. If it is real, state that it is legitimate.**

    **Only return the classification message and nothing else.**
    Note: Don't return empty or null, you only need to return message for the input text
    """

    response = model.generate_content(prompt)
    return response.text.strip() if response else "Classification failed."


# --- URL detection improvements ---
def safe_browsing_check(url):
    """Checks URL against Google Safe Browsing API for known threats."""
    if not SAFE_BROWSING_API_KEY:
        return None  # No API key, fallback to LLM

    threat_types = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]

    payload = {
        "client": {"clientId": "flask-app", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": threat_types,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(
            f"{SAFE_BROWSING_URL}?key={SAFE_BROWSING_API_KEY}",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        response.raise_for_status()
        matches = response.json().get("matches")
        if matches:
            threat_type = matches[0].get("threatType", "UNKNOWN").upper()
            # Map to simple categories
            if threat_type == "SOCIAL_ENGINEERING":
                return "Phishing"
            elif threat_type == "MALWARE":
                return "Malware"
            elif threat_type == "UNWANTED_SOFTWARE":
                return "Unsafe"
            else:
                return "Unknown"
        return "Safe"
    except requests.RequestException as e:
        print(f"Safe Browsing API Error: {e}")
        return None

def url_detection(url):
    """Determines URL safety using Safe Browsing first, then LLM fallback."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return "Invalid URL"

    classification = safe_browsing_check(url)

    # Trigger LLM fallback for Safe or Unknown results if URL is suspicious
    if classification == "Safe" or classification is None:
        # Use LLM to check the URL anyway
        prompt = f"""
        You are a cybersecurity AI. Classify the following URL as one of:
        - Safe
        - Phishing
        - Malware
        - Defacement

        URL: {url}
        Return only the category, no extra text.
        """
        response = model.generate_content(prompt)
        if response and hasattr(response, "text"):
            category = response.text.strip().split()[0].capitalize()
            if category not in ["Safe", "Phishing", "Malware", "Defacement"]:
                return "Unknown"
            return category + " (LLM Fallback)"
    
    return classification


# Routes

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/scam/', methods=['POST'])
def detect_scam():
    if 'file' not in request.files:
        return render_template("index.html", message="No file uploaded.")

    file = request.files['file']
    extracted_text = ""

    if file.filename.endswith('.pdf'):
        try:
            pdf_reader = PyPDF2.PdfReader(file)
            extracted_text = " ".join([page.extract_text() for page in pdf_reader.pages if page.extract_text()])
        except Exception as e:
            return render_template("index.html", message=f"Error reading PDF file: {e}")

    elif file.filename.endswith('.txt'):
        try:
            extracted_text = file.read().decode("utf-8")
        except:
            return render_template("index.html", message="Error reading TXT file.")
            
    else:
        return render_template("index.html", message="Invalid file type. Please upload a PDF or TXT file.")

    if not extracted_text.strip():
        return render_template("index.html", message="File is empty or text could not be extracted.")

    # Call the LLM to classify content
    message = predict_fake_or_real_email_content(extracted_text)
    
    return render_template("index.html", message=message, detection_type="scam_email")


@app.route('/predict', methods=['POST'])
def predict_url():
    url = request.form.get('url', '').strip()

    if not url.startswith(("http://", "https://")):
        # We need to render the input field so the user sees what they typed
        return render_template("index.html", url_error="Invalid URL format. Must start with http:// or https://", input_url=url)

    # Call the specialized URL detection function
    classification = url_detection(url)
    
    return render_template("index.html", input_url=url, predicted_class=classification, detection_type="url_check")


if __name__ == '__main__':
    # You should set debug=False for production
    app.run(debug=True)
