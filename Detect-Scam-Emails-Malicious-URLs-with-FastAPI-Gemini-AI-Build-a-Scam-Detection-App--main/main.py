from flask import Flask, render_template, request
# NEW import style for the modern Google GenAI SDK
from google import genai
import os
import PyPDF2
from dotenv import load_dotenv
import requests
import json

# Load environment variables from .env file (local dev)
load_dotenv()

app = Flask(__name__)

# get keys from env
# NOTE: we pass this API key to the genai.Client below to avoid relying on an exact env var name
GEMINI_API_KEY = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

if not GEMINI_API_KEY:
    raise ValueError("GOOGLE_API_KEY or GEMINI_API_KEY not found. Please set it as an environment variable.")

# --- NEW: create a client instance for the GenAI SDK ---
# We pass api_key explicitly so it's clear and works in Render env.
client = genai.Client(api_key=GEMINI_API_KEY)

# Helper to call the model (replaces old model = genai.GenerativeModel(...))
MODEL_NAME = "gemini-2.5-flash"

def generate_from_gemini(prompt: str, max_output_tokens: int | None = None):
    """Call the new client.models.generate_content and return text output."""
    # If you want extra control you can pass a config object; keep it simple for now.
    response = client.models.generate_content(
        model=MODEL_NAME,
        contents=prompt,
        # You can add generation config here using types.GenerateContentConfig if needed.
    )
    # new SDK exposes response.text for simple cases
    return getattr(response, "text", None)

# functions
def predict_fake_or_real_email_content(text):
    prompt = f"""
    You are an expert in identifying scam messages in text, email etc. Analyze the given text and classify it as:

    - Real/Legitimate (Authentic, safe message)
    - Scam/Fake (Phishing, fraud, or suspicious message)

    For the following Text:
    {text}

    Return a clear message indicating whether this content is real or a scam.
    If it is a scam, mention why it seems fraudulent. If it is real, state that it is legitimate.

    Only return the classification message and nothing else.
    """
    response_text = generate_from_gemini(prompt)
    return (response_text or "Classification failed.").strip()

# --- URL detection (unchanged logic, but uses new client for LLM fallback) ---
def safe_browsing_check(url):
    if not SAFE_BROWSING_API_KEY:
        return None

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
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return "Invalid URL"

    classification = safe_browsing_check(url)

    if classification == "Safe" or classification is None:
        prompt = f"""
        You are a cybersecurity AI. Classify the following URL as one of:
        - Safe
        - Phishing
        - Malware
        - Defacement

        URL: {url}
        Return only the category, no extra text.
        """
        response_text = generate_from_gemini(prompt)
        if response_text:
            category = response_text.strip().split()[0].capitalize()
            if category not in ["Safe", "Phishing", "Malware", "Defacement"]:
                return "Unknown"
            return category + " (LLM Fallback)"

    return classification

# Routes (unchanged)
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

    message = predict_fake_or_real_email_content(extracted_text)
    return render_template("index.html", message=message, detection_type="scam_email")

@app.route('/predict', methods=['POST'])
def predict_url():
    url = request.form.get('url', '').strip()
    if not url.startswith(("http://", "https://")):
        return render_template("index.html", url_error="Invalid URL format. Must start with http:// or https://", input_url=url)
    classification = url_detection(url)
    return render_template("index.html", input_url=url, predicted_class=classification, detection_type="url_check")

if __name__ == '__main__':
    # In production set debug=False and use a proper WSGI server or Render's default web start
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
