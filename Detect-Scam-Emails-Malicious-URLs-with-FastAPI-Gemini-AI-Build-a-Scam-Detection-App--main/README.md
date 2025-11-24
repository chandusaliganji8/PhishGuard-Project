# Detect Scam Emails & Malicious URLs

A small web application that helps detect scam / phishing email content and classify URLs as benign or malicious using a two-layer approach:

- Layer 1: Google Safe Browsing API (fast, deterministic threat matches)
- Layer 2: Gemini (Google) generative AI model used as a fallback and to analyze email/text contents

This project provides a simple UI to upload text or PDF files (for email content analysis) and to paste/submit URLs (for URL classification). It is implemented in Python with Flask and served with Waitress for production-like serving.

## Features

- Classify email/text content as "Real/Legitimate" or "Scam/Fake" using a Gemini prompt-based classifier.
- Check URLs with Google Safe Browsing API to detect known threats (phishing, malware, social engineering, etc.).
- Use Gemini AI as a second-layer analysis for URL detection when Safe Browsing returns no matches.
- Accepts PDF and TXT uploads for email or document scanning.

## How it works (high level)

1. User uploads a .pdf or .txt file via the web form. The app extracts text (PyPDF2 for PDFs) and sends it to a Gemini prompt which returns a classification message.
2. For URLs, the app first queries Google Safe Browsing API. If a threat match is returned, the app shows the threat type. If Safe Browsing finds no threat, the same URL is analyzed by Gemini using a specialized prompt to classify it as benign, phishing, malware, or defacement.

This hybrid approach combines the reliability of a curated threat database (Safe Browsing) with an AI model that can analyze patterns and suspicious indicators when a URL is not in the database.

## Files

- main.py — Flask application containing routes, the Gemini prompts, Safe Browsing integration, file parsing logic, and the Waitress server call.
- templates/index.html — Simple web UI for file upload and URL submission.
- README.md — This file.

## Requirements

- Python 3.9+ (3.10/3.11 recommended)
- The app uses these Python packages (non-exhaustive):
	- Flask
	- waitress
	- google-generativeai
	- PyPDF2
	- python-dotenv
	- requests

If you prefer, create a virtual environment and install packages with pip. Example:

powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install flask waitress google-generativeai PyPDF2 python-dotenv requests


Alternatively, create a requirements.txt file with the packages above and run pip install -r requirements.txt.

## Environment / API keys

The application requires API keys stored in environment variables. Create a .env file in the same directory as main.py with the following keys:


GOOGLE_API_KEY=<your_gemini_api_key>
GOOGLE_SAFE_BROWSING_API_KEY=<your_google_safe_browsing_api_key>


- GOOGLE_API_KEY is used by the google.generativeai client to call the Gemini model.
- GOOGLE_SAFE_BROWSING_API_KEY is used to query the Safe Browsing v4 REST API for threat matches.

Keep these keys secret. Do not commit .env to source control.

## Run locally

1. Activate your virtual environment.
2. Ensure the .env file has the two API keys.
3. Start the app:

powershell
python main.py


The app uses waitress to serve on 0.0.0.0:5000 by default. Open your browser at http://localhost:5000/.

## Usage

- Email / Document scanning: Upload a .pdf or .txt file and submit the form. The server extracts text and sends it to Gemini for classification.
- URL checking: Paste a full URL (including http:// or https://) into the URL field and submit. The UI will show either a Safe Browsing match or the Gemini-classified label.

## Notes, limitations & safety

- Gemini responses are prompt-dependent and may occasionally produce incorrect classifications. Use the output as a guidance aid, not a definitive judgement.
- Google Safe Browsing is authoritative for known threats, but it does not detect every malicious site. That is why a fallback AI analysis is implemented.
- Running this app may incur API usage charges depending on your Gemini / Google Cloud account and usage patterns.
- The app sends text and URLs to external APIs (Gemini and Google Safe Browsing). Avoid uploading sensitive personal data.

## Security

- Store API keys in environment variables and restrict key permissions where possible.
- If deploying to production, serve the app behind HTTPS and enable proper access controls.

## Extending the project (suggestions)

- Add a requirements.txt and/or pyproject.toml for reproducible installs.
- Add unit tests for prompt formatting and URL parsing.
- Add logging and rate limiting for API calls.
- Implement server-side caching for Safe Browsing results to reduce API calls and cost.

## License

This repository does not include a license file. If you intend to share or distribute the code, add an appropriate LICENSE file (for example MIT, Apache 2.0, etc.).

## Contact / Attribution

If you need help running or extending the app, open an issue or reach out to the project owner.