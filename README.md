# VISION-CLI v3.0

VISION-CLI is an advanced, enterprise-grade threat intelligence and cybercrime prevention CLI built in Python. Designed to stop data leaks, detect AI-generated media, and block phishing attacks—all from your terminal.

## Features (v3.0)

### 1. 🕵️ Leak Scanner (`leak`)
Scans files and directories for hardcoded secrets, passwords, and PII.
*   **Regex Engine**: Detects common secrets (API keys, tokens, emails).
*   **Deep Vision OCR**: Using `pytesseract`, the scanner can extract text from images and screenshots to detect passwords leaked visually.

### 2. 🤖 AI Morph Checker (`morph`)
Analyzes images to determine if they are authentic or AI-generated.
*   **Deep Learning Pipeline**: Leverages HuggingFace `transformers` and PyTorch to run pixel-level inference on images.
*   **Batch Scanning**: Capable of scanning entire directories of `.jpg`, `.png`, and `.webp` images simultaneously.
*   **Metadata Fallback**: If ML libraries aren't installed, it falls back to a binary signature scan to detect common AI tools (Midjourney, DALL-E) and traditional editors (Photoshop).

### 3. 🚨 Breach Lookup (`breach`)
Checks if an email address has been compromised in a known data breach.
*   **Live Threat Intel**: Directly queries the `XposedOrNot` API over the network in real-time. No API key required.

### 4. 🎣 Phish Analyzer (`phish`)
Scans URLs and domains for phishing indicators.
*   **Live Database**: Queries the `PhishStats` live threat database to see if the URL is actively malicious.
*   **Heuristic Scoring**: Analyzes URL structure for suspicious TLDs, excessive subdomains, and IP-masking.
*   **SSL Verification**: Connects over the network to inspect the SSL certificate age and validity.

### 5. 🏢 Enterprise Ready
*   **JSON Pipelines**: Append `--json` to any command to suppress standard output and receive a structured JSON blob, perfect for CI/CD integration (e.g., GitHub Actions, SIEM ingestion).
*   **Config Management**: Automatically generates a `config.yaml` to securely store future API keys.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/SHAURYASANYAL3/VISION-CLI.git
   cd VISION-CLI
   ```

2. Install the core requirements:
   ```bash
   pip install -r requirements.txt
   ```
   *(Note: Installing PyTorch and Transformers for the AI morph checker requires a substantial download.)*

3. **(Optional)** Install Tesseract-OCR on your host OS for the `leak` command's visual text extraction capabilities.

## Usage

**Global Flags:**
*   `--json`: Output results in JSON format.

**Command Examples:**

```bash
# Scan a directory for text and visual (OCR) leaks
python cli.py leak "/path/to/project"

# Check if an image (or folder of images) is AI-generated
python cli.py morph "/path/to/image.jpg"

# Check if an email is in a dark web database
python cli.py breach "admin@example.com"

# Analyze a suspicious link
python cli.py phish "http://suspicious-login.xyz"
```
