# VISION-CLI v5.0.0 (Enterprise Edition)

**VISION-CLI** is an advanced, enterprise-grade threat intelligence and cybercrime prevention CLI built in Python. Designed to stop data leaks, detect AI-generated media, and block phishing attacks—all from your terminal.

🚀 **New in v5.0**: A massive architectural overhaul delivering production-ready stability. Features include O(1) memory profiling with `mmap` for scanning 100GB+ files, Exponential Backoff for resilient API calls, strict zero-trust config permissions, and a modular plugin architecture tested with 100% Mock E2E coverage.

## Installation

The easiest way to install VISION-CLI is directly from PyPI (globally available on your system):

```bash
pip install vision-cli
```

### Manual Installation (from source)
1. Clone the repository:
   ```bash
   git clone https://github.com/SHAURYASANYAL3/VISION-CLI.git
   cd VISION-CLI
   ```
2. Install via pip:
   ```bash
   pip install .
   ```
*(Note: Installing PyTorch and Transformers for the AI morph checker requires a substantial download. You can also install Tesseract-OCR on your host OS for the `leak` command's visual text extraction capabilities.)*

## Features

### 1. 🕵️ Leak Scanner (`leak`)
Scans files and directories for hardcoded secrets, passwords, and PII using an ultra-fast multi-threaded scanner. Now automatically ignores noisy directories like `.git` and `node_modules`.
*   **Regex Engine**: Detects common secrets (API keys, tokens, emails).
*   **Deep Vision OCR**: Using `pytesseract`, the scanner can extract text from images to detect passwords leaked visually.

### 2. 🤖 AI Morph Checker (`morph`)
Analyzes images to determine if they are authentic or AI-generated.
*   **Deep Learning Pipeline**: Leverages HuggingFace `transformers` to run pixel-level inference on images.
*   **Metadata Fallback**: If ML libraries aren't installed, it falls back to a signature scan to detect common AI tools (Midjourney, DALL-E) and traditional editors (Photoshop).

### 3. 🚨 Breach Lookup (`breach`)
Checks if an email address has been compromised in a known data breach using the `XposedOrNot` live API.

### 4. 🎣 Phish Analyzer (`phish`)
Scans URLs and domains for phishing indicators.
*   **VirusTotal Integration**: Query over 70+ security engines. (Requires API key, see configuration below).
*   **Live Database**: Queries `PhishStats`.
*   **Heuristic Scoring & SSL Verification**: Analyzes URL structure for suspicious indicators and inspects the SSL certificate age.

## Configuration & Environment Variables

VISION-CLI stores its configuration file at `~/.vision_cli_config.yaml`.
You can pass API keys via the config file, or ideally, through environment variables (perfect for CI/CD environments):

*   **VirusTotal API Key**: `VISION_VT_API_KEY`
    ```bash
    export VISION_VT_API_KEY="your_api_key_here"
    ```

## Usage

**Global Flags:**
*   `--json`: Output results in JSON format (suppresses the `rich` animated UI, ideal for scripts).

**Command Examples:**

```bash
# Scan a directory for text and visual (OCR) leaks
vision-cli leak "/path/to/project"

# Check if an image (or folder of images) is AI-generated
vision-cli morph "/path/to/image.jpg"

# Check if an email is in a dark web database
vision-cli breach "admin@example.com"

# Analyze a suspicious link
vision-cli phish "http://suspicious-login.xyz"
```

## Troubleshooting & Logs

If VISION-CLI crashes or encounters an unexpected error, a safe generic error will be shown on the terminal. Detailed diagnostic logs are saved to `~/.vision_cli.log`.

## Development & CI
This project uses automated GitHub Actions workflows to lint (flake8) and test (pytest) the code on every push.
```bash
pip install -r requirements.txt
pip install pytest flake8
pytest
flake8 vision_cli
```
