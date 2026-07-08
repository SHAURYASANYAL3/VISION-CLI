import argparse
import re
import os
import json
import urllib.request
import urllib.error
import yaml
import socket
import ssl
import datetime
from urllib.parse import urlparse

CONFIG_FILE = "config.yaml"

def load_config():
    if not os.path.exists(CONFIG_FILE):
        default_config = {
            "api_keys": {
                "alienvault": "",
                "hibp": ""
            }
        }
        with open(CONFIG_FILE, 'w') as f:
            yaml.dump(default_config, f)
        return default_config
    
    with open(CONFIG_FILE, 'r') as f:
        return yaml.safe_load(f) or {}

def cmd_leak(args, config):
    if not args.json:
        print(f"[*] Scanning {args.path} for leaks...")
    
    patterns = {
        "Email": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
        "Generic Secret": r'(?i)(password|secret|api_key|token)[^\w]{1,5}["\']?([a-zA-Z0-9]{10,})["\']?'
    }
    
    result = {"status": "success", "scanned_files": 0, "leaks_found": []}
    
    if not os.path.exists(args.path):
        if args.json:
            print(json.dumps({"status": "error", "message": "Path does not exist"}))
        else:
            print("[-] Path does not exist.")
        return
        
    def scan_text(content, filepath, method="text"):
        found_something = False
        for name, pat in patterns.items():
            matches = re.findall(pat, content)
            if matches:
                result["leaks_found"].append({"file": filepath, "type": name, "count": len(matches), "method": method})
                if not args.json:
                    print(f"[!] {name} found in {filepath} ({len(matches)} occurrences via {method})")
                found_something = True
        return found_something

    def scan_file(filepath):
        # First, try to read as text
        try:
            with open(filepath, 'r', encoding='utf-8', errors='strict') as f:
                content = f.read()
            scan_text(content, filepath, "text")
            return True
        except UnicodeDecodeError:
            # If it's a binary file, see if it's an image and try OCR
            try:
                import pytesseract
                from PIL import Image
                img = Image.open(filepath)
                # Ensure tesseract is installed on the system
                text = pytesseract.image_to_string(img)
                scan_text(text, filepath, "ocr")
                return True
            except ImportError:
                if not args.json:
                    print(f"[-] OCR skipped for {filepath}: pytesseract or PIL not installed.")
                return False
            except Exception as e:
                # Not an image or tesseract not configured properly
                return False
        except Exception:
            return False

    if os.path.isfile(args.path):
        if scan_file(args.path):
            result["scanned_files"] += 1
    else:
        for root, _, files in os.walk(args.path):
            for file in files:
                if scan_file(os.path.join(root, file)):
                    result["scanned_files"] += 1
                    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[+] Leak scan complete. Scanned {result['scanned_files']} file(s).")

def cmd_morph(args, config):
    if not args.json:
        print(f"[*] Checking {args.image} for morphs...")
    
    result = {"status": "success", "target": args.image, "method": "", "findings": []}
    files_to_scan = []
    
    if os.path.isfile(args.image):
        files_to_scan.append(args.image)
    elif os.path.isdir(args.image):
        for root, _, files in os.walk(args.image):
            for file in files:
                if file.lower().endswith(('.png', '.jpg', '.jpeg', '.webp')):
                    files_to_scan.append(os.path.join(root, file))
    
    if not files_to_scan:
        if args.json:
            print(json.dumps({"status": "error", "message": "No images found"}))
        else:
            print("[-] No images found to scan.")
        return

    try:
        from PIL import Image
        from transformers import pipeline
        import logging
        logging.getLogger("transformers").setLevel(logging.ERROR)
        
        result["method"] = "advanced_ml_batch"
        if not args.json:
            print(f"[*] Advanced ML libraries found. Running Deep Learning scan on {len(files_to_scan)} images...")
            
        pipe = pipeline("image-classification", model="umm-maybe/AI-image-detector")
        
        for filepath in files_to_scan:
            try:
                img = Image.open(filepath)
                predictions = pipe(img)
                file_findings = {"file": filepath, "predictions": []}
                for res in predictions[:2]:
                    file_findings["predictions"].append({"label": res['label'], "confidence": res['score']})
                    if not args.json:
                        print(f"[+] {filepath} -> {res['label']}: {round(res['score'] * 100, 2)}% confidence")
                result["findings"].append(file_findings)
            except Exception as e:
                pass # Skip broken images
        
        if args.json:
            print(json.dumps(result, indent=2))

    except ImportError:
        result["method"] = "basic_metadata_batch"
        if not args.json:
            print("[!] ML libraries not found. Falling back to v1.0 metadata scan.")
        
        for filepath in files_to_scan:
            try:
                with open(filepath, 'rb') as f:
                    data = f.read()
                    sus_strings = [
                        b'Photoshop', b'GIMP', b'Canva',
                        b'Midjourney', b'DALL-E', b'DALL\x00E', b'Stable Diffusion', b'ComfyUI', b'InvokeAI'
                    ]
                    for s in sus_strings:
                        if s in data:
                            sig = s.decode('utf-8', errors='ignore')
                            result["findings"].append({"file": filepath, "signature_found": sig})
                            if not args.json:
                                print(f"[!] Warning: {filepath} contains metadata signature for {sig}")
            except Exception:
                continue
                
        if not args.json:
            print(f"[+] Metadata scan complete for {len(files_to_scan)} files.")
        if args.json:
            print(json.dumps(result, indent=2))

def cmd_breach(args, config):
    if not args.json:
        print(f"[*] Checking {args.email} for breaches...")
    
    result = {"status": "success", "email": args.email, "breaches": []}
    
    try:
        import requests
        if not args.json:
            print("[*] Querying XposedOrNot threat intelligence API...")
            
        # Using XposedOrNot, a free alternative to HIBP that requires no API key
        response = requests.get(f"https://api.xposedornot.com/v1/check-email/{args.email}")
        
        if response.status_code == 200:
            data = response.json()
            breaches = data.get("breaches", [])
            for b in breaches:
                result["breaches"].append(b[0] if isinstance(b, list) else b)
                
            if not args.json:
                print(f"[!] DANGER: Email found in {len(result['breaches'])} known data breaches!")
                for b in result['breaches'][:5]:
                    print(f"    - {b}")
                if len(result['breaches']) > 5:
                    print("    ... and more.")
        elif response.status_code == 404:
            if not args.json:
                print("[+] Email looks clean. No breaches found.")
        else:
            if not args.json:
                print(f"[-] API returned unexpected status code: {response.status_code}")
                
        if args.json:
            print(json.dumps(result, indent=2))
            
    except ImportError:
        if args.json:
            print(json.dumps({"status": "error", "message": "requests library not found"}))
        else:
            print("[!] 'requests' library not found. Run: pip install -r requirements.txt")

def cmd_phish(args, config):
    if not args.json:
        print(f"[*] Analyzing URL for phishing indicators: {args.url}")
        
    result = {"status": "success", "url": args.url, "risk_score": 0, "indicators": []}
    
    parsed = urlparse(args.url)
    domain = parsed.netloc or parsed.path
    
    # 1. LIVE API THREAT INTEL (PhishStats)
    try:
        import requests
        if not args.json:
            print("[*] Querying Live Threat Databases (PhishStats)...")
        # PhishStats API for known malicious URLs
        ps_url = f"https://phishstats.info:2096/api/phishing?_where=(url,eq,{args.url})"
        # Add timeout to not block forever
        resp = requests.get(ps_url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) > 0:
                result["indicators"].append("CRITICAL: URL found in live PhishStats malicious database!")
                result["risk_score"] += 100
        else:
            if not args.json:
                print("[-] Could not reach PhishStats API.")
    except Exception as e:
        if not args.json:
            print(f"[-] Live threat query failed: {e}")

    # Heuristics
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        result["indicators"].append("Uses IP address instead of domain name")
        result["risk_score"] += 40
        
    sus_tlds = ['.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq']
    if any(domain.endswith(tld) for tld in sus_tlds):
        result["indicators"].append("Uses historically suspicious Top Level Domain (TLD)")
        result["risk_score"] += 30
        
    if len(domain.split('.')) > 4:
        result["indicators"].append("Excessive subdomains (common in credential harvesting)")
        result["risk_score"] += 20
        
    # SSL Check
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3.0)
            s.connect((domain, 443))
            cert = s.getpeercert()
            
            not_before = datetime.datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
            age = (datetime.datetime.utcnow() - not_before).days
            
            if age < 30:
                result["indicators"].append(f"SSL certificate is very new ({age} days old)")
                result["risk_score"] += 30
    except Exception as e:
        result["indicators"].append(f"Failed to verify secure SSL/TLS connection: {str(e)[:50]}")
        result["risk_score"] += 25

    # Determine verdict
    if result["risk_score"] >= 60:
        verdict = "CRITICAL RISK (Highly likely phishing)"
    elif result["risk_score"] >= 30:
        verdict = "MODERATE RISK (Suspicious indicators found)"
    else:
        verdict = "LOW RISK (Looks generally safe)"
        
    result["verdict"] = verdict

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[*] Risk Score: {result['risk_score']}/100")
        print(f"[*] Verdict: {verdict}")
        if result["indicators"]:
            print("[!] Suspicious Indicators Found:")
            for ind in result["indicators"]:
                print(f"    - {ind}")

def main():
    parser = argparse.ArgumentParser(description="VISION-CLI v3.0 - Advanced Cybercrime Stopper")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    
    subparsers = parser.add_subparsers(dest="command", required=True)

    leak_parser = subparsers.add_parser("leak", help="Scan for leaked secrets/PII")
    leak_parser.add_argument("path", help="File or directory to scan")

    morph_parser = subparsers.add_parser("morph", help="Check image for manipulation")
    morph_parser.add_argument("image", help="Path to image file")

    breach_parser = subparsers.add_parser("breach", help="Lookup email in live breaches")
    breach_parser.add_argument("email", help="Email to check")
    
    phish_parser = subparsers.add_parser("phish", help="Analyze URL for phishing indicators")
    phish_parser.add_argument("url", help="URL to analyze")

    args = parser.parse_args()
    config = load_config()

    if args.command == "leak":
        cmd_leak(args, config)
    elif args.command == "morph":
        cmd_morph(args, config)
    elif args.command == "breach":
        cmd_breach(args, config)
    elif args.command == "phish":
        cmd_phish(args, config)

if __name__ == "__main__":
    main()
