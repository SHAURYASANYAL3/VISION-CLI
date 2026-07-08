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
import concurrent.futures
import contextlib
import logging
from urllib.parse import urlparse

LOG_FILE = os.path.expanduser("~/.vision_cli.log")
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("vision-cli")
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.table import Table
    from rich.panel import Panel
    console = Console()
    RICH_ENABLED = True
except ImportError:
    # Basic fallback if rich isn't installed yet
    class Console:
        def print(self, *args, **kwargs):
            print(*args)
        def status(self, *args, **kwargs):
            return contextlib.nullcontext()
    console = Console()
    RICH_ENABLED = False
    class Panel:
        def __init__(self, text, **kwargs): self.text = text
        def __str__(self): return self.text
    class Table:
        def __init__(self, **kwargs): self.rows = []
        def add_column(self, *args, **kwargs): pass
        def add_row(self, *args): self.rows.append(args)
        def __str__(self): return "\\n".join(str(r) for r in self.rows)

CONFIG_FILE = os.path.expanduser("~/.vision_cli_config.yaml")

def load_config():
    if not os.path.exists(CONFIG_FILE):
        default_config = {
            "api_keys": {
                "alienvault": "",
                "hibp": "",
                "virustotal": ""
            }
        }
        try:
            fd = os.open(CONFIG_FILE, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
            with open(fd, 'w') as f:
                yaml.dump(default_config, f)
        except Exception:
            pass
        return default_config
    
    with open(CONFIG_FILE, 'r') as f:
        config = yaml.safe_load(f) or {}
        if "api_keys" not in config:
            config["api_keys"] = {}
        if "virustotal" not in config["api_keys"]:
            config["api_keys"]["virustotal"] = ""
            try:
                fd = os.open(CONFIG_FILE, os.O_WRONLY | os.O_TRUNC, 0o600)
                with open(fd, 'w') as f:
                    yaml.dump(config, f)
            except Exception:
                pass
        return config

def cmd_leak(args, config):
    if not args.json and RICH_ENABLED:
        console.print(Panel(f"Scanning [bold cyan]{args.path}[/bold cyan] for leaked secrets", title="VISION-CLI Leak Scanner", border_style="blue"))
    elif not args.json:
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
            console.print("[bold red][-] Path does not exist.[/bold red]" if RICH_ENABLED else "[-] Path does not exist.")
        return
        
    def scan_file(filepath):
        findings = []
        ext = os.path.splitext(filepath)[1].lower()
        img_exts = {'.png', '.jpg', '.jpeg', '.webp', '.bmp', '.tiff'}
        
        if ext in img_exts:
            try:
                import pytesseract
                from PIL import Image
                img = Image.open(filepath)
                text = pytesseract.image_to_string(img)
                for name, pat in patterns.items():
                    matches = re.findall(pat, text)
                    if matches:
                        findings.append({"file": filepath, "type": name, "count": len(matches), "method": "ocr"})
                return True, findings
            except Exception:
                return False, []
                
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for chunk in iter(lambda: f.read(4096 * 1024), ''):
                    if not chunk:
                        break
                    for name, pat in patterns.items():
                        matches = re.findall(pat, chunk)
                        if matches:
                            findings.append({"file": filepath, "type": name, "count": len(matches), "method": "text"})
            return True, findings
        except Exception:
            return False, []

    files_to_scan = []
    if os.path.isfile(args.path):
        files_to_scan.append(args.path)
    else:
        for root, dirs, files in os.walk(args.path):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'node_modules']
            for file in files:
                if not file.startswith('.'):
                    files_to_scan.append(os.path.join(root, file))

    if not args.json and RICH_ENABLED:
        progress = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), console=console)
        task_id = progress.add_task("[cyan]Scanning files...", total=len(files_to_scan))
        progress.start()
    else:
        progress = None
        task_id = None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_file = {executor.submit(scan_file, f): f for f in files_to_scan}
        for future in concurrent.futures.as_completed(future_to_file):
            success, findings = future.result()
            if success:
                result["scanned_files"] += 1
                result["leaks_found"].extend(findings)
            if progress:
                progress.advance(task_id)

    if progress:
        progress.stop()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["leaks_found"]:
            if RICH_ENABLED:
                table = Table(title="[!] Leaks Discovered", style="red")
                table.add_column("File", style="cyan")
                table.add_column("Type", style="magenta")
                table.add_column("Occurrences", justify="right", style="green")
                table.add_column("Method", style="yellow")
                
                for leak in result["leaks_found"]:
                    table.add_row(leak["file"], leak["type"], str(leak["count"]), leak["method"])
                
                console.print(table)
            else:
                for leak in result["leaks_found"]:
                    print(f"[!] {leak['type']} found in {leak['file']} ({leak['count']} occurrences via {leak['method']})")
        else:
            console.print("\n[bold green][+] No leaks detected.[/bold green]" if RICH_ENABLED else "[+] No leaks detected.")
            
        console.print(f"\n[dim]Total files scanned: {result['scanned_files']}[/dim]" if RICH_ENABLED else f"Total files scanned: {result['scanned_files']}")
    return len(result["leaks_found"]) > 0

def cmd_morph(args, config):
    if not args.json and RICH_ENABLED:
        console.print(Panel(f"Analyzing [bold cyan]{args.image}[/bold cyan] for AI generation", title="VISION-CLI Morph Checker", border_style="magenta"))
    elif not args.json:
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
            console.print("[bold red][-] No images found to scan.[/bold red]" if RICH_ENABLED else "[-] No images found to scan.")
        return

    try:
        from PIL import Image
        from transformers import pipeline
        import logging
        logging.getLogger("transformers").setLevel(logging.ERROR)
        
        result["method"] = "advanced_ml_batch"
        if not args.json:
            console.print("[bold green][*] Advanced ML libraries active. Initializing Deep Learning pipeline...[/bold green]" if RICH_ENABLED else "[*] Advanced ML libraries active. Running pipeline...")
            
        pipe = pipeline("image-classification", model="umm-maybe/AI-image-detector")
        
        if not args.json and RICH_ENABLED:
            progress = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), console=console)
            task_id = progress.add_task("[magenta]Analyzing pixels...", total=len(files_to_scan))
            progress.start()
        else:
            progress = None
            task_id = None

        def scan_img(filepath):
            try:
                img = Image.open(filepath)
                return filepath, pipe(img)
            except Exception:
                return filepath, None

        # Limit to 2 workers for ML to prevent OOM
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_to_file = {executor.submit(scan_img, f): f for f in files_to_scan}
            for future in concurrent.futures.as_completed(future_to_file):
                filepath, predictions = future.result()
                if predictions:
                    file_findings = {"file": filepath, "predictions": []}
                    for res in predictions[:2]:
                        file_findings["predictions"].append({"label": res['label'], "confidence": res['score']})
                    result["findings"].append(file_findings)
                if progress:
                    progress.advance(task_id)
                    
        if progress:
            progress.stop()

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if RICH_ENABLED:
                table = Table(title="[*] Morph Analysis Results")
                table.add_column("File", style="cyan")
                table.add_column("Top Prediction", style="magenta")
                table.add_column("Confidence", justify="right", style="green")
                
                for finding in result["findings"]:
                    top = finding["predictions"][0]
                    table.add_row(finding["file"], top["label"], f"{round(top['confidence'] * 100, 2)}%")
                console.print(table)
            else:
                for finding in result["findings"]:
                    top = finding["predictions"][0]
                    print(f"{finding['file']} -> {top['label']}: {round(top['confidence'] * 100, 2)}%")
        return any(f["predictions"][0]["label"] in ["AI_GENERATED", "FAKE", "manipulated"] and f["predictions"][0]["confidence"] > 0.6 for f in result["findings"] if f["predictions"])

    except ImportError:
        result["method"] = "basic_metadata_batch"
        if not args.json:
            console.print("[bold yellow][!] ML libraries not found. Falling back to fast metadata scan.[/bold yellow]" if RICH_ENABLED else "[!] ML libraries not found. Falling back to fast metadata scan.")
        
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
                                console.print(f"[bold red][!] Warning: {filepath} contains signature for {sig}[/bold red]" if RICH_ENABLED else f"[!] Warning: {filepath} contains signature for {sig}")
            except Exception:
                continue
                
        if not args.json:
            console.print(f"[bold green][+] Metadata scan complete for {len(files_to_scan)} files.[/bold green]" if RICH_ENABLED else f"[+] Metadata scan complete for {len(files_to_scan)} files.")
        if args.json:
            print(json.dumps(result, indent=2))
        return len(result["findings"]) > 0

def cmd_breach(args, config):
    if not args.json and RICH_ENABLED:
        console.print(Panel(f"Looking up [bold cyan]{args.email}[/bold cyan] in global data breaches", title="VISION-CLI Breach Lookup", border_style="red"))
    elif not args.json:
        print(f"[*] Checking {args.email} for breaches...")
    
    result = {"status": "success", "email": args.email, "breaches": []}
    
    try:
        import requests
        
        with console.status("[bold green]Querying XposedOrNot threat intelligence API...") if not args.json and RICH_ENABLED else contextlib.nullcontext():
            response = requests.get(f"https://api.xposedornot.com/v1/check-email/{args.email}")
            
            if response.status_code == 200:
                data = response.json()
                breaches = data.get("breaches", [])
                for b in breaches:
                    result["breaches"].append(b[0] if isinstance(b, list) else b)
                    
                if not args.json:
                    if RICH_ENABLED:
                        console.print(f"\n[bold red][!] DANGER: Email found in {len(result['breaches'])} known data breaches![/bold red]")
                        table = Table(show_header=False, box=None)
                        for b in result['breaches'][:10]:
                            table.add_row(f"[red]• {b}[/red]")
                        if len(result['breaches']) > 10:
                            table.add_row(f"[dim]... and {len(result['breaches']) - 10} more.[/dim]")
                        console.print(table)
                    else:
                        print(f"[!] DANGER: Email found in {len(result['breaches'])} known data breaches!")
            elif response.status_code == 404:
                if not args.json:
                    console.print("\n[bold green][+] Email looks clean. No breaches found.[/bold green]" if RICH_ENABLED else "[+] Email looks clean. No breaches found.")
            else:
                if not args.json:
                    console.print(f"\n[bold yellow][-] API returned unexpected status code: {response.status_code}[/bold yellow]" if RICH_ENABLED else f"[-] API returned unexpected status code: {response.status_code}")
                
        if args.json:
            print(json.dumps(result, indent=2))
        return len(result["breaches"]) > 0
            
    except ImportError:
        if args.json:
            print(json.dumps({"status": "error", "message": "requests library not found"}))
        else:
            console.print("[bold red][!] 'requests' library not found. Run: pip install -r requirements.txt[/bold red]" if RICH_ENABLED else "[!] 'requests' library not found. Run: pip install -r requirements.txt")

def cmd_phish(args, config):
    if not args.json and RICH_ENABLED:
        console.print(Panel(f"Analyzing URL for phishing indicators:\n[bold cyan]{args.url}[/bold cyan]", title="VISION-CLI Phish Analyzer", border_style="yellow"))
    elif not args.json:
        print(f"[*] Analyzing URL for phishing indicators: {args.url}")
        
    result = {"status": "success", "url": args.url, "risk_score": 0, "indicators": []}
    
    parsed = urlparse(args.url)
    domain = parsed.netloc or parsed.path
    
    import requests
    
    # 1. VIRUS TOTAL INTEGRATION
    vt_key = os.environ.get("VISION_VT_API_KEY") or config.get("api_keys", {}).get("virustotal", "")
    if vt_key:
        if not args.json:
            console.print("[bold green][*] VirusTotal API key detected. Querying 70+ engines...[/bold green]" if RICH_ENABLED else "[*] VirusTotal API key detected. Querying 70+ engines...")
        try:
            headers = {"x-apikey": vt_key}
            vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            resp = requests.get(vt_url, headers=headers, timeout=5)
            if resp.status_code == 200:
                stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                phishing = stats.get("phishing", 0)
                if malicious > 0 or phishing > 0:
                    result["indicators"].append(f"CRITICAL: VirusTotal flagged this domain! (Malicious: {malicious}, Phishing: {phishing})")
                    result["risk_score"] += 100
        except Exception as e:
            if not args.json:
                console.print(f"[dim]VirusTotal query failed: {e}[/dim]" if RICH_ENABLED else f"VirusTotal query failed: {e}")
    
    # 2. PhishStats
    try:
        ps_url = f"https://phishstats.info:2096/api/phishing?_where=(url,eq,{args.url})"
        resp = requests.get(ps_url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) > 0:
                result["indicators"].append("CRITICAL: URL found in live PhishStats malicious database!")
                result["risk_score"] += 100
    except Exception:
        pass

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
        s = socket.create_connection((domain, 443), timeout=3.0)
        with ctx.wrap_socket(s, server_hostname=domain) as ss:
            ss.settimeout(3.0)
            cert = ss.getpeercert()
            not_before = datetime.datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
            age = (datetime.datetime.utcnow() - not_before).days
            if age < 30:
                result["indicators"].append(f"SSL certificate is very new ({age} days old)")
                result["risk_score"] += 30
    except Exception as e:
        result["indicators"].append(f"Failed to verify secure SSL/TLS connection")
        result["risk_score"] += 25

    # Determine verdict
    if result["risk_score"] >= 60:
        verdict = "CRITICAL RISK (Highly likely phishing)"
        color = "red"
    elif result["risk_score"] >= 30:
        verdict = "MODERATE RISK (Suspicious indicators found)"
        color = "yellow"
    else:
        verdict = "LOW RISK (Looks generally safe)"
        color = "green"
        
    result["verdict"] = verdict

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if RICH_ENABLED:
            console.print(f"\n[*] Risk Score: [bold {color}]{result['risk_score']}/100[/bold {color}]")
            console.print(f"[*] Verdict: [bold {color}]{verdict}[/bold {color}]\n")
            
            if result["indicators"]:
                table = Table(title="[!] Suspicious Indicators", show_header=False, style="yellow")
                for ind in result["indicators"]:
                    table.add_row(ind)
                console.print(table)
        else:
            print(f"[*] Risk Score: {result['risk_score']}/100")
            print(f"[*] Verdict: {verdict}")
    return result["risk_score"] >= 60

def animated_banner():
    if RICH_ENABLED:
        import time
        from rich.align import Align
        from rich.text import Text
        from rich.live import Live
        banner = r"""
 __      __.___  _________ .___ ________    _______                _________ .____    .___ 
/  \    /  \   |/   _____/ |   |\_____  \   \      \               \_   ___ \|    |   |   |
\   \/\/   /   |\_____  \  |   | /   |   \  /   |   \    ______    /    \  \/|    |   |   |
 \        /|   |/        \ |   |/    |    \/    |    \  /_____/    \     \___|    |___|   |
  \__/\  / |___/_______  / |___|\_______  /\____|__  /              \______  /_______ \___|
       \/              \/               \/         \/                      \/        \/    
"""
        console.print(Align.center(f"[bold cyan]{banner}[/bold cyan]"))
        
        text_str = "Advanced Cybercrime Stopper v4.0 - Initiating Systems..."
        with Live(Text("", style="bold magenta", justify="center"), refresh_per_second=20, transient=False) as live:
            for i in range(len(text_str) + 1):
                live.update(Text(text_str[:i], style="bold magenta", justify="center"))
                time.sleep(0.02)
        print()

def main():
    import sys
    try:
        parser = argparse.ArgumentParser(description="VISION-CLI v4.0 - Advanced Cybercrime Stopper")
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

        if not args.json:
            animated_banner()

        has_issues = False
        if args.command == "leak":
            logger.info(f"Running leak scan on {args.path}")
            has_issues = cmd_leak(args, config)
        elif args.command == "morph":
            logger.info(f"Running morph scan on {args.image}")
            has_issues = cmd_morph(args, config)
        elif args.command == "breach":
            logger.info(f"Checking breach for {args.email}")
            has_issues = cmd_breach(args, config)
        elif args.command == "phish":
            logger.info(f"Checking phish URL {args.url}")
            has_issues = cmd_phish(args, config)
            
        if has_issues:
            sys.exit(1)

    except KeyboardInterrupt:
        logger.info("User aborted process (KeyboardInterrupt)")
        console.print("\n[bold yellow][!] Process aborted by user.[/bold yellow]")
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        console.print(f"\n[bold red][!] An unexpected error occurred. Check {LOG_FILE} for details.[/bold red]")

if __name__ == "__main__":
    main()
