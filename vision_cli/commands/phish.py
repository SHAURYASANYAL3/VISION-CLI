import json
import urllib.request
import ssl
import socket
import datetime
import re
import os
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from rich.table import Table

def get_session():
    """Returns a requests Session with exponential backoff retries."""
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[ 429, 500, 502, 503, 504 ])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def execute(args, config, console, RICH_ENABLED):
    result = {"status": "success", "url": args.url, "risk_score": 0, "indicators": []}
    parsed = urlparse(args.url)
    domain = parsed.netloc or parsed.path
    
    session = get_session()
    
    vt_key = os.environ.get("VISION_VT_API_KEY") or config.get("api_keys", {}).get("virustotal", "")
    if vt_key:
        try:
            headers = {"x-apikey": vt_key}
            vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            resp = session.get(vt_url, headers=headers, timeout=5)
            if resp.status_code == 200:
                stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                phishing = stats.get("phishing", 0)
                if malicious > 0 or phishing > 0:
                    result["indicators"].append(f"CRITICAL: VirusTotal flagged this domain! (Malicious: {malicious}, Phishing: {phishing})")
                    result["risk_score"] += 100
        except Exception:
            pass
            
    try:
        ps_url = f"https://phishstats.info:2096/api/phishing?_where=(url,eq,{args.url})"
        resp = session.get(ps_url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) > 0:
                result["indicators"].append("CRITICAL: URL found in live PhishStats malicious database!")
                result["risk_score"] += 100
    except Exception:
        pass

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
    except Exception:
        result["indicators"].append("Failed to verify secure SSL/TLS connection")
        result["risk_score"] += 25

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
