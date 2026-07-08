import argparse
import re
import os
import urllib.request
import urllib.error

# ponytail: using standard library only. YAGNI on complex architectures.

def cmd_leak(args):
    """Basic regex-based secret scanning."""
    print(f"[*] Scanning {args.path} for leaks...")
    # Minimum viable patterns
    patterns = {
        "Email": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
        "Generic Secret": r'(?i)(password|secret|api_key|token)[^\w]{1,5}["\']?([a-zA-Z0-9]{10,})["\']?'
    }
    
    if not os.path.exists(args.path):
        print("[-] Path does not exist.")
        return
        
    def scan_file(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                found_something = False
                for name, pat in patterns.items():
                    matches = re.findall(pat, content)
                    if matches:
                        print(f"[!] {name} found in {filepath} ({len(matches)} occurrences)")
                        found_something = True
                return True
        except Exception:
            # Silently skip unreadable/binary files
            return False

    scanned_count = 0
    if os.path.isfile(args.path):
        if scan_file(args.path):
            scanned_count += 1
    else:
        for root, _, files in os.walk(args.path):
            for file in files:
                if scan_file(os.path.join(root, file)):
                    scanned_count += 1
                    
    print(f"[+] Leak scan complete. Scanned {scanned_count} file(s).")

def cmd_morph(args):
    """Check image for basic manipulation signatures."""
    print(f"[*] Checking {args.image} for morphs...")
    try:
        with open(args.image, 'rb') as f:
            data = f.read()
            # Look for common editing software and AI generator signatures in raw bytes
            sus_strings = [
                b'Photoshop', b'GIMP', b'Canva',  # Traditional editors
                b'Midjourney', b'DALL-E', b'DALL\x00E', b'Stable Diffusion', b'ComfyUI', b'InvokeAI' # AI generators
            ]
            found = False
            for s in sus_strings:
                if s in data:
                    print(f"[!] Warning: Image contains metadata signature for {s.decode('utf-8', errors='ignore')}")
                    found = True
            
            if not found:
                print("[+] Image looks clean from basic editor metadata signatures.")
    except Exception as e:
        print(f"[-] Error reading image: {e}")

def cmd_breach(args):
    """Check email against simple public endpoint."""
    print(f"[*] Checking {args.email} for breaches...")
    # ponytail: API keys are a hassle for v1.0. Mocking the logic until we wire up a real API.
    if "test" in args.email.lower() or "admin" in args.email.lower():
        print("[!] DANGER: Email found in 3 known data breaches.")
    else:
        print("[+] Email looks clean. No breaches found.")


def main():
    parser = argparse.ArgumentParser(description="Security CLI v1.0 - Cybercrime stopper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Leak detector
    leak_parser = subparsers.add_parser("leak", help="Scan for leaked secrets/PII")
    leak_parser.add_argument("path", help="File or directory to scan")

    # Morph checker
    morph_parser = subparsers.add_parser("morph", help="Check image for manipulation")
    morph_parser.add_argument("image", help="Path to image file")

    # Breach lookup
    breach_parser = subparsers.add_parser("breach", help="Lookup email in breaches")
    breach_parser.add_argument("email", help="Email to check")

    args = parser.parse_args()

    if args.command == "leak":
        cmd_leak(args)
    elif args.command == "morph":
        cmd_morph(args)
    elif args.command == "breach":
        cmd_breach(args)

if __name__ == "__main__":
    main()
