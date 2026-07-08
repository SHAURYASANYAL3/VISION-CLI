import os
import re
import json
import concurrent.futures
import mmap
from rich.table import Table

# Pre-compile regex for performance
PATTERNS = {
    "Email": re.compile(b'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+'),
    "Generic Secret": re.compile(b'(?i)(password|secret|api_key|token)[^\\w]{1,5}["\']?([a-zA-Z0-9]{10,})["\']?')
}

IMG_EXTS = {'.png', '.jpg', '.jpeg', '.webp', '.bmp', '.tiff'}

def scan_file(filepath):
    """Scans a file efficiently using mmap for large files or targeted OCR for images."""
    findings = []
    ext = os.path.splitext(filepath)[1].lower()
    
    if ext in IMG_EXTS:
        try:
            import pytesseract
            from PIL import Image
            img = Image.open(filepath)
            text = pytesseract.image_to_string(img).encode('utf-8')
            for name, pat in PATTERNS.items():
                matches = pat.findall(text)
                if matches:
                    findings.append({"file": filepath, "type": name, "count": len(matches), "method": "ocr"})
            return True, findings
        except Exception:
            return False, []
            
    try:
        size = os.path.getsize(filepath)
        if size == 0:
            return True, []
            
        with open(filepath, 'rb') as f:
            # For small files, read entirely. For large files, memory map.
            if size < 10 * 1024 * 1024:
                content = f.read()
                for name, pat in PATTERNS.items():
                    matches = pat.findall(content)
                    if matches:
                        findings.append({"file": filepath, "type": name, "count": len(matches), "method": "text"})
            else:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    for name, pat in PATTERNS.items():
                        matches = pat.findall(mm)
                        if matches:
                            findings.append({"file": filepath, "type": name, "count": len(matches), "method": "mmap"})
        return True, findings
    except Exception:
        return False, []

def execute(args, config, console, RICH_ENABLED, progress_deps):
    files_to_scan = []
    if os.path.isfile(args.path):
        files_to_scan.append(args.path)
    else:
        for root, dirs, files in os.walk(args.path):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'node_modules']
            for file in files:
                if not file.startswith('.'):
                    files_to_scan.append(os.path.join(root, file))

    result = {"status": "success", "scanned_files": 0, "leaks_found": []}
    
    progress, task_id = progress_deps
    
    # Thread pool for concurrency
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, os.cpu_count() or 4 + 4)) as executor:
        future_to_file = {executor.submit(scan_file, f): f for f in files_to_scan}
        for future in concurrent.futures.as_completed(future_to_file):
            success, findings = future.result()
            if success:
                result["scanned_files"] += 1
                result["leaks_found"].extend(findings)
            if progress:
                progress.advance(task_id)

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
