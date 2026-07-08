import os
import json
import concurrent.futures
from rich.table import Table

def scan_img(filepath, pipe):
    from PIL import Image
    try:
        img = Image.open(filepath)
        return filepath, pipe(img)
    except Exception:
        return filepath, None

def execute(args, config, console, RICH_ENABLED, progress_deps):
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
        return False

    try:
        from PIL import Image
        from transformers import pipeline
        import logging
        logging.getLogger("transformers").setLevel(logging.ERROR)
        
        result["method"] = "advanced_ml_batch"
        pipe = pipeline("image-classification", model="umm-maybe/AI-image-detector")
        
        progress, task_id = progress_deps
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_to_file = {executor.submit(scan_img, f, pipe): f for f in files_to_scan}
            for future in concurrent.futures.as_completed(future_to_file):
                filepath, predictions = future.result()
                if predictions:
                    file_findings = {"file": filepath, "predictions": []}
                    for res in predictions[:2]:
                        file_findings["predictions"].append({"label": res['label'], "confidence": res['score']})
                    result["findings"].append(file_findings)
                if progress:
                    progress.advance(task_id)

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
            except Exception:
                continue
                
        if args.json:
            print(json.dumps(result, indent=2))
        return len(result["findings"]) > 0
