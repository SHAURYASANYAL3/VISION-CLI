import json
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from rich.table import Table

def get_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[ 429, 500, 502, 503, 504 ])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def execute(args, config, console, RICH_ENABLED):
    result = {"status": "success", "email": args.email, "breaches": []}
    session = get_session()
    
    try:
        response = session.get(f"https://api.xposedornot.com/v1/check-email/{args.email}", timeout=5)
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
            
    except Exception:
        if not args.json:
            console.print("[bold red][!] Network error querying API.[/bold red]" if RICH_ENABLED else "[!] Network error querying API.")
            
    if args.json:
        print(json.dumps(result, indent=2))
    return len(result["breaches"]) > 0
