import argparse
import sys
import contextlib
import logging
import os

from vision_cli.core.config import load_config
from vision_cli.commands import leak, morph, breach, phish

LOG_FILE = os.path.expanduser("~/.vision_cli.log")
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("vision-cli")

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich.align import Align
    from rich.text import Text
    from rich.live import Live
    import time
    console = Console()
    RICH_ENABLED = True
except ImportError:
    class Console:
        def print(self, *args, **kwargs): print(*args)
        def status(self, *args, **kwargs): return contextlib.nullcontext()
    console = Console()
    RICH_ENABLED = False

def animated_banner():
    if RICH_ENABLED:
        banner = r"""
 __      __.___  _________ .___ ________    _______                _________ .____    .___ 
/  \    /  \   |/   _____/ |   |\_____  \   \      \               \_   ___ \|    |   |   |
\   \/\/   /   |\_____  \  |   | /   |   \  /   |   \    ______    /    \  \/|    |   |   |
 \        /|   |/        \ |   |/    |    \/    |    \  /_____/    \     \___|    |___|   |
  \__/\  / |___/_______  / |___|\_______  /\____|__  /              \______  /_______ \___|
       \/              \/               \/         \/                      \/        \/    
"""
        console.print(Align.center(f"[bold cyan]{banner}[/bold cyan]"))
        text_str = "Advanced Cybercrime Stopper v5.0 - Enterprise Edition"
        with Live(Text("", style="bold magenta", justify="center"), refresh_per_second=20, transient=False) as live:
            for i in range(len(text_str) + 1):
                live.update(Text(text_str[:i], style="bold magenta", justify="center"))
                time.sleep(0.01)
        print()

def main():
    try:
        parser = argparse.ArgumentParser(description="VISION-CLI v5.0 - Enterprise Cybercrime Stopper")
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
            if not args.json and RICH_ENABLED:
                from rich.panel import Panel
                console.print(Panel(f"Scanning [bold cyan]{args.path}[/bold cyan] for leaked secrets", title="VISION-CLI Leak Scanner", border_style="blue"))
                progress = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), console=console)
                task_id = progress.add_task("[cyan]Scanning files...", total=100)
                progress.start()
                progress_deps = (progress, task_id)
            else:
                progress_deps = (None, None)
            
            try:
                has_issues = leak.execute(args, config, console, RICH_ENABLED, progress_deps)
            finally:
                if progress_deps[0]:
                    progress_deps[0].stop()

        elif args.command == "morph":
            logger.info(f"Running morph scan on {args.image}")
            if not args.json and RICH_ENABLED:
                from rich.panel import Panel
                console.print(Panel(f"Analyzing [bold cyan]{args.image}[/bold cyan] for AI generation", title="VISION-CLI Morph Checker", border_style="magenta"))
                progress = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), console=console)
                task_id = progress.add_task("[magenta]Analyzing pixels...", total=100)
                progress.start()
                progress_deps = (progress, task_id)
            else:
                progress_deps = (None, None)
                
            try:
                has_issues = morph.execute(args, config, console, RICH_ENABLED, progress_deps)
            finally:
                if progress_deps[0]:
                    progress_deps[0].stop()

        elif args.command == "breach":
            logger.info(f"Checking breach for {args.email}")
            has_issues = breach.execute(args, config, console, RICH_ENABLED)
            
        elif args.command == "phish":
            logger.info(f"Checking phish URL {args.url}")
            has_issues = phish.execute(args, config, console, RICH_ENABLED)
            
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
