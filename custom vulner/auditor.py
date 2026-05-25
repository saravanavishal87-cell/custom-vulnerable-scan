import argparse
import sys
import os
import requests
import urllib.parse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

# Import auditing engine components
from core.headers import HeaderAuditor
from core.cookies import CookieAuditor
from core.robots import RobotsAuditor
from core.reporter import ReportGenerator

BANNER = r"""
 _   _       _
| | | |     | |
| | | |_   _| | ___ __ _ _ __
| | | | | | | |/ __/ _` | '_ \
| |_| | |_| | | (_| (_| | | | |
 \___/ \__,_|_|\___\__,_|_| |_|

 Passive Web Security Configuration Auditor
"""

def print_banner(console: Console):
    console.print(Panel(
        BANNER.strip(),
        box=box.DOUBLE,
        style="bold color(99)",
        subtitle="v1.0.0 | Defensive Auditing Tool",
        subtitle_align="right"
    ))

def main():
    parser = argparse.ArgumentParser(description="Vulcan Passive Security Configuration Auditor")
    parser.add_argument("target", help="The target web application URL to audit (e.g., https://example.com)")
    parser.add_argument("--json", help="Path to write JSON report output", default="vulcan_report.json")
    parser.add_argument("--html", help="Path to write HTML report output", default="vulcan_report.html")
    parser.add_argument("--timeout", help="HTTP timeout in seconds", type=int, default=10)
    args = parser.parse_args()

    console = Console()
    print_banner(console)

    target_url = args.target
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    parsed = urllib.parse.urlparse(target_url)
    if not parsed.netloc:
        console.print(f"[bold red]Error:[/bold red] Invalid target URL format: '{args.target}'")
        sys.exit(1)

    console.print(Panel(
        f"[bold white]Target Host:[/bold white] {parsed.netloc}\n"
        f"[bold white]Target Scheme:[/bold white] {parsed.scheme}\n"
        f"[bold white]Target Address:[/bold white] {target_url}\n\n"
        "[bold yellow]DISCLAIMER:[/bold yellow] This passive auditor performs standard defensive configuration checks.\n"
        "No active exploitation payloads or fuzzing directives will be sent.",
        title="[bold color(99)]Audit Session Details[/bold color(99)]",
        box=box.ROUNDED
    ))

    # Initialize results structures
    audit_results = {
        "headers": {},
        "cookies": [],
        "robots": {}
    }

    try:
        with Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Step 1: Establish Connection & Retrieve Response Headers
            task1 = progress.add_task("[cyan]Connecting to target and fetching base headers...", total=1)
            headers_response = requests.get(target_url, timeout=args.timeout, headers={
                "User-Agent": "VulcanPassiveAuditor/1.0"
            })
            progress.update(task1, completed=1)

            # Step 2: Audit Response Headers
            task2 = progress.add_task("[cyan]Analyzing HTTP response headers & security policies...", total=1)
            header_auditor = HeaderAuditor(headers_response.headers)
            audit_results["headers"] = header_auditor.audit()
            progress.update(task2, completed=1)

            # Step 3: Audit Session Cookies
            task3 = progress.add_task("[cyan]Inspecting cookies security flags...", total=1)
            cookie_auditor = CookieAuditor(headers_response.cookies)
            audit_results["cookies"] = cookie_auditor.audit()
            progress.update(task3, completed=1)

            # Step 4: Audit Robots.txt
            task4 = progress.add_task("[cyan]Checking robots.txt for crawl exclusions and route mapping...", total=1)
            robots_auditor = RobotsAuditor(target_url)
            audit_results["robots"] = robots_auditor.audit()
            progress.update(task4, completed=1)

    except requests.exceptions.RequestException as e:
        console.print(f"\n[bold red]HTTP Connection Failure:[/bold red] Could not reach {target_url}\n[dim]{e}[/dim]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Audit System Interrupted:[/bold red] An unexpected error occurred.\n[dim]{e}[/dim]")
        sys.exit(1)

    # 5. Output Summary Dashboard in Terminal
    console.print("\n" + "="*70)
    console.print("[bold color(99)]*   AUDIT RESULTS SUMMARY[/bold color(99)]")
    console.print("="*70)

    # Headers table
    h_table = Table(title="HTTP Security Response Headers", box=box.SIMPLE)
    h_table.add_column("Header Directive", style="cyan")
    h_table.add_column("Status", style="bold")
    h_table.add_column("Audit Remarks")

    # Present headers in table
    for ph in audit_results["headers"]["present_headers"]:
        h_table.add_row(ph["header"], "[green]Configured[/green]", f"Value: {ph['value'][:40]}..." if len(ph['value']) > 40 else ph['value'])

    # Missing headers in table
    for mh in audit_results["headers"]["missing_headers"]:
        sev_color = "yellow" if mh["header"] in ["Content-Security-Policy", "Strict-Transport-Security"] else "blue"
        h_table.add_row(mh["header"], f"[{sev_color}]Missing[/{sev_color}]", mh["description"])

    console.print(h_table)

    # Information Leakage Table
    v_table = Table(title="Exposed Software & Infrastructure Signatures", box=box.SIMPLE)
    v_table.add_column("Exposed Header", style="magenta")
    v_table.add_column("Exposed Software Footprint", style="yellow")
    v_table.add_column("Recommendation")

    for vh in audit_results["headers"]["verbose_headers"]:
        v_table.add_row(vh["header"], vh["value"], vh["recommendation"])

    if audit_results["headers"]["verbose_headers"]:
        console.print(v_table)
    else:
        console.print("\n[green] OK: No software version signatures detected in HTTP response headers.[/green]")

    # Cookie Security Table
    if audit_results["cookies"]:
        c_table = Table(title="Cookie Security Audits", box=box.SIMPLE)
        c_table.add_column("Cookie Name", style="cyan")
        c_table.add_column("Domain / Path", style="dim")
        c_table.add_column("Security Deficiencies", style="bold red")

        for c_find in audit_results["cookies"]:
            issues_str = ", ".join([iss["attribute"] for iss in c_find["issues"]])
            c_table.add_row(c_find["name"], f"{c_find['domain']}{c_find['path']}", f"Lacks: {issues_str}")
        console.print(c_table)
    else:
        console.print("\n[green] OK: No cookie deficiencies detected or no application cookies set during request.[/green]")

    # Robots Table
    robots_res = audit_results["robots"]
    if robots_res.get("exists", False):
        if robots_res.get("sensitive_paths"):
            r_table = Table(title="robots.txt Excluded Paths Information Leakage", box=box.SIMPLE)
            r_table.add_column("Rule Path Excluded", style="yellow")
            r_table.add_column("Matched Keywords", style="magenta")
            r_table.add_column("Details")
            for sr in robots_res["sensitive_paths"]:
                r_table.add_row(sr["path"], ", ".join(sr["matched_keywords"]), sr["description"])
            console.print(r_table)
        else:
            console.print(f"\n[green] OK: robots.txt loaded successfully. Discovered {len(robots_res.get('disallowed_paths', []))} safe crawled rules.[/green]")
    else:
        console.print(f"\n[dim]robots.txt check complete: status {robots_res.get('status_code', 404)} (file not present).[/dim]")

    # 6. Generate reports
    reporter = ReportGenerator(target_url, audit_results)
    reporter.to_json(args.json)
    html_path = reporter.to_html(args.html)

    console.print("\n" + "="*70)
    console.print(f"[bold green] OK: Configuration Audit Successfully Finished![/bold green]")
    console.print(f"  * JSON database written: [bold white]{args.json}[/bold white]")
    console.print(f"  * Beautiful HTML dashboard report written: [bold white]{html_path}[/bold white]")
    console.print("="*70 + "\n")

if __name__ == "__main__":
    main()
