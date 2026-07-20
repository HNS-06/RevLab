"""
YARA CLI Command Module
"""
import typer
from typing import Optional
from .theme import console, print_banner, print_header, create_table, make_badge, COLOR_CYAN, COLOR_BRAND
from ..parsers.loader import load_binary
from ..analysis.yara_engine import scan_yara

app = typer.Typer(help="Scan binary against built-in or custom YARA signature rules.")

@app.callback(invoke_without_command=True)
def run_yara(
    filepath: str = typer.Argument(..., help="Path to target binary file"),
    rules: Optional[str] = typer.Option(None, "--rules", "-r", help="Path to custom YARA rule file or directory")
):
    """Scans binary against YARA signatures and reports matched rule names & tags."""
    print_banner()
    print_header("YARA Signature Rule Scanner", filepath)

    with console.status("[bold #4CB9E7]Scanning binary against YARA rules...", spinner="dots"):
        bin_obj = load_binary(filepath)
        matches = scan_yara(bin_obj, custom_rule_path=rules)

    if not matches:
        console.print("[bold green]✔ No YARA rule matches triggered for this binary.[/]")
        return

    console.print(f"Total YARA Rule Matches: [bold red]{len(matches)}[/]\n")

    table = create_table("Matched YARA Rules & Indicators", [
        ("Rule Name", "left", "bold brand"),
        ("Severity", "center", "bold"),
        ("Tags", "left", "cyan"),
        ("Description", "left", "white"),
        ("Matched Strings", "left", "dim")
    ])

    for match in matches:
        sev = match.meta.get("severity", "MEDIUM")
        badge = make_badge(sev, "danger" if sev == "HIGH" else "warning")
        tags_str = ", ".join(match.tags) if match.tags else "None"
        desc = match.meta.get("description", "Signature Rule Match")
        
        matched_sample = []
        for off, ident, val in match.strings_matched[:3]:
            matched_sample.append(f"{ident} @ 0x{off:X} ({val[:20]})")
        
        table.add_row(
            match.rule_name,
            badge,
            tags_str,
            desc,
            "\n".join(matched_sample) if matched_sample else "-"
        )

    console.print(table)
