"""
Sections CLI Command
"""
import typer
from .theme import console, print_banner, print_header, create_table, make_badge, COLOR_CYAN, COLOR_BRAND
from ..parsers.loader import load_binary
from ..analysis.sections import analyze_sections
from ..analysis.entropy import calculate_shannon_entropy, render_ascii_entropy_bar

app = typer.Typer(help="Inspect binary headers, section permissions, and virtual sizes.")

@app.callback(invoke_without_command=True)
def run_sections(filepath: str = typer.Argument(..., help="Path to target binary file")):
    """Displays section headers, R/W/X permissions, virtual size, and entropy."""
    print_banner()
    print_header("Binary Sections Inspection", filepath)

    with console.status("[bold #4CB9E7]Analyzing section layout & permissions...", spinner="dots"):
        bin_obj = load_binary(filepath)
        sec_res = analyze_sections(bin_obj)

    table = create_table("Section Layout & Permissions", [
        ("Name", "left", "bold brand"),
        ("Virt Addr", "left", "cyan"),
        ("Virt Size", "right", "white"),
        ("Raw Size", "right", "white"),
        ("Perms", "center", "bold green"),
        ("Entropy", "left", "white"),
        ("Flags", "left", "dim")
    ])

    for sec in bin_obj.sections:
        sec_bytes = bin_obj.raw_bytes[sec.raw_offset : sec.raw_offset + sec.raw_size]
        ent = calculate_shannon_entropy(sec_bytes)
        ent_str = render_ascii_entropy_bar(ent, width=15)
        perm_colored = sec.permissions
        if "w" in sec.permissions and "x" in sec.permissions:
            perm_colored = f"[bold red]{sec.permissions}[/]"

        table.add_row(
            sec.name,
            f"0x{sec.virtual_address:08X}",
            f"{sec.virtual_size:,} B",
            f"{sec.raw_size:,} B",
            perm_colored,
            ent_str,
            ", ".join(sec.flags) if sec.flags else "-"
        )

    console.print(table)

    if sec_res["anomalies"]:
        console.print()
        console.print("[bold red]⚠ Anomalies Detected:[/]")
        for anom in sec_res["anomalies"]:
            console.print(f"  • {anom}")
