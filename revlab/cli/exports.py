"""
Exports CLI Command
"""
import typer
from .theme import console, print_banner, print_header, create_table, COLOR_CYAN, COLOR_BRAND
from ..parsers.loader import load_binary
from ..analysis.exports import analyze_exports

app = typer.Typer(help="Inspect binary export symbols and ordinal offsets.")

@app.callback(invoke_without_command=True)
def run_exports(filepath: str = typer.Argument(..., help="Path to target binary file")):
    """Displays exported functions and ordinal addresses."""
    print_banner()
    print_header("Export Directory Inspection", filepath)

    with console.status("[bold #4CB9E7]Reading exported symbols...", spinner="dots"):
        bin_obj = load_binary(filepath)
        exp_res = analyze_exports(bin_obj)

    if not bin_obj.exports:
        console.print("[dim]No exported symbols found in this binary.[/]")
        return

    table = create_table("Exported Functions & Symbols", [
        ("Ordinal", "right", "white"),
        ("Function Name", "left", "bold brand"),
        ("Address RVA", "left", "bold cyan")
    ])

    for exp in bin_obj.exports:
        table.add_row(str(exp.ordinal), exp.name, f"0x{exp.address:08X}")

    console.print(table)
