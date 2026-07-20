"""
Imports CLI Command
"""
import typer
from .theme import console, print_banner, print_header, create_table, make_badge, COLOR_CYAN, COLOR_BRAND
from ..parsers.loader import load_binary
from ..analysis.imports import analyze_imports

app = typer.Typer(help="Inspect binary imports and flag suspicious Windows APIs.")

@app.callback(invoke_without_command=True)
def run_imports(filepath: str = typer.Argument(..., help="Path to target binary file")):
    """Displays imported libraries, functions, and flags suspicious security APIs."""
    print_banner()
    print_header("Import Directory & API Risk Analysis", filepath)

    with console.status("[bold #4CB9E7]Analyzing imports & API categories...", spinner="dots"):
        bin_obj = load_binary(filepath)
        imp_res = analyze_imports(bin_obj)

    console.print(f"Total Imports: [bold cyan]{imp_res['total_imports']}[/]  │  Suspicious APIs Flagged: [bold red]{imp_res['suspicious_count']}[/]")
    console.print()

    table = create_table("Imported Functions & Risk Flags", [
        ("Library / DLL", "left", "bold brand"),
        ("Function Name", "left", "cyan"),
        ("Category", "left", "white"),
        ("Risk Level", "center", "bold")
    ])

    for imp in bin_obj.imports:
        if imp.is_suspicious:
            badge = make_badge("SUSPICIOUS", "danger")
            func_str = f"[bold red]{imp.function_name}[/]"
            cat_str = f"[yellow]{imp.category}[/]"
        else:
            badge = make_badge("SAFE", "success")
            func_str = imp.function_name
            cat_str = imp.category

        table.add_row(imp.library, func_str, cat_str, badge)

    console.print(table)
