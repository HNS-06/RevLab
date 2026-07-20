"""
Entropy CLI Command
"""
import typer
from .theme import console, print_banner, print_header, create_table, COLOR_CYAN, COLOR_BRAND
from ..parsers.loader import load_binary
from ..analysis.entropy import analyze_entropy, render_ascii_entropy_bar

app = typer.Typer(help="Calculate overall and section-by-section Shannon entropy.")

@app.callback(invoke_without_command=True)
def run_entropy(filepath: str = typer.Argument(..., help="Path to target binary file")):
    """Displays file-wide entropy, section entropy, and packed binary alerts."""
    print_banner()
    print_header("Shannon Entropy Analysis", filepath)

    with console.status("[bold #4CB9E7]Calculating Shannon entropy...", spinner="dots"):
        bin_obj = load_binary(filepath)
        ent_res = analyze_entropy(bin_obj)

    overall_bar = render_ascii_entropy_bar(ent_res["overall_entropy"], width=30)
    console.print(f"Overall File Entropy: {overall_bar}")
    console.print()

    table = create_table("Section-by-Section Entropy Breakdown", [
        ("Section Name", "left", "bold brand"),
        ("Entropy Value", "left", "white"),
        ("Status", "left", "cyan")
    ])

    for name, ent, status in ent_res["section_entropies"]:
        bar = render_ascii_entropy_bar(ent, width=20)
        table.add_row(name, bar, status)

    console.print(table)

    if ent_res["is_packed"]:
        console.print()
        console.print("[bold red]⚡ PACKER ALERT:[/] Binary shows high entropy indicative of packing, compression, or encryption.")
