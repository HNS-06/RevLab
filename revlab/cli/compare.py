"""
Binary Comparison CLI Command
"""
import typer
from .theme import console, print_banner, print_header, create_table, COLOR_CYAN, COLOR_BRAND
from ..parsers.loader import load_binary
from ..analysis.similarity import compare_binaries

app = typer.Typer(help="Compare two binaries and calculate similarity diffing metrics.")

@app.callback(invoke_without_command=True)
def run_compare(
    binary1: str = typer.Argument(..., help="Path to first binary"),
    binary2: str = typer.Argument(..., help="Path to second binary")
):
    """Calculates similarity score, import diffs, string overlaps, and size delta."""
    print_banner()
    print_header("Binary Diffing & Similarity Comparison", f"{binary1} vs {binary2}")

    with console.status("[bold #4CB9E7]Comparing binary layouts, imports & hashes...", spinner="dots"):
        b1 = load_binary(binary1)
        b2 = load_binary(binary2)
        diff = compare_binaries(b1, b2)

    score_color = "green" if diff["similarity_score"] > 80 else ("yellow" if diff["similarity_score"] > 50 else "red")
    console.print(f"Overall Similarity Score: [bold {score_color}]{diff['similarity_score']}%[/]  │  Identical SHA256: [bold]{diff['is_identical']}[/]")
    console.print()

    table = create_table("Comparative Analysis Breakdown", [
        ("Metric / Comparison", "left", "bold brand"),
        ("Value / Result", "left", "bold cyan")
    ])
    table.add_row("File Size Delta", f"{diff['size_diff']:,} Bytes")
    table.add_row("Entropy Delta", str(diff['entropy_diff']))
    table.add_row("Import Overlap Similarity", f"{diff['import_similarity_pct']}%")
    table.add_row("Shared Imports Count", str(diff['shared_imports_count']))
    table.add_row("String Overlap Similarity", f"{diff['string_similarity_pct']}%")
    table.add_row("Shared Strings Count", str(diff['shared_strings_count']))

    console.print(table)
