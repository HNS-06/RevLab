"""
History CLI Command
"""
import typer
from .theme import console, print_banner, print_header, create_table, COLOR_CYAN, COLOR_BRAND
from ..database.sqlite import get_history

app = typer.Typer(help="Query historical analysis records from SQLite database.")

@app.callback(invoke_without_command=True)
def run_history(limit: int = typer.Option(15, "--limit", "-l", help="Number of records to retrieve")):
    """Displays analysis history table recorded in SQLite."""
    print_banner()
    print_header("Analysis History Database Query")

    records = get_history(limit=limit)
    if not records:
        console.print("[dim]No historical analysis runs found in SQLite database (~/.revlab.db).[/]")
        return

    table = create_table("Recent Binary Analyses", [
        ("ID", "right", "dim"),
        ("Timestamp", "left", "white"),
        ("Filename", "left", "bold brand"),
        ("Format", "left", "cyan"),
        ("Entropy", "right", "white"),
        ("Packed", "center", "yellow"),
        ("Suspicious APIs", "right", "red")
    ])

    for r in records:
        table.add_row(
            str(r["id"]),
            r["timestamp"],
            r["filename"],
            r["file_format"] or "-",
            f"{r['entropy']:.2f}" if r["entropy"] else "0.00",
            "YES" if r["is_packed"] else "NO",
            str(r["suspicious_imports"] or 0)
        )

    console.print(table)
