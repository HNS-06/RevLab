import typer
from .theme import console, print_banner, print_header, create_table, COLOR_CYAN, COLOR_BRAND
from ..parsers.loader import load_binary
from ..analysis.strings import extract_strings
from ..analysis.deobfuscation import deobfuscate_strings

app = typer.Typer(help="Extract ASCII and UTF-16 strings with regex pattern categorization.")

@app.callback(invoke_without_command=True)
def run_strings(
    filepath: str = typer.Argument(..., help="Path to target binary file"),
    min_len: int = typer.Option(4, "--min-len", "-m", help="Minimum string length filter"),
    limit: int = typer.Option(50, "--limit", "-l", help="Maximum strings to display"),
    deobfuscate: bool = typer.Option(False, "--deobfuscate", "-d", help="Run stack string & XOR de-obfuscation engine")
):
    """Extracts strings and categorizes IPs, URLs, Paths, Registry keys, and Base64."""
    print_banner()
    print_header("Extracted Strings & Indicator Categorization", filepath)

    with console.status("[bold #4CB9E7]Extracting & categorizing strings...", spinner="dots"):
        bin_obj = load_binary(filepath)
        str_res = extract_strings(bin_obj, min_len=min_len)
        deob_res = deobfuscate_strings(bin_obj) if deobfuscate else None

    console.print(f"Total Standard Extracted Strings: [bold cyan]{str_res['total_strings']:,}[/]")
    if deob_res:
        console.print(f"De-obfuscated Hidden Strings Found: [bold red]{deob_res['total_deobfuscated']}[/]")
    console.print()

    if deob_res and deob_res["results"]:
        table_deob = create_table("De-obfuscated & Stack Strings", [
            ("Method / Key", "left", "bold brand"),
            ("Offset / Addr", "left", "cyan"),
            ("Category", "left", "yellow"),
            ("De-obfuscated Value", "left", "bold red")
        ])
        for item in deob_res["results"]:
            table_deob.add_row(item.method, item.offset_or_addr, item.category, item.value)
        console.print(table_deob)
        console.print()

    table = create_table(f"Top {limit} Standard Extracted Strings", [
        ("Offset", "left", "cyan"),
        ("Type", "center", "bold brand"),
        ("Category", "left", "yellow"),
        ("Value", "left", "white")
    ])

    for item in str_res["all_strings"][:limit]:
        val = item.value if len(item.value) <= 60 else item.value[:57] + "..."
        cat_style = f"[bold yellow]{item.category}[/]" if item.category != "General" else "[dim]General[/]"
        table.add_row(f"0x{item.offset:08X}", item.string_type, cat_style, val)

    console.print(table)
