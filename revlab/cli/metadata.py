"""
Metadata CLI Command
"""
import typer
from .theme import console, print_banner, print_header, create_table, COLOR_CYAN, COLOR_BRAND
from ..parsers.loader import load_binary
from ..analysis.metadata import analyze_metadata
from ..analysis.hashes import calculate_hashes

app = typer.Typer(help="Inspect binary metadata, headers, and cryptographic hashes.")

@app.callback(invoke_without_command=True)
def run_metadata(filepath: str = typer.Argument(..., help="Path to target binary file")):
    """Displays headers, architecture, entry point, and file hashes."""
    print_banner()
    print_header("Binary Metadata & Header Inspection", filepath)

    with console.status("[bold #4CB9E7]Loading binary & headers...", spinner="dots"):
        bin_obj = load_binary(filepath)
        meta = analyze_metadata(bin_obj)
        hashes = calculate_hashes(bin_obj)

    # General Information Table
    table_gen = create_table("File Characteristics", [
        ("Property", "left", "bold cyan"),
        ("Value", "left", "white")
    ])
    table_gen.add_row("Filename", meta["filename"])
    table_gen.add_row("File Size", meta["filesize_formatted"])
    table_gen.add_row("File Format", meta["file_format"])
    table_gen.add_row("Architecture", meta["architecture"])
    table_gen.add_row("Bit Width", f"{meta['bits']}-bit")
    table_gen.add_row("Endianness", meta["endianness"].capitalize())
    table_gen.add_row("Entry Point Address", meta["entry_point"])

    console.print(table_gen)
    console.print()

    # Hashes Table
    table_hash = create_table("Cryptographic & Import Hashes", [
        ("Algorithm", "left", "bold brand"),
        ("Hash Value", "left", "bold cyan")
    ])
    table_hash.add_row("MD5", hashes["md5"])
    table_hash.add_row("SHA-1", hashes["sha1"])
    table_hash.add_row("SHA-256", hashes["sha256"])
    table_hash.add_row("ImpHash", hashes["imphash"])

    console.print(table_hash)
    console.print()

    # Specific Headers Table
    if meta["headers"]:
        table_hdr = create_table("Format Headers Detail", [
            ("Header Key", "left", "bold brand"),
            ("Value", "left", "cyan"),
            ("Description", "left", "dim")
        ])
        for h in meta["headers"]:
            table_hdr.add_row(str(h.key), str(h.value), str(h.description))
        console.print(table_hdr)
