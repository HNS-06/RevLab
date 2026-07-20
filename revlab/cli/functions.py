"""
Functions CLI Command
"""
import typer
from .theme import console, print_banner, print_header, create_table, COLOR_CYAN, COLOR_BRAND
from ..parsers.loader import load_binary
from ..disassembler.capstone_engine import disassemble_bytes
from ..disassembler.function_finder import find_functions

app = typer.Typer(help="Discover functions, prologues, and function basic block counts.")

@app.callback(invoke_without_command=True)
def run_functions(filepath: str = typer.Argument(..., help="Path to target binary file")):
    """Discovers binary function prologues and basic block statistics."""
    print_banner()
    print_header("Function Discovery & Prologue Analysis", filepath)

    with console.status("[bold #4CB9E7]Scanning function prologues & call targets...", spinner="dots"):
        bin_obj = load_binary(filepath)
        code_bytes = bin_obj.read_at_rva(bin_obj.entry_point, 4096)
        insns = disassemble_bytes(code_bytes, bin_obj.entry_point, bin_obj.architecture, bin_obj.bits)
        funcs = find_functions(insns)

    table = create_table("Discovered Function Symbols", [
        ("Address", "left", "bold cyan"),
        ("Name", "left", "bold brand"),
        ("Size", "right", "white"),
        ("Basic Blocks", "right", "yellow"),
        ("Outbound Calls", "right", "white")
    ])

    for fn in funcs:
        table.add_row(
            f"0x{fn.address:08X}",
            fn.name,
            f"{fn.size} B",
            str(fn.basic_blocks_count),
            str(len(fn.calls))
        )

    console.print(table)
