"""
Opcodes CLI Command
"""
import typer
from .theme import console, print_banner, print_header, create_table, COLOR_CYAN, COLOR_BRAND
from ..parsers.loader import load_binary
from ..analysis.opcodes import analyze_opcodes

app = typer.Typer(help="Analyze opcode distribution frequencies and mnemonic breakdown.")

@app.callback(invoke_without_command=True)
def run_opcodes(filepath: str = typer.Argument(..., help="Path to target binary file")):
    """Displays top mnemonics frequency distribution and opcode category metrics."""
    print_banner()
    print_header("Opcode Frequency & Instruction Statistics", filepath)

    with console.status("[bold #4CB9E7]Disassembling & profiling opcodes...", spinner="dots"):
        bin_obj = load_binary(filepath)
        op_res = analyze_opcodes(bin_obj)

    console.print(f"Total Disassembled Sample Instructions: [bold cyan]{op_res['total_disassembled']}[/]")
    console.print()

    # Category Table
    table_cat = create_table("Instruction Category Distribution", [
        ("Category", "left", "bold brand"),
        ("Instruction Count", "right", "bold cyan")
    ])
    for cat, count in op_res["categories"].items():
        table_cat.add_row(cat, str(count))
    console.print(table_cat)
    console.print()

    # Top Mnemonics Table
    table_top = create_table("Top 15 Executable Mnemonics", [
        ("Mnemonic", "left", "bold brand"),
        ("Count", "right", "white"),
        ("Percentage", "right", "bold cyan")
    ])
    for mnem, count, pct in op_res["top_mnemonics"]:
        table_top.add_row(mnem, str(count), f"{pct}%")
    console.print(table_top)
