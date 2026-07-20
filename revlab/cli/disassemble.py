"""
Disassemble CLI Command
"""
import typer
from typing import Optional
from .theme import console, print_banner, print_header, format_disasm_line, COLOR_CYAN, COLOR_BRAND
from ..parsers.loader import load_binary
from ..disassembler.capstone_engine import disassemble_bytes

app = typer.Typer(help="Disassemble binary code at entrypoint or specified address.")

@app.callback(invoke_without_command=True)
def run_disassemble(
    filepath: str = typer.Argument(..., help="Path to target binary file"),
    address: Optional[str] = typer.Option(None, "--address", "-a", help="Virtual address / RVA to disassemble from"),
    count: int = typer.Option(40, "--count", "-c", help="Number of instructions to disassemble")
):
    """Disassembles binary machine instructions with syntax color highlights."""
    print_banner()
    print_header("Binary Machine Disassembly", filepath)

    with console.status("[bold #4CB9E7]Loading & disassembling executable bytes...", spinner="dots"):
        bin_obj = load_binary(filepath)
        rva = int(address, 16) if address else bin_obj.entry_point
        code_bytes = bin_obj.read_at_rva(rva, count * 15)
        instructions = disassemble_bytes(code_bytes, rva, bin_obj.architecture, bin_obj.bits, count=count)

    console.print(f"Disassembling at RVA: [bold cyan]0x{rva:08X}[/] ({len(instructions)} instructions)\n")
    for insn in instructions:
        line = format_disasm_line(insn.address, insn.hex_bytes, insn.mnemonic, insn.operands)
        console.print(line)
