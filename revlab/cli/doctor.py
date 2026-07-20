"""
Doctor Diagnostic CLI Command
"""
import typer
import sys
from .theme import console, print_banner, print_header, create_table, make_badge, COLOR_CYAN, COLOR_BRAND
from ..disassembler.capstone_engine import HAS_CAPSTONE

app = typer.Typer(help="Run system diagnostic checks for optional dependencies & environment.")

@app.callback(invoke_without_command=True)
def run_doctor():
    """Checks Python version, capstone, pefile, pyelftools, lief, networkx, textual."""
    print_banner()
    print_header("RevLab Environment & Dependency Diagnostic")

    table = create_table("Dependency & Engine Status", [
        ("Component / Module", "left", "bold brand"),
        ("Status", "center", "bold"),
        ("Description / Capability", "left", "dim")
    ])

    # Python Version
    py_ver = f"Python {sys.version.split()[0]}"
    table.add_row("Python Core", make_badge("OK", "success"), py_ver)

    # pefile
    try:
        import pefile
        table.add_row("pefile Engine", make_badge("INSTALLED", "success"), f"v{pefile.__version__} - PE Executable Parser")
    except ImportError:
        table.add_row("pefile Engine", make_badge("MISSING", "warning"), "PE Parser (pip install pefile)")

    # pyelftools
    try:
        import elftools
        table.add_row("pyelftools Engine", make_badge("INSTALLED", "success"), "ELF Linux Executable Parser")
    except ImportError:
        table.add_row("pyelftools Engine", make_badge("MISSING", "warning"), "ELF Parser (pip install pyelftools)")

    # LIEF
    try:
        import lief
        table.add_row("LIEF Engine", make_badge("INSTALLED", "success"), f"v{lief.__version__} - Multi-format Binary Instrumentation")
    except ImportError:
        table.add_row("LIEF Engine", make_badge("OPTIONAL", "info"), "Library to Instrument Executable Formats")

    # Capstone
    if HAS_CAPSTONE:
        import capstone
        table.add_row("Capstone Disassembler", make_badge("INSTALLED", "success"), f"v{capstone.__version__} - Multi-Arch Disassembly Engine")
    else:
        table.add_row("Capstone Disassembler", make_badge("FALLBACK", "warning"), "Using internal x86/x64 heuristic disassembler (pip install capstone)")

    # NetworkX
    try:
        import networkx
        table.add_row("NetworkX Graphing", make_badge("INSTALLED", "success"), f"v{networkx.__version__} - CFG & Callgraph Analyzer")
    except ImportError:
        table.add_row("NetworkX Graphing", make_badge("MISSING", "warning"), "CFG Generator (pip install networkx)")

    # Textual
    try:
        import textual
        table.add_row("Textual TUI Framework", make_badge("INSTALLED", "success"), f"v{textual.__version__} - Terminal Interactive Dashboard")
    except ImportError:
        table.add_row("Textual TUI Framework", make_badge("OPTIONAL", "info"), "Interactive Dashboard (pip install textual)")

    console.print(table)
