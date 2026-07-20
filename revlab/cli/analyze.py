"""
Master Analyze CLI Command
"""
import typer
from rich.panel import Panel
from rich.text import Text
from .theme import console, print_banner, print_header, create_table, make_badge, COLOR_CYAN, COLOR_BRAND, COLOR_DIM, COLOR_RED, COLOR_GREEN, COLOR_GOLD
from ..parsers.loader import load_binary
from ..analysis.statistics import generate_summary_statistics
from ..analysis.metadata import analyze_metadata
from ..analysis.hashes import calculate_hashes
from ..analysis.entropy import analyze_entropy, render_ascii_entropy_bar
from ..analysis.imports import analyze_imports
from ..analysis.sections import analyze_sections
from ..analysis.compiler import detect_compiler_and_packer
from ..database.sqlite import log_analysis

app = typer.Typer(help="Run comprehensive static binary analysis pipeline.")

@app.callback(invoke_without_command=True)
def run_analyze(filepath: str = typer.Argument(..., help="Path to target binary file")):
    """Performs end-to-end static binary analysis and displays summary dashboard."""
    print_banner()
    print_header("Comprehensive Static Binary Analysis", filepath)

    with console.status("[bold #4CB9E7]Running analysis pipeline (Headers, Sections, Imports, Hashes, Entropy)...", spinner="dots"):
        bin_obj = load_binary(filepath)
        hashes = calculate_hashes(bin_obj)
        meta = analyze_metadata(bin_obj)
        ent_res = analyze_entropy(bin_obj)
        imp_res = analyze_imports(bin_obj)
        sec_res = analyze_sections(bin_obj)
        comp_pack = detect_compiler_and_packer(bin_obj)
        summary = generate_summary_statistics(bin_obj)

        # Log into SQLite database
        log_analysis(summary)

    # 1. Top Executive Summary Panel
    exec_text = Text()
    exec_text.append("Target File: ", style=COLOR_DIM)
    exec_text.append(f"{bin_obj.filename}\n", style=f"bold {COLOR_CYAN}")
    exec_text.append("Format: ", style=COLOR_DIM)
    exec_text.append(f"{bin_obj.file_format.value} ({bin_obj.architecture.value})\n", style="white")
    exec_text.append("Entry Point: ", style=COLOR_DIM)
    exec_text.append(f"{hex(bin_obj.entry_point)}", style=COLOR_CYAN)
    exec_text.append("  │  Compiler: ", style=COLOR_DIM)
    exec_text.append(f"{comp_pack['compiler']}\n", style="white")
    
    exec_text.append("Packer Status: ", style=COLOR_DIM)
    if bin_obj.is_packed:
        exec_text.append(f"PACKED ({comp_pack['packer']})  ", style=f"bold {COLOR_RED}")
    else:
        exec_text.append("NATIVE UNPACKED  ", style=f"bold {COLOR_GREEN}")

    exec_text.append("│  Risk Indicators: ", style=COLOR_DIM)
    if imp_res['suspicious_count'] > 0 or sec_res['anomalies']:
        exec_text.append(f"{imp_res['suspicious_count']} Suspicious APIs Flagged", style=f"bold {COLOR_GOLD}")
    else:
        exec_text.append("Clean / Low Risk", style=f"bold {COLOR_GREEN}")

    console.print(Panel(exec_text, title=f"[bold {COLOR_BRAND}]Executive Binary Assessment[/]", border_style=COLOR_BRAND))
    console.print()

    # 2. Cryptographic Hashes Table
    table_hash = create_table("Cryptographic & Import Hashes", [
        ("Algorithm", "left", "bold brand"),
        ("Value", "left", "cyan")
    ])
    table_hash.add_row("MD5", hashes["md5"])
    table_hash.add_row("SHA-1", hashes["sha1"])
    table_hash.add_row("SHA-256", hashes["sha256"])
    table_hash.add_row("ImpHash", hashes["imphash"])
    console.print(table_hash)
    console.print()

    # 3. Section Overview & Entropy Table
    table_sec = create_table("Sections & Entropy Overview", [
        ("Name", "left", "bold brand"),
        ("Virt Addr", "left", "cyan"),
        ("Virt Size", "right", "white"),
        ("Raw Size", "right", "white"),
        ("Perms", "center", "bold green"),
        ("Entropy Bar", "left", "white")
    ])

    for sec in bin_obj.sections[:8]:
        sec_bytes = bin_obj.raw_bytes[sec.raw_offset : sec.raw_offset + sec.raw_size]
        ent = sec.entropy or 0.0
        bar = render_ascii_entropy_bar(ent, width=15)
        table_sec.add_row(sec.name, f"0x{sec.virtual_address:08X}", f"{sec.virtual_size:,} B", f"{sec.raw_size:,} B", sec.permissions, bar)

    console.print(table_sec)
    console.print()

    # 4. Top Suspicious Imports
    if imp_res["suspicious_count"] > 0:
        table_susp = create_table(f"Top Suspicious APIs ({imp_res['suspicious_count']} Total)", [
            ("Library / DLL", "left", "bold brand"),
            ("Function Name", "left", "bold red"),
            ("Category", "left", "yellow")
        ])
        for cat, imps in imp_res["categories"].items():
            for imp in imps[:5]:
                table_susp.add_row(imp.library, imp.function_name, cat)
        console.print(table_susp)
        console.print()

    console.print(f"[bold green]✔ Analysis logged to SQLite database (~/.revlab.db).[/]")
