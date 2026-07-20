"""
Control Flow Graph CLI Command
"""
import typer
import os
from typing import Optional
from .theme import console, print_banner, print_header, COLOR_CYAN, COLOR_BRAND
from ..parsers.loader import load_binary
from ..analysis.cfg import generate_cfg
from ..analysis.cfg_web import generate_web_cfg_html

app = typer.Typer(help="Generate Control Flow Graph (CFG) and basic block representation.")

@app.callback(invoke_without_command=True)
def run_cfg(
    filepath: str = typer.Argument(..., help="Path to target binary file"),
    web: bool = typer.Option(False, "--web", "-w", help="Export interactive HTML web visualizer"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output HTML file path for web visualizer")
):
    """Generates Control Flow Graph basic blocks and control flow tree."""
    print_banner()
    print_header("Control Flow Graph (CFG) Construction", filepath)

    with console.status("[bold #4CB9E7]Building Control Flow Graph basic blocks...", spinner="dots"):
        bin_obj = load_binary(filepath)
        cfg_res = generate_cfg(bin_obj)

        if web:
            html_content = generate_web_cfg_html(bin_obj)
            out_file = output or f"revlab_cfg_{bin_obj.filename}.html"
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(html_content)
            console.print(f"✔ Interactive Web CFG exported to: [bold cyan]{os.path.abspath(out_file)}[/]\n")

    console.print(f"Graph Nodes (Basic Blocks): [bold cyan]{cfg_res['nodes_count']}[/]  │  Control Edges: [bold cyan]{cfg_res['edges_count']}[/]  │  DAG: [bold green]{cfg_res['is_dag']}[/]\n")
    console.print(cfg_res["ascii_tree"])
