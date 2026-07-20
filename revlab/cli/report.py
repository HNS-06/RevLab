"""
Report Export CLI Command
"""
import typer
import os
from .theme import console, print_banner, print_header, COLOR_CYAN, COLOR_BRAND
from ..parsers.loader import load_binary
from ..analysis.statistics import generate_summary_statistics
from ..reports.json_report import generate_json_report
from ..reports.markdown import generate_markdown_report
from ..reports.html import generate_html_report

app = typer.Typer(help="Export binary analysis reports in JSON, Markdown, or HTML format.")

@app.callback(invoke_without_command=True)
def run_report(
    filepath: str = typer.Argument(..., help="Path to target binary file"),
    format_type: str = typer.Option("markdown", "--format", "-f", help="Output format: json, markdown, html"),
    output: str = typer.Option(None, "--output", "-o", help="Output file destination path")
):
    """Exports structured binary analysis report."""
    print_banner()
    print_header("Report Generator Engine", filepath)

    with console.status(f"[bold #4CB9E7]Generating {format_type.upper()} report...", spinner="dots"):
        bin_obj = load_binary(filepath)
        summary = generate_summary_statistics(bin_obj)

        if format_type.lower() == "json":
            content = generate_json_report(summary)
            ext = ".json"
        elif format_type.lower() == "html":
            content = generate_html_report(summary)
            ext = ".html"
        else:
            content = generate_markdown_report(summary)
            ext = ".md"

        if not output:
            output = f"revlab_report_{bin_obj.filename}{ext}"

        with open(output, "w", encoding="utf-8") as f:
            f.write(content)

    console.print(f"✔ Report exported successfully: [bold cyan]{os.path.abspath(output)}[/]")
