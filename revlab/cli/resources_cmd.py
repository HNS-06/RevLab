"""
Resources CLI Command Module
"""
import typer
from .theme import console, print_banner, print_header, create_table, COLOR_CYAN, COLOR_BRAND
from ..parsers.loader import load_binary
from ..analysis.resources import analyze_resources_and_rich

app = typer.Typer(help="Inspect PE Rich Header build telemetry and .rsrc embedded resources.")

@app.callback(invoke_without_command=True)
def run_resources(filepath: str = typer.Argument(..., help="Path to target binary file")):
    """Displays decrypted MSVC Rich Header build records and .rsrc entries."""
    print_banner()
    print_header("PE Rich Header & Resource Inspection", filepath)

    with console.status("[bold #4CB9E7]Decrypting Rich Header & parsing .rsrc...", spinner="dots"):
        bin_obj = load_binary(filepath)
        res_data = analyze_resources_and_rich(bin_obj)

    rich_records = res_data["rich_header"]
    if rich_records:
        table_rich = create_table(f"MSVC Rich Header Build Telemetry ({len(rich_records)} Tools)", [
            ("Tool ID", "left", "bold brand"),
            ("Build Number", "right", "cyan"),
            ("Count", "right", "white"),
            ("Description", "left", "yellow")
        ])
        for r in rich_records:
            table_rich.add_row(f"0x{r.tool_id:04X}", str(r.build_number), str(r.use_count), r.description)
        console.print(table_rich)
        console.print()
    else:
        console.print("[dim]No MSVC Rich Header present in binary.[/]\n")

    resources = res_data["resources"]
    if resources:
        table_res = create_table(f"Embedded Resources (.rsrc)", [
            ("Type Name", "left", "bold brand"),
            ("Name / ID", "left", "cyan"),
            ("Size", "right", "white"),
            ("File Offset", "right", "dim")
        ])
        for item in resources:
            table_res.add_row(item.type_name, item.name_or_id, f"{item.size:,} B", f"0x{item.offset:08X}")
        console.print(table_res)
    else:
        console.print("[dim]No embedded .rsrc resources found.[/]")
