"""
Textual Interactive Terminal Dashboard (TUI)
"""
import typer
from typing import Optional
from rich.text import Text
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, DataTable, TabbedContent, TabPane
from ..parsers.loader import load_binary
from ..analysis.metadata import analyze_metadata
from ..analysis.sections import analyze_sections
from ..analysis.imports import analyze_imports
from ..analysis.strings import extract_strings

app = typer.Typer(help="Launch Textual interactive TUI dashboard for binary inspection.")

class RevLabTUIApp(App):
    CSS = """
    Screen {
        background: #1e1e2e;
        color: #f8f8f2;
    }
    Header {
        background: #da7756;
        color: #ffffff;
    }
    TabbedContent {
        background: #282a36;
    }
    DataTable {
        height: 100%;
        background: #1e1e2e;
    }
    .status-box {
        padding: 1 2;
        background: #282a36;
        border: solid #da7756;
        margin: 1;
    }
    """

    def __init__(self, filepath: str):
        super().__init__()
        self.filepath = filepath
        self.bin_obj = load_binary(filepath)
        self.meta = analyze_metadata(self.bin_obj)
        self.sec_res = analyze_sections(self.bin_obj)
        self.imp_res = analyze_imports(self.bin_obj)
        self.str_res = extract_strings(self.bin_obj, min_len=4)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(
            f"⚡ REV LAB DASHBOARD  │  Target: {self.bin_obj.filename}  │  Format: {self.bin_obj.file_format.value}",
            classes="status-box"
        )
        with TabbedContent(initial="tab-overview"):
            with TabPane("Overview & Hashes", id="tab-overview"):
                table = DataTable()
                table.add_columns("Property", "Value")
                table.add_row("Filename", self.meta["filename"])
                table.add_row("File Size", self.meta["filesize_formatted"])
                table.add_row("Architecture", self.meta["architecture"])
                table.add_row("Entry Point", self.meta["entry_point"])
                table.add_row("MD5", self.bin_obj.hashes.get("md5", "N/A"))
                table.add_row("SHA-256", self.bin_obj.hashes.get("sha256", "N/A"))
                table.add_row("ImpHash", self.bin_obj.hashes.get("imphash", "N/A"))
                yield table

            with TabPane("Sections", id="tab-sections"):
                table = DataTable()
                table.add_columns("Name", "Virtual Addr", "Virtual Size", "Raw Size", "Permissions")
                for sec in self.bin_obj.sections:
                    table.add_row(sec.name, f"0x{sec.virtual_address:08X}", f"{sec.virtual_size} B", f"{sec.raw_size} B", sec.permissions)
                yield table

            with TabPane("Imports & APIs", id="tab-imports"):
                table = DataTable()
                table.add_columns("DLL", "Function", "Category", "Suspicious")
                for imp in self.bin_obj.imports[:100]:
                    table.add_row(imp.library, imp.function_name, imp.category, "YES" if imp.is_suspicious else "NO")
                yield table

            with TabPane("Strings", id="tab-strings"):
                table = DataTable()
                table.add_columns("Offset", "Type", "Category", "String")
                for s in self.str_res["all_strings"][:100]:
                    table.add_row(f"0x{s.offset:08X}", s.string_type, s.category, s.value[:50])
                yield table

        yield Footer()

@app.callback(invoke_without_command=True)
def run_tui(filepath: str = typer.Argument(..., help="Path to target binary file")):
    """Launches interactive Textual terminal dashboard for binary inspection."""
    tui_app = RevLabTUIApp(filepath)
    tui_app.run()
