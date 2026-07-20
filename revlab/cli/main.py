"""
RevLab Main Typer CLI Application Router with Short Aliases
"""
import typer
from .analyze import run_analyze
from .metadata import run_metadata
from .sections import run_sections
from .imports import run_imports
from .exports import run_exports
from .strings import run_strings
from .entropy import run_entropy
from .opcodes import run_opcodes
from .disassemble import run_disassemble
from .functions import run_functions
from .cfg import run_cfg
from .compare import run_compare
from .report import run_report
from .history import run_history
from .doctor import run_doctor
from .tui import run_tui
from .yara_cmd import run_yara
from .resources_cmd import run_resources
from .serve import run_serve

app = typer.Typer(
    name="revlab",
    help="⚡ REV LAB — Static Binary Analysis & Reverse Engineering Toolkit",
    add_completion=False,
    no_args_is_help=True
)

# Standard Commands
app.command(name="analyze", help="Run comprehensive static binary analysis pipeline.")(run_analyze)
app.command(name="metadata", help="Inspect binary metadata, headers, and cryptographic hashes.")(run_metadata)
app.command(name="sections", help="Inspect binary headers, section permissions, and virtual sizes.")(run_sections)
app.command(name="imports", help="Inspect binary imports and flag suspicious Windows APIs.")(run_imports)
app.command(name="exports", help="Inspect binary export symbols and ordinal offsets.")(run_exports)
app.command(name="strings", help="Extract ASCII and UTF-16 strings with regex pattern categorization.")(run_strings)
app.command(name="entropy", help="Calculate overall and section-by-section Shannon entropy.")(run_entropy)
app.command(name="opcodes", help="Analyze opcode distribution frequencies and mnemonic breakdown.")(run_opcodes)
app.command(name="disassemble", help="Disassemble binary code at entrypoint or specified address.")(run_disassemble)
app.command(name="functions", help="Discover functions, prologues, and function basic block counts.")(run_functions)
app.command(name="cfg", help="Generate Control Flow Graph (CFG) and basic block representation.")(run_cfg)
app.command(name="compare", help="Compare two binaries and calculate similarity diffing metrics.")(run_compare)
app.command(name="report", help="Export binary analysis reports in JSON, Markdown, or HTML format.")(run_report)
app.command(name="history", help="Query historical analysis records from SQLite database.")(run_history)
app.command(name="doctor", help="Run system diagnostic checks for optional dependencies & environment.")(run_doctor)
app.command(name="tui", help="Launch Textual interactive TUI dashboard for binary inspection.")(run_tui)
app.command(name="yara", help="Scan binary against built-in or custom YARA signature rules.")(run_yara)
app.command(name="resources", help="Inspect PE Rich Header build telemetry and .rsrc embedded resources.")(run_resources)
app.command(name="serve", help="Launch RevLab headless REST API server.")(run_serve)

# Convenient Short Aliases (a, s, d, sec, imp, exp, meta, ent, op, fn, g, cmp, rep, h, doc, ui, yr, res, srv)
app.command(name="a", help="[Short Alias] analyze")(run_analyze)
app.command(name="meta", help="[Short Alias] metadata")(run_metadata)
app.command(name="sec", help="[Short Alias] sections")(run_sections)
app.command(name="imp", help="[Short Alias] imports")(run_imports)
app.command(name="exp", help="[Short Alias] exports")(run_exports)
app.command(name="s", help="[Short Alias] strings")(run_strings)
app.command(name="ent", help="[Short Alias] entropy")(run_entropy)
app.command(name="op", help="[Short Alias] opcodes")(run_opcodes)
app.command(name="d", help="[Short Alias] disassemble")(run_disassemble)
app.command(name="disasm", help="[Short Alias] disassemble")(run_disassemble)
app.command(name="fn", help="[Short Alias] functions")(run_functions)
app.command(name="g", help="[Short Alias] cfg")(run_cfg)
app.command(name="cmp", help="[Short Alias] compare")(run_compare)
app.command(name="rep", help="[Short Alias] report")(run_report)
app.command(name="h", help="[Short Alias] history")(run_history)
app.command(name="doc", help="[Short Alias] doctor")(run_doctor)
app.command(name="ui", help="[Short Alias] tui")(run_tui)
app.command(name="yr", help="[Short Alias] yara")(run_yara)
app.command(name="res", help="[Short Alias] resources")(run_resources)
app.command(name="srv", help="[Short Alias] serve")(run_serve)

if __name__ == "__main__":
    app()
