"""
RevLab Theme System
Claude Code Inspired Visual Aesthetics using Rich
"""
import sys
import io

# Force UTF-8 console output encoding on Windows
if sys.platform == "win32":
    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "buffer"):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
from typing import List, Tuple, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.style import Style
from rich.theme import Theme
from rich.box import ROUNDED, HEAVY, DOUBLE, MINIMAL
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn

# Palette definitions (Claude Code Inspired)
COLOR_BRAND = "#DA7756"     # Terracotta / Claude Warm Orange
COLOR_CYAN = "#4CB9E7"      # Slate Cyan / Electric Teal
COLOR_PURPLE = "#C678DD"    # Muted Violet / Soft Purple
COLOR_GREEN = "#4EBE96"     # Mint / Emerald Green
COLOR_GOLD = "#E5C07B"      # Amber / Gold
COLOR_RED = "#E06C75"       # Crimson Coral
COLOR_DIM = "#8A8F9E"       # Soft Muted Slate Gray
COLOR_WHITE = "#ABB2BF"     # Crisp Text
COLOR_HEADER = "#61AFEF"    # Bright Accent Blue

# Custom Rich Theme
REVLAB_THEME = Theme({
    "brand": Style(color=COLOR_BRAND, bold=True),
    "cyan": Style(color=COLOR_CYAN),
    "purple": Style(color=COLOR_PURPLE),
    "success": Style(color=COLOR_GREEN, bold=True),
    "warning": Style(color=COLOR_GOLD, bold=True),
    "danger": Style(color=COLOR_RED, bold=True),
    "dim": Style(color=COLOR_DIM),
    "header": Style(color=COLOR_HEADER, bold=True),
    "addr": Style(color=COLOR_CYAN, bold=True),
    "mnemonic": Style(color=COLOR_BRAND, bold=True),
    "operands": Style(color=COLOR_WHITE),
    "bytes": Style(color=COLOR_DIM),
})

console = Console(theme=REVLAB_THEME)

def print_banner():
    """Prints the signature Claude Code inspired RevLab banner."""
    banner_text = Text()
    banner_text.append("⚡ ", style=COLOR_BRAND)
    banner_text.append("REV LAB ", style=f"bold {COLOR_BRAND}")
    banner_text.append("v1.0.0", style=f"bold {COLOR_CYAN}")
    banner_text.append("  │  ", style=COLOR_DIM)
    banner_text.append("Static Binary Analysis & Inspection Toolkit", style=f"italic {COLOR_WHITE}")

    panel = Panel(
        banner_text,
        box=ROUNDED,
        border_style=COLOR_BRAND,
        padding=(0, 2),
        expand=False
    )
    console.print(panel)

def print_header(title: str, subtitle: Optional[str] = None):
    """Prints a styled section header."""
    header_text = Text()
    header_text.append("▸ ", style=COLOR_BRAND)
    header_text.append(title.upper(), style=f"bold {COLOR_CYAN}")
    if subtitle:
        header_text.append(f"  ({subtitle})", style=COLOR_DIM)
    
    console.print()
    console.print(header_text)
    console.print(Text("─" * (len(title) + 10), style=COLOR_DIM))

def make_badge(label: str, style_type: str = "info") -> str:
    """Returns a formatted badge string."""
    colors = {
        "info": (COLOR_CYAN, "black"),
        "success": ("black", COLOR_GREEN),
        "warning": ("black", COLOR_GOLD),
        "danger": ("white", COLOR_RED),
        "brand": ("white", COLOR_BRAND),
    }
    fg, bg = colors.get(style_type, (COLOR_CYAN, "black"))
    return f"[{fg} on {bg}] {label} [/{fg} on {bg}]"

def create_table(title: str, columns: List[Tuple[str, str, str]]) -> Table:
    """
    Creates a standardized Rich Table with Claude Code aesthetics.
    columns: list of (column_name, justify, style)
    """
    table = Table(
        title=f"[bold {COLOR_BRAND}]{title}[/]",
        box=ROUNDED,
        border_style=COLOR_DIM,
        header_style=f"bold {COLOR_CYAN}",
        row_styles=["", "on #21252B"],
        expand=True
    )
    for name, justify, col_style in columns:
        # Resolve 'brand' to hex color
        resolved_style = col_style.replace("brand", COLOR_BRAND).replace("cyan", COLOR_CYAN)
        table.add_column(name, justify=justify, style=resolved_style)
    return table

def create_progress():
    """Creates a custom Rich progress bar for multi-step tasks."""
    return Progress(
        SpinnerColumn(spinner_name="dots", style=COLOR_BRAND),
        TextColumn(f"[bold {COLOR_CYAN}]{{task.description}}"),
        BarColumn(bar_width=40, complete_style=COLOR_GREEN, finished_style=COLOR_CYAN),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console
    )

def format_disasm_line(address: int, hex_bytes: str, mnemonic: str, operands: str, comment: str = "") -> str:
    """Formats a single disassembly instruction line with rich color highlights."""
    addr_str = f"[bold {COLOR_CYAN}]0x{address:08X}[/]"
    bytes_str = f"[{COLOR_DIM}]{hex_bytes:<16}[/]"
    mnem_str = f"[bold {COLOR_BRAND}]{mnemonic:<8}[/]"
    ops_str = f"[{COLOR_WHITE}]{operands:<24}[/]"
    cmt_str = f"[{COLOR_DIM}]; {comment}[/]" if comment else ""
    return f"  {addr_str}  {bytes_str} {mnem_str} {ops_str} {cmt_str}"
