"""
Markdown Report Generator Module
"""
from typing import Dict, Any

def generate_markdown_report(summary: Dict[str, Any]) -> str:
    """Generates a clean GitHub-Flavored Markdown static analysis report."""
    md = []
    md.append(f"# RevLab Static Analysis Report - {summary.get('filename')}\n")
    md.append(f"**Format:** `{summary.get('format')}`  ")
    md.append(f"**Architecture:** `{summary.get('architecture')}`  ")
    md.append(f"**Entry Point:** `{summary.get('entry_point')}`  ")
    md.append(f"**Packer:** `{summary.get('packer')}`  ")
    md.append(f"**Compiler:** `{summary.get('compiler')}`\n")

    md.append("## Cryptographic Hashes\n")
    hashes = summary.get("hashes", {})
    md.append(f"- **MD5:** `{hashes.get('md5')}`")
    md.append(f"- **SHA-1:** `{hashes.get('sha1')}`")
    md.append(f"- **SHA-256:** `{hashes.get('sha256')}`")
    md.append(f"- **ImpHash:** `{hashes.get('imphash')}`\n")

    md.append("## Analysis Summary\n")
    md.append(f"- **Overall Shannon Entropy:** `{summary.get('entropy')}` / 8.0")
    md.append(f"- **Total Sections:** `{summary.get('sections_count')}`")
    md.append(f"- **Total Imports:** `{summary.get('imports_count')}`")
    md.append(f"- **Suspicious APIs Count:** `{summary.get('suspicious_imports_count')}`")
    md.append(f"- **Extracted Strings Count:** `{summary.get('strings_count')}`\n")

    md.append("---\n*Generated automatically by RevLab static analysis toolkit.*")
    return "\n".join(md)
