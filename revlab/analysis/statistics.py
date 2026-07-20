"""
High-Level Statistical Summary Generator
"""
from typing import Dict, Any
from ..parsers.common import BinaryObject
from .hashes import calculate_hashes
from .entropy import analyze_entropy
from .imports import analyze_imports
from .sections import analyze_sections
from .compiler import detect_compiler_and_packer
from .strings import extract_strings

def generate_summary_statistics(binary: BinaryObject) -> Dict[str, Any]:
    """Runs all primary analyses and aggregates a comprehensive summary dict."""
    hashes = calculate_hashes(binary)
    entropy_res = analyze_entropy(binary)
    imports_res = analyze_imports(binary)
    sections_res = analyze_sections(binary)
    comp_pack = detect_compiler_and_packer(binary)
    strings_res = extract_strings(binary, min_len=4)

    return {
        "filename": binary.filename,
        "format": binary.file_format.value,
        "architecture": binary.architecture.value,
        "entry_point": hex(binary.entry_point),
        "hashes": hashes,
        "entropy": entropy_res["overall_entropy"],
        "is_packed": binary.is_packed,
        "packer": comp_pack["packer"],
        "compiler": comp_pack["compiler"],
        "sections_count": len(binary.sections),
        "imports_count": len(binary.imports),
        "suspicious_imports_count": imports_res["suspicious_count"],
        "exports_count": len(binary.exports),
        "strings_count": strings_res["total_strings"],
        "anomalies_count": len(sections_res["anomalies"])
    }
