"""
Sections Inspection & Anomaly Detection Module
"""
from typing import Dict, List
from ..parsers.common import BinaryObject

def analyze_sections(binary: BinaryObject) -> Dict[str, any]:
    """Analyzes section layout, permissions (R/W/X), and flags anomalous characteristics."""
    anomalies: List[str] = []

    for sec in binary.sections:
        # Check for RWX (Readable, Writable, Executable) permission anomaly
        if "w" in sec.permissions and "x" in sec.permissions:
            anomalies.append(f"Section '{sec.name}' is both WRITABLE and EXECUTABLE (RWX) - High Risk for Shellcode Execution")

        # Check for non-standard section names
        standard_names = {".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".reloc", ".rsrc", ".tls", ".pdata", ".rodata", ".text,text", ".data,data"}
        if sec.name not in standard_names and not sec.name.startswith("."):
            anomalies.append(f"Section '{sec.name}' has non-standard name (possible packer/obfuscator)")

        # Check for zero raw size with large virtual size (BSS or unpacked code injection)
        if sec.raw_size == 0 and sec.virtual_size > 4096:
            anomalies.append(f"Section '{sec.name}' has 0 raw size but large virtual size ({sec.virtual_size} bytes)")

    return {
        "total_sections": len(binary.sections),
        "sections": binary.sections,
        "anomalies": anomalies
    }
