"""
Compiler & Packer Signature Detection Module
"""
from typing import Dict, Optional
from ..parsers.common import BinaryObject

PACKER_SIGNATURES = [
    ("UPX", [b"UPX0", b"UPX1", b"UPX!"]),
    ("Themida / WinLicense", [b".themida", b".aress", b".oreans"]),
    ("VMProtect", [b".vmp0", b".vmp1", b".vmp2"]),
    ("ASPack", [b".aspack", b".adata"]),
    ("PECompact", [b"PEC2", b"PECompact2"]),
    ("PyInstaller", [b"pyi-windows-manifest", b"PyInstaller", b"pyimod"]),
    ("NSI Installer", [b"NullsoftInst"]),
]

COMPILER_SIGNATURES = [
    ("Microsoft Visual C/C++ (MSVC)", [b"Microsoft Visual C++", b"MSVCR", b"MSVCP", b"VCRUNTIME"]),
    ("GCC / MinGW", [b"GCC: (GNU)", b"MinGW", b"libgcc"]),
    ("Clang / LLVM", [b"clang version", b"LLVM"]),
    ("Go Compiler", [b"go.buildid", b"Go build ID:", b"runtime.main"]),
    ("Rust Compiler", [b"rustc", b"/rustc/", b"std::panicking"]),
    ("Borland Delphi / C++ Builder", [b"Borland", b"Delphi", b"Software\\Borland\\"]),
]

def detect_compiler_and_packer(binary: BinaryObject) -> Dict[str, Optional[str]]:
    """Scans binary raw bytes and section names to identify compilers and packers."""
    detected_packer = None
    detected_compiler = None

    # Check section names first for packers
    sec_names = [sec.name.upper() for sec in binary.sections]
    for sec_name in sec_names:
        if "UPX" in sec_name:
            detected_packer = "UPX Executable Packer"
            break
        elif "VMP" in sec_name:
            detected_packer = "VMProtect"
            break
        elif "THEMIDA" in sec_name:
            detected_packer = "Themida"
            break

    data = binary.raw_bytes[:1024*1024]  # Scan first 1MB

    # Scan for Packer Signatures
    if not detected_packer:
        for name, sigs in PACKER_SIGNATURES:
            if any(sig in data for sig in sigs):
                detected_packer = name
                break

    # Scan for Compiler Signatures
    for name, sigs in COMPILER_SIGNATURES:
        if any(sig in data for sig in sigs):
            detected_compiler = name
            break

    if detected_packer:
        binary.is_packed = True
        binary.packer_name = detected_packer

    return {
        "compiler": detected_compiler or "Unknown / Generic C/C++",
        "packer": detected_packer or "None Detected (Native Unpacked)"
    }
