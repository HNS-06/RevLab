"""
Common Data Structures for Unified Binary Representation
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional

class BinaryFormat(str, Enum):
    PE = "PE (Windows Executable)"
    ELF = "ELF (Linux Executable)"
    MACHO = "Mach-O (macOS Executable)"
    RAW = "Raw Binary Blob"

class Architecture(str, Enum):
    X86 = "x86 (32-bit)"
    X64 = "x86_64 (64-bit)"
    ARM = "ARM (32-bit)"
    ARM64 = "ARM64 (64-bit)"
    MIPS = "MIPS"
    UNKNOWN = "Unknown Architecture"

@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_offset: int
    permissions: str  # e.g., "r-x", "rw-", "rwx"
    entropy: float = 0.0
    flags: List[str] = field(default_factory=list)

@dataclass
class ImportSymbol:
    library: str
    function_name: str
    ordinal: Optional[int] = None
    address: Optional[int] = None
    is_suspicious: bool = False
    category: str = "General"

@dataclass
class ExportSymbol:
    name: str
    ordinal: int
    address: int

@dataclass
class HeaderField:
    key: str
    value: Any
    description: str = ""

@dataclass
class BinaryObject:
    filepath: str
    filename: str
    filesize: int
    file_format: BinaryFormat
    architecture: Architecture
    bits: int
    endianness: str
    entry_point: int
    headers: List[HeaderField] = field(default_factory=list)
    sections: List[Section] = field(default_factory=list)
    imports: List[ImportSymbol] = field(default_factory=list)
    exports: List[ExportSymbol] = field(default_factory=list)
    raw_bytes: bytes = field(default_factory=bytes, repr=False)
    hashes: Dict[str, str] = field(default_factory=dict)
    is_packed: bool = False
    packer_name: Optional[str] = None

    def get_section_by_name(self, name: str) -> Optional[Section]:
        for sec in self.sections:
            if sec.name == name or sec.name.strip('\x00') == name:
                return sec
        return None

    def read_at_rva(self, rva: int, size: int) -> bytes:
        """Translates RVA / Virtual Address to file offset and returns raw bytes."""
        for sec in self.sections:
            if sec.virtual_address <= rva < sec.virtual_address + max(sec.virtual_size, sec.raw_size):
                offset = sec.raw_offset + (rva - sec.virtual_address)
                if offset < len(self.raw_bytes):
                    return self.raw_bytes[offset:offset + size]
        # Fallback 1: check if rva corresponds to raw offset directly
        if rva < len(self.raw_bytes):
            return self.raw_bytes[rva:rva + size]
        # Fallback 2: first executable section raw bytes
        for sec in self.sections:
            if "x" in sec.permissions or "EXEC" in sec.flags or sec.name.lower() in (".text", "code"):
                return self.raw_bytes[sec.raw_offset : sec.raw_offset + size]
        return self.raw_bytes[:size]
