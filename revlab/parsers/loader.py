"""
Binary Loader Factory & Format Detector
"""
import os
from .common import BinaryObject, BinaryFormat, Architecture, Section, HeaderField
from .pe import parse_pe
from .elf import parse_elf
from .macho import parse_macho

def load_binary(filepath: str) -> BinaryObject:
    """
    Loads binary from filepath, auto-detects binary magic, and returns a unified BinaryObject.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Binary file not found: {filepath}")

    with open(filepath, "rb") as f:
        raw_bytes = f.read()

    if len(raw_bytes) == 0:
        raise ValueError(f"File is empty: {filepath}")

    magic = raw_bytes[:4]

    # Detect PE Magic: 'MZ' (0x4D 0x5A)
    if magic[:2] == b"MZ":
        try:
            return parse_pe(filepath, raw_bytes)
        except Exception:
            pass

    # Detect ELF Magic: '\x7fELF' (0x7F 0x45 0x4C 0x46)
    if magic == b"\x7fELF":
        try:
            return parse_elf(filepath, raw_bytes)
        except Exception:
            pass

    # Detect Mach-O Magic: 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe
    if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        try:
            return parse_macho(filepath, raw_bytes)
        except Exception:
            pass

    # Fallback: Raw Binary Loader
    headers = [
        HeaderField("Format", "Raw Binary", "Unrecognized file signature"),
        HeaderField("File Size", len(raw_bytes), "Total size in bytes")
    ]
    raw_section = Section(
        name=".raw",
        virtual_address=0,
        virtual_size=len(raw_bytes),
        raw_size=len(raw_bytes),
        raw_offset=0,
        permissions="rwx",
        flags=["RAW"]
    )

    return BinaryObject(
        filepath=filepath,
        filename=os.path.basename(filepath),
        filesize=len(raw_bytes),
        file_format=BinaryFormat.RAW,
        architecture=Architecture.UNKNOWN,
        bits=64,
        endianness="little",
        entry_point=0,
        headers=headers,
        sections=[raw_section],
        raw_bytes=raw_bytes
    )
