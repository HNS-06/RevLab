"""
PE (Portable Executable) Parser Module
"""
import pefile
from typing import List, Dict, Any
from .common import BinaryObject, BinaryFormat, Architecture, Section, ImportSymbol, ExportSymbol, HeaderField

def parse_pe(filepath: str, raw_bytes: bytes) -> BinaryObject:
    """Parses a Portable Executable (PE) binary using pefile."""
    pe = pefile.PE(data=raw_bytes)

    # Determine Architecture & Bits
    machine = pe.FILE_HEADER.Machine
    if machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
        arch = Architecture.X64
        bits = 64
    elif machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
        arch = Architecture.X86
        bits = 32
    elif machine in (pefile.MACHINE_TYPE.get('IMAGE_FILE_MACHINE_ARM64', 0xAA64), 0xAA64):
        arch = Architecture.ARM64
        bits = 64
    elif machine in (pefile.MACHINE_TYPE.get('IMAGE_FILE_MACHINE_ARM', 0x01C0), 0x01C0):
        arch = Architecture.ARM
        bits = 32
    else:
        arch = Architecture.UNKNOWN
        bits = 32

    # Headers
    headers = [
        HeaderField("Magic", hex(pe.DOS_HEADER.e_magic), "DOS Header Magic (MZ)"),
        HeaderField("Machine", hex(pe.FILE_HEADER.Machine), f"Machine Architecture ({arch.value})"),
        HeaderField("Subsystem", pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "Unknown"), "Target Subsystem"),
        HeaderField("ImageBase", hex(pe.OPTIONAL_HEADER.ImageBase), "Preferred Loading Base Address"),
        HeaderField("AddressOfEntryPoint", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), "Entry Point RVA"),
        HeaderField("SizeOfImage", hex(pe.OPTIONAL_HEADER.SizeOfImage), "Virtual Size of Image in Memory"),
        HeaderField("NumberOfSections", pe.FILE_HEADER.NumberOfSections, "Count of PE Sections"),
        HeaderField("CheckSum", hex(pe.OPTIONAL_HEADER.CheckSum), "Header Checksum"),
        HeaderField("CompileTimestamp", pe.FILE_HEADER.TimeDateStamp, "Compilation Epoch Timestamp"),
    ]

    # Sections
    sections = []
    for sec in pe.sections:
        name = sec.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        flags = []
        perms = []
        chars = sec.Characteristics
        if chars & 0x40000000:
            perms.append('r')
        else:
            perms.append('-')
        if chars & 0x80000000:
            perms.append('w')
        else:
            perms.append('-')
        if chars & 0x20000000:
            perms.append('x')
            flags.append("EXEC")
        else:
            perms.append('-')
            
        if chars & 0x00000020:
            flags.append("CODE")
        if chars & 0x00000040:
            flags.append("INITIALIZED_DATA")
        if chars & 0x00000080:
            flags.append("UNINITIALIZED_DATA")

        section_obj = Section(
            name=name if name else ".unnamed",
            virtual_address=sec.VirtualAddress,
            virtual_size=sec.Misc_VirtualSize,
            raw_size=sec.SizeOfRawData,
            raw_offset=sec.PointerToRawData,
            permissions="".join(perms),
            flags=flags
        )
        sections.append(section_obj)

    # Imports
    imports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore') if entry.dll else "Unknown.dll"
            for imp in entry.imports:
                func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else f"Ordinal_{imp.ordinal}"
                imports.append(ImportSymbol(
                    library=dll_name,
                    function_name=func_name,
                    ordinal=imp.ordinal,
                    address=imp.address
                ))

    # Exports
    exports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            func_name = exp.name.decode('utf-8', errors='ignore') if exp.name else f"Ordinal_{exp.ordinal}"
            exports.append(ExportSymbol(
                name=func_name,
                ordinal=exp.ordinal,
                address=exp.address
            ))

    return BinaryObject(
        filepath=filepath,
        filename=filepath.replace("\\", "/").split("/")[-1],
        filesize=len(raw_bytes),
        file_format=BinaryFormat.PE,
        architecture=arch,
        bits=bits,
        endianness="little",
        entry_point=pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        headers=headers,
        sections=sections,
        imports=imports,
        exports=exports,
        raw_bytes=raw_bytes
    )
