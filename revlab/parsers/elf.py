"""
ELF (Executable and Linkable Format) Parser Module
"""
import io
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from .common import BinaryObject, BinaryFormat, Architecture, Section, ImportSymbol, ExportSymbol, HeaderField

def parse_elf(filepath: str, raw_bytes: bytes) -> BinaryObject:
    """Parses an ELF binary using pyelftools."""
    stream = io.BytesIO(raw_bytes)
    elf = ELFFile(stream)

    header = elf.header
    e_machine = header['e_machine']
    bits = elf.elfclass

    if 'x86' in e_machine.lower() or '386' in e_machine.lower():
        arch = Architecture.X86 if bits == 32 else Architecture.X64
    elif 'x86_64' in e_machine.lower() or 'amd64' in e_machine.lower() or 'x64' in e_machine.lower():
        arch = Architecture.X64
    elif 'arm' in e_machine.lower():
        arch = Architecture.ARM64 if bits == 64 else Architecture.ARM
    elif 'aarch64' in e_machine.lower():
        arch = Architecture.ARM64
    else:
        arch = Architecture.UNKNOWN

    endianness = "little" if elf.little_endian else "big"

    headers = [
        HeaderField("Magic", "\\x7fELF", "ELF Identification Magic"),
        HeaderField("Class", f"ELF{bits}", f"{bits}-bit Architecture"),
        HeaderField("Data", f"{endianness.capitalize()}-endian", "Byte Endianness"),
        HeaderField("Machine", e_machine, f"Target Machine ({arch.value})"),
        HeaderField("Type", header['e_type'], "Object File Type"),
        HeaderField("Entry Point", hex(header['e_entry']), "Program Entry Address"),
        HeaderField("Section Headers Count", header['e_shnum'], "Count of Section Headers"),
        HeaderField("Program Headers Count", header['e_phnum'], "Count of Segment Headers"),
    ]

    sections = []
    imports = []
    exports = []

    for sec in elf.iter_sections():
        name = sec.name
        flags = []
        perms = []
        sec_flags = sec['sh_flags']
        
        # Read permissions
        perms.append('r')
        if sec_flags & 0x1:  # SHF_WRITE
            perms.append('w')
        else:
            perms.append('-')
        if sec_flags & 0x4:  # SHF_EXECINSTR
            perms.append('x')
            flags.append("EXEC")
        else:
            perms.append('-')

        if sec_flags & 0x2:
            flags.append("ALLOC")

        section_obj = Section(
            name=name if name else f".sec_{sec.name}",
            virtual_address=sec['sh_addr'],
            virtual_size=sec['sh_size'],
            raw_size=sec['sh_size'],
            raw_offset=sec['sh_offset'],
            permissions="".join(perms),
            flags=flags
        )
        sections.append(section_obj)

        # Parse Symbol Tables for Imports/Exports
        if isinstance(sec, SymbolTableSection):
            for symbol in sec.iter_symbols():
                sym_name = symbol.name
                if not sym_name:
                    continue
                bind = symbol['st_info']['bind']
                sym_type = symbol['st_info']['type']
                shndx = symbol['st_shndx']

                if shndx == 'SHN_UNDEF':
                    imports.append(ImportSymbol(
                        library="Dynamic Linker",
                        function_name=sym_name,
                        address=symbol['st_value']
                    ))
                elif bind in ('STB_GLOBAL', 'STB_WEAK') and sym_type in ('STT_FUNC', 'STT_OBJECT'):
                    exports.append(ExportSymbol(
                        name=sym_name,
                        ordinal=0,
                        address=symbol['st_value']
                    ))

    return BinaryObject(
        filepath=filepath,
        filename=filepath.replace("\\", "/").split("/")[-1],
        filesize=len(raw_bytes),
        file_format=BinaryFormat.ELF,
        architecture=arch,
        bits=bits,
        endianness=endianness,
        entry_point=header['e_entry'],
        headers=headers,
        sections=sections,
        imports=imports,
        exports=exports,
        raw_bytes=raw_bytes
    )
