"""
Mach-O (macOS / iOS Executable) Parser Module
"""
import struct
from .common import BinaryObject, BinaryFormat, Architecture, Section, ImportSymbol, ExportSymbol, HeaderField

# Mach-O Constants
MH_MAGIC = 0xfeedface
MH_CIGAM = 0xcefaedfe
MH_MAGIC_64 = 0xfeedfacf
MH_CIGAM_64 = 0xcffaedfe
FAT_MAGIC = 0xcafebabe
FAT_CIGAM = 0xbebafeca

CPU_TYPE_X86 = 7
CPU_TYPE_X86_64 = 7 | 0x01000000
CPU_TYPE_ARM = 12
CPU_TYPE_ARM64 = 12 | 0x01000000

def parse_macho(filepath: str, raw_bytes: bytes) -> BinaryObject:
    """Parses Mach-O binaries by reading Mach-O header structures."""
    if len(raw_bytes) < 32:
        raise ValueError("File too small for Mach-O header")

    magic = struct.unpack("<I", raw_bytes[:4])[0]
    
    is_64 = magic in (MH_MAGIC_64, MH_CIGAM_64)
    little_endian = magic in (MH_MAGIC, MH_MAGIC_64)
    endian = "<" if little_endian else ">"

    if is_64:
        cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack(
            f"{endian}IIIIIII", raw_bytes[4:32]
        )
        header_size = 32
    else:
        cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack(
            f"{endian}IIIIII", raw_bytes[4:28]
        )
        header_size = 28

    if cputype == CPU_TYPE_X86_64:
        arch = Architecture.X64
        bits = 64
    elif cputype == CPU_TYPE_X86:
        arch = Architecture.X86
        bits = 32
    elif cputype == CPU_TYPE_ARM64:
        arch = Architecture.ARM64
        bits = 64
    elif cputype == CPU_TYPE_ARM:
        arch = Architecture.ARM
        bits = 32
    else:
        arch = Architecture.UNKNOWN
        bits = 64 if is_64 else 32

    headers = [
        HeaderField("Magic", hex(magic), "Mach-O Header Magic"),
        HeaderField("CPU Type", hex(cputype), f"Target Architecture ({arch.value})"),
        HeaderField("File Type", hex(filetype), "Mach-O File Type"),
        HeaderField("Number of Load Commands", ncmds, "Count of Load Commands"),
        HeaderField("Size of Load Commands", sizeofcmds, "Total Size of Load Commands"),
        HeaderField("Flags", hex(flags), "Header Flags"),
    ]

    sections: list[Section] = []
    imports: list[ImportSymbol] = []
    exports: list[ExportSymbol] = []
    entry_point = 0x100000000 if is_64 else 0x1000

    # Parse Load Commands for Segments/Sections
    offset = header_size
    for _ in range(ncmds):
        if offset + 8 > len(raw_bytes):
            break
        cmd, cmdsize = struct.unpack(f"{endian}II", raw_bytes[offset:offset+8])
        
        # LC_SEGMENT (0x1) or LC_SEGMENT_64 (0x19)
        if cmd in (0x1, 0x19):
            is_seg64 = (cmd == 0x19)
            if is_seg64:
                segname = raw_bytes[offset+8:offset+24].decode('utf-8', errors='ignore').rstrip('\x00')
                vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags_seg = struct.unpack(
                    f"{endian}QQQQiiII", raw_bytes[offset+24:offset+72]
                )
                sec_offset = offset + 72
            else:
                segname = raw_bytes[offset+8:offset+24].decode('utf-8', errors='ignore').rstrip('\x00')
                vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags_seg = struct.unpack(
                    f"{endian}IIIIiiII", raw_bytes[offset+24:offset+56]
                )
                sec_offset = offset + 56

            # Iterate Sections within Segment
            for _ in range(nsects):
                if is_seg64:
                    if sec_offset + 80 > len(raw_bytes):
                        break
                    sectname = raw_bytes[sec_offset:sec_offset+16].decode('utf-8', errors='ignore').rstrip('\x00')
                    segname_sec = raw_bytes[sec_offset+16:sec_offset+32].decode('utf-8', errors='ignore').rstrip('\x00')
                    addr, size, offset_raw = struct.unpack(f"{endian}QQI", raw_bytes[sec_offset+32:sec_offset+52])[:3]
                    sec_offset += 80
                else:
                    if sec_offset + 68 > len(raw_bytes):
                        break
                    sectname = raw_bytes[sec_offset:sec_offset+16].decode('utf-8', errors='ignore').rstrip('\x00')
                    segname_sec = raw_bytes[sec_offset+16:sec_offset+32].decode('utf-8', errors='ignore').rstrip('\x00')
                    addr, size, offset_raw = struct.unpack(f"{endian}III", raw_bytes[sec_offset+32:sec_offset+44])[:3]
                    sec_offset += 68

                full_sec_name = f"{segname_sec},{sectname}"
                sections.append(Section(
                    name=full_sec_name,
                    virtual_address=addr,
                    virtual_size=size,
                    raw_size=size,
                    raw_offset=offset_raw,
                    permissions="r-x" if "text" in sectname.lower() else "rw-",
                    flags=[segname_sec]
                ))

        # LC_MAIN (0x80000028)
        elif cmd == 0x80000028:
            entry_off = struct.unpack(f"{endian}Q", raw_bytes[offset+8:offset+16])[0]
            entry_point = entry_off

        offset += cmdsize

    return BinaryObject(
        filepath=filepath,
        filename=filepath.replace("\\", "/").split("/")[-1],
        filesize=len(raw_bytes),
        file_format=BinaryFormat.MACHO,
        architecture=arch,
        bits=bits,
        endianness="little" if little_endian else "big",
        entry_point=entry_point,
        headers=headers,
        sections=sections,
        imports=imports,
        exports=exports,
        raw_bytes=raw_bytes
    )
