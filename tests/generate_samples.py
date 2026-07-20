"""
Synthetic Sample Binary Generator for PE, ELF, Mach-O, and Raw formats
"""
import os
import struct

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")

def create_sample_pe(filepath: str):
    """Generates a minimal valid PE executable header and payload."""
    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    struct.pack_into("<I", dos_header, 60, 64)  # e_lfanew -> 64

    nt_signature = b"PE\x00\x00"

    # IMAGE_FILE_HEADER (20 bytes)
    file_header = struct.pack(
        "<HHIIIHH",
        0x8664,  # x86_64
        2,       # NumberOfSections = 2 (.text, .data)
        0x64B2F5C0, # TimeDateStamp
        0, 0,
        240,     # SizeOfOptionalHeader
        0x0022   # Characteristics (EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE)
    )

    # IMAGE_OPTIONAL_HEADER64
    opt_header = bytearray(240)
    struct.pack_into("<H", opt_header, 0, 0x020B)       # Magic (PE32+)
    struct.pack_into("<I", opt_header, 16, 0x1000)      # AddressOfEntryPoint
    struct.pack_into("<I", opt_header, 20, 0x1000)      # BaseOfCode
    struct.pack_into("<Q", opt_header, 24, 0x00400000)  # ImageBase
    struct.pack_into("<I", opt_header, 32, 0x1000)      # SectionAlignment
    struct.pack_into("<I", opt_header, 36, 0x200)       # FileAlignment
    struct.pack_into("<I", opt_header, 56, 0x3000)      # SizeOfImage
    struct.pack_into("<I", opt_header, 60, 0x400)       # SizeOfHeaders
    struct.pack_into("<H", opt_header, 68, 3)           # Subsystem (CUI)
    struct.pack_into("<I", opt_header, 108, 16)         # NumberOfRvaAndSizes

    # Section 1: .text (40 bytes)
    sec_text = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x1000, 0x200, 0x1000, 0x200, 0, 0, 0, 0,
        0x60000020 # CODE | EXEC | READ
    )

    # Section 2: .data (40 bytes)
    sec_data = struct.pack(
        "<8sIIIIIIHHI",
        b".data\x00\x00\x00",
        0x2000, 0x200, 0x2000, 0x400, 0, 0, 0, 0,
        0xC0000040 # INITIALIZED_DATA | READ | WRITE
    )

    header_bytes = bytes(dos_header) + nt_signature + file_header + opt_header + sec_text + sec_data
    header_bytes = header_bytes.ljust(0x200, b"\x00")

    # Code payload x86_64: push rbp; mov rbp, rsp; xor eax, eax; ret
    code_payload = b"\x55\x48\x89\xe5\x31\xc0\xc3" + b"VirtualAllocEx\x00CheckRemoteDebuggerPresent\x00https://example.com/api\x00"
    code_payload = code_payload.ljust(0x200, b"\x90")

    data_payload = b"HKEY_LOCAL_MACHINE\\Software\\RevLab\x00192.168.1.100\x00C:\\Windows\\System32\\cmd.exe\x00"
    data_payload = data_payload.ljust(0x200, b"\x00")

    pe_bytes = header_bytes + code_payload + data_payload
    with open(filepath, "wb") as f:
        f.write(pe_bytes)

def create_sample_elf(filepath: str):
    """Generates a minimal valid ELF 64-bit binary."""
    # ELF Header 64-bit (64 bytes)
    elf_header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        2,      # ET_EXEC
        0x3E,   # x86_64
        1,      # EV_CURRENT
        0x400000, # e_entry
        64,     # e_phoff
        0,      # e_shoff
        0,      # e_flags
        64,     # e_ehsize
        56,     # e_phentsize
        1,      # e_phnum
        64,     # e_shentsize
        0,      # e_shnum
        0       # e_shstrndx
    )
    # Code payload
    code = b"\x31\xc0\x48\x89\xd8\xc3" + b"IsDebuggerPresent\x00/usr/bin/python3\x00"
    elf_bytes = elf_header.ljust(512, b"\x90") + code
    with open(filepath, "wb") as f:
        f.write(elf_bytes)

def generate_all_samples():
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    sample_pe = os.path.join(SAMPLES_DIR, "sample_pe.exe")
    sample_elf = os.path.join(SAMPLES_DIR, "sample_elf.elf")
    
    create_sample_pe(sample_pe)
    create_sample_elf(sample_elf)
    return sample_pe, sample_elf

if __name__ == "__main__":
    generate_all_samples()
