"""
De-obfuscation & Stack Strings / Single-Byte XOR Brute-Force Engine
"""
import re
from dataclasses import dataclass
from typing import List, Dict, Any
from ..parsers.common import BinaryObject
from ..disassembler.capstone_engine import disassemble_bytes

@dataclass
class DeobfuscatedString:
    method: str  # "Stack String" or "XOR Key 0xXX"
    offset_or_addr: str
    value: str
    category: str = "General"

def deobfuscate_strings(binary: BinaryObject) -> Dict[str, Any]:
    """Runs stack strings extraction and single-byte XOR decryption scans."""
    results: List[DeobfuscatedString] = []

    # 1. Extract Stack Strings from Code Disassembly
    stack_strings = extract_stack_strings(binary)
    results.extend(stack_strings)

    # 2. XOR Single-Byte Brute-Force
    xor_strings = bruteforce_xor_strings(binary)
    results.extend(xor_strings)

    return {
        "total_deobfuscated": len(results),
        "results": results
    }

def extract_stack_strings(binary: BinaryObject, min_len: int = 4) -> List[DeobfuscatedString]:
    """Scans code disassembly for stack string byte moves."""
    stack_strings = []
    code_bytes = b""
    base_addr = binary.entry_point or 0x1000

    for sec in binary.sections:
        if "x" in sec.permissions or "EXEC" in sec.flags or sec.name.lower() in (".text", "code"):
            code_bytes = binary.raw_bytes[sec.raw_offset : sec.raw_offset + min(sec.raw_size, 4096)]
            base_addr = sec.virtual_address
            break

    if not code_bytes:
        code_bytes = binary.raw_bytes[:2048]

    instructions = disassemble_bytes(code_bytes, base_addr, binary.architecture, binary.bits)

    current_chars = []
    start_addr = 0

    for insn in instructions:
        mnem = insn.mnemonic.lower()
        ops = insn.operands.lower()

        # Check for byte store to stack: mov byte ptr [rbp - X], 0xXX or mov [ebp - X], 0xXX
        if mnem in ("mov", "movb") and ("ptr" in ops or "[" in ops) and "0x" in ops:
            try:
                parts = ops.split(",")
                if len(parts) == 2:
                    val_str = parts[1].strip()
                    if val_str.startswith("0x"):
                        val_byte = int(val_str, 16)
                        if 0x20 <= val_byte <= 0x7E:
                            if not current_chars:
                                start_addr = insn.address
                            current_chars.append(chr(val_byte))
                            continue
            except Exception:
                pass

        if len(current_chars) >= min_len:
            val_str = "".join(current_chars)
            stack_strings.append(DeobfuscatedString(
                method="Stack String Assembly",
                offset_or_addr=f"0x{start_addr:08X}",
                value=val_str,
                category=classify_deobfuscated(val_str)
            ))

        current_chars = []

    return stack_strings

def bruteforce_xor_strings(binary: BinaryObject, min_len: int = 6) -> List[DeobfuscatedString]:
    """Brute-forces single-byte XOR keys (0x01..0xFF) searching for hidden URLs, IPs, APIs."""
    xor_results = []
    data = binary.raw_bytes[:65536]  # Scan first 64KB

    target_regex = re.compile(r'https?://[^\s]+|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|HKEY_[A-Z_]+|VirtualAllocEx|CreateProcessA|WriteProcessMemory', re.IGNORECASE)

    raw_text = data.decode('latin-1', errors='ignore')

    for key in range(1, 256):
        decrypted = bytes([b ^ key for b in data])
        dec_text = decrypted.decode('latin-1', errors='ignore')
        for match in target_regex.finditer(dec_text):
            val = match.group()
            # Only include if candidate string was NOT already present in raw unencrypted bytes
            if len(val) >= min_len and val not in raw_text:
                xor_results.append(DeobfuscatedString(
                    method=f"XOR Key 0x{key:02X}",
                    offset_or_addr=f"0x{match.start():08X}",
                    value=val,
                    category=classify_deobfuscated(val)
                ))

    # Deduplicate results
    seen = set()
    unique = []
    for item in xor_results:
        if item.value not in seen:
            seen.add(item.value)
            unique.append(item)

    return unique[:15]

def classify_deobfuscated(val: str) -> str:
    """Classifies de-obfuscated string category."""
    if "http" in val.lower() or "www." in val.lower():
        return "URL / Domain"
    elif re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', val):
        return "IPv4 Address"
    elif "HKEY_" in val or "Software\\" in val:
        return "Windows Registry"
    elif any(api in val for api in ("Virtual", "Process", "Thread", "Memory", "Write", "Read", "Alloc")):
        return "Suspicious API"
    return "De-obfuscated Text"
