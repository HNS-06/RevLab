"""
Opcode Frequency Statistics & Mnemonic Profiling Module
"""
from collections import Counter
from typing import Dict, List, Tuple
from ..parsers.common import BinaryObject
from ..disassembler.capstone_engine import disassemble_bytes

def analyze_opcodes(binary: BinaryObject, sample_size: int = 4096) -> Dict[str, any]:
    """Analyzes opcode distribution and opcode frequencies from binary executable sections."""
    # Find executable section (.text or code section)
    code_bytes = b""
    base_addr = binary.entry_point or 0x1000

    for sec in binary.sections:
        if "x" in sec.permissions or "EXEC" in sec.flags or sec.name.lower() in (".text", "code", "__text"):
            offset = sec.raw_offset
            size = min(sec.raw_size, sample_size)
            code_bytes = binary.raw_bytes[offset : offset + size]
            base_addr = sec.virtual_address
            break

    if not code_bytes:
        code_bytes = binary.raw_bytes[:sample_size]

    # Disassemble code sample
    instructions = disassemble_bytes(code_bytes, base_addr, binary.architecture, binary.bits)

    mnemonics = [insn.mnemonic.lower() for insn in instructions]
    counts = Counter(mnemonics)

    # Classify instructions by type
    categories = {
        "Data Movement": 0,    # mov, lea, push, pop
        "Arithmetic / Logic": 0, # add, sub, xor, and, or, inc, dec
        "Control Flow": 0,      # jmp, jz, jnz, call, ret
        "System / Other": 0,    # nop, int, syscall
    }

    for mnem, count in counts.items():
        if mnem in ("mov", "lea", "push", "pop", "movzx", "movsx"):
            categories["Data Movement"] += count
        elif mnem in ("add", "sub", "xor", "and", "or", "inc", "dec", "cmp", "test", "shl", "shr"):
            categories["Arithmetic / Logic"] += count
        elif mnem.startswith("j") or mnem in ("call", "ret", "b", "bl"):
            categories["Control Flow"] += count
        else:
            categories["System / Other"] += count

    total_instructions = len(instructions)
    top_mnemonics: List[Tuple[str, int, float]] = [
        (mnem, count, round((count / total_instructions) * 100, 2))
        for mnem, count in counts.most_common(15)
    ] if total_instructions > 0 else []

    return {
        "total_disassembled": total_instructions,
        "top_mnemonics": top_mnemonics,
        "categories": categories,
        "instructions": instructions[:50]  # First 50 instructions sample
    }
