"""
Capstone Disassembler Wrapper & Fallback Engine
"""
from typing import List, Optional
from .instruction import Instruction
from ..parsers.common import Architecture, BinaryObject

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

def get_capstone_mode(arch: Architecture, bits: int):
    """Maps Architecture enum to Capstone constants."""
    if not HAS_CAPSTONE:
        return None, None

    if arch in (Architecture.X86, Architecture.X64):
        c_arch = capstone.CS_ARCH_X86
        c_mode = capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32
    elif arch == Architecture.ARM:
        c_arch = capstone.CS_ARCH_ARM
        c_mode = capstone.CS_MODE_ARM
    elif arch == Architecture.ARM64:
        c_arch = capstone.CS_ARCH_ARM64
        c_mode = capstone.CS_MODE_ARM
    else:
        c_arch = capstone.CS_ARCH_X86
        c_mode = capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32
    return c_arch, c_mode

def disassemble_bytes(code: bytes, base_address: int, arch: Architecture = Architecture.X64, bits: int = 64, count: Optional[int] = None) -> List[Instruction]:
    """
    Disassembles raw code bytes starting at base_address.
    Uses Capstone if available, otherwise falls back to a custom x86/x64 decoder.
    """
    instructions: List[Instruction] = []

    if HAS_CAPSTONE:
        c_arch, c_mode = get_capstone_mode(arch, bits)
        if c_arch is not None:
            try:
                md = capstone.Cs(c_arch, c_mode)
                md.detail = True
                for i, insn in enumerate(md.disasm(code, base_address)):
                    if count and i >= count:
                        break
                    
                    is_call = insn.mnemonic.lower() in ("call", "bl", "blx")
                    is_jump = insn.mnemonic.lower().startswith("j") or insn.mnemonic.lower() in ("b", "bx")
                    is_ret = insn.mnemonic.lower() in ("ret", "retn", "bx lr")
                    is_cond = is_jump and insn.mnemonic.lower() not in ("jmp", "b")

                    target = None
                    # Attempt to extract jump/call numeric target
                    if (is_call or is_jump) and insn.op_str:
                        try:
                            if insn.op_str.startswith("0x"):
                                target = int(insn.op_str, 16)
                            elif insn.op_str.isdigit():
                                target = int(insn.op_str)
                        except ValueError:
                            target = None

                    instructions.append(Instruction(
                        address=insn.address,
                        size=insn.size,
                        bytes=insn.bytes,
                        mnemonic=insn.mnemonic,
                        operands=insn.op_str,
                        branch_target=target,
                        is_call=is_call,
                        is_jump=is_jump,
                        is_ret=is_ret,
                        is_conditional=is_cond
                    ))
                return instructions
            except Exception:
                pass

    # Fallback Lightweight Disassembler for x86/x64
    return fallback_disassemble(code, base_address, count)

def fallback_disassemble(code: bytes, base_address: int, count: Optional[int] = None) -> List[Instruction]:
    """Simple opcode heuristic disassembler fallback for x86/x64 binaries."""
    instructions = []
    offset = 0
    curr_addr = base_address

    opcodes_map = {
        0x55: ("push", "rbp/ebp", 1),
        0x48: ("mov", "rbp, rsp", 3),  # 48 89 E5
        0xE8: ("call", "near_ptr", 5),
        0xE9: ("jmp", "near_ptr", 5),
        0xEB: ("jmp", "short_ptr", 2),
        0xC3: ("ret", "", 1),
        0x90: ("nop", "", 1),
        0x31: ("xor", "eax, eax", 2),
        0x89: ("mov", "reg, reg", 2),
        0x8B: ("mov", "reg, [mem]", 2),
        0x85: ("test", "eax, eax", 2),
        0x3B: ("cmp", "eax, edx", 2),
        0x74: ("jz", "label", 2),
        0x75: ("jnz", "label", 2),
        0x0F: ("two_byte", "", 2),
    }

    while offset < len(code):
        if count and len(instructions) >= count:
            break

        b = code[offset]
        addr = curr_addr + offset

        if b in opcodes_map:
            mnem, ops, size = opcodes_map[b]
            insn_bytes = code[offset:offset+size]
            
            target = None
            is_call = mnem == "call"
            is_jump = mnem.startswith("j")
            is_ret = mnem == "ret"

            if mnem in ("call", "jmp") and size == 5 and offset + 5 <= len(code):
                rel = int.from_bytes(code[offset+1:offset+5], byteorder='little', signed=True)
                target = addr + 5 + rel
                ops = f"0x{target:08X}"
            elif is_jump and size == 2 and offset + 2 <= len(code):
                rel = int.from_bytes(code[offset+1:offset+2], byteorder='little', signed=True)
                target = addr + 2 + rel
                ops = f"0x{target:08X}"

            instructions.append(Instruction(
                address=addr,
                size=len(insn_bytes),
                bytes=insn_bytes,
                mnemonic=mnem,
                operands=ops,
                branch_target=target,
                is_call=is_call,
                is_jump=is_jump,
                is_ret=is_ret
            ))
            offset += size
        else:
            insn_bytes = code[offset:offset+1]
            instructions.append(Instruction(
                address=addr,
                size=1,
                bytes=insn_bytes,
                mnemonic="db",
                operands=f"0x{b:02X}"
            ))
            offset += 1

    return instructions
