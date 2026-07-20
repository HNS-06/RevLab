"""
Function Prologue Finder and Symbol Discovery
"""
from dataclasses import dataclass, field
from typing import List, Dict
from .instruction import Instruction
from .basic_blocks import BasicBlock, build_basic_blocks

@dataclass
class FunctionSymbol:
    address: int
    name: str
    size: int
    basic_blocks_count: int
    instructions_count: int
    calls: List[int] = field(default_factory=list)

def find_functions(instructions: List[Instruction]) -> List[FunctionSymbol]:
    """Scans instruction stream for function prologues and call targets."""
    funcs: Dict[int, FunctionSymbol] = {}

    # Heuristic prologues
    for i, insn in enumerate(instructions):
        is_prologue = False
        # x86/x64 prologue: push rbp / push ebp
        if insn.mnemonic.lower() in ("push", "pushl", "pushq") and insn.operands.lower() in ("rbp", "ebp"):
            is_prologue = True
        elif insn.mnemonic.lower() == "sub" and "rsp" in insn.operands.lower():
            is_prologue = True
        elif insn.is_call and insn.branch_target:
            # Call target is also a function entry
            if insn.branch_target not in funcs:
                funcs[insn.branch_target] = FunctionSymbol(
                    address=insn.branch_target,
                    name=f"sub_{insn.branch_target:08X}",
                    size=0,
                    basic_blocks_count=1,
                    instructions_count=0
                )

        if is_prologue:
            if insn.address not in funcs:
                funcs[insn.address] = FunctionSymbol(
                    address=insn.address,
                    name=f"sub_{insn.address:08X}",
                    size=0,
                    basic_blocks_count=1,
                    instructions_count=0
                )

    # If no prologue matched, register entry point
    if not funcs and instructions:
        entry_addr = instructions[0].address
        funcs[entry_addr] = FunctionSymbol(
            address=entry_addr,
            name="main_entry",
            size=len(instructions) * 4,
            basic_blocks_count=len(build_basic_blocks(instructions)),
            instructions_count=len(instructions)
        )

    # Calculate sizes & stats
    sorted_addrs = sorted(funcs.keys())
    for idx, addr in enumerate(sorted_addrs):
        next_addr = sorted_addrs[idx + 1] if idx + 1 < len(sorted_addrs) else (instructions[-1].address + instructions[-1].size if instructions else addr + 64)
        fn_insns = [i for i in instructions if addr <= i.address < next_addr]
        funcs[addr].instructions_count = len(fn_insns)
        funcs[addr].size = sum(i.size for i in fn_insns)
        funcs[addr].basic_blocks_count = len(build_basic_blocks(fn_insns))
        funcs[addr].calls = [i.branch_target for i in fn_insns if i.is_call and i.branch_target]

    return list(funcs.values())
