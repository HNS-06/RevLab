"""
Basic Block Finder for Control Flow Analysis
"""
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional
from .instruction import Instruction

@dataclass
class BasicBlock:
    start_address: int
    end_address: int
    instructions: List[Instruction] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)

    @property
    def terminator(self) -> Optional[Instruction]:
        return self.instructions[-1] if self.instructions else None

def build_basic_blocks(instructions: List[Instruction]) -> List[BasicBlock]:
    """Partitions a sequence of instructions into Basic Blocks."""
    if not instructions:
        return []

    leaders: Set[int] = {instructions[0].address}

    # Find leaders (targets of jumps/calls or instruction following jump/call/ret)
    for i, insn in enumerate(instructions):
        if insn.is_jump or insn.is_call:
            if insn.branch_target is not None:
                leaders.add(insn.branch_target)
            if i + 1 < len(instructions):
                leaders.add(instructions[i + 1].address)
        elif insn.is_ret:
            if i + 1 < len(instructions):
                leaders.add(instructions[i + 1].address)

    # Group instructions into basic blocks
    blocks: List[BasicBlock] = []
    block_map: Dict[int, BasicBlock] = {}
    current_block: Optional[BasicBlock] = None

    for insn in instructions:
        if insn.address in leaders or current_block is None:
            if current_block and current_block.instructions:
                current_block.end_address = current_block.instructions[-1].address
                blocks.append(current_block)
                block_map[current_block.start_address] = current_block

            current_block = BasicBlock(start_address=insn.address, end_address=insn.address)

        current_block.instructions.append(insn)

    if current_block and current_block.instructions:
        current_block.end_address = current_block.instructions[-1].address
        blocks.append(current_block)
        block_map[current_block.start_address] = current_block

    # Build CFG Edges (successors/predecessors)
    for block in blocks:
        term = block.terminator
        if not term:
            continue

        if term.branch_target and term.branch_target in block_map:
            block.successors.append(term.branch_target)
            block_map[term.branch_target].predecessors.append(block.start_address)

        if term.is_conditional or (not term.is_jump and not term.is_ret):
            # Fallthrough successor
            next_addr = term.address + term.size
            if next_addr in block_map:
                block.successors.append(next_addr)
                block_map[next_addr].predecessors.append(block.start_address)

    return blocks
