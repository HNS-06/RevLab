"""
Control Flow Graph (CFG) Construction & ASCII Graph Visualizer
"""
import networkx as nx
from typing import Dict, Any, List
from ..parsers.common import BinaryObject
from ..disassembler.capstone_engine import disassemble_bytes
from ..disassembler.basic_blocks import build_basic_blocks

def generate_cfg(binary: BinaryObject, sample_size: int = 2048) -> Dict[str, Any]:
    """Generates NetworkX DiGraph for binary Control Flow Graph."""
    code_bytes = b""
    base_addr = binary.entry_point or 0x1000

    for sec in binary.sections:
        if "x" in sec.permissions or "EXEC" in sec.flags or sec.name.lower() in (".text", "code", "__text"):
            code_bytes = binary.raw_bytes[sec.raw_offset : sec.raw_offset + min(sec.raw_size, sample_size)]
            base_addr = sec.virtual_address
            break

    if not code_bytes:
        code_bytes = binary.raw_bytes[:sample_size]

    instructions = disassemble_bytes(code_bytes, base_addr, binary.architecture, binary.bits)
    blocks = build_basic_blocks(instructions)

    G = nx.DiGraph()
    for block in blocks:
        G.add_node(
            f"0x{block.start_address:08X}",
            start_address=block.start_address,
            end_address=block.end_address,
            insn_count=len(block.instructions)
        )

    for block in blocks:
        for succ_addr in block.successors:
            G.add_edge(f"0x{block.start_address:08X}", f"0x{succ_addr:08X}")

    # Render ASCII tree preview
    ascii_tree = render_ascii_cfg(blocks)

    return {
        "nodes_count": G.number_of_nodes(),
        "edges_count": G.number_of_edges(),
        "is_dag": nx.is_directed_acyclic_graph(G),
        "graph": G,
        "ascii_tree": ascii_tree
    }

def render_ascii_cfg(blocks: List[Any]) -> str:
    """Renders a simple ASCII representation of CFG basic blocks and control flows."""
    lines = ["Control Flow Graph (CFG) Overview:\n"]
    for b in blocks[:10]:
        start = f"0x{b.start_address:08X}"
        succs = ", ".join(f"0x{s:08X}" for s in b.successors) if b.successors else "End / Return"
        lines.append(f"  [ Block {start} ] ({len(b.instructions)} insns)")
        lines.append(f"      └─► {succs}")
    return "\n".join(lines)
