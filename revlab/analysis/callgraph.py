"""
Function Callgraph Construction Module
"""
import networkx as nx
from typing import Dict, Any
from ..parsers.common import BinaryObject
from ..disassembler.capstone_engine import disassemble_bytes
from ..disassembler.function_finder import find_functions

def generate_callgraph(binary: BinaryObject, sample_size: int = 4096) -> Dict[str, Any]:
    """Generates function callgraph DiGraph."""
    code_bytes = b""
    base_addr = binary.entry_point or 0x1000

    for sec in binary.sections:
        if "x" in sec.permissions or "EXEC" in sec.flags:
            code_bytes = binary.raw_bytes[sec.raw_offset : sec.raw_offset + min(sec.raw_size, sample_size)]
            base_addr = sec.virtual_address
            break

    if not code_bytes:
        code_bytes = binary.raw_bytes[:sample_size]

    instructions = disassemble_bytes(code_bytes, base_addr, binary.architecture, binary.bits)
    functions = find_functions(instructions)

    G = nx.DiGraph()
    func_map = {fn.address: fn.name for fn in functions}

    for fn in functions:
        G.add_node(fn.name, address=fn.address, size=fn.size)

    for fn in functions:
        for target in fn.calls:
            target_name = func_map.get(target, f"sub_{target:08X}")
            G.add_edge(fn.name, target_name)

    return {
        "functions_count": len(functions),
        "call_edges_count": G.number_of_edges(),
        "graph": G,
        "functions": functions
    }
