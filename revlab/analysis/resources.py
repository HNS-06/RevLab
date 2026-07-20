"""
PE Rich Header Decryptor & .rsrc Resource Table Inspector
"""
import struct
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from ..parsers.common import BinaryObject

@dataclass
class RichHeaderRecord:
    tool_id: int
    build_number: int
    use_count: int
    description: str

@dataclass
class ResourceItem:
    type_name: str
    name_or_id: str
    size: int
    offset: int

def analyze_resources_and_rich(binary: BinaryObject) -> Dict[str, Any]:
    """Extracts Rich Header records and lists .rsrc resource entries."""
    rich_records = extract_rich_header(binary.raw_bytes)
    resources = extract_resource_table(binary)

    return {
        "rich_header": rich_records,
        "resources": resources,
        "total_resources": len(resources)
    }

def extract_rich_header(raw_bytes: bytes) -> List[RichHeaderRecord]:
    """Finds and decrypts MSVC Rich Header between 'DanS' and 'Rich' markers."""
    records: List[RichHeaderRecord] = []

    rich_idx = raw_bytes.find(b"Rich")
    if rich_idx == -1 or rich_idx < 32:
        return records

    xor_key = struct.unpack("<I", raw_bytes[rich_idx+4:rich_idx+8])[0]

    # Scan backwards for 'DanS' magic (0x47414E53 XOR key)
    dans_masked = struct.unpack("<I", b"DanS")[0] ^ xor_key
    
    dans_idx = -1
    for i in range(rich_idx - 8, 64, -4):
        val = struct.unpack("<I", raw_bytes[i:i+4])[0]
        if val == dans_masked:
            dans_idx = i
            break

    if dans_idx == -1:
        return records

    # Decrypt records (each record is 8 bytes: [tool_id:16 | build:16], use_count:32)
    curr = dans_idx + 16  # Skip 16 bytes padded header
    while curr < rich_idx:
        q1 = struct.unpack("<I", raw_bytes[curr:curr+4])[0] ^ xor_key
        q2 = struct.unpack("<I", raw_bytes[curr+4:curr+8])[0] ^ xor_key
        
        build_num = q1 & 0xFFFF
        tool_id = (q1 >> 16) & 0xFFFF
        count = q2

        records.append(RichHeaderRecord(
            tool_id=tool_id,
            build_number=build_num,
            use_count=count,
            description=get_tool_description(tool_id)
        ))
        curr += 8

    return records

def extract_resource_table(binary: BinaryObject) -> List[ResourceItem]:
    """Inspects section table for .rsrc section and parses resource entries."""
    items: List[ResourceItem] = []
    sec = binary.get_section_by_name(".rsrc")
    if not sec:
        return items

    rsrc_data = binary.raw_bytes[sec.raw_offset : sec.raw_offset + sec.raw_size]
    if len(rsrc_data) < 16:
        return items

    # Simple heuristic scanning for resource type signatures
    if b"<assembly" in rsrc_data or b"manifest" in rsrc_data.lower():
        items.append(ResourceItem(type_name="RT_MANIFEST", name_or_id="1", size=len(rsrc_data), offset=sec.raw_offset))

    items.append(ResourceItem(
        type_name="PE Resource Section",
        name_or_id=".rsrc",
        size=sec.raw_size,
        offset=sec.raw_offset
    ))
    return items

def get_tool_description(tool_id: int) -> str:
    """Maps MSVC tool ID to human readable compiler/linker descriptions."""
    tool_map = {
        0x0001: "Imported Symbol / Linker",
        0x00AA: "MSVC C++ Compiler",
        0x00AB: "MSVC C Compiler",
        0x00B0: "MSASM Assembler",
        0x00C1: "CVTRES Resource Converter",
        0x00C2: "LINK Linker Engine",
    }
    return tool_map.get(tool_id, "MSVC Build Tool")
