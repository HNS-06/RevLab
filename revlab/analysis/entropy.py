"""
Shannon Entropy Analysis Module
"""
import math
from typing import Dict, List, Tuple
from ..parsers.common import BinaryObject, Section

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon Entropy for a byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    
    entropy = 0.0
    length = len(data)
    for count in byte_counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
        
    return round(entropy, 4)

def analyze_entropy(binary: BinaryObject) -> Dict[str, any]:
    """Analyzes file-wide entropy and section-by-section entropy."""
    overall_entropy = calculate_shannon_entropy(binary.raw_bytes)

    section_entropies: List[Tuple[str, float, str]] = []
    high_entropy_sections = []

    for sec in binary.sections:
        # Extract section bytes
        sec_bytes = binary.raw_bytes[sec.raw_offset : sec.raw_offset + sec.raw_size]
        sec_entropy = calculate_shannon_entropy(sec_bytes)
        sec.entropy = sec_entropy

        status = "Normal"
        if sec_entropy > 7.2:
            status = "High (Packed/Encrypted)"
            high_entropy_sections.append(sec.name)
        elif sec_entropy < 1.0 and sec.raw_size > 512:
            status = "Low (Sparse/Nulls)"

        section_entropies.append((sec.name, sec_entropy, status))

    # Determine if packed based on overall entropy or UPX/.pack sections
    is_packed = overall_entropy > 7.1 or len(high_entropy_sections) > 0
    if is_packed:
        binary.is_packed = True
        if not binary.packer_name:
            binary.packer_name = "Generic Packer / High Entropy"

    return {
        "overall_entropy": overall_entropy,
        "section_entropies": section_entropies,
        "is_packed": is_packed,
        "high_entropy_sections": high_entropy_sections
    }

def render_ascii_entropy_bar(entropy: float, width: int = 30) -> str:
    """Renders a colorful ASCII visual bar representing entropy level."""
    filled = int((entropy / 8.0) * width)
    bar = "█" * filled + "░" * (width - filled)
    
    if entropy > 7.2:
        return f"[red]{bar}[/] {entropy:.2f}/8.0 (Packed)"
    elif entropy > 6.0:
        return f"[yellow]{bar}[/] {entropy:.2f}/8.0 (Medium)"
    else:
        return f"[green]{bar}[/] {entropy:.2f}/8.0 (Normal)"
