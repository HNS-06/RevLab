"""
Binary Hash Calculation Engine
"""
import hashlib
from typing import Dict
from ..parsers.common import BinaryObject

def calculate_hashes(binary: BinaryObject) -> Dict[str, str]:
    """Calculates standard cryptographic hashes and PE import hash (ImpHash)."""
    raw = binary.raw_bytes
    hashes = {
        "md5": hashlib.md5(raw).hexdigest(),
        "sha1": hashlib.sha1(raw).hexdigest(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }

    # ImpHash calculation for PE binaries
    if binary.imports:
        imp_str = ",".join(f"{imp.library.lower()}:{imp.function_name.lower()}" for imp in binary.imports)
        hashes["imphash"] = hashlib.md5(imp_str.encode('utf-8')).hexdigest()
    else:
        hashes["imphash"] = "N/A"

    # Store in BinaryObject
    binary.hashes = hashes
    return hashes
