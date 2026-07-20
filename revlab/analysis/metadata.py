"""
Binary Metadata Enrichment Module
"""
from typing import Dict, Any
from ..parsers.common import BinaryObject

def analyze_metadata(binary: BinaryObject) -> Dict[str, Any]:
    """Extracts and formats binary high-level metadata."""
    return {
        "filename": binary.filename,
        "filepath": binary.filepath,
        "filesize_bytes": binary.filesize,
        "filesize_formatted": f"{binary.filesize / 1024:.2f} KB" if binary.filesize < 1024*1024 else f"{binary.filesize / (1024*1024):.2f} MB",
        "file_format": binary.file_format.value,
        "architecture": binary.architecture.value,
        "bits": binary.bits,
        "endianness": binary.endianness,
        "entry_point": hex(binary.entry_point),
        "headers": binary.headers
    }
