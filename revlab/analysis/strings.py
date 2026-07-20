"""
String Extraction & Pattern Categorization Module
"""
import re
from dataclasses import dataclass
from typing import List, Dict
from ..parsers.common import BinaryObject

@dataclass
class ExtractedString:
    offset: int
    string_type: str  # "ASCII" or "UTF-16"
    value: str
    category: str = "General"

# Regex rules for interested indicators
PATTERNS = {
    "IPv4 Address": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
    "URL / Domain": re.compile(r'https?://[^\s/$.?#].[^\s]*|www\.[^\s]+\.[a-z]{2,}', re.IGNORECASE),
    "Windows Registry": re.compile(r'HKEY_[A-Z_]+|\bSoftware\\Microsoft\\Windows\\CurrentVersion\\[^\s]+', re.IGNORECASE),
    "File Path": re.compile(r'[a-zA-Z]:\\[\\\w\s\.-]+|/(?:usr|etc|var|tmp|bin|sbin)/[\w\.-]+'),
    "Base64 Candidate": re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'),
}

def extract_strings(binary: BinaryObject, min_len: int = 4) -> Dict[str, any]:
    """Extracts ASCII and UTF-16 strings from binary raw bytes."""
    data = binary.raw_bytes
    extracted: List[ExtractedString] = []

    # 1. ASCII string extraction
    ascii_pattern = re.compile(b'[\x20-\x7e]{' + str(min_len).encode() + b',}')
    for match in ascii_pattern.finditer(data):
        val = match.group().decode('ascii', errors='ignore')
        cat = classify_string(val)
        extracted.append(ExtractedString(
            offset=match.start(),
            string_type="ASCII",
            value=val,
            category=cat
        ))

    # 2. UTF-16 LE string extraction
    utf16_pattern = re.compile(b'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + b',}')
    for match in utf16_pattern.finditer(data):
        val = match.group().decode('utf-16le', errors='ignore')
        cat = classify_string(val)
        extracted.append(ExtractedString(
            offset=match.start(),
            string_type="UTF-16",
            value=val,
            category=cat
        ))

    # Group by Category
    categorized: Dict[str, List[ExtractedString]] = {}
    for item in extracted:
        if item.category not in categorized:
            categorized[item.category] = []
        categorized[item.category].append(item)

    return {
        "total_strings": len(extracted),
        "categorized": categorized,
        "all_strings": extracted
    }

def classify_string(val: str) -> str:
    """Classifies string based on regex pattern rules."""
    for category, regex in PATTERNS.items():
        if category == "Base64 Candidate":
            if len(val) >= 16 and regex.match(val):
                return category
        elif regex.search(val):
            return category
    return "General"
