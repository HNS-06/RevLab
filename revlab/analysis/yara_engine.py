"""
YARA Signature Scanning Engine
"""
import re
import os
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from ..parsers.common import BinaryObject

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

@dataclass
class YaraMatch:
    rule_name: str
    namespace: str
    tags: List[str]
    meta: Dict[str, Any]
    strings_matched: List[Tuple[int, str, str]] = field(default_factory=list) # (offset, identifier, value)

BUILTIN_RULES = """
rule AntiDebugging_APIs {
    meta:
        description = "Detects common Windows anti-debugging API strings"
        severity = "MEDIUM"
    strings:
        $a1 = "IsDebuggerPresent" ascii wide
        $a2 = "CheckRemoteDebuggerPresent" ascii wide
        $a3 = "NtQueryInformationProcess" ascii wide
        $a4 = "OutputDebugStringA" ascii wide
    condition:
        any of ($a*)
}

rule UPX_Packed_Executable {
    meta:
        description = "Detects UPX packer section signatures"
        severity = "HIGH"
    strings:
        $u1 = "UPX0" ascii
        $u2 = "UPX1" ascii
        $u3 = "UPX!" ascii
    condition:
        2 of ($u*)
}

rule Shellcode_Prologue {
    meta:
        description = "Detects common shellcode function prologues or NOP sleds"
        severity = "HIGH"
    strings:
        $s1 = { 90 90 90 90 90 90 90 90 }
        $s2 = { 55 48 89 E5 }
        $s3 = { 31 C0 64 8B 40 30 }
    condition:
        any of ($s*)
}

rule Network_Downloader_Indicators {
    meta:
        description = "Detects HTTP downloading APIs and URL strings"
        severity = "MEDIUM"
    strings:
        $n1 = "URLDownloadToFileA" ascii wide
        $n2 = "InternetOpenUrlA" ascii wide
        $n3 = "HttpSendRequestA" ascii wide
    condition:
        any of ($n*)
}
"""

def scan_yara(binary: BinaryObject, custom_rule_path: Optional[str] = None) -> List[YaraMatch]:
    """Scans binary raw bytes against built-in YARA rules and optional custom rule path."""
    matches: List[YaraMatch] = []

    if HAS_YARA:
        try:
            rule_sources = {"builtin": BUILTIN_RULES}
            if custom_rule_path and os.path.exists(custom_rule_path):
                if os.path.isfile(custom_rule_path):
                    with open(custom_rule_path, "r", encoding="utf-8", errors="ignore") as f:
                        rule_sources["custom"] = f.read()
                elif os.path.isdir(custom_rule_path):
                    for fname in os.listdir(custom_rule_path):
                        if fname.endswith(".yar") or fname.endswith(".yara"):
                            fpath = os.path.join(custom_rule_path, fname)
                            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                                rule_sources[fname] = f.read()

            compiled_rules = yara.compile(sources=rule_sources)
            yara_results = compiled_rules.match(data=binary.raw_bytes)

            for match in yara_results:
                matched_strings = []
                for s in match.strings:
                    # s is tuple (offset, identifier, data)
                    off = s[0]
                    identifier = s[1]
                    s_data = s[2].decode('utf-8', errors='ignore') if isinstance(s[2], bytes) else str(s[2])
                    matched_strings.append((off, identifier, s_data))

                matches.append(YaraMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    tags=list(match.tags),
                    meta=dict(match.meta),
                    strings_matched=matched_strings
                ))
            return matches
        except Exception:
            pass

    # Heuristic Regex Fallback Scanner if yara-python isn't installed
    return fallback_yara_scan(binary)

def fallback_yara_scan(binary: BinaryObject) -> List[YaraMatch]:
    """Lightweight built-in signature fallback when yara-python is not installed."""
    data = binary.raw_bytes
    matches = []

    # Check Anti-Debug
    anti_debug_terms = [b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent", b"NtQueryInformationProcess"]
    found = []
    for term in anti_debug_terms:
        idx = data.find(term)
        if idx != -1:
            found.append((idx, "$api", term.decode('ascii')))

    if found:
        matches.append(YaraMatch(
            rule_name="AntiDebugging_APIs",
            namespace="builtin_fallback",
            tags=["anti_debug"],
            meta={"description": "Detects common Windows anti-debugging API strings", "severity": "MEDIUM"},
            strings_matched=found
        ))

    # Check UPX
    upx_terms = [b"UPX0", b"UPX1", b"UPX!"]
    found_upx = []
    for term in upx_terms:
        idx = data.find(term)
        if idx != -1:
            found_upx.append((idx, "$upx", term.decode('ascii')))

    if len(found_upx) >= 2:
        matches.append(YaraMatch(
            rule_name="UPX_Packed_Executable",
            namespace="builtin_fallback",
            tags=["packer", "upx"],
            meta={"description": "Detects UPX packer section signatures", "severity": "HIGH"},
            strings_matched=found_upx
        ))

    return matches
