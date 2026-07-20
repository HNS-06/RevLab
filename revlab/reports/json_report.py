"""
JSON Report Exporter
"""
import json
from typing import Dict, Any

def generate_json_report(summary: Dict[str, Any]) -> str:
    """Serializes analysis summary dictionary to JSON string."""
    return json.dumps(summary, indent=2, default=str)
