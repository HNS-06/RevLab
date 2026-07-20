"""
HTML Report Generator Engine
"""
import os
from jinja2 import Environment, FileSystemLoader
from typing import Dict, Any

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

def generate_html_report(summary: Dict[str, Any]) -> str:
    """Renders HTML report using Jinja2 template."""
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("report_template.html")
    return template.render(summary=summary)
