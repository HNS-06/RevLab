"""
Interactive Web-Based Control Flow Graph Generator
"""
from typing import Dict, Any
from ..parsers.common import BinaryObject
from .cfg import generate_cfg

def generate_web_cfg_html(binary: BinaryObject) -> str:
    """Generates an interactive HTML page with vis-network for CFG navigation."""
    cfg_data = generate_cfg(binary)
    G = cfg_data["graph"]

    nodes_json = []
    for node_id, attrs in G.nodes(data=True):
        label = f"Block {node_id}\\n({attrs.get('insn_count', 0)} insns)"
        nodes_json.append({"id": node_id, "label": label, "shape": "box", "color": {"background": "#282a36", "border": "#4cb9e7"}, "font": {"color": "#ffffff"}})

    edges_json = []
    for u, v in G.edges():
        edges_json.append({"from": u, "to": v, "arrows": "to", "color": {"color": "#da7756"}})

    import json
    nodes_str = json.dumps(nodes_json)
    edges_str = json.dumps(edges_json)

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>RevLab Web CFG - {binary.filename}</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style type="text/css">
        body {{ margin: 0; padding: 0; background: #1e1e2e; color: #fff; font-family: monospace; }}
        #header {{ padding: 15px; background: #da7756; font-size: 18px; font-weight: bold; }}
        #mynetwork {{ width: 100vw; height: calc(100vh - 60px); border: none; }}
    </style>
</head>
<body>
    <div id="header">⚡ REV LAB Interactive CFG Visualizer — {binary.filename} ({cfg_data['nodes_count']} Blocks, {cfg_data['edges_count']} Edges)</div>
    <div id="mynetwork"></div>
    <script type="text/javascript">
        var container = document.getElementById('mynetwork');
        var data = {{
            nodes: new vis.DataSet({nodes_str}),
            edges: new vis.DataSet({edges_str})
        }};
        var options = {{
            layout: {{ hierarchical: {{ direction: 'UD', sortMethod: 'directed' }} }},
            physics: {{ hierarchicalRepulsion: {{ nodeDistance: 150 }} }}
        }};
        var network = new vis.Network(container, data, options);
    </script>
</body>
</html>"""
    return html
