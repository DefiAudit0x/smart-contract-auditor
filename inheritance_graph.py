"""Inheritance Graph - inheritance diagram using Mermaid."""
import html as _html
import re
from typing import List, Dict

# Safe characters for contract names and parent identifiers. Anything else
# (angle brackets, quotes, event handlers, newlines…) is stripped so the
# values can never break out of the HTML/Mermaid contexts they end up in.
_SAFE_IDENT_RE = re.compile(r"[^A-Za-z0-9_. ,]", re.DOTALL)


def _sanitize_parents(parents: List[str]) -> List[str]:
    return [_SAFE_IDENT_RE.sub("", p).strip() for p in parents]


def extract_inheritance(code: str) -> List[Dict]:
    """Extract inheritance relationships from Solidity code."""
    contracts = []
    pattern = re.compile(
        r"(abstract\s+)?(contract|interface|library)\s+(\w+)\s*"
        r"(?:is\s+([^{]+))?"
    )
    for match in pattern.finditer(code):
        is_abstract = bool(match.group(1))
        kind = match.group(2)
        name = match.group(3)
        parents = [p.strip() for p in match.group(4).split(",") if p.strip()] if match.group(4) else []
        parents = _sanitize_parents(parents)
        contracts.append({
            "name": name,
            "kind": kind,
            "abstract": is_abstract,
            "parents": parents,
        })
    return contracts


def generate_mermaid_graph(contracts: List[Dict]) -> str:
    """Generate Mermaid diagram from inheritance relationships."""
    if not contracts:
        return "```mermaid\ngraph TD\n  _No_inheritance_\n```"

    lines = ["```mermaid", "graph TD"]
    for c in contracts:
        node_id = c["name"].replace(" ", "_")
        style = ""
        if c["kind"] == "interface":
            style = ":::interface"
        elif c["kind"] == "abstract":
            style = ":::abstract"
        elif c["abstract"]:
            style = ":::abstract"
        lines.append(f"  {node_id}{style}")
        for p in c["parents"]:
            parent_id = p.replace(" ", "_")
            lines.append(f"  {parent_id} -->|inherits| {node_id}")
    lines.append("")
    lines.append("classDef interface fill:#58a6ff,stroke:#1f6feb")
    lines.append("classDef abstract fill:#d29922,stroke:#9e6a03")
    lines.append("```")
    return "\n".join(lines)


def generate_html_graph(contracts: List[Dict]) -> str:
    """Generate HTML with interactive Mermaid diagram."""
    mermaid_code = generate_mermaid_graph(contracts)
    html = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head><meta charset="UTF-8">
<title>Inheritance Graph</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>mermaid.initialize({{startOnLoad:true,theme:'dark'}})</script>
<style>
body {{ background:#0d1117; color:#c9d1d9; font-family:sans-serif; padding:2rem; text-align:center; }}
h1 {{ color:#58a6ff; }}
.mermaid {{ max-width:1000px; margin:2rem auto; }}
table {{ margin:2rem auto; border-collapse:collapse; }}
th,td {{ border:1px solid #30363d; padding:0.5rem 1rem; }}
th {{ background:#161b22; color:#58a6ff; }}
td {{ text-align:right; }}
</style>
</head>
<body>
<h1>Inheritance Graph</h1>
<div class="mermaid">
{mermaid_code.replace('```mermaid','').replace('```','')}
</div>
<h2>Contracts</h2>
<table><tr><th>Name</th><th>Type</th><th>Parents</th></tr>
"""
    for c in contracts:
        parents = _html.escape(", ".join(c["parents"])) if c["parents"] else "—"
        safe_name = _html.escape(str(c["name"]))
        safe_kind = _html.escape(str(c["kind"]))
        icon = {"contract": "📄", "interface": "🔷", "library": "📚"}.get(c["kind"], "📄")
        html += f"<tr><td>{icon} {safe_name}</td><td>{safe_kind}</td><td>{parents}</td></tr>\n"
    html += "</table></body></html>"
    return html
