"""sarif_export — converts audit reports to SARIF format (GitHub Security Tab compatible)."""

import json
import os
import re
import urllib.parse
from datetime import datetime, timezone
from typing import List, Dict, Optional

FINDING_RE = re.compile(
    r'^(?:\s*[\d\-\*\.\)]+\s*)?(?:#{1,3}\s*)?(Critical|High|Medium|Low|Info)\s*[:\-\—]\s*(.+?)$',
    re.IGNORECASE | re.MULTILINE,
)

SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

LEVEL_MAP = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.0,
}

LINE_RE = re.compile(r'[Ll]ine\s*:?\s*(\d+)', re.IGNORECASE)


def _parse_findings(report: str) -> List[Dict]:
    findings = []
    current = None
    for line in report.split("\n"):
        m = FINDING_RE.match(line.strip())
        if m:
            if current:
                findings.append(current)
            sev = m.group(1).lower()
            current = {
                "severity": sev,
                "title": m.group(2).strip().rstrip(":"),
                "description": line.strip(),
                "lines": [],
            }
        elif current and line.strip():
            current["description"] += "\n" + line.strip()
            lm = LINE_RE.search(line)
            if lm:
                current["lines"].append(int(lm.group(1)))
    if current:
        findings.append(current)
    return findings


def _rule_id(idx: int, finding: Dict) -> str:
    name = finding.get("title", f"finding-{idx}")[:40]
    safe = re.sub(r'[^a-zA-Z0-9]', '-', name).strip("-").lower()
    return f"SCA-{idx:03d}-{safe}" if safe else f"SCA-{idx:03d}"


def _strip_markdown(text: str) -> str:
    return text.replace("**", "").replace("*", "").replace("`", "")

def _artifact_uri(label: str) -> str:
    """Percent-encoded relative URI registered against SRCROOT (M26
    remediation): labels derived from user input previously produced
    invalid URIs (spaces, '#', non-ASCII) and unregistered uriBaseIds,
    both of which break GitHub Security Tab ingestion."""
    safe = urllib.parse.quote(str(label or "contract"), safe="-_./")
    return f"{safe}.sol"

def report_to_sarif(report: str, code: str = "", label: str = "Smart Contract") -> str:
    findings = _parse_findings(_strip_markdown(report))
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2-1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Smart Contract Auditor",
                        "version": "2.1.0",
                        "informationUri": "https://github.com/DefiAudit0x/smart-contract-auditor",
                        "rules": [],
                    }
                },
                "artifacts": [
                    {
                        "location": {"uri": _artifact_uri(label), "uriBaseId": "SRCROOT"},
                        "contents": {"text": code or "// source not provided"},
                    }
                ],
                "results": [],
                "originalUriBaseIds": {"SRCROOT": {"uri": "file:///"}},
                "columnKind": "utf16CodeUnits",
            }
        ],
    }

    driver = sarif["runs"][0]["tool"]["driver"]
    results = sarif["runs"][0]["results"]

    for i, f in enumerate(findings):
        rid = _rule_id(i, f)
        driver["rules"].append({
            "id": rid,
            "name": f.get("title", f"Finding {i+1}"),
            "shortDescription": {"text": f.get("title", "")[:200]},
            "fullDescription": {"text": f.get("description", "")[:1000]},
            "defaultConfiguration": {"level": SEVERITY_MAP.get(f["severity"], "warning")},
            "properties": {
                "security-severity": str(LEVEL_MAP.get(f["severity"], 5.0)),
                "tags": ["security", f["severity"]],
            },
        })

        locations = []
        lines_arr = code.split("\n") if code else []
        if lines:
            for ln in lines:
                # Bound-check the line number (M26 remediation): it comes
                # from an LLM report or attacker text and may exceed the
                # file - an IndexError here crashed the whole SARIF path.
                snippet = lines_arr[ln - 1][:120] if 0 < ln <= len(lines_arr) else ""
                locations.append({
                    "physicalLocation": {
                        "artifactLocation": {"uri": _artifact_uri(label), "uriBaseId": "SRCROOT"},
                        "region": {
                            "startLine": ln,
                            "snippet": {"text": snippet},
                        },
                    }
                })
        else:
            locations.append({
                "physicalLocation": {
                    "artifactLocation": {"uri": _artifact_uri(label), "uriBaseId": "SRCROOT"},
                    "region": {"startLine": 1},
                }
            })

        results.append({
            "ruleId": rid,
            "ruleIndex": i,
            "level": SEVERITY_MAP.get(f["severity"], "warning"),
            "message": {"text": f.get("description", "")[:500]},
            "locations": locations,
        })

    return json.dumps(sarif, indent=2)


def generate_sarif(findings: list, output_path: str = "") -> str:
    """Converts a list of Finding dataclass objects to SARIF format.

    Each finding must have: agent_name, severity, category, file, description, fix, line.
    """
    SEVERITY_MAP = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
    }

    def _make_rule(finding) -> dict:
        return {
            "id": finding.agent_name,
            "shortDescription": {"text": finding.agent_name},
            "fullDescription": {"text": finding.description},
            "defaultConfiguration": {"level": SEVERITY_MAP.get(finding.severity, "note")},
            "properties": {"category": finding.category, "severity": finding.severity},
        }

    def _make_result(finding, rule_index: int) -> dict:
        location = {}
        if finding.file:
            # Percent-encoded relative URI (M26 remediation): a raw local
            # directory as uriBaseId was never registered in
            # originalUriBaseIds - a SARIF schema violation that breaks
            # GitHub Security Tab ingestion.
            loc = {"uri": urllib.parse.quote(str(finding.file).replace(os.sep, "/"), safe="-_./")}
            location["physicalLocation"] = {"artifactLocation": loc}
            if finding.line:
                location["physicalLocation"]["region"] = {
                    "startLine": finding.line,
                    "startColumn": 1,
                }
        result = {
            "ruleId": finding.agent_name,
            "ruleIndex": rule_index,
            "level": SEVERITY_MAP.get(finding.severity, "note"),
            "message": {"text": finding.description},
            "properties": {
                "severity": finding.severity,
                "category": finding.category,
                "fix": finding.fix,
            },
        }
        if location:
            result["locations"] = [location]
        return result

    rules = {}
    for f in findings:
        if f.agent_name not in rules:
            rules[f.agent_name] = _make_rule(f)
    rules_list = list(rules.values())
    rules_index = {r["id"]: i for i, r in enumerate(rules_list)}

    results = []
    for f in findings:
        rule_idx = rules_index.get(f.agent_name, 0)
        results.append(_make_result(f, rule_idx))

    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Smart Contract Auditor",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/DefiAudit0x/smart-contract-auditor",
                        "rules": rules_list,
                    }
                },
                "results": results,
                "columnKind": "utf16CodeUnits",
                "properties": {
                    "analyzedAt": datetime.now(timezone.utc).isoformat(),
                    "totalFindings": len(findings),
                },
            }
        ],
    }

    text = json.dumps(doc, indent=2, ensure_ascii=False)
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(text)
    return text
