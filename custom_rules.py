"""Custom Rules - user-defined detection patterns."""
import logging
import os
import re
import json
import threading
from typing import List, Dict

logger = logging.getLogger(__name__)

# Administrative limits for user-supplied rules (M7 remediation).
MAX_RULES = 200
MAX_PATTERN_LENGTH = 500
MAX_NAME_LENGTH = 100
MAX_DESCRIPTION_LENGTH = 500
RULE_SCAN_TIMEOUT_SECONDS = 2.0
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}
# Canary input that backtracking-prone patterns (e.g. (a+)+$) choke on
# almost immediately while benign patterns finish instantly.
_CANARY_INPUT = "a" * 32 + "!"


RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")
os.makedirs(RULES_DIR, exist_ok=True)
RULES_FILE = os.path.join(RULES_DIR, "custom_rules.json")


def _regex_finishes(compiled, sample, timeout=RULE_SCAN_TIMEOUT_SECONDS):
    """Run compiled.search on `sample` in a daemon thread; False when it
    does not finish within `timeout` seconds (backtracking bomb)."""
    outcome = [True]

    def _run():
        try:
            compiled.search(sample)
        except Exception:
            outcome[0] = False

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        return False
    return outcome[0]


def _find_matches_with_timeout(pattern, code, timeout=RULE_SCAN_TIMEOUT_SECONDS):
    """Return list of matches (capped) or None when the rule times out.

    The worker is a throwaway daemon thread: an abandoned pattern keeps
    burning only its own thread instead of the request/scan thread.
    """
    matches = []
    done = threading.Event()

    def _run():
        try:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                matches.append(match)
                if len(matches) >= 1000:
                    break
        except re.error:
            pass
        finally:
            done.set()

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    if not done.wait(timeout):
        return None
    return matches


class CustomRule:
    """A custom detection rule."""

    def __init__(self, name: str, pattern: str, severity: str = "medium",
                 description: str = "", lang: str = "solidity"):
        self.name = (name or "").strip()
        self.pattern = pattern or ""
        # Canonical severity only: free-form values would otherwise fall
        # out of the report rendering's severity ordering (M7 remediation).
        normalized = (severity or "info").strip().lower()
        self.severity = normalized if normalized in ALLOWED_SEVERITIES else "info"
        self.description = (description or "").strip()
        self.lang = lang

    def to_dict(self) -> dict:
        return {"name": self.name, "pattern": self.pattern,
                "severity": self.severity, "description": self.description,
                "lang": self.lang}

    @classmethod
    def from_dict(cls, d: dict) -> "CustomRule":
        return cls(d["name"], d["pattern"], d.get("severity", "medium"),
                    d.get("description", ""), d.get("lang", "solidity"))


class CustomRulesEngine:
    """Custom rules engine."""

    def __init__(self):
        self.rules: List[CustomRule] = []
        self._load()

    def _load(self):
        if os.path.isfile(RULES_FILE):
            try:
                with open(RULES_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.rules = [CustomRule.from_dict(d) for d in data]
            except Exception:
                self.rules = []

    def _save(self):
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            json.dump([r.to_dict() for r in self.rules], f, ensure_ascii=False, indent=2)

    def add_rule(self, rule: CustomRule):
        """Validate then store a rule (M7 remediation).

        Bounded count/length, compilable pattern, canonical severity, and a
        canary run that rejects catastrophic-backtracking patterns before
        they can ever reach the scan engine.
        """
        if len(self.rules) >= MAX_RULES:
            raise ValueError(f"Too many custom rules (limit {MAX_RULES})")
        if not rule.name or len(rule.name) > MAX_NAME_LENGTH:
            raise ValueError("Rule name must be 1-100 characters")
        if len(rule.description) > MAX_DESCRIPTION_LENGTH:
            raise ValueError("Rule description is too long")
        if len(rule.pattern) > MAX_PATTERN_LENGTH:
            raise ValueError(f"Rule pattern is too long (limit {MAX_PATTERN_LENGTH} characters)")
        if any(r.name == rule.name for r in self.rules):
            raise ValueError("A rule with this name already exists")
        try:
            compiled = re.compile(rule.pattern, re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"Invalid regex: {e}")
        if not _regex_finishes(compiled, _CANARY_INPUT):
            raise ValueError("Pattern rejected: catastrophic backtracking risk")
        self.rules.append(rule)
        self._save()

    def remove_rule(self, name: str):
        self.rules = [r for r in self.rules if r.name != name]
        self._save()

    def list_rules(self) -> List[dict]:
        return [r.to_dict() for r in self.rules]

    def scan(self, code: str, lang: str = "solidity") -> List[Dict]:
        """Scan code with all custom rules and return findings.

        Every rule runs under a hard timeout (M7 remediation): even a rule
        that slipped through validation cannot pin the scan thread with a
        catastrophic-backtracking pattern.
        """
        findings = []
        for rule in self.rules:
            if rule.lang != "all" and rule.lang != lang:
                continue
            matches = _find_matches_with_timeout(rule.pattern, code)
            if matches is None:
                logger.warning("Custom rule '%s' timed out during scan; skipped", rule.name)
                continue
            for match in matches:
                line_no = code[:match.start()].count("\n") + 1
                findings.append({
                    "rule": rule.name,
                    "severity": rule.severity,
                    "line": line_no,
                    "match": match.group()[:100],
                    "description": rule.description,
                })
        return findings

    def scan_to_text(self, code: str, lang: str = "solidity") -> str:
        """Scan + return report text."""
        findings = self.scan(code, lang)
        if not findings:
            return "## Custom Rules\n\n_No custom rule matches found._"
        lines = ["# Custom Rules Scan\n"]
        by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in findings:
            by_severity.setdefault(f["severity"], []).append(f)
        for sev in ["critical", "high", "medium", "low", "info"]:
            items = by_severity.get(sev, [])
            if not items:
                continue
            lines.append(f"### {sev.upper()} ({len(items)})")
            for it in items:
                lines.append(f"- Line {it['line']}: [{it['rule']}] {it['description']}")
                lines.append(f"  `{it['match']}`")
            lines.append("")
        return "\n".join(lines)


_ENGINE = CustomRulesEngine()


def get_rules_engine() -> CustomRulesEngine:
    return _ENGINE
