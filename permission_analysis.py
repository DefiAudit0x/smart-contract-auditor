"""Permission Analysis - full permission matrix for each contract."""
import re
from typing import List, Dict, Optional


ROLE_PATTERNS = [
    r"onlyOwner\b",
    r"onlyRole\s*\(\s*(\w+)\s*\)",
    r"hasRole\s*\(\s*(\w+)\s*",
    r"\bmodifier\s+(\w+)\s*\([^)]*\)\s*\{[^}]*require\s*\([^;]*msg\.sender[^;]*\)",
    r"\brequire\s*\(\s*msg\.sender\s*==\s*(\w+)",
    r"\brequire\s*\(\s*[\w.]+\s*==\s*msg\.sender\s*\)",
    r"\bif\s*\(\s*msg\.sender\s*!=\s*(\w+)",
    r"\b_checkRole\s*\(\s*(\w+)",
    r"\bauthorizer\.\w+\s*\(",
    r"\bonlyGovernance\b",
    r"\bonlyAdmin\b",
    r"\bonlyOperator\b",
]

# Kept for callers that import the legacy pattern table. analyze_permissions now
# parses complete declarations so overloads cannot inherit another's suffix.
FUNCTION_VISIBILITIES = [
    (r"function\s+(\w+)\s*\([^)]*\)\s*(?:public|external)", "writable"),
    (r"function\s+(\w+)\s*\([^)]*\)\s*(?:internal|private)", "internal"),
    (r"function\s+(\w+)\s*\([^)]*\)\s*(?:public|external)\s*(?:view|pure)", "readable"),
    (r"function\s+(\w+)\s*\([^)]*\)\s*(?:view|pure)\s*(?:public|external)", "readable"),
]


def _mask_solidity_comments_and_strings(code: str) -> str:
    """Blank comments and strings so declaration parsing uses Solidity code only."""
    masked = list(code)
    state = "code"
    quote = None
    index = 0
    while index < len(code):
        char = code[index]
        if state == "code":
            if code.startswith("//", index):
                masked[index] = masked[index + 1] = " "
                index += 2
                state = "line_comment"
            elif code.startswith("/*", index):
                masked[index] = masked[index + 1] = " "
                index += 2
                state = "block_comment"
            elif char in ("'", '"'):
                masked[index] = " "
                quote = char
                index += 1
                state = "string"
            else:
                index += 1
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                masked[index] = " "
            index += 1
        elif state == "block_comment":
            if code.startswith("*/", index):
                masked[index] = masked[index + 1] = " "
                index += 2
                state = "code"
            else:
                if char != "\n":
                    masked[index] = " "
                index += 1
        else:
            if char == "\\":
                masked[index] = " "
                index += 1
                if index < len(code):
                    if code[index] != "\n":
                        masked[index] = " "
                    index += 1
            elif char == quote:
                masked[index] = " "
                index += 1
                quote = None
                state = "code"
            else:
                if char != "\n":
                    masked[index] = " "
                index += 1
    return "".join(masked)


def _function_declarations(code: str) -> List[Dict]:
    """Return declaration-local access and modifiers for each named function."""
    masked = _mask_solidity_comments_and_strings(code)
    declarations = []
    for match in re.finditer(r"\bfunction\s+(\w+)\s*\(", masked, re.IGNORECASE):
        open_paren = match.end() - 1
        depth = 0
        close_paren = None
        for index in range(open_paren, len(masked)):
            if masked[index] == "(":
                depth += 1
            elif masked[index] == ")":
                depth -= 1
                if depth == 0:
                    close_paren = index
                    break
        if close_paren is None:
            continue

        terminators = [
            pos for pos in (
                masked.find("{", close_paren + 1),
                masked.find(";", close_paren + 1),
            ) if pos >= 0
        ]
        if not terminators:
            continue
        suffix = masked[close_paren + 1:min(terminators)]
        visibility_match = re.search(
            r"\b(public|external|internal|private)\b", suffix, re.IGNORECASE
        )
        visibility = visibility_match.group(1).lower() if visibility_match else ""

        if visibility in ("internal", "private"):
            access = "internal"
        elif re.search(r"\b(view|pure)\b", suffix, re.IGNORECASE):
            access = "readable"
        else:
            access = "writable"

        modifiers = re.findall(
            r"\b(only\w+|hasRole|whenNotPaused|whenPaused)\b",
            suffix,
            re.IGNORECASE,
        )
        declarations.append({
            "name": match.group(1), "access": access, "modifiers": modifiers,
        })
    return declarations


def analyze_permissions(code: str) -> str:
    """Comprehensive permission matrix analysis."""
    roles = set()
    functions: List[Dict] = []
    state_vars: List[str] = []
    role_assignments: List[str] = []

    # Detect roles
    for pat in ROLE_PATTERNS:
        for match in re.finditer(pat, code, re.IGNORECASE):
            if match.lastindex and match.group(1):
                roles.add(match.group(1))
            else:
                if "onlyOwner" in match.group() or "onlyGovernance" in match.group() or \
                   "onlyAdmin" in match.group() or "onlyOperator" in match.group():
                    roles.add(match.group().replace("modifier ", "").strip())

    # Parse declarations independently, then conservatively aggregate overloads
    # by name for the existing one-row-per-name report format.
    declarations_by_name = {}
    for declaration in _function_declarations(code):
        declarations_by_name.setdefault(declaration["name"], []).append(declaration)

    for name, declarations in declarations_by_name.items():
        writable = [item for item in declarations if item["access"] == "writable"]
        readable = [item for item in declarations if item["access"] == "readable"]
        relevant = writable or readable or declarations
        access = "writable" if writable else "readable" if readable else "internal"
        modifier_sets = {tuple(sorted(item["modifiers"])) for item in relevant}
        modifiers = sorted({modifier for item in relevant for modifier in item["modifiers"]})
        functions.append({
            "name": name,
            "access": access,
            "modifiers": modifiers,
            "has_unprotected_writable": any(not item["modifiers"] for item in writable),
            "mixed_protection": len(modifier_sets) > 1,
        })

    # Public state variables
    for m in re.finditer(r"(public|internal|private)\s+(\w+\s+\w+)\s*;", code):
        var = m.group(2).strip()
        state_vars.append(var)

    # --- Build report ---
    result = ["# Permission Analysis Matrix\n"]

    # Summary
    result.append("## Summary")
    result.append(f"- Roles detected: {len(roles)}")
    result.append(f"- Functions: {len(functions)} total")
    result.append(f"  - Writable: {sum(1 for f in functions if f['access']=='writable')}")
    result.append(f"  - Readable: {sum(1 for f in functions if f['access']=='readable')}")
    result.append(f"  - Internal: {sum(1 for f in functions if f['access']=='internal')}")
    result.append("")

    # Roles
    if roles:
        result.append("## Roles / Modifiers")
        for r in sorted(roles):
            result.append(f"- `{r}`")
        result.append("")

    # Function matrix
    result.append("## Function Matrix")
    result.append("| Function | Access | Role Protection |")
    result.append("|----------|--------|-----------------|")
    for f in sorted(functions, key=lambda x: x["name"]):
        mods = ", ".join(f.get("modifiers", [])) if f.get("modifiers") else "none"
        if f.get("mixed_protection"):
            mods = f"mixed across overloads ({mods})"
        icon = {"writable": "✏️", "readable": "👁", "internal": "🔒"}.get(f["access"], "❓")
        result.append(f"| {icon} `{f['name']}` | {f['access']} | {mods} |")
    result.append("")

    # Security recommendations
    result.append("## Security Recommendations")
    writable_unprotected = [
        f for f in functions
        if f["access"] == "writable" and f.get(
            "has_unprotected_writable", not f.get("modifiers")
        )
    ]
    if writable_unprotected:
        result.append(f"⚠️ **{len(writable_unprotected)} writable function(s) without role protection:**")
        for f in writable_unprotected[:10]:
            result.append(f"- `{f['name']}` — consider adding onlyOwner/onlyRole modifier")
        result.append("")
    else:
        result.append("✅ All writable functions are role-protected")
        result.append("")

    # Public variables
    public_vars = [v for v in state_vars if v.startswith("public")]
    if public_vars:
        result.append(f"ℹ️ {len(public_vars)} public state variable(s) — consider private + getter")
        for v in public_vars[:5]:
            result.append(f"- `{v}`")
        result.append("")

    return "\n".join(result)
