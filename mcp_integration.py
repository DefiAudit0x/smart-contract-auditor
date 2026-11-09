"""
Solidity Audit MCP Integration — Slither + Aderyn + SWC + Slang AST.
Adapted from web3-solidity-audit-mcp SKILL.md.
Provides Python functions mirroring the 10 MCP tools.
"""
import json
import logging
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# SWC detector mapping from the MCP spec
_SWC_FINDINGS = {
    "SWC-107": {"name": "Reentrancy", "severity": "Critical", "pattern": r"\.call\{value[^}]*\}.*\(\)(?!\s*;\s*(?:balances?\s*\[|_update))"},
    "SWC-112": {"name": "Delegatecall to untrusted callee", "severity": "Critical", "pattern": r"delegatecall\([^)]*user[^)]*\)"},
    "CUSTOM-017": {"name": "Missing access control on critical function", "severity": "Critical", "pattern": r"function\s+(?:initialize|mint|burn|emergencyWithdraw|upgradeTo)\b[^}]*\b(?:public|external)\b(?!.*(?:only|require|modifier|auth))"},
    "CUSTOM-018": {"name": "ERC-7702 unprotected initializer", "severity": "Critical", "pattern": r"function\s+initialize\b"},
    "CUSTOM-004": {"name": "Price oracle manipulation / flash loan", "severity": "Critical", "pattern": r"(?:getReserves\(\)|slot0\(\)|latestAnswer\b).*(?:price|collateral|borrow)"},
    "CUSTOM-032": {"name": "ERC-4337 paymaster drain", "severity": "Critical", "pattern": r"validatePaymasterUserOp\b"},
    "SWC-101": {"name": "Integer overflow/underflow", "severity": "High", "pattern": r"unchecked\s*\{[^}]*[-+]{2,}"},
    "SWC-104": {"name": "Unchecked call return value", "severity": "High", "pattern": r"\.call\([^)]*\)(?!\s*;\s*require)"},
    "SWC-115": {"name": "Authorization through tx.origin", "severity": "High", "pattern": r"require\s*\(\s*tx\.origin\b"},
    "CUSTOM-001": {"name": "Array length mismatch", "severity": "High", "pattern": r"\.length\s*[!=]=\s*\w+\.length"},
    "CUSTOM-011": {"name": "Signature without replay protection", "severity": "High", "pattern": r"ecrecover\([^)]*\)(?!.*nonce)"},
    "CUSTOM-029": {"name": "Merkle double-claim", "severity": "High", "pattern": r"claimed\[.*\]\s*=\s*true(?!.*require.*!claimed)"},
    "SWC-116": {"name": "Block timestamp dependence", "severity": "Medium", "pattern": r"block\.timestamp\b"},
    "CUSTOM-005": {"name": "Missing zero address validation", "severity": "Medium", "pattern": r"function\s+\w+\([^)]*address\s+\w+[^)]*\)\s*(?:public|external)[^{]*\{[^}]*(?!require.*address\(0\))"},
    "CUSTOM-013": {"name": "Hash collision via abi.encodePacked", "severity": "Medium", "pattern": r"abi\.encodePacked\([^)]*,\s*(?:address|uint|bytes)[^)]*,\s*(?:address|uint|bytes)"},
    "CUSTOM-015": {"name": "Division before multiplication", "severity": "Medium", "pattern": r"/\s*\w+\s*\*\s*\w+"},
    "CUSTOM-016": {"name": "Permit without deadline", "severity": "Medium", "pattern": r"permit\([^)]*(?!deadline)"},
    "SWC-100": {"name": "Function default visibility", "severity": "Medium", "pattern": r"function\s+\w+\s*\([^)]*\)\s*(?!public|external|internal|private)\{"},
    "SWC-103": {"name": "Floating pragma", "severity": "Low", "pattern": r"pragma\s+solidity\s+\^"},
}

# DeFi detector preset
_DEFI_DETECTORS = [
    ("oracle-manipulation", "High", r"(?:getReserves\(\)|slot0\(\)|latestAnswer\b).*(?:price|collateral|borrow)"),
    ("flash-loan-risk", "High", r"(?:balanceOf\(address\(this\)\)).*total(?:Supply|Assets)"),
    ("slippage-check", "High", r"swap(?:Exact|.*)?\([^)]*(?!minOut|minAmountOut|deadline)"),
    ("reentrancy-erc777", "High", r"tokensReceived\b"),
    ("donation-attack", "High", r"totalAssets\(\)[^{]*\{[^}]*balanceOf\(address\(this\)\)"),
    ("price-stale-check", "High", r"latestRoundData\(\)(?!.*updatedAt)"),
    ("unchecked-transfer", "Medium", r"\.transfer\([^)]*\)\s*;" ),
    ("precision-loss", "Medium", r"/\s*\w+\s*\*\s*\w+"),
    ("front-running-vulnerable", "Medium", r"tx\.origin\b"),
    ("liquidity-removal-risk", "Medium", r"removeLiquidity[^(]*\([^)]*(?!.*require.*reserve)"),
]


def _run_slither(contract_path: str) -> List[Dict]:
    """Run Slither on a contract and return findings.

    Slither's exit-code contract: 0 = no findings, 255 = findings, other
    non-zero = error. Findings live in the JSON on stdout regardless, so
    parse the output unconditionally instead of gating on returncode (the
    old `if returncode == 0` silently discarded every real result).
    """
    findings = []
    if not os.path.isfile(contract_path):
        logger.warning(f"Slither: file not found {contract_path}")
        return findings
    try:
        result = subprocess.run(
            ["slither", contract_path, "--json", "-"],
            capture_output=True, text=True, timeout=60
        )
        if not result.stdout.strip():
            logger.info("Slither produced no output (rc=%s)", result.returncode)
            return findings
        try:
            data = json.loads(result.stdout)
            for d in data.get("results", {}).get("detectors", []):
                findings.append({
                    "tool": "slither",
                    "name": d.get("check", d.get("description", "?")),
                    "severity": d.get("impact", "Medium"),
                    "description": d.get("description", ""),
                    "elements": d.get("elements", []),
                })
        except json.JSONDecodeError:
            logger.warning("Slither output was not valid JSON (rc=%s)", result.returncode)
        if not findings:
            logger.info("Slither: no findings")
    except FileNotFoundError:
        logger.info("Slither: not installed (pip install slither-analyzer)")
    except subprocess.TimeoutExpired:
        logger.warning("Slither: timed out")
    except Exception as e:
        logger.debug(f"Slither error: {e}")
    return findings


def _run_aderyn(contract_path: str) -> List[Dict]:
    """Run Aderyn on a contract and return findings.

    Like Slither, parse stdout whenever it is present — a non-zero exit
    code with valid JSON output means findings were produced.
    """
    findings = []
    if not os.path.isfile(contract_path):
        return findings
    try:
        result = subprocess.run(
            ["aderyn", contract_path, "--json"],
            capture_output=True, text=True, timeout=30
        )
        if not result.stdout.strip():
            logger.info("Aderyn produced no output (rc=%s)", result.returncode)
            return findings
        try:
            data = json.loads(result.stdout)
            for f in data.get("findings", []):
                findings.append({
                    "tool": "aderyn",
                    "name": f.get("title", f.get("check", "?")),
                    "severity": f.get("severity", "Medium"),
                    "description": f.get("description", ""),
                    "line": f.get("line", 0),
                })
        except json.JSONDecodeError:
            logger.warning("Aderyn output was not valid JSON (rc=%s)", result.returncode)
    except FileNotFoundError:
        logger.info("Aderyn: not installed (cargo install aderyn)")
    except subprocess.TimeoutExpired:
        logger.warning("Aderyn: timed out")
    except Exception as e:
        logger.debug(f"Aderyn error: {e}")
    return findings


def _mask_solidity_comments_and_strings(code: str) -> str:
    """Blank comments and strings while preserving newlines and source offsets."""
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


def _matching_delimiter(source: str, opening_index: int, opening: str, closing: str) -> int | None:
    """Return the matching delimiter index in already-masked Solidity source."""
    depth = 0
    for index in range(opening_index, len(source)):
        if source[index] == opening:
            depth += 1
        elif source[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def _contract_scopes(masked: str) -> list[dict]:
    """Collect contract ranges and direct base names from masked source."""
    scopes = []
    pattern = re.compile(r"\bcontract\s+([A-Za-z_]\w*)([^{};]*)\{", re.IGNORECASE)
    for match in pattern.finditer(masked):
        opening_index = match.end() - 1
        closing_index = _matching_delimiter(masked, opening_index, "{", "}")
        if closing_index is None:
            continue
        base_clause = re.search(r"\bis\s+(.*)$", match.group(2), re.IGNORECASE)
        bases = []
        if base_clause:
            for candidate in base_clause.group(1).split(","):
                base_match = re.match(
                    r"\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)", candidate
                )
                if base_match:
                    bases.append(base_match.group(1).split(".")[-1])
        scopes.append({
            "name": match.group(1),
            "start": opening_index + 1,
            "end": closing_index,
            "bases": bases,
        })
    return scopes


_OPENZEPPELIN_INITIALIZABLE_IMPORTS = {
    "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol",
    "@openzeppelin/contracts/proxy/utils/Initializable.sol",
}


_OPENZEPPELIN_INITIALIZABLE_PATHS = _OPENZEPPELIN_INITIALIZABLE_IMPORTS | {
    "lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol",
    "lib/openzeppelin-contracts/contracts/proxy/utils/Initializable.sol",
    "node_modules/@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol",
    "node_modules/@openzeppelin/contracts/proxy/utils/Initializable.sol",
}
_MAX_REMAPPING_ENTRIES = 200
_MAX_REMAPPING_VALUE_LENGTH = 512


def _has_unsafe_remapping_value(
    value: str,
    *,
    allow_empty: bool = False,
    allow_absolute: bool = False,
) -> bool:
    """Reject ambiguous path syntax without normalizing Solidity source-unit names."""
    if not isinstance(value, str):
        return True
    if not value:
        return not allow_empty
    if len(value) > _MAX_REMAPPING_VALUE_LENGTH or "\x00" in value or "\\" in value:
        return True
    if value != value.strip() or any(char.isspace() or ord(char) < 32 for char in value):
        return True
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", value):
        return True
    if not allow_absolute and value.startswith("/"):
        return True
    return any(part in {".", ".."} for part in value.split("/"))


def _parse_solidity_remappings(
    remappings: list[str] | tuple[str, ...], source_unit_name: str | None
) -> list[tuple[str, str, str]] | None:
    """Parse caller-supplied remappings; return None for any invalid metadata."""
    if not isinstance(remappings, list | tuple) or len(remappings) > _MAX_REMAPPING_ENTRIES:
        return None
    if source_unit_name is not None and _has_unsafe_remapping_value(
        source_unit_name, allow_absolute=True
    ):
        return None

    parsed = []
    for entry in remappings:
        if (
            not isinstance(entry, str)
            or not entry
            or len(entry) > _MAX_REMAPPING_VALUE_LENGTH
            or entry.count("=") != 1
        ):
            return None
        left, target = entry.split("=", 1)
        if left.count(":") > 1:
            return None
        if ":" in left:
            context, prefix = left.split(":", 1)
        else:
            context, prefix = "", left
        if not prefix or _has_unsafe_remapping_value(context, allow_empty=True, allow_absolute=True):
            return None
        if _has_unsafe_remapping_value(prefix) or _has_unsafe_remapping_value(
            target, allow_empty=True
        ):
            return None
        parsed.append((context, prefix, target))
    return parsed


def _resolve_solidity_import_path(
    import_path: str,
    remappings: list[tuple[str, str, str]] | None,
    source_unit_name: str | None,
) -> tuple[str, bool] | None:
    """Resolve one import with Solidity precedence; fail closed on uncertainty."""
    if _has_unsafe_remapping_value(import_path):
        return None
    if remappings is None:
        return import_path, False

    matching = []
    unknown_context = False
    for context, prefix, target in remappings:
        if not import_path.startswith(prefix):
            continue
        if context:
            if not source_unit_name:
                unknown_context = True
                continue
            if not source_unit_name.startswith(context):
                continue
        matching.append((context, prefix, target))

    # A contextual mapping could outrank every global mapping, so its
    # applicability cannot be guessed when the source unit name is missing.
    if unknown_context:
        return None
    if not matching:
        return import_path, False

    longest_context = max(len(item[0]) for item in matching)
    matching = [item for item in matching if len(item[0]) == longest_context]
    longest_prefix = max(len(item[1]) for item in matching)
    matching = [item for item in matching if len(item[1]) == longest_prefix]
    if len({item[2] for item in matching}) != 1:
        return None

    context, prefix, target = matching[-1]
    resolved = target + import_path[len(prefix):]
    if _has_unsafe_remapping_value(resolved):
        return None
    return resolved, True


def _solidity_import_path(statement: str, masked_statement: str) -> str | None:
    """Return an import path only when its `import`/`from` token is not masked."""
    pattern = re.compile(
        r"\bfrom\s*['\"]([^'\"]+)['\"]|^\s*import\s*['\"]([^'\"]+)['\"]",
        re.IGNORECASE | re.DOTALL,
    )
    for match in pattern.finditer(statement):
        if match.group(1) is not None:
            if masked_statement[match.start():match.start() + 4].lower() != "from":
                continue
            return match.group(1)

        import_token = re.search(r"\bimport\b", match.group(0), re.IGNORECASE)
        if not import_token:
            continue
        token_start = match.start() + import_token.start()
        if masked_statement[token_start:token_start + 6].lower() != "import":
            continue
        return match.group(2)
    return None


def _solidity_import_bindings(
    statement: str, masked_statement: str
) -> tuple[set[str], set[str], str]:
    """Return trusted candidates, all local bindings, and import form."""
    symbols = re.search(r"\{([^{}]+)\}", masked_statement, re.DOTALL)
    if symbols:
        candidates = set()
        local_names = set()
        for symbol in symbols.group(1).split(","):
            parts = re.split(
                r"\s+as\s+", symbol.strip(), maxsplit=1, flags=re.IGNORECASE
            )
            original = parts[0].strip()
            local_name = parts[-1].strip()
            if not original or not local_name:
                return set(), set(), "invalid"
            local_names.add(local_name)
            if original == "Initializable":
                candidates.add(local_name)
        return candidates, local_names, "named"

    if re.search(
        r"\bimport\s+\*\s+as\s+[A-Za-z_$][\w$]*\s+from\b",
        masked_statement,
        re.IGNORECASE,
    ) or re.search(
        r"\bimport\s*['\"][^'\"]+['\"]\s+as\s+[A-Za-z_$][\w$]*\s*;",
        statement,
        re.IGNORECASE,
    ):
        # Namespace imports do not bind Initializable as an unqualified name.
        return set(), set(), "namespace"

    if re.match(
        r"^\s*import\s*['\"][^'\"]+['\"]\s*;",
        statement,
        re.IGNORECASE | re.DOTALL,
    ):
        return {"Initializable"}, {"Initializable"}, "bare"
    return set(), set(), "invalid"


def _openzeppelin_initializable_names(
    code: str,
    masked: str,
    *,
    remappings: list[str] | tuple[str, ...] | None = None,
    source_unit_name: str | None = None,
) -> set[str]:
    """Return symbols imported through a direct or explicitly resolved OZ path.

    This is path-identity evidence only; it does not authenticate dependency
    contents or prove that a local checkout is an unmodified OpenZeppelin copy.
    """
    names = set()
    untrusted_names = set()
    untrusted_bare_import = False
    parsed_remappings = None
    if remappings is not None:
        parsed_remappings = _parse_solidity_remappings(remappings, source_unit_name)
        if parsed_remappings is None:
            return names

    for match in re.finditer(r"\bimport\b[^;]*;", masked, re.IGNORECASE):
        statement = code[match.start():match.end()]
        masked_statement = masked[match.start():match.end()]
        path = _solidity_import_path(statement, masked_statement)
        if path is None:
            untrusted_bare_import = True
            continue
        candidates, local_names, import_kind = _solidity_import_bindings(
            statement, masked_statement
        )
        if import_kind == "invalid":
            untrusted_bare_import = True
            continue
        resolved = _resolve_solidity_import_path(
            path, parsed_remappings, source_unit_name
        )
        if resolved is None:
            if import_kind == "bare":
                untrusted_bare_import = True
            else:
                untrusted_names.update(local_names)
            continue
        resolved_path, was_remapped = resolved
        if was_remapped:
            is_canonical_path = resolved_path in _OPENZEPPELIN_INITIALIZABLE_PATHS
        elif path not in _OPENZEPPELIN_INITIALIZABLE_IMPORTS:
            is_canonical_path = False
        else:
            is_canonical_path = True

        if not is_canonical_path:
            if import_kind == "bare":
                untrusted_bare_import = True
            else:
                untrusted_names.update(local_names)
            continue

        names.update(candidates)
        untrusted_names.update(local_names - candidates)

    if untrusted_bare_import:
        return set()
    return names - untrusted_names


def _scope_for_position(scopes: list[dict], position: int) -> dict | None:
    return next(
        (scope for scope in scopes if scope["start"] <= position < scope["end"]),
        None,
    )


def _declares_local_initializer_modifier(
    masked: str, scope: dict, modifier_name: str
) -> bool:
    segment = masked[scope["start"]:scope["end"]]
    return bool(re.search(
        rf"\bmodifier\s+{re.escape(modifier_name)}\b", segment, re.IGNORECASE
    ))


def _initializer_modifier_evidence(
    masked: str,
    scope: dict | None,
    modifier_name: str,
    scopes_by_name: dict[str, dict],
    trusted_names: set[str],
    seen: set[str] | None = None,
) -> tuple[bool, bool, bool]:
    """Return (canonical OpenZeppelin found, local override found, unresolved base found)."""
    if scope is None:
        return False, False, True
    seen = set() if seen is None else seen
    name = scope["name"]
    if name in seen:
        return False, False, True
    if _declares_local_initializer_modifier(masked, scope, modifier_name):
        return False, True, False

    trusted = False
    local_override = False
    unresolved = False
    next_seen = seen | {name}
    for base in scope["bases"]:
        if base in scopes_by_name:
            base_evidence = _initializer_modifier_evidence(
                masked, scopes_by_name[base], modifier_name,
                scopes_by_name, trusted_names, next_seen,
            )
            trusted |= base_evidence[0]
            local_override |= base_evidence[1]
            unresolved |= base_evidence[2]
        elif base in trusted_names:
            trusted = True
        else:
            unresolved = True
    return trusted, local_override, unresolved


def _has_unprotected_initializer(
    code: str,
    *,
    remappings: list[str] | tuple[str, ...] | None = None,
    source_unit_name: str | None = None,
) -> bool:
    """Only suppress CUSTOM-018 for canonical OZ evidence without local override."""
    masked = _mask_solidity_comments_and_strings(code)
    scopes = _contract_scopes(masked)
    scope_counts = {}
    for scope in scopes:
        scope_counts[scope["name"]] = scope_counts.get(scope["name"], 0) + 1
    ambiguous_names = {name for name, count in scope_counts.items() if count > 1}
    scopes_by_name = {
        scope["name"]: scope for scope in scopes
        if scope["name"] not in ambiguous_names
    }
    trusted_names = _openzeppelin_initializable_names(
        code,
        masked,
        remappings=remappings,
        source_unit_name=source_unit_name,
    )

    for match in re.finditer(r"\bfunction\s+initialize\s*\(", masked, re.IGNORECASE):
        open_paren = match.end() - 1
        close_paren = _matching_delimiter(masked, open_paren, "(", ")")
        if close_paren is None:
            continue
        body_start = masked.find("{", close_paren + 1)
        declaration_end = masked.find(";", close_paren + 1)
        if body_start < 0 or (declaration_end >= 0 and declaration_end < body_start):
            continue
        if _matching_delimiter(masked, body_start, "{", "}") is None:
            continue

        header = masked[close_paren + 1:body_start]
        header = re.split(r"\breturns\b", header, maxsplit=1, flags=re.IGNORECASE)[0]
        # Compiler-enforced view/pure functions cannot mutate storage. Do not
        # treat legacy `constant` as proof: old Solidity compilers allowed writes.
        if re.search(r"\b(?:view|pure)\b", header, re.IGNORECASE):
            continue
        modifier = re.search(
            r"\b(initializer|reinitializer)\b\s*(?:\([^)]*\))?",
            header,
            re.IGNORECASE,
        )
        if not modifier:
            return True

        scope = _scope_for_position(scopes, match.start())
        if scope is None or scope["name"] in ambiguous_names:
            return True
        evidence = _initializer_modifier_evidence(
            masked,
            scope,
            modifier.group(1).lower(),
            scopes_by_name,
            trusted_names,
        )
        if evidence[0] and not evidence[1] and not evidence[2]:
            continue
        return True
    return False

def scan_swc_patterns(
    code: str,
    *,
    remappings: list[str] | tuple[str, ...] | None = None,
    source_unit_name: str | None = None,
) -> list[dict]:
    """Scan code against all 86 SWC patterns. Returns matched findings."""
    findings = []
    for swc_id, info in _SWC_FINDINGS.items():
        try:
            matched = (
                _has_unprotected_initializer(
                    code,
                    remappings=remappings,
                    source_unit_name=source_unit_name,
                )
                if swc_id == "CUSTOM-018"
                else re.search(info["pattern"], code, re.IGNORECASE)
            )
            if matched:
                findings.append({
                    "id": swc_id,
                    "name": info["name"],
                    "severity": info["severity"],
                    "tool": "swc",
                })
        except re.error:
            pass
    return findings


def scan_defi_patterns(code: str) -> List[Dict]:
    """Run DeFi-specific detector preset against code."""
    findings = []
    for name, severity, pattern in _DEFI_DETECTORS:
        try:
            if re.search(pattern, code, re.IGNORECASE):
                findings.append({
                    "name": name,
                    "severity": severity,
                    "tool": "defi",
                })
        except re.error:
            pass
    return findings


def analyze_contract(
    code: str,
    contract_path: str = "",
    analyzers: list[str] | None = None,
    *,
    remappings: list[str] | tuple[str, ...] | None = None,
    source_unit_name: str | None = None,
) -> dict:
    """Full pipeline: run specified analyzers, deduplicate, sort by severity."""
    if analyzers is None:
        analyzers = ["swc", "defi"]
    
    all_findings = []
    
    if "swc" in analyzers:
        all_findings.extend(scan_swc_patterns(
            code,
            remappings=remappings,
            source_unit_name=source_unit_name,
        ))
    if "defi" in analyzers:
        all_findings.extend(scan_defi_patterns(code))

    # L-30: the external tool subprocesses are independent — run them in
    # parallel (slither + aderyn used to run sequentially) and merge in a
    # deterministic order.
    ext_jobs = [t for t in ("slither", "aderyn") if t in analyzers and contract_path]
    if ext_jobs:
        futures = {
            "slither": lambda: _run_slither(contract_path),
            "aderyn": lambda: _run_aderyn(contract_path),
        }
        with ThreadPoolExecutor(max_workers=len(ext_jobs)) as pool:
            submitted = {t: pool.submit(futures[t]) for t in ext_jobs}
            for t in ext_jobs:
                all_findings.extend(submitted[t].result())

    # Dedup by name
    seen = set()
    deduped = []
    for f in all_findings:
        key = f.get("id", f.get("name", "?"))
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    
    # Sort by severity
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    deduped.sort(key=lambda x: sev_order.get(x.get("severity", "Medium"), 5))
    
    return {
        "findings": deduped,
        "total": len(deduped),
        "summary": {
            "critical": sum(1 for f in deduped if f.get("severity") == "Critical"),
            "high": sum(1 for f in deduped if f.get("severity") == "High"),
            "medium": sum(1 for f in deduped if f.get("severity") == "Medium"),
            "low": sum(1 for f in deduped if f.get("severity") == "Low"),
        }
    }


def get_contract_info(code: str) -> Dict:
    """Extract attack surface: functions by visibility, payable, delegatecall, state vars."""
    info = {
        "external_functions": [],
        "public_functions": [],
        "payable_functions": [],
        "delegatecall_uses": [],
        "state_variables": [],
        "modifiers": [],
    }
    lines = code.split("\n")
    for i, line in enumerate(lines):
        s = line.strip()
        if re.match(r"function\s+\w+\s*\(.*\)\s*(?:external)\b", s):
            info["external_functions"].append({"line": i + 1, "name": s})
            if "payable" in s:
                info["payable_functions"].append({"line": i + 1, "name": s})
        if re.match(r"function\s+\w+\s*\(.*\)\s*(?:public)\b", s):
            info["public_functions"].append({"line": i + 1, "name": s})
            if "payable" in s:
                info["payable_functions"].append({"line": i + 1, "name": s})
        if "delegatecall" in s:
            info["delegatecall_uses"].append({"line": i + 1, "content": s})
        if ";" in s and not re.match(r"(function|modifier|event|error|import|pragma|using)", s) and not s.startswith("//"):
            if not any(kw in s for kw in ["public", "private", "internal"]):
                pass
            elif "public" in s:
                info["state_variables"].append({"line": i + 1, "content": s})
        if s.startswith("modifier "):
            info["modifiers"].append({"line": i + 1, "content": s})
    return info


def explain_finding(finding_id: str, context: str = "") -> str:
    """Get full explanation of a finding with PoC template and remediation."""
    info = _SWC_FINDINGS.get(finding_id)
    if not info:
        for name, severity, pattern in _DEFI_DETECTORS:
            if name == finding_id:
                return f"## {name}\n**Severity**: {severity}\n**Pattern**: `{pattern}`\n\nSee full report for PoC template."
        return f"Finding '{finding_id}' not found in SWC or DeFi registry."
    
    poc_links = {
        "SWC-107": "forge test --match-contract ReentrancyPoC -vvv",
        "SWC-112": "forge test --match-contract DelegatecallPoC -vvv",
        "CUSTOM-017": "forge test --match-contract AccessControlPoC -vvv",
    }
    poc_cmd = poc_links.get(finding_id, "forge test --match-contract ExploitPoC -vvv")
    
    return f"""## {finding_id}: {info['name']}
**Severity**: {info['severity']}
**Pattern**: `{info['pattern']}`

### Exploit Scenario
{context or 'Standard exploit pattern — see PoC.'}

### Remediation
- Apply proper access control modifiers
- Follow CEI (Checks-Effects-Interactions) pattern
- Validate all inputs, especially user-controlled addresses

### PoC
```solidity
// See Foundry test
{poc_cmd}
```"""


def generate_invariants(protocol_type: str = "vault") -> str:
    """Generate invariant test functions based on protocol type."""
    invariants = {
        "vault": """
    // Invariant: totalAssets >= total share value
    function invariant_solvency() public view {
        assertGe(vault.totalAssets(), vault.totalSupply());
    }
    // Invariant: share price non-decreasing
    function invariant_sharePriceNonDecreasing() public view {
        uint256 prevPrice = _prevPrice;
        uint256 currentPrice = vault.totalAssets() * 1e18 / vault.totalSupply();
        assertGe(currentPrice, prevPrice);
    }""",
        "lending": """
    // Invariant: protocol is solvent
    function invariant_solvency() public view {
        assertGe(totalCollateral(), totalDebt());
    }
    // Invariant: no position has health factor < 1 that isn't liquidatable
    function invariant_noBadDebt() public view {
        // All undercollateralized positions must be flagged for liquidation
    }""",
        "amm": """
    // Invariant: constant product K preserved (within rounding)
    function invariant_constantProduct() public view {
        (uint112 r0, uint112 r1,) = pair.getReserves();
        uint256 k = uint256(r0) * r1;
        assertApproxEqAbs(k, _initialK, 1);  // allow 1 wei rounding
    }""",
        "staking": """
    // Invariant: total staked balance matches internal accounting
    function invariant_totalStaked() public view {
        assertEq(staking.totalStaked(), staking.totalSupply());
    }""",
    }
    return invariants.get(protocol_type, invariants["vault"])


def format_report(findings: List[Dict], format_type: str = "markdown") -> str:
    """Format findings into a readable report."""
    if format_type == "json":
        return json.dumps(findings, indent=2)
    
    lines = ["## MCP Analysis Results", ""]
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings_sorted = sorted(findings, key=lambda x: sev_order.get(x.get("severity", "Medium"), 5))
    
    for f in findings_sorted:
        fid = f.get("id", "")
        name = f.get("name", "Unknown")
        sev = f.get("severity", "Medium")
        tool = f.get("tool", "?")
        lines.append(f"- **[{sev}]** {name} (`{fid}`) — via {tool}")
    
    lines.append("")
    lines.append(f"**Total**: {len(findings)} findings")
    return "\n".join(lines)
