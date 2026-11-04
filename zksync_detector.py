"""
ZKsync Era Attack Vector Detector.
Adapted from web3-hunt-zksync-era SKILL.md — 25 attack vectors tested, 0 findings.
Used as a DEFENSE STUDY to recognize hardened vs vulnerable patterns.
"""
import logging
import re
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# The 25 attack vectors tested against ZKsync Era (0 found)
_ATTACK_VECTORS = [
    {"id": 1, "name": "UnsafeBytes offset miscalculation", "class": "incomplete_path",
     "defense": "All callers pre-validate message length before UnsafeBytes calls",
     "check": r"_parse\w+Message\b|UnsafeBytes\b"},
    {"id": 2, "name": "Legacy/new boundary double-withdrawal", "class": "off_by_one",
     "defense": "try/catch returns false on decode failure; encoding prefix discriminator prevents collision",
     "check": r"_isLegacy\b|try\s*\{[^}]*decode"},
    {"id": 3, "name": "secondBridgeAddress return value manipulation", "class": "access_control",
     "defense": ">0xFFFF check blocks system contracts; L2-side msg.sender auth",
     "check": r"requestL2Transaction\b|secondBridgeAddress\b"},
    {"id": 4, "name": "Failed deposit claim wrong amount (legacy encoding)", "class": "accounting_desync",
     "defense": "Legacy hash uses try/catch; depositHappened tracks per-encoding-version",
     "check": r"claimFailedDeposit\b|depositHappened\b"},
    {"id": 5, "name": "V29 interop root forgery", "class": "access_control",
     "defense": "addChainBatchRoot requires onlyChain + onlyL2; historical roots verified via Merkle",
     "check": r"addChainBatchRoot\b|onlyChain\b"},
    {"id": 6, "name": "Missing access control on sibling function", "class": "access_control",
     "defense": "Every external function has appropriate modifier",
     "check": r"function\s+\w+\s*\([^)]*\)\s*(public|external)"},
    {"id": 7, "name": "Fee-on-transfer token accounting desync", "class": "accounting_desync",
     "defense": "if (amount != _amount) revert TokensWithFeesNotSupported()",
     "check": r"TokensWithFeesNotSupported\b|amount\s*!=\s*_amount\b"},
    {"id": 8, "name": "Governance timelock bypass", "class": "access_control",
     "defense": "5-role RBAC via AccessControlEnumerable; block.timestamp >= commitTimestamp + delay",
     "check": r"commitTimestamp\b|ValidatorTimelock\b|timelock\b",},
    {"id": 9, "name": "GatewayTransactionFilterer bypass", "class": "access_control",
     "defense": "transactionFilterer == address(0), not used", "check": r"transactionFilterer\b"},
    {"id": 10, "name": "Precommitment sentinel collision", "class": "off_by_one",
     "defense": "_revertBatches properly resets precommitment", "check": r"_revertBatches\b|precommitment\b"},
    {"id": 11, "name": "L2→L1 message forgery", "class": "access_control",
     "defense": "Anyone can call sendToL1, but L1 verifies sender=0x8008 in log",
     "check": r"sendToL1\b|0x8008\b"},
    {"id": 12, "name": "Compressor state diff manipulation", "class": "access_control",
     "defense": "publishCompressedBytecode called only from bootloader context",
     "check": r"publishCompressedBytecode\b|bootloaderContext\b"},
    {"id": 13, "name": "Admin privilege escalation", "class": "proxy_upgrade",
     "defense": "Diamond proxy admin is governance; no facet can self-modify",
     "check": r"DiamondProxy\b|diamondCut\b"},
    {"id": 14, "name": "Fee calculation overflow", "class": "accounting_desync",
     "defense": "All fee math uses SafeMath or checked arithmetic", "check": r"unchecked[^}]*fee|fee\s*[-+*]"},
    {"id": 15, "name": "Free L2 transaction abuse", "class": "incomplete_path",
     "defense": "reservedDynamic field properly handled; bootloader validates gas",
     "check": r"reservedDynamic\b|bootloader\b"},
    {"id": 16, "name": "DataEncoding L1/L2 mismatch", "class": "off_by_one",
     "defense": "All 10 encode/decode pairs verified consistent", "check": r"encode\w*\(|decode\w*\("},
    {"id": 17, "name": "NTV token registration race", "class": "incomplete_path",
     "defense": "_ensureTokenRegistered is idempotent", "check": r"_ensureTokenRegistered\b|idempotent\b"},
    {"id": 18, "name": "Asset ID collision", "class": "off_by_one",
     "defense": "keccak256(chainId, ntvAddress, tokenAddress)", "check": r"assetId\b|keccak256.*tokenAddress"},
    {"id": 19, "name": "Beacon proxy CREATE2 collision", "class": "proxy_upgrade",
     "defense": "address determined by deployer+salt+bytecodeHash", "check": r"CREATE2\b|create2\b"},
    {"id": 20, "name": "Cross-contract reentrancy", "class": "reentrancy",
     "defense": "Each contract has independent ReentrancyGuard AND follows CEI",
     "check": r"ReentrancyGuard\b|nonReentrant\b"},
    {"id": 21, "name": "Address aliasing collision", "class": "off_by_one",
     "defense": "Bijective mapping (add/subtract offset mod 2^160)", "check": r"addressAliasing\b|L2_ETH_TOKEN\b"},
    {"id": 22, "name": "Diamond proxy selector clash", "class": "proxy_upgrade",
     "defense": "Explicit selector mapping in DiamondCut; duplicates would revert",
     "check": r"selector\b|facet\b"},
    {"id": 23, "name": "Priority tree manipulation", "class": "incomplete_path",
     "defense": "Merkle range proofs; unprocessedIndex only moves forward",
     "check": r"unprocessedIndex\b|priorityTree\b|Merkle\b"},
    {"id": 24, "name": "Chain migration state corruption", "class": "incomplete_path",
     "defense": "forwardedBridgeMint validates consistency; atomic revert on mismatch",
     "check": r"forwardedBridgeMint\b|chainMigration\b"},
    {"id": 25, "name": "Cross-chain message replay", "class": "signature_replay",
     "defense": "isWithdrawalFinalized[chainId][batch][index] prevents replay",
     "check": r"isWithdrawalFinalized\b|finalizedWithdrawals\b"},
]

# Defense patterns that make protocols hardened
_DEFENSE_PATTERNS = [
    {
        "name": "CEI Everywhere",
        "description": "Check-Effect-Interact pattern on ALL withdrawal/claim/deposit paths. State update BEFORE external call.",
        "check": r"(balances?\[.*\]\s*[-+*]?=\s*\w+\s*;)[^;]*\.call",
        "vulnerable_pattern": r"\.call[^;]*;[^}]*balances?\[",
    },
    {
        "name": "Independent Access Control",
        "description": "Each contract independently enforces access — no single RBAC failure cascades.",
        "check": r"onlyRole\b|onlyCallFrom\b|require.*msg\.sender\s*==",
    },
    {
        "name": "Encoding Collision Resistance",
        "description": "Different encoding versions have distinct first bytes — impossible to confuse formats.",
        "check": r"ENCODING_VERSION\b|version\s*=",
    },
    {
        "name": "Mature Legacy Boundary Handling",
        "description": "Multiple bridge generations coexist with version checks, try/catch, and fallback paths.",
        "check": r"legacy\b|version\b|try\s*\{|V\d+\b",
    },
    {
        "name": "Audit Fix Quality",
        "description": "Fixes are thorough — not just patches but architectural improvements.",
        "check": r"_disableInitializers\b|ReentrancyGuard\b|CEI\b",
    },
]



# Precondition model (issue #24). Presence of an attack-vector trigger
# regex is NOT a finding: a vector is CONFIRMED only when its modelled
# vulnerable condition holds and its modelled defense is absent.
# Vectors not in _CONFIRMED_VECTORS are never confirmed from presence
# alone; they are reported as presence_only (trigger present, condition
# not established) or defensive (trigger present, defense present).
# Defense patterns are translated from each vector's own defense text
# where a code pattern exists; where no code pattern exists the vector
# stays presence_only by design.
_VECTOR_DEFENSES = {
    1: (r"require\s*\([^)]*length|msg\.length\s*>|_validate\w*Length", "message length pre-validated"),
    2: (r"try\s*\{[^}]*decode", "try/catch on decode failure"),
    3: (r"0xFFFF|msg\.sender\s*==", "system-contract / sender check"),
    4: (r"depositHappened", "deposit tracked per encoding version"),
    5: (r"onlyChain|Merkle", "onlyChain / Merkle root verification"),
    7: (r"TokensWithFeesNotSupported|balanceBefore|balanceAfter", "fee-token check / balance-delta tracking"),
    8: (r"commitTimestamp|ValidatorTimelock", "timelock delay check"),
    9: (r"transactionFilterer\s*==\s*address\(0\)", "filterer disabled (address(0))"),
    10: (r"_revertBatches", "precommitment reset on revert"),
    11: (r"0x8008", "L1 sender verification (0x8008)"),
    12: (r"bootloaderContext|onlyBootloader", "bootloader-only context"),
    13: (r"governance|DiamondProxy", "governance-controlled diamond admin"),
    14: (r"SafeMath|checked", "checked arithmetic / SafeMath"),
    15: (r"bootloader.*valid|reservedDynamic", "bootloader gas validation"),
    16: (r"ENCODING_VERSION|version\s*=", "encoding version discriminator"),
    17: (r"_ensureTokenRegistered", "idempotent token registration"),
    18: (r"keccak256\s*\([^)]*chainId", "chainId-bound asset id"),
    19: (r"CREATE2|create2", "deployer+salt+bytecodeHash address"),
    21: (r"addressAliasing|L2_ETH_TOKEN", "bijective aliasing mapping"),
    22: (r"DiamondCut|selector", "explicit selector mapping"),
    23: (r"Merkle|unprocessedIndex", "Merkle range proofs / forward-only index"),
    24: (r"forwardedBridgeMint", "consistency-validated bridge mint"),
    25: (r"isWithdrawalFinalized", "finalization replay guard"),
}
# Vectors whose vulnerable condition is modelled concretely enough to
# confirm from code (trigger present + defense absent + condition below).
# 6 and 20 are function-scoped (see _unguarded_public_functions /
# _call_before_write_unguarded); 1, 7, 14 are file/function conditions.
_CONFIRMED_CONDITIONS = {
    1: (r"UnsafeBytes\b|_parse\w+Message\b", "UnsafeBytes / message parsing without length pre-validation"),
    7: (r"\.transfer\s*\(|safeTransfer\s*\(", "token transfer without fee-token / balance-delta check"),
    14: (r"unchecked\s*\{[^}]*fee", "fee math inside an unchecked block"),
}


def _function_ranges(code: str):
    """Function blocks: name, start/end lines, signature, body (brace-matched)."""
    lines = code.split("\n")
    ranges = []
    i = 0
    while i < len(lines):
        m = re.search(r"\bfunction\s+(\w+)\s*\(", lines[i])
        if not m:
            i += 1
            continue
        start = i
        depth = 0
        started = False
        end = len(lines) - 1
        for j in range(start, len(lines)):
            depth += lines[j].count("{") - lines[j].count("}")
            if "{" in lines[j]:
                started = True
            if started and depth <= 0:
                end = j
                break
        sig_end = start
        while sig_end <= end and "{" not in lines[sig_end]:
            sig_end += 1
        ranges.append({
            "name": m.group(1),
            "start_line": start + 1,
            "end_line": end + 1,
            "signature": "\n".join(lines[start:min(sig_end + 1, end + 1)]),
            "body": "\n".join(lines[start:end + 1]),
        })
        i = end + 1
    return ranges


def _unguarded_public_functions(code: str):
    """Public/external functions with no only*/require(msg.sender) guard."""
    out = []
    for fn in _function_ranges(code):
        sig = fn["signature"]
        if not re.search(r"\b(public|external)\b", sig):
            continue
        if re.search(r"\bonly\w+\b|require\s*\(\s*msg\.sender\s*==", sig + "\n" + fn["body"]):
            continue
        out.append(fn)
    return out


def _call_before_write_unguarded(code: str):
    """Functions where an external call precedes a balances write, unguarded.

    Returns evidence dicts. A write-before-call in the same function, or
    nonReentrant on the signature, makes that function defensive, not
    vulnerable — the same CEI logic as the defense patterns, scoped per
    function instead of globally.
    """
    out = []
    for fn in _function_ranges(code):
        body = fn["body"]
        if "nonReentrant" in fn["signature"]:
            continue
        call_m = re.search(r"\.call\s*(?:\{[^}]*\})?\s*\(", body)
        write_m = re.search(r"balances?\s*\[.*\]\s*[-+*]?=", body)
        if not call_m or not write_m:
            continue
        if write_m.start() < call_m.start():
            continue  # CEI: state updated before the call
        out.append({
            "function": fn["name"],
            "line": fn["start_line"],
            "content": body.strip()[:120].replace("\n", " "),
            "condition": "external call precedes a balances write in the same function, without nonReentrant",
        })
    return out


def check_defense_patterns(code: str) -> List[Dict]:
    """Check which defense patterns the code implements."""
    results = []
    for dp in _DEFENSE_PATTERNS:
        implemented = bool(re.search(dp["check"], code, re.IGNORECASE))
        results.append({
            "name": dp["name"],
            "description": dp["description"],
            "implemented": implemented,
        })
    return results


def check_vulnerable_patterns(code: str) -> Dict:
    """Check for vulnerable versions of defense patterns, evidence-gated.

    Returns (all keys kept for API compatibility):
      * defenses: as before, presence of each defense pattern.
      * vulnerable_patterns_found: CEI findings only, each with function,
        line, matched evidence and status="confirmed". A function with
        write-before-call or nonReentrant is defensive, not vulnerable.
      * attack_vectors / attack_vectors_applicable: CONFIRMED vectors only
        (precondition met, defense absent), each with status and evidence.
        Mere presence of a trigger regex is NOT counted here.
      * attack_vectors_presence_only: triggers present but the vulnerable
        condition is not established — explicitly not findings.
      * attack_vectors_defensive: triggers present but the modelled
        defense is present — explicitly not findings.
      * estimated_hardenability: rated on confirmed findings only.
      * findings: confirmed vectors + CEI findings, for pre-scan callers
        that expect a "findings" key (previously absent, so pre-scan
        silently dropped every zkSync result).
    """
    # CEI, function-scoped
    cei_evidence = _call_before_write_unguarded(code)
    vulnerable = []
    for ev in cei_evidence:
        vulnerable.append({
            "pattern": "CEI Everywhere",
            "vulnerable_match": True,
            "status": "confirmed",
            "function": ev["function"],
            "line": ev["line"],
            "evidence": ev["content"],
            "condition": ev["condition"],
        })
    defense_status = check_defense_patterns(code)

    confirmed = []
    presence_only = []
    defensive = []
    for av in _ATTACK_VECTORS:
        trigger = av["check"]
        if not re.search(trigger, code, re.IGNORECASE):
            continue
        defense = _VECTOR_DEFENSES.get(av["id"])
        if defense and re.search(defense[0], code, re.IGNORECASE):
            defensive.append({**av, "status": "defensive", "defense": defense[1]})
            continue
        if av["id"] == 6:
            unguarded = _unguarded_public_functions(code)
            if unguarded:
                confirmed.append({**av, "status": "confirmed",
                                  "evidence": [{"function": f["name"], "line": f["start_line"]} for f in unguarded],
                                  "condition": "public/external function without an access guard"})
            else:
                presence_only.append({**av, "status": "presence_only",
                                      "note": "trigger present, but every public/external function is guarded"})
            continue
        if av["id"] == 20:
            # Cross-contract reentrancy: the trigger (ReentrancyGuard) is
            # itself a defense, so presence alone can never confirm it.
            # Confirm only via the call-before-write condition above.
            if cei_evidence:
                confirmed.append({**av, "status": "confirmed",
                                  "evidence": cei_evidence,
                                  "condition": "external call precedes a balances write without nonReentrant"})
            else:
                defensive.append({**av, "status": "defensive",
                                  "defense": "ReentrancyGuard / CEI present, no unguarded call-before-write found"})
            continue
        cond = _CONFIRMED_CONDITIONS.get(av["id"])
        if cond and re.search(cond[0], code, re.IGNORECASE):
            confirmed.append({**av, "status": "confirmed",
                              "evidence": cond[1], "condition": cond[1]})
        else:
            presence_only.append({**av, "status": "presence_only",
                                  "note": "trigger present, but the vulnerable precondition is not established"})

    findings = [{"kind": "attack_vector", **v} for v in confirmed]
    findings += [{"kind": "vulnerable_pattern", **v} for v in vulnerable]

    return {
        "defenses": defense_status,
        "vulnerable_patterns_found": vulnerable,
        "attack_vectors_applicable": len(confirmed),
        "attack_vectors": confirmed,
        "attack_vectors_presence_only": presence_only,
        "attack_vectors_defensive": defensive,
        "estimated_hardenability": "high" if not confirmed and not vulnerable else (
            "medium" if len(confirmed) < 5 else "low"
        ),
        "findings": findings,
    }


def format_zksync_report(result: Dict) -> str:
    """Format ZKsync analysis results."""
    lines = ["### ZKsync Defense Analysis"]
    
    lines.append("\n**Defense Patterns:**")
    for d in result.get("defenses", []):
        status = "✅" if d["implemented"] else "❌"
        lines.append(f"- {status} {d['name']}: {d['description']}")
    
    if result.get("vulnerable_patterns_found"):
        lines.append("\n**⚠ Vulnerable Pattern Variants Detected (confirmed, with evidence):**")
        for v in result["vulnerable_patterns_found"]:
            ev = v.get("evidence", "")
            fn = v.get("function", "")
            lines.append(f"- {v['pattern']} (function {fn}, line {v.get('line', '?')}): {ev}")
    
    lines.append(f"\n**Confirmed Applicable Attack Vectors**: {result['attack_vectors_applicable']}/25")
    for av in result.get("attack_vectors", [])[:10]:
        lines.append(f"- #{av['id']} {av['name']} ({av['class']}) — confirmed: {av.get('condition', '')}")
    if len(result.get("attack_vectors", [])) > 10:
        lines.append(f"  ... and {len(result['attack_vectors']) - 10} more")
    if result.get("attack_vectors_presence_only"):
        lines.append(f"\n**Presence only (NOT confirmed findings)**: {len(result['attack_vectors_presence_only'])}")
        for av in result["attack_vectors_presence_only"][:10]:
            lines.append(f"- #{av['id']} {av['name']} ({av['class']}) — trigger present, precondition not established")
    
    hardness = result.get("estimated_hardenability", "unknown")
    if hardness == "high":
        lines.append("\n**Estimate (on confirmed findings only)**: Protocol appears HARDENED — expect 0 confirmed findings")
    elif hardness == "medium":
        lines.append("\n**Estimate (on confirmed findings only)**: Protocol has some defenses — moderate chance of confirmed findings")
    else:
        lines.append("\n**Estimate (on confirmed findings only)**: Protocol appears VULNERABLE — good hunting prospects")
    
    return "\n".join(lines)
