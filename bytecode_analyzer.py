import os, re, json, logging, tempfile
from typing import Optional, List, Dict
from analyzers.base import Finding

logger = logging.getLogger(__name__)

Opcodes = {
    "SELFDESTRUCT": "0xFF",
    "DELEGATECALL": "0xF4",
    "CALL": "0xF1",
    "CALLCODE": "0xF2",
    "TIMESTAMP": "0x42",
    "NUMBER": "0x43",
    "GASLIMIT": "0x45",
    "BLOCKHASH": "0x40",
    "ORIGIN": "0x32",
    "ADDRESS": "0x30",
    "SLOAD": "0x54",
    "SSTORE": "0x55",
    "SELFBALANCE": "0x47",
}


def _parse_hex(bytecode: str) -> bytes:
    bc = bytecode.strip()
    if bc.startswith("0x"):
        bc = bc[2:]
    try:
        return bytes.fromhex(bc)
    except Exception:
        return b""


def _analyze_opcodes(raw: bytes) -> List[Dict]:
    """Linear disassembly with PUSH-operand awareness (M28 remediation).

    The previous per-byte substring search matched opcode bytes inside PUSH
    operands, constants and ABI data - flagging nearly every real contract
    with Critical/High findings. Opcodes are now identified only at
    execution boundaries via the existing linear disassembler.
    """
    if not raw:
        return []
    from gas_profiler import _disassemble
    try:
        ops = _disassemble(raw.hex())
    except Exception as e:
        logger.debug("Disassembly failed: %s", e)
        return []
    seen = {o["op"] for o in ops if not o["op"].startswith("UNKNOWN_")}
    return [
        {"opcode": name, "code": Opcodes[name]}
        for name in Opcodes
        if name in seen
    ]


def decompile_bytecode(bytecode: str) -> Optional[str]:
    tmp_name = None
    try:
        import subprocess
        with tempfile.NamedTemporaryFile(suffix=".hex", delete=False, mode="w") as f:
            f.write(bytecode)
            f.flush()
            tmp_name = f.name
            proc = subprocess.run(["panoramix", tmp_name], capture_output=True, text=True, timeout=30)
            if proc.returncode == 0:
                return proc.stdout[:3000]
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.debug(f"Decompiler error: {e}")
    finally:
        # Temp file is removed on success AND failure (M28 remediation).
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
    return None


def analyze_bytecode(bytecode: str, address: str = "") -> List[Finding]:
    """Report opcode presence as informational context (M28 remediation).

    A single opcode's presence in deployed bytecode is not by itself a
    vulnerability: SELFDESTRUCT in an owned emergency-exit path, or a
    DELEGATECALL into a known-safe implementation, are legitimate designs.
    Contextual severity is the audit's job, not the opcode scanner's.
    """
    findings = []
    raw = _parse_hex(bytecode)
    op_findings = _analyze_opcodes(raw) if raw else []

    for op in op_findings:
        findings.append(Finding(
            agent_name=f"Opcode: {op['opcode']}",
            severity="Info",
            category="Bytecode Analysis",
            file=address or "unknown",
            function_name="",
            description=f"Bytecode contains {op['opcode']} ({op['code']}) - presence is informational; assess exploitation context manually",
            fix="Verify this opcode is expected in the contract design and properly guarded",
        ))

    if not findings:
        findings.append(Finding(
            agent_name="No Critical Opcodes",
            severity="Info",
            category="Bytecode Analysis",
            file=address or "unknown",
            function_name="",
            description="No notable opcodes detected in bytecode",
            fix="",
        ))

    return findings


def analyze_contract_from_explorer(address: str) -> List[Finding]:
    try:
        import requests
        apikey = os.environ.get("ETHERSCAN_API_KEY", "")
        if not apikey:
            return []
        resp = requests.get("https://api.etherscan.io/api", params={
            "module": "contract", "action": "getsourcecode",
            "address": address, "apikey": apikey,
        }, timeout=15)
        data = resp.json()
        if data.get("status") != "1":
            return []
        src = data["result"][0]
        bytecode = src.get("Bytecode", "")
        if bytecode and bytecode != "0x":
            return analyze_bytecode(bytecode, address)
    except Exception as e:
        logger.warning(f"Explorer analysis failed: {e}")
    return []
