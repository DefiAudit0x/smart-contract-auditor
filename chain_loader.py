"""
Fetch source code of smart contracts from chain explorers (Etherscan, Basescan, etc.)
"""
import json
import logging
import os
import re
import time
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

# Supports 10 major chains — add any new chain here
CHAIN_CONFIG: Dict[str, Dict] = {
    # Per-chain credential isolation (M19 remediation): each provider gets
    # its own env var instead of broadcasting ETHERSCAN_API_KEY to nine
    # third-party domains with no contractual duty toward that secret.
    "ethereum":  {"api_url": "https://api.etherscan.io/api",          "explorer": "Etherscan",     "key_var": "ETHERSCAN_API_KEY"},
    "bsc":       {"api_url": "https://api.bscscan.com/api",           "explorer": "BscScan",       "key_var": "BSCSCAN_API_KEY"},
    "polygon":   {"api_url": "https://api.polygonscan.com/api",       "explorer": "PolygonScan",   "key_var": "POLYGONSCAN_API_KEY"},
    "arbitrum":  {"api_url": "https://api.arbiscan.io/api",           "explorer": "ArbiScan",      "key_var": "ARBISCAN_API_KEY"},
    "optimism":  {"api_url": "https://api-optimistic.etherscan.io/api","explorer": "OptimisticScan","key_var": "OPTIMISM_API_KEY"},
    "avalanche": {"api_url": "https://api.snowtrace.io/api",          "explorer": "SnowTrace",     "key_var": "SNOWTRACE_API_KEY"},
    "base":      {"api_url": "https://api.basescan.org/api",          "explorer": "BaseScan",      "key_var": "BASESCAN_API_KEY"},
    "celo":      {"api_url": "https://api.celoscan.io/api",           "explorer": "CeloScan",      "key_var": "CELOSCAN_API_KEY"},
    "gnosis":    {"api_url": "https://api.gnosisscan.io/api",         "explorer": "GnosisScan",    "key_var": "GNOSISSCAN_API_KEY"},
    "scroll":    {"api_url": "https://api.scrollscan.com/api",        "explorer": "ScrollScan",    "key_var": "SCROLLSCAN_API_KEY"},
}

ETHERSCAN_API_KEY: str = os.getenv("ETHERSCAN_API_KEY", "")

def _resolve_api_key(cfg: Dict, override: str = "") -> str:
    """Explicit per-call override wins; otherwise the chain's own env var.
    Empty and the 'YourApiKeyToken' placeholder both resolve to keyless
    requests - the sentinel literal is never transmitted (M19 remediation)."""
    if override and override.strip() != "YourApiKeyToken":
        return override
    val = os.getenv(cfg.get("key_var", ""), "").strip()
    if not val or val == "YourApiKeyToken":
        return ""
    return val


def _fetch_abi_source(api_url: str, address: str, apikey: str) -> Optional[Dict]:
    """Fetch source code + ABI from explorer API."""
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": apikey,
    }
    try:
        r = requests.get(api_url, params=params, timeout=30)
        data = r.json()
        if data.get("status") != "1":
            logger.warning(f"API returned: {data.get('message', 'unknown')}")
            return None
        result = data.get("result", [{}])[0]
        return result
    except requests.Timeout:
        logger.warning(f"Timeout fetching {address}")
        return None
    except Exception as e:
        logger.warning(f"Failed to fetch {address}: {e}")
        return None


def load_from_explorer(address: str, chain: str = "ethereum",
                       api_key: str = "") -> Optional[Dict]:
    """Fetch contract from explorer. Returns {name, code, compiler, ...} or None."""
    chain = chain.lower()
    cfg = CHAIN_CONFIG.get(chain)
    if not cfg:
        logger.error(f"Unsupported chain: {chain}. Choose from: {', '.join(CHAIN_CONFIG.keys())}")
        return None

    if not re.match(r'^0x[a-fA-F0-9]{40}$', address):
        logger.error(f"Invalid address: {address}")
        return None

    apikey = _resolve_api_key(cfg, api_key)
    result = _fetch_abi_source(cfg["api_url"], address, apikey)
    if not result:
        return None

    source_code = result.get("SourceCode", "")
    if not source_code or not source_code.strip():
        logger.warning(f"Contract {address} is not verified on {cfg['explorer']}")
        return None
    # Etherscan sometimes wraps code in {{...}} for multi-file contracts
    if source_code.startswith("{{") and source_code.endswith("}}"):
        try:
            parsed = json.loads(source_code[1:-1])
            sources = parsed.get("sources", {})
            combined = ""
            for fpath, fdata in sources.items():
                content = fdata.get("content", "")
                combined += f"\n\n// File: {fpath}\n{content}"
            source_code = combined.strip()
        except (json.JSONDecodeError, AttributeError):
            source_code = source_code.strip("{}").strip()

    contract_name = result.get("ContractName", "Unknown")
    compiler = result.get("CompilerVersion", "")
    abi_raw = result.get("ABI", "")
    try:
        abi = json.loads(abi_raw) if isinstance(abi_raw, str) else abi_raw
    except (json.JSONDecodeError, TypeError):
        abi = []

    return {
        "name": contract_name,
        "code": source_code,
        "compiler": compiler,
        "abi": abi,
        "chain": chain,
        "address": address,
        "explorer": cfg["explorer"],
    }


def list_supported_chains() -> str:
    return ", ".join(f"{k} ({v['explorer']})" for k, v in CHAIN_CONFIG.items())
