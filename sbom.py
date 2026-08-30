"""SBOM — Software Bill of Materials for smart contract dependencies."""

import json
import logging
import os
import re
from typing import List, Dict, Optional
from dataclasses import dataclass, field

try:
    import requests
    _has_requests = True
except ImportError:
    _has_requests = False

logger = logging.getLogger(__name__)

IMPORT_RE = re.compile(
    r'^\s*import\s+(?:\{[^}]*\}\s+from\s+)?["\']([^"\']+)["\']\s*;',
    re.MULTILINE,
)

PRAGMA_RE = re.compile(r'^\s*pragma\s+solidity\s+([^;]+);', re.MULTILINE)

_KNOWN_PACKAGES = {
    "@openzeppelin/": "OpenZeppelin Contracts",
    "@uniswap/": "Uniswap",
    "@aave/": "Aave",
    "@chainlink/": "Chainlink",
    "@balancer-labs/": "Balancer",
    "@curvefi/": "Curve",
    "@makerdao/": "MakerDAO",
    "@compound-finance/": "Compound",
    "@lido/": "Lido",
    "@sushi/": "SushiSwap",
    "@pancakeswap/": "PancakeSwap",
    "@layerzerolabs/": "LayerZero",
    "@wormhole/": "Wormhole",
    "@solmate/": "Solmate (rari-capital)",
    "@forge-std/": "Foundry Forge Std",
}

_HARDCODED_VULNERABLE = {
    "0.4.22": ["CVE-2023-34460"],
    "0.4.24": ["CVE-2023-34461"],
    "0.4.25": ["CVE-2023-34462"],
    "0.5.0": ["CVE-2022-39378"],
    "0.5.1": ["CVE-2022-39378"],
    "0.6.0": ["CVE-2022-38721"],
    "0.6.1": ["CVE-2022-38721"],
    "0.7.0": ["CVE-2022-38723"],
    "0.7.1": ["CVE-2022-38723"],
    "0.7.2": ["CVE-2022-38723"],
    "0.7.3": ["CVE-2022-38723"],
    "0.7.4": ["CVE-2022-38723"],
    "0.7.5": ["CVE-2022-38723"],
    "0.7.6": ["CVE-2022-38723"],
    "0.8.0": ["CVE-2023-40014"],
    "0.8.1": ["CVE-2023-40014"],
    "0.8.2": ["CVE-2023-40014"],
    "0.8.3": ["CVE-2023-40014"],
    "0.8.4": ["CVE-2023-40014"],
    "0.8.5": ["CVE-2023-40014"],
    "0.8.6": ["CVE-2023-40014"],
    "0.8.7": ["CVE-2023-40014"],
    "0.8.8": ["CVE-2023-40014"],
    "0.8.9": ["CVE-2023-40014"],
    "0.8.10": ["CVE-2023-40014"],
    "0.8.11": ["CVE-2023-40014"],
    "0.8.12": ["CVE-2023-40014"],
    "0.8.13": ["CVE-2023-40014"],
    "0.8.14": ["CVE-2023-40014"],
    "0.8.15": ["CVE-2023-40014"],
    "0.8.16": ["CVE-2023-40014"],
    "0.8.17": ["CVE-2023-40014"],
    "0.8.18": ["CVE-2023-40014"],
    "0.8.19": [],
}

_KNOWN_VULNERABLE = _HARDCODED_VULNERABLE
_cves_json_path = os.path.join(os.path.dirname(__file__), "known_cves.json")
if os.path.isfile(_cves_json_path):
    try:
        with open(_cves_json_path, "r", encoding="utf-8") as _f:
            _external = json.load(_f)
        if _external:
            _KNOWN_VULNERABLE = _external
            logger.info("Loaded CVE data from known_cves.json")
    except Exception as _e:
        logger.warning(f"Failed to read known_cves.json: {_e}")

@dataclass
class Dependency:
    name: str
    version: str = ""
    known_package: str = ""
    cves: List[str] = field(default_factory=list)
    license: str = ""


@dataclass
class SBOMResult:
    pragma: str = ""
    compiler_version: str = ""
    compiler_cves: List[str] = field(default_factory=list)
    dependencies: List[Dependency] = field(default_factory=list)


def parse_imports(code: str) -> List[str]:
    return IMPORT_RE.findall(code)


def parse_pragma(code: str) -> str:
    m = PRAGMA_RE.search(code)
    return m.group(1).strip() if m else ""


def identify_package(path: str) -> str:
    for prefix, name in _KNOWN_PACKAGES.items():
        if prefix in path:
            return name
    parts = path.split("/")
    if len(parts) >= 2:
        return parts[0]
    return ""


def check_version_cves(pragma_range: str, resolved: str = "") -> List[str]:
    """CVEs affecting a Solidity compiler version (M27 remediation).

    The old substring match on the pragma text flagged `^0.8.0` (a RANGE
    whose floor is 0.8.0) with every 0.8.0 CVE even though the range also
    admits the patched 0.8.19+. Version evaluation now uses real range
    semantics: a range without a resolved compiler version produces NO
    assertion; a resolved version is checked with packaging specifiers.
    """
    if not pragma_range:
        return []
    pinned = pragma_range.strip()
    has_range_ops = bool(re.search(r"[\^~>=<\*]", pinned))
    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version, InvalidVersion
    except ImportError:
        SpecifierSet = None

    def _floor_to_semver(v: str) -> str:
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", v)
        if not m:
            return ""
        parts = m.group(1).split(".")
        while len(parts) < 3:
            parts.append("0")
        return ".".join(parts)

    if resolved:
        # Resolve against the declared range when possible.
        if SpecifierSet is not None and has_range_ops:
            floor = _floor_to_semver(pinned)
            minor = re.search(r"(\d+)\.(\d+)\.\d+", floor)
            spec = None
            if pinned.startswith("^") and minor:
                spec = f">={floor},<{int(minor.group(1))}.{int(minor.group(2)) + 1}.0"
            elif pinned.startswith("~") and minor:
                spec = f">={floor},<{minor.group(1)}.{minor.group(2)}.255"
            else:
                spec = pinned.replace(" ", "")
            try:
                in_range = Version(resolved) in SpecifierSet(spec)
            except InvalidVersion:
                in_range = False
        else:
            in_range = _floor_to_semver(pinned) == _floor_to_semver(resolved) or pinned == resolved
    elif has_range_ops:
        # A range alone cannot pin the actual compiler - no CVE assertion
        return []
    else:
        in_range = True  # pinned, exact pragma - substring is exact here

    if not in_range:
        return []

    version_key = resolved if resolved else _floor_to_semver(pinned)
    cves = []
    for ver, vulns in _KNOWN_VULNERABLE.items():
        if re.search(r'(?<!\d)' + re.escape(ver) + r'(?!\d)', version_key):
            cves.extend(vulns)
    return cves


OSV_API = "https://api.osv.dev/v1/query"
_OSV_CACHE: Dict[str, list] = {}


def query_osv(package_name: str, version: str = "") -> List[dict]:
    """Query OSV.dev API for known vulnerabilities in a package."""
    cache_key = f"{package_name}@{version}"
    if cache_key in _OSV_CACHE:
        return _OSV_CACHE[cache_key]
    if not _has_requests:
        return []
    try:
        resp = requests.post(OSV_API, json={
            "package": {"name": package_name, "ecosystem": "npm"},
            "version": version or "",
        }, timeout=10)
        if resp.ok:
            data = resp.json()
            vulns = data.get("vulns", [])
            _OSV_CACHE[cache_key] = vulns
            return vulns
    except Exception as e:
        logger.debug(f"OSV query failed for {package_name}: {e}")
    return []


def analyze_sbom(code: str) -> SBOMResult:
    result = SBOMResult()
    result.pragma = parse_pragma(code)

    major = re.search(r'(\d+\.\d+\.\d+)', result.pragma)
    result.compiler_version = major.group(1) if major else result.pragma

    # NOTE: compiler_version here is the pragma FLOOR (e.g. 0.8.0 for
    # ^0.8.0), not the compiler actually used - it is NOT passed as
    # 'resolved' so an ambiguous range makes no CVE assertion (M27).
    result.compiler_cves = check_version_cves(result.pragma)

    seen = set()
    imports = [imp for imp in parse_imports(code) if not (imp in seen or seen.add(imp))]

    from concurrent.futures import ThreadPoolExecutor, as_completed
    dep_map = {}
    # Only query OSV for RECOGNIZED packages (M27 remediation): querying
    # the npm ecosystem with arbitrary Solidity import paths matched
    # unrelated npm CVEs purely by name.
    queryable = [imp for imp in imports if identify_package(imp)]
    with ThreadPoolExecutor(max_workers=5) as pool:
        fut_map = {pool.submit(query_osv, imp): imp for imp in queryable}
        for fut in as_completed(fut_map):
            imp = fut_map[fut]
            dep = Dependency(name=imp)
            dep.known_package = identify_package(imp)
            try:
                osv_results = fut.result()
                for v in osv_results:
                    cve_id = v.get("id", "")
                    if cve_id:
                        dep.cves.append(cve_id)
            except Exception:
                pass
            dep_map[imp] = dep

    result.dependencies = [dep_map[imp] for imp in imports]
    return result


def format_sbom_text(result: SBOMResult) -> str:
    parts = ["## SBOM — Software Bill of Materials\n"]

    parts.append(f"**Compiler**: Solidity {result.compiler_version}")
    parts.append(f"**Pragma**: {result.pragma}\n")

    if not result.dependencies:
        parts.append("_No external dependencies detected._\n")
        return "\n".join(parts)

    parts.append(f"### Dependencies ({len(result.dependencies)})\n")
    parts.append("| # | Import Path | Known Package |")
    parts.append("|---|------------|--------------|")
    for i, dep in enumerate(result.dependencies, 1):
        pkg = dep.known_package or "-"
        parts.append(f"| {i} | `{dep.name}` | {pkg} |")
    parts.append("")

    if result.compiler_cves:
        parts.append("### ⚠ Compiler CVEs\n")
        for cve in result.compiler_cves:
            parts.append(f"- **Solidity {result.compiler_version}**: {cve}")
            parts.append(f"  - Upgrade Solidity to avoid this CVE")
        parts.append("")

    risk = "Low"
    if result.compiler_cves:
        risk = "Medium" if len(result.compiler_cves) <= 2 else "High"
    parts.append(f"**Overall Dependency Risk**: {risk}")

    return "\n".join(parts)


def generate_sbom_json(result: SBOMResult) -> str:
    # CycloneDX conformance (M27 remediation): specVersion 1.5 (evidence is
    # a 1.5 field), no fabricated MIT licenses, no 'compiler' component
    # type (not in the enum) - compiler data moves to document properties,
    # and the invalid pkg:npm purl for Solidity paths is dropped.
    components = []
    for d in result.dependencies:
        components.append({
            "type": "library",
            "name": d.known_package or d.name,
            "version": "",
            "evidence": {"identity": [{"field": "name", "confidence": 0.5}]},
        })
    properties = [
        {"name": "solidity.pragma", "value": result.pragma or ""},
        {"name": "solidity.compiler.version", "value": result.compiler_version or ""},
    ]
    if result.compiler_cves:
        properties.append({"name": "solidity.compiler.cves", "value": ",".join(result.compiler_cves)})
    return json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {
                "type": "application",
                "name": "Smart Contract Audit Target",
                "version": "1.0.0",
            },
            "properties": properties,
        },
        "components": components,
        "dependencies": [
            {"ref": d.known_package or d.name, "dependsOn": []}
            for d in result.dependencies
        ],
    }, indent=2)
