"""
PoC (Proof-of-Concept) generation and sound execution for Critical findings.

Verdict semantics (three-state, deliberately explicit):
  PROVED       — the PoC test suite passed, confirming the exploit works.
  DISPROVED    — the PoC compiled and ran, and its assertions failed:
                 the exploit did not reproduce.
  INCONCLUSIVE — compile/setup failure, missing toolchain, or zero tests
                 ran. NEVER treated as evidence in either direction.
"""
import os, json, logging, tempfile, subprocess, re, shutil, time
from pathlib import Path
from typing import List, Optional
from analyzers.base import Finding

logger = logging.getLogger(__name__)
PROOFS_DIR = os.path.join(os.path.dirname(__file__), "proofs")
os.makedirs(PROOFS_DIR, exist_ok=True)

POC_PROMPT = """You are an expert in Foundry (Solidity testing framework).
Write a complete Foundry test file (.t.sol) that PROVES the following vulnerability EXISTS.

Vulnerability: {vulnerability}
Severity: {severity}
Description: {description}

Victim Contract Code:
```solidity
{code}
```

Requirements:
1. Create a test that calls the vulnerable function with the EXACT attack payload
2. The test suite must PASS (be green) when the vulnerability is real — assert the
   exploit's effects directly (e.g. attacker drained funds, unauthorized state
   change succeeded, invariant broken). Consume expected reverts with
   `vm.expectRevert` so the proof test still passes.
3. Use `vm.startPrank(attacker)`, `deal()`, and other Foundry cheatcodes
4. Import `forge-std/Test.sol` and `../src/Victim.sol` (the victim source is
   provided as src/Victim.sol in the project)
5. The test function name must start with `testPoC`
6. If it's a reentrancy, create an attacker contract that calls back
7. Add console.log assertions to prove the exploit worked
8. ONLY output the Solidity code, no explanation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
...
```
"""

POC_FRAMEWORK = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
{poc_body}
"""

FOUNDRY_TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

{poc_code}
"""


DANGEROUS_CHEATCODES = [
    r"vm\.ffi\s*\(",
    r"vm\.broadcast\s*\(",
    r"vm\.startBroadcast\s*\(",
    r"vm\.stopBroadcast\s*\(",
    r"vm\.writeFile\s*\(",
    r"vm\.readFile\s*\(",
    r"vm\.removeFile\s*\(",
    r"vm\.createDir\s*\(",
    r"vm\.writeJson\s*\(",
    r"vm\.setEnv\s*\(",
    r"vm\.getEnv\s*\(",
    r"vm\.projectRoot\s*\(",
    r"vm\.envOr\s*\(",
    r"vm\.envBool\s*\(",
    r"vm\.envUint\s*\(",
    r"vm\.envInt\s*\(",
    r"vm\.envAddress\s*\(",
    r"vm\.envBytes32\s*\(",
    r"vm\.envString\s*\(",
    r"vm\.envBytes\s*\(",
    r"vm\.keyExists\s*\(",
    r"vm\.keyExistsJson\s*\(",
    r"vm\.serializeJson\s*\(",
    r"vm\.parseJson\s*\(",
    # L-29: 'parseThomas' was a typo — the real cheatcode is parseToml.
    r"vm\.parseToml\s*\(",
    r"vm\.linkSymbol\s*\(",
]

def _has_dangerous_cheatcodes(code: str) -> bool:
    for pattern in DANGEROUS_CHEATCODES:
        if re.search(pattern, code):
            return True
    return False

def _clean_poc(raw: str) -> str:
    """Extract Solidity code from LLM response."""
    m = re.search(r"```solidity\n?(.*?)```", raw, re.DOTALL)
    if m:
        return m.group(1).strip()
    m = re.search(r"```\n?(.*?)```", raw, re.DOTALL)
    if m:
        return m.group(1).strip()
    return raw.strip()


def generate_poc(finding: Finding, full_code: str) -> Optional[str]:
    from agents import call_model_with_fallback
    prompt = POC_PROMPT.format(
        vulnerability=finding.agent_name,
        severity=finding.severity,
        description=finding.description,
        code=full_code[:2000],
    )
    try:
        raw = call_model_with_fallback(prompt)
        code = _clean_poc(raw)
        if _has_dangerous_cheatcodes(code):
            logger.error(f"PoC for {finding.agent_name} contains dangerous cheatcodes (vm.ffi/vm.broadcast) — rejecting")
            return None
        if not code or len(code) < 100:
            logger.warning(f"PoC too short for {finding.agent_name}")
            return None
        safe = re.sub(r'[^a-zA-Z0-9_\u0600-\u06FF-]', '_', finding.agent_name)[:40]
        fname = f"PoC_{safe}_{finding.file.replace('/', '_')}.t.sol"
        path = os.path.join(PROOFS_DIR, fname)
        with open(path, "w", encoding="utf-8") as f:
            f.write(code)
        logger.info(f"PoC saved: {path}")
        return path
    except Exception as e:
        logger.warning(f"PoC generation failed: {e}")
        return None


_FORGE_PASSED_RE = re.compile(r"(\d+)\s+passed")
_FORGE_FAILED_RE = re.compile(r"(\d+)\s+failed")


def _parse_forge_summary(output: str) -> Optional[tuple]:
    """Extract (passed, failed) counts from a `forge test` summary.

    Returns None when no summary was printed — which means compilation or
    setup failed and the run carries no evidential weight either way.
    """
    passed = _FORGE_PASSED_RE.search(output)
    failed = _FORGE_FAILED_RE.search(output)
    if not passed and not failed:
        return None
    return (
        int(passed.group(1)) if passed else 0,
        int(failed.group(1)) if failed else 0,
    )


def _build_poc_project(poc_path: str, victim_code: str) -> Path:
    """Assemble a real temporary Foundry project for one PoC run.

    The generated PoC imports `forge-std/Test.sol` and `../src/Victim.sol`;
    neither exists next to the bare proof file, so running forge directly in
    PROOFS_DIR can only fail to compile — which the old evaluator then read
    as "vulnerability disproved". Each run now gets its own project.
    """
    proj = Path(tempfile.mkdtemp(prefix="poc_run_"))
    (proj / "src").mkdir()
    (proj / "test").mkdir()
    (proj / "foundry.toml").write_text(
        "[profile.default]\nsrc = 'src'\nout = 'out'\nlibs = ['lib']\nsolc_version = '0.8.25'\n\n[profile.default.fuzz]\nruns = 32\n",
        encoding="utf-8",
    )
    if victim_code:
        (proj / "src" / "Victim.sol").write_text(victim_code, encoding="utf-8")
    poc_source = Path(poc_path).read_text(encoding="utf-8")
    (proj / "test" / "PoC.t.sol").write_text(poc_source, encoding="utf-8")
    return proj


def run_foundry_test(poc_path: str, project_dir: str = ".", use_docker: bool = True,
                     victim_code: str = "") -> dict:
    """Execute a PoC in an isolated temporary Foundry project.

    Returns {"status": PROVED|DISPROVED|INCONCLUSIVE, "passed": bool,
    "output": str, "error": str}. `passed` is kept for backward
    compatibility and is True only for PROVED.
    """
    result = {"status": "INCONCLUSIVE", "passed": False, "output": "", "error": ""}
    if use_docker and not shutil.which("docker"):
        result["error"] = "Docker not found. Install Docker: https://docs.docker.com/get-docker/"
        return result
    if not use_docker and not shutil.which("forge"):
        result["error"] = "forge not installed. Install Foundry: https://book.getfoundry.sh/getting-started/installation"
        return result

    proj = _build_poc_project(poc_path, victim_code)
    try:
        if use_docker:
            command = [
                "docker", "run", "--rm",
                "--network", "none",
                "--read-only",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--pids-limit", "128",
                "--memory", "512m",
                "--cpus", "1",
                "-v", f"{proj}:/app",
                "-w", "/app",
                "ghcr.io/foundry-rs/foundry:latest",
                "forge", "test", "--match-path", "test/PoC.t.sol",
            ]
            cwd = None
        else:
            command = [
                "forge", "test", "--match-path", "test/PoC.t.sol",
            ]
            cwd = str(proj)
        proc = subprocess.run(
            command, cwd=cwd, capture_output=True, text=True, timeout=120,
        )
        output = (proc.stdout + proc.stderr)
        result["output"] = output[-4000:]

        counts = _parse_forge_summary(output)
        if counts is None:
            # Compilation/setup failure: the absence of a test summary is
            # never evidence that the vulnerability is absent.
            result["error"] = "Forge produced no test summary (compile or setup failure)"
            return result
        passed_n, failed_n = counts
        if passed_n == 0 and failed_n == 0:
            # forge exits 0 even when nothing matched the path.
            result["error"] = "No tests matched the PoC path"
            return result
        if failed_n > 0:
            result["status"] = "DISPROVED"
        else:
            result["status"] = "PROVED"
        result["passed"] = result["status"] == "PROVED"
        return result
    except FileNotFoundError:
        result["error"] = "forge not installed. Install Foundry: https://book.getfoundry.sh/getting-started/installation"
    except subprocess.TimeoutExpired:
        result["error"] = "Test timed out (120s)"
    except Exception as e:
        result["error"] = f"PoC execution failed: {type(e).__name__}"
    finally:
        shutil.rmtree(proj, ignore_errors=True)
    return result


def _has_docker() -> bool:
    """Check if Docker CLI is available on the system."""
    return shutil.which("docker") is not None


def run_foundry_test_docker(code: str, proof_dir: str) -> str:
    """
    Run a Foundry PoC test inside a Docker container.

    Builds a Docker image with Foundry, writes the PoC code into a temporary
    Foundry project, mounts it as a volume, and executes `forge test` inside
    the container. Falls back to local subprocess execution if Docker is not
    available.

    Args:
        code: Raw Solidity source of the PoC test.
        proof_dir: Directory to use as the project root (for fallback and
                   dependency resolution).

    Returns:
        Combined stdout/stderr output as a string.
    """
    if not _has_docker():
        logger.warning("Docker is not available; refusing unisolated PoC execution")
        return "Inconclusive: Docker is not available; PoC was not executed"

    tmpdir = tempfile.mkdtemp(prefix="foundry_poc_")
    try:
        test_dir = os.path.join(tmpdir, "test")
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(test_dir)
        os.makedirs(src_dir)

        poc_path = os.path.join(test_dir, "PoC.t.sol")
        with open(poc_path, "w", encoding="utf-8") as f:
            f.write(code)

        dockerfile_path = os.path.join(tmpdir, "Dockerfile")
        with open(dockerfile_path, "w", encoding="utf-8") as f:
            f.write("FROM ghcr.io/foundry-rs/foundry:latest\nWORKDIR /app\n")

        build_proc = subprocess.run(
            ["docker", "build", "-t", "foundry-test", tmpdir],
            capture_output=True, text=True, timeout=60,
        )
        if build_proc.returncode != 0:
            raise RuntimeError(f"Docker build failed: {build_proc.stderr}")

        run_proc = subprocess.run(
            [            "docker", "run", "--rm",
             "--network", "none",
             "--read-only",
             "--cap-drop", "ALL",
             "--security-opt", "no-new-privileges",
             "--pids-limit", "128",
             "--memory", "512m",
             "--cpus", "1",
             "-v", f"{tmpdir}:/app",

             "-w", "/app",
             "foundry-test",
             "forge", "test", "--match-path", "test/PoC.t.sol", "-vvv"],
            capture_output=True, text=True, timeout=120,
        )
        output = run_proc.stdout + run_proc.stderr
        if run_proc.returncode != 0:
            logger.warning("Foundry test failed:\n%s", output)
        return output

    except subprocess.TimeoutExpired:
        return "Error: Test timed out (120s)"
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr or str(e)}"
    except Exception as e:
        return f"Error: {e}"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def batch_generate_pocs(findings: List[Finding], codes: dict) -> List[dict]:
    results = []
    for f in findings:
        code = codes.get(f.file, "")
        if not code:
            continue
        path = generate_poc(f, code)
        if path:
            results.append({"finding": f, "poc_path": path, "status": "generated"})
        else:
            results.append({"finding": f, "poc_path": None, "status": "failed"})
    return results
