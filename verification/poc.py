"""Safe, reproducible execution wrapper for repository-owned Foundry PoCs."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class PocStatus(str, Enum):
    PASSED = "Passed"
    FAILED = "Failed"
    INCONCLUSIVE = "Inconclusive"


@dataclass(frozen=True)
class PocResult:
    poc_file: str
    status: PocStatus
    reason: str
    output: str = ""


def _safe_poc_path(poc_path: Path, project_root: Path) -> Path:
    resolved_poc = poc_path.resolve()
    resolved_root = project_root.resolve()
    if resolved_root not in resolved_poc.parents:
        raise ValueError("PoC path must be inside the project root")
    if not resolved_poc.name.endswith(".t.sol"):
        raise ValueError("PoC file must use the .t.sol suffix")
    return resolved_poc


def run_foundry_poc(
    poc_path: str | Path,
    project_root: str | Path,
    timeout_seconds: int = 120,
) -> PocResult:
    """Run one repository-owned PoC with no shell and no network access."""
    poc = Path(poc_path)
    root = Path(project_root)
    try:
        safe_poc = _safe_poc_path(poc, root)
    except (OSError, ValueError) as exc:
        return PocResult(str(poc), PocStatus.INCONCLUSIVE, str(exc))

    forge = shutil.which("forge")
    if not forge:
        return PocResult(
            str(safe_poc),
            PocStatus.INCONCLUSIVE,
            "Foundry forge is not installed",
        )

    source = safe_poc.read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="defiaudit_poc_") as temporary:
        temporary_root = Path(temporary)
        test_dir = temporary_root / "test"
        test_dir.mkdir()
        (temporary_root / "foundry.toml").write_text(
            "[profile.default]\nsolc_version = '0.8.25'\n\n",
            encoding="utf-8",
        )
        test_file = test_dir / safe_poc.name
        test_file.write_text(source, encoding="utf-8")
        command = [
            forge,
            "test",
            "--root",
            str(temporary_root),
            "--match-path",
            f"test/{safe_poc.name}",
            "--offline",
            "--no-match-coverage",
        ]
        try:
            process = subprocess.run(
                command,
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return PocResult(str(safe_poc), PocStatus.FAILED, "PoC timed out")
        except OSError as exc:
            return PocResult(str(safe_poc), PocStatus.INCONCLUSIVE, str(exc))

    output = (process.stdout + process.stderr)[-4000:]
    if process.returncode == 0:
        return PocResult(str(safe_poc), PocStatus.PASSED, "Foundry test passed", output)
    return PocResult(str(safe_poc), PocStatus.FAILED, "Foundry test failed", output)


__all__ = ["PocResult", "PocStatus", "run_foundry_poc"]
