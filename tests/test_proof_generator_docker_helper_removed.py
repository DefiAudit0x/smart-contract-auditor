"""Deletion lock for the legacy Docker PoC helper, and a mocked
proof that the surviving Docker path is the provisioned one.

``run_foundry_test_docker`` was deleted: a whole-repo grep at the
time of deletion found zero callers and zero documented uses (no
code, test, README, or workflow referenced it), and it could never
have run a forge-std-importing PoC — it wrote no foundry.toml
remappings and provided no forge-std, unlike ``run_foundry_test``,
which assembles the project via ``_build_poc_project`` (with
``_provide_forge_std``) before mounting it into the ``--network
none`` container. Giving the dead helper the same provisioning
would have meant duplicating that assembly for zero users, so it
was removed instead of fixed. Use ``run_foundry_test(...,
use_docker=True, victim_code=...)`` for Docker PoC execution.

No test here depends on a real docker, forge, or network:
toolchains are faked with monkeypatched ``shutil.which`` and
``subprocess.run`` (the PR #45 lesson: never assert real
toolchain presence or absence).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import proof_generator as pg

POC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";
import "../src/Victim.sol";
contract T is Test {
    function testPoC() public {}
}
"""

VICTIM = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract V {}
"""


def _fake_forge_std(root: Path) -> Path:
    src = root / "forge-std-src" / "src"
    src.mkdir(parents=True)
    (src / "Test.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
        "contract Test {}\n",
        encoding="utf-8",
    )
    return root / "forge-std-src"


def test_run_foundry_test_docker_is_deleted():
    assert not hasattr(pg, "run_foundry_test_docker")
    # _has_docker existed only to serve the deleted helper;
    # run_foundry_test consults shutil.which("docker") directly.
    assert not hasattr(pg, "_has_docker")


def test_run_foundry_test_docker_path_is_provisioned_and_proves(
    tmp_path, monkeypatch
):
    """Surviving Docker path: host-side forge-std, network-none mount.

    Faked docker presence, faked FORGE_STD_PATH checkout, and a
    faked `forge test` summary — no container is ever started.
    The captured command must be the network-none Docker run
    against the foundry image, and a passing summary must map to
    PROVED (the deleted helper returned a raw string with no
    PROVED/DISPROVED/INCONCLUSIVE semantics at all).
    """
    fake = _fake_forge_std(tmp_path)
    monkeypatch.setenv("FORGE_STD_PATH", str(fake))
    monkeypatch.setattr(
        pg.shutil,
        "which",
        lambda name: "/usr/bin/docker" if name == "docker" else None,
    )
    seen = {}

    class _Proc:
        stdout = "Ran 1 test suite: 1 passed, 0 failed\n"
        stderr = ""
        returncode = 0

    def _fake_run(command, **kwargs):
        seen["command"] = list(command)
        return _Proc()

    monkeypatch.setattr(pg.subprocess, "run", _fake_run)
    poc = tmp_path / "PoC.t.sol"
    poc.write_text(POC, encoding="utf-8")
    result = pg.run_foundry_test(str(poc), use_docker=True, victim_code=VICTIM)
    assert result["status"] == "PROVED"
    assert result["passed"] is True
    command = seen["command"]
    assert command[0] == "docker"
    assert "--network" in command and "none" in command
    assert "--read-only" in command
    assert "ghcr.io/foundry-rs/foundry:latest" in command
    assert "forge" in command and "test" in command
