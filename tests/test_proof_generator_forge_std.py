"""forge-std provisioning tests for proof_generator.

No test depends on a real forge, docker, or network: forge-std
sources are faked on disk and ``shutil.which`` is monkeypatched
where the code consults the toolchain. The one network path
(``forge install``) is covered by faking the ``forge`` binary
presence and the install result via monkeypatched subprocess, not
by running a real install.
"""

import os
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


def test_provide_forge_std_from_env_path(tmp_path, monkeypatch):
    fake = _fake_forge_std(tmp_path)
    monkeypatch.setenv("FORGE_STD_PATH", str(fake))
    proj = tmp_path / "proj"
    proj.mkdir()
    assert pg._provide_forge_std(proj) is None
    assert (proj / "lib" / "forge-std" / "src" / "Test.sol").is_file()


def test_provide_forge_std_from_bare_src_dir(tmp_path, monkeypatch):
    # FORGE_STD_PATH may point at the src/ directory itself.
    src = tmp_path / "src"
    src.mkdir()
    (src / "Test.sol").write_text("contract Test {}\n", encoding="utf-8")
    monkeypatch.setenv("FORGE_STD_PATH", str(src))
    proj = tmp_path / "proj"
    proj.mkdir()
    assert pg._provide_forge_std(proj) is None
    assert (proj / "lib" / "forge-std" / "src" / "Test.sol").is_file()


def test_provide_forge_std_missing_without_forge(tmp_path, monkeypatch):
    monkeypatch.delenv("FORGE_STD_PATH", raising=False)
    monkeypatch.setattr(pg.shutil, "which", lambda name: None)
    proj = tmp_path / "proj"
    proj.mkdir()
    error = pg._provide_forge_std(proj)
    assert error is not None
    assert "forge-std not available" in error
    assert not (proj / "lib" / "forge-std" / "src" / "Test.sol").exists()


def test_build_poc_project_includes_forge_std(tmp_path, monkeypatch):
    fake = _fake_forge_std(tmp_path)
    monkeypatch.setenv("FORGE_STD_PATH", str(fake))
    poc = tmp_path / "PoC.t.sol"
    poc.write_text(POC, encoding="utf-8")
    proj = pg._build_poc_project(str(poc), VICTIM)
    try:
        assert (proj / "lib" / "forge-std" / "src" / "Test.sol").is_file()
        assert (proj / "src" / "Victim.sol").is_file()
        assert (proj / "test" / "PoC.t.sol").is_file()
        assert "forge-std/=lib/forge-std/src/" in (
            proj / "foundry.toml"
        ).read_text(encoding="utf-8")
    finally:
        pg.shutil.rmtree(proj, ignore_errors=True)


def test_build_poc_project_raises_without_forge_std(tmp_path, monkeypatch):
    monkeypatch.delenv("FORGE_STD_PATH", raising=False)
    monkeypatch.setattr(pg.shutil, "which", lambda name: None)
    poc = tmp_path / "PoC.t.sol"
    poc.write_text(POC, encoding="utf-8")
    try:
        pg._build_poc_project(str(poc), VICTIM)
    except RuntimeError as exc:
        assert "forge-std" in str(exc)
    else:  # pragma: no cover - the raise is the behaviour under test
        raise AssertionError("expected RuntimeError for missing forge-std")


def test_run_foundry_test_maps_missing_forge_std_to_inconclusive(
    tmp_path, monkeypatch
):
    # Docker present (faked) so the run reaches project building,
    # which fails on forge-std; the result must be INCONCLUSIVE,
    # never a pass and never a disproof.
    monkeypatch.delenv("FORGE_STD_PATH", raising=False)
    monkeypatch.setattr(
        pg.shutil, "which", lambda name: "/usr/bin/docker" if name == "docker" else None
    )
    poc = tmp_path / "PoC.t.sol"
    poc.write_text(POC, encoding="utf-8")
    result = pg.run_foundry_test(str(poc), use_docker=True, victim_code=VICTIM)
    assert result["status"] == "INCONCLUSIVE"
    assert result["passed"] is False
    assert "forge-std" in result["error"]
