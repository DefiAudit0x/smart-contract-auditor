"""Regression tests for PHASE 7 input and execution hardening."""

import stat
import zipfile
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from env_check import EnvChecker
from github_loader import extract_repo_info
from web_ui import _safe_report_path
from security_utils import (
    extract_zip_safely,
    normalize_relative_member,
    validate_github_repository_url,
    validate_zip_infos,
)


def test_github_url_accepts_only_canonical_https_repositories():
    assert validate_github_repository_url("https://github.com/DefiAudit0x/smart-contract-auditor") == (
        "DefiAudit0x",
        "smart-contract-auditor",
    )
    assert extract_repo_info("https://github.com/DefiAudit0x/smart-contract-auditor.git") == (
        "DefiAudit0x",
        "smart-contract-auditor",
    )
    for value in (
        "http://github.com/a/b",
        "https://evil.example/github.com/a/b",
        "https://github.com@evil.example/a/b",
        "https://github.com:443/a/b",
        "https://github.com/a/b?redirect=http://169.254.169.254",
        "https://github.com/a/b/tree/main",
    ):
        assert validate_github_repository_url(value) is None
        assert extract_repo_info(value) == (None, None)


def test_archive_relative_paths_reject_traversal_and_windows_drives():
    for value in ("../escape.sol", "/absolute.sol", "C:\\escape.sol", "a/../../b.sol", "bad\x00.sol"):
        with pytest.raises(ValueError):
            normalize_relative_member(value)


def test_archive_rejects_symlink_members():
    info = zipfile.ZipInfo("link.sol")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(__import__("io").BytesIO(), "w") as archive:
        archive.writestr(info, "../../etc/passwd")
        with pytest.raises(ValueError, match="symlinks"):
            validate_zip_infos(archive)


def test_archive_member_limit_is_enforced():
    with zipfile.ZipFile(__import__("io").BytesIO(), "w") as archive:
        archive.writestr("one.sol", "contract One {}")
        archive.writestr("two.sol", "contract Two {}")
        with pytest.raises(ValueError, match="too many"):
            validate_zip_infos(archive, max_members=1)


def test_env_checker_uses_argument_lists_without_shell():
    with patch("env_check.subprocess.run", return_value=SimpleNamespace(stdout="ok", stderr="", returncode=0)) as run:
        assert EnvChecker()._cmd("forge --version")[0] is True
    args, kwargs = run.call_args
    assert args[0] == ["forge", "--version"]
    assert kwargs["shell"] is False


def test_report_path_rejects_traversal_and_absolute_names():
    assert _safe_report_path("../secret.txt") is None
    assert _safe_report_path("/etc/passwd") is None
    assert _safe_report_path("nested/report.txt") is None


def test_archive_rejects_scripts():
    with zipfile.ZipFile(__import__("io").BytesIO(), "w") as archive:
        archive.writestr("run.sh", "echo unsafe")
        with pytest.raises(ValueError, match="executable or script"):
            validate_zip_infos(archive)


def test_safe_extraction_preserves_nested_source_and_rejects_scripts(tmp_path):
    buffer = __import__("io").BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("src/Contract.sol", "contract Contract {}")
    buffer.seek(0)
    with zipfile.ZipFile(buffer, "r") as archive:
        extracted = extract_zip_safely(archive, tmp_path)
    assert extracted == [tmp_path / "src" / "Contract.sol"]
    assert extracted[0].read_text(encoding="utf-8") == "contract Contract {}"
