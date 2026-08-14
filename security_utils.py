"""Small, dependency-light security guards shared by HTTP and archive paths."""

from __future__ import annotations

import os
import re
import shutil
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit


MAX_ZIP_MEMBERS = 1000
MAX_ZIP_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
_GITHUB_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_BLOCKED_ARCHIVE_EXTENSIONS = (".exe", ".sh", ".bat", ".cmd", ".dll", ".so", ".dylib", ".ps1")
_BLOCKED_ARCHIVE_DIRS = {"__pycache__", "node_modules"}


def normalize_relative_member(name: str) -> str:
    """Return a safe POSIX-relative archive member or raise ValueError."""
    if not isinstance(name, str) or not name or "\x00" in name:
        raise ValueError("archive member has an invalid name")
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if normalized.startswith("/") or path.is_absolute():
        raise ValueError("archive member must be relative")
    if re.match(r"^[A-Za-z]:", normalized) or ".." in path.parts:
        raise ValueError("archive member contains path traversal")
    cleaned = "/".join(part for part in path.parts if part not in ("", "."))
    if not cleaned:
        raise ValueError("archive member has an empty path")
    return cleaned


def validate_zip_infos(
    archive: zipfile.ZipFile,
    *,
    allowed_extensions: tuple[str, ...] | None = None,
    max_members: int = MAX_ZIP_MEMBERS,
    max_uncompressed_bytes: int = MAX_ZIP_UNCOMPRESSED_BYTES,
) -> list[tuple[zipfile.ZipInfo, str]]:
    """Validate archive names, symlinks, member count, and expansion size."""
    infos = archive.infolist()
    if len(infos) > max_members:
        raise ValueError("archive contains too many members")
    total = 0
    validated: list[tuple[zipfile.ZipInfo, str]] = []
    for info in infos:
        normalized = normalize_relative_member(info.filename)
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000:
            raise ValueError("archive symlinks are not allowed")
        if any(part in _BLOCKED_ARCHIVE_DIRS for part in PurePosixPath(normalized).parts):
            raise ValueError("archive contains blocked dependency/cache directories")
        if not info.is_dir() and normalized.lower().endswith(_BLOCKED_ARCHIVE_EXTENSIONS):
            raise ValueError("archive contains an executable or script")
        if info.file_size < 0 or info.file_size > max_uncompressed_bytes:
            raise ValueError("archive member is too large")
        total += info.file_size
        if total > max_uncompressed_bytes:
            raise ValueError("archive expands beyond the allowed size")
        if allowed_extensions and not info.is_dir():
            if not normalized.lower().endswith(allowed_extensions):
                continue
        validated.append((info, normalized))
    return validated


def extract_zip_safely(
    archive: zipfile.ZipFile,
    destination: str | Path,
    *,
    allowed_extensions: tuple[str, ...] | None = None,
) -> list[Path]:
    """Extract validated regular files without using unsafe archive extraction."""
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    for info, normalized in validate_zip_infos(archive, allowed_extensions=allowed_extensions):
        target = (root / normalized).resolve()
        if os.path.commonpath((str(root), str(target))) != str(root):
            raise ValueError("archive member escapes destination")
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(info, "r") as source, target.open("wb") as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)
        extracted.append(target)
    return extracted


def validate_github_repository_url(value: str) -> tuple[str, str] | None:
    """Accept only canonical HTTPS github.com owner/repository URLs."""
    if not isinstance(value, str) or len(value) > 512:
        return None
    parsed = urlsplit(value.strip())
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        return None
    if parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
        return None
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 2:
        return None
    owner, repo = parts
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo or not _GITHUB_NAME.fullmatch(owner) or not _GITHUB_NAME.fullmatch(repo):
        return None
    return owner, repo
