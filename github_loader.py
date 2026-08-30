import logging
import os
import re
import requests
from typing import List, Dict, Optional, Tuple

from security_utils import validate_github_repository_url

if not logging.getLogger().hasHandlers():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def extract_repo_info(repo_url: str) -> Tuple[Optional[str], Optional[str]]:
    parsed = validate_github_repository_url(repo_url)
    if parsed:
        return parsed
    return None, None


SUPPORTED_EXTS: tuple = (".sol", ".vy", ".move", ".clsp", ".clib", ".rs", ".py")
MAX_FILES_LIMIT = 20
# L-28: cap per-file downloads so a huge blob cannot exhaust memory, and
# authenticate raw-file requests when a token is available so private
# repositories do not silently fail after a successful listing.
MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024


def get_all_sol_files(username: str, repo_name: str, github_token: Optional[str] = None) -> List[Dict[str, str]]:
    api_base = f"https://api.github.com/repos/{username}/{repo_name}"
    headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    try:
        r = requests.get(api_base, headers=headers, timeout=15)
        r.raise_for_status()
        default_branch = r.json().get("default_branch", "main")
        logger.info(f"✅ Repository accessed. Branch: {default_branch}")

        tree_url = f"{api_base}/git/trees/{default_branch}?recursive=1"
        r = requests.get(tree_url, headers=headers, timeout=30)
        r.raise_for_status()
        tree_data = r.json()

        sol_paths = []
        for item in tree_data.get("tree", []):
            if item["type"] == "blob" and any(item["path"].endswith(ext) for ext in SUPPORTED_EXTS):
                sol_paths.append(item["path"])
        sol_paths.sort(key=lambda p: (
            "test" in p.lower() or "mock" in p.lower() or "migration" in p.lower(),
        ))
        sol_paths = sol_paths[:MAX_FILES_LIMIT]

        contracts = []
        # L-28: prefer the caller-supplied token, fall back to the env —
        # raw.githubusercontent requests for private repos 404 without it.
        gh_token = (github_token or "").strip() or os.getenv("GITHUB_TOKEN", "").strip()
        dl_headers = {"Authorization": f"Bearer {gh_token}"} if gh_token else {}
        for path in sol_paths:
            raw_url = f"https://raw.githubusercontent.com/{username}/{repo_name}/{default_branch}/{path}"
            try:
                with requests.get(raw_url, timeout=15, headers=dl_headers, stream=True) as r:
                    if r.status_code != 200:
                        logger.warning(f"⚠️ Failed to download {path}: HTTP {r.status_code}")
                        continue
                    chunks, total = [], 0
                    for chunk in r.iter_content(chunk_size=65536):
                        total += len(chunk)
                        if total > MAX_DOWNLOAD_BYTES:
                            raise ValueError(f"{path} exceeds {MAX_DOWNLOAD_BYTES} byte download cap")
                        chunks.append(chunk)
                    contracts.append({"name": path, "code": b"".join(chunks).decode("utf-8", errors="replace")})
                    logger.info(f"✅ Found: {path}")
            except Exception as e:
                logger.warning(f"⚠️ Error downloading {path}: {e}")

        logger.info(f"📊 Found {len(contracts)} contract(s).")
        return contracts

    except requests.exceptions.RequestException as e:
        logger.error(f"❌ GitHub API request failed: {e}")
        return []


def download_contracts(repo_url: str, github_token: Optional[str] = None) -> List[Dict[str, str]]:
    username, repo_name = extract_repo_info(repo_url)
    if not username or not repo_name:
        logger.error("❌ Invalid GitHub URL. Must be: https://github.com/username/repo")
        return []

    logger.info(f"🔍 Connecting to: {username}/{repo_name} ...")
    return get_all_sol_files(username, repo_name, github_token)
