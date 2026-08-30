import os, json, logging, html
import ipaddress
import socket
from typing import Dict, List, Optional
from urllib.parse import urlsplit
from datetime import datetime, timezone
from analyzers.base import Finding

logger = logging.getLogger(__name__)

# Optional egress allowlist: set WEBHOOK_ALLOWED_HOSTS="discord.com,hooks.slack.com"
# to hard-restrict outbound webhooks; when unset any public HTTPS host is allowed.
WEBHOOK_ALLOWED_HOSTS = {
    h.strip().lower()
    for h in os.environ.get("WEBHOOK_ALLOWED_HOSTS", "").split(",")
    if h.strip()
}

DISCORD_COLORS = {
    "Critical": 15158332,
    "High": 15105570,
    "Medium": 15844367,
    "Low": 3066993,
    "Info": 1752220,
    "Gas": 10181046,
}

SLACK_COLORS = {
    "Critical": "#e74c3c",
    "High": "#e67e22",
    "Medium": "#f1c40f",
    "Low": "#3498db",
    "Info": "#95a5a6",
    "Gas": "#9b59b6",
}


def _severity_emoji(sev: str) -> str:
    return {
        "Critical": "🔴",
        "High": "🟠",
        "Medium": "🟡",
        "Low": "🔵",
        "Info": "ℹ️",
        "Gas": "⛽",
    }.get(sev, "⚪")


def _truncate(text: str, maxlen: int = 500) -> str:
    return text[:maxlen] + "..." if len(text) > maxlen else text


# ──────────────────────────────────────────
# Discord
# ──────────────────────────────────────────

def send_discord_webhook(
    webhook_url: str,
    findings: List[Finding],
    project: str = "",
    summary: Optional[Dict] = None,
):
    if not webhook_url:
        return
    payload = _build_discord_payload(findings, project, summary)
    if payload and "embeds" in payload:
        _post_webhook(webhook_url, payload)


def _build_discord_payload(
    findings: List[Finding],
    project: str = "",
    summary: Optional[Dict] = None,
) -> Dict:
    if not findings:
        return {"embeds": [{"title": "✅ No vulnerabilities found", "color": 3066993}]}

    embeds = []
    color = DISCORD_COLORS.get(findings[0].severity, 1752220)

    embed = {
        "title": f"Smart Contract Audit Report{' - ' + project if project else ''}",
        "color": color,
        # Discord rejects '+00:00Z'; the ISO-8601 'Z' suffix is the valid form
        # (M14 remediation).
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    if summary:
        total = summary.get("total", len(findings))
        embed["description"] = (
            f"**{total}** findings: "
            + " ".join(
                f"{_severity_emoji(k)} **{k}**: {v}"
                for k, v in summary.get("severity", {}).items()
            )
        )

    details = []
    for f in findings[:10]:
        details.append(
            f"{_severity_emoji(f.severity)} **[{f.severity}]** {_truncate(f.description, 200)}\n"
            f"└ {f.file}:{f.line} | {f.category}"
        )

    if len(findings) > 10:
        details.append(f"\n... and {len(findings) - 10} more findings")

    # Field value limit is 1024 chars (embed total 6000): chunk details into
    # ≤1000-char fields, keep at most 5 fields per embed, and note overflow
    # instead of silently dropping the whole notification with HTTP 400
    # (M14 remediation).
    fields = []
    current = []
    current_len = 0
    for d in details:
        d = d[:1000]
        if current and current_len + len(d) > 1000:
            fields.append(current)
            current = []
            current_len = 0
        current.append(d)
        current_len += len(d)
    if current:
        fields.append(current)

    max_fields = 5
    embed_fields = []
    for i, chunk in enumerate(fields[:max_fields]):
        embed_fields.append({
            "name": f"Findings ({i + 1})",
            "value": "\n\n".join(chunk)[:1000],
            "inline": False,
        })
    if len(fields) > max_fields:
        embed_fields.append({
            "name": "Findings (truncated)",
            "value": f"Report too large for Discord embeds — {len(findings)} findings total; see the full report.",
            "inline": False,
        })
    embed["fields"] = embed_fields
    embed["footer"] = {"text": "Smart Contract Auditor"}

    embeds.append(embed)

    return {"embeds": embeds}


# ──────────────────────────────────────────
# Slack
# ──────────────────────────────────────────

def send_slack_webhook(
    webhook_url: str,
    findings: List[Finding],
    project: str = "",
    summary: Optional[Dict] = None,
):
    if not webhook_url:
        return
    payload = _build_slack_payload(findings, project, summary)
    if payload:
        _post_webhook(webhook_url, payload)


def _build_slack_payload(
    findings: List[Finding],
    project: str = "",
    summary: Optional[Dict] = None,
) -> Dict:
    if not findings:
        return {"blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": "✅ No vulnerabilities found"}}]}

    blocks = []

    title = f"*Smart Contract Audit Report{' - ' + project if project else ''}*"
    blocks.append({"type": "header", "text": {"type": "plain_text", "text": f"Audit Report {project}" if project else "Audit Report", "emoji": True}})

    if summary:
        sev_parts = []
        for k, v in summary.get("severity", {}).items():
            color = SLACK_COLORS.get(k, "#95a5a6")
            sev_parts.append(f"*{k}*: {v}")
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{summary.get('total', len(findings))}* findings | {' · '.join(sev_parts)}"},
        })

    blocks.append({"type": "divider"})

    for f in findings[:10]:
        color = SLACK_COLORS.get(f.severity, "#95a5a6")
        emoji = _severity_emoji(f.severity)
        text = (
            f"{emoji} *[{f.severity}]* {_truncate(f.description, 300)}\n"
            f"`{f.file}:{f.line}` • {f.category}"
        )
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": text},
        })

    if len(findings) > 10:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"... and {len(findings) - 10} more findings"},
        })

    return {"text": f"Audit Report: {len(findings)} findings", "blocks": blocks}


# ──────────────────────────────────────────
# Common
# ──────────────────────────────────────────

def _assert_webhook_url(url: str):
    """Outbound-webhook guard (M13 remediation): https only, optionally
    allow-listed via WEBHOOK_ALLOWED_HOSTS, and never resolving to
    private/link-local space — the first web-facing caller of this module
    must not become an SSRF primitive against 169.254.169.254 or internal
    admin panels."""
    parts = urlsplit(url or "")
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("Webhook URL must be https with a hostname")
    if WEBHOOK_ALLOWED_HOSTS and parts.hostname.lower() not in WEBHOOK_ALLOWED_HOSTS:
        raise ValueError("Webhook host is not in WEBHOOK_ALLOWED_HOSTS")
    try:
        addr_infos = socket.getaddrinfo(parts.hostname, 443)
    except socket.gaierror as e:
        raise ValueError(f"Webhook host does not resolve: {e}")
    for _fam, _type, _proto, _canonname, sa in addr_infos:
        ip = ipaddress.ip_address(sa[0])
        if ip.is_private or ip.is_link_local or ip.is_loopback:
            raise ValueError("Webhook host resolves to a private/link-local address")


def _post_webhook(url: str, payload: Dict):
    try:
        _assert_webhook_url(url)
        import requests
        # No redirect follow-through: a 3xx must not turn an allowed host
        # into a smuggled internal target.
        resp = requests.post(url, json=payload, timeout=15, allow_redirects=False)
        if resp.status_code not in (200, 204):
            logger.warning(f"Webhook returned {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        logger.error(f"Webhook error: {e}")


def send_report(
    webhook_url: str,
    findings: List[Finding],
    webhook_type: str = "discord",
    project: str = "",
    summary: Optional[Dict] = None,
):
    if webhook_type == "slack":
        send_slack_webhook(webhook_url, findings, project, summary)
    else:
        send_discord_webhook(webhook_url, findings, project, summary)
