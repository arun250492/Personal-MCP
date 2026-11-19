"""Shared helpers for the triage checks."""

from __future__ import annotations

import logging
import ssl
from typing import Any, Literal

import httpx

from .._version import __version__
from ..netguard import NetPolicy

# httpx logs every request URL at INFO; keep checked targets out of server logs.
logging.getLogger("httpx").setLevel(logging.WARNING)

Status = Literal["pass", "warn", "fail", "info"]

USER_AGENT = f"IsItMe-Triage/{__version__} (+https://github.com/arun250492/Personal-MCP)"

STATUS_ICON = {"pass": "✅", "warn": "⚠️", "fail": "❌", "info": "ℹ️"}


def finding(check: str, status: Status, title: str, detail: str = "", fix: str = "") -> dict[str, Any]:
    f: dict[str, Any] = {"check": check, "status": status, "title": title}
    if detail:
        f["detail"] = detail
    if fix:
        f["fix"] = fix
    return f


def worst(findings: list[dict[str, Any]]) -> Status:
    order = {"fail": 3, "warn": 2, "pass": 1, "info": 0}
    if not findings:
        return "info"
    top = max(findings, key=lambda f: order[f["status"]])["status"]
    return "pass" if top == "info" else top


def ssl_context(policy: NetPolicy, verify: bool = True) -> ssl.SSLContext:
    if not verify:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    ctx = ssl.create_default_context()
    if policy.ca_file:
        ctx.load_verify_locations(cafile=policy.ca_file)
    return ctx


def api_client(policy: NetPolicy, timeout: float | None = None) -> httpx.AsyncClient:
    """Client for fixed, trusted endpoints (DNS-over-HTTPS, vendor status pages)."""
    return httpx.AsyncClient(
        timeout=timeout or policy.total_timeout,
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
        trust_env=policy.trust_env,
    )


def text_report(title: str, findings: list[dict[str, Any]], extra: list[str] | None = None) -> str:
    lines = [title]
    for f in findings:
        line = f"{STATUS_ICON[f['status']]} {f['title']}"
        if f.get("detail"):
            line += f" — {f['detail']}"
        lines.append(line)
        if f.get("fix"):
            lines.append(f"   ↳ Fix: {f['fix']}")
    if extra:
        lines.extend(extra)
    return "\n".join(lines)
